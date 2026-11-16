"""Insights for Pro / MSP: the management report, trends, the rule-tuning advisor and MSP usage.

All numbers come straight from the database. Every query is limited to the SIEMs the signed-in user may
see (admins and unrestricted users: all), so an MSP customer's viewer only ever sees their own figures.
"""
import os
from datetime import datetime, timedelta, timezone

from db import get_connection

MINUTES_PER_ALERT = max(1, int(os.getenv("ARDEA_MINUTES_PER_ALERT", "10") or 10))
CLOSING = ("Benign Positive", "False Positive")
# Tactics the tuning advisor never suggests silencing (same spirit as the never_auto_close playbooks).
NEVER_TUNE_TACTICS = ("Credential Access", "Lateral Movement", "Impact", "Exfiltration")
RANGES = {"7d": 7, "30d": 30, "90d": 90}


# --------------------------------------------------------------------------- period + scope
def period_from_args(args, now=None) -> dict:
    """?range=7d|30d|90d or ?month=YYYY-MM. Returns start/end (UTC) and a label."""
    now = now or datetime.now(timezone.utc)
    month = (args.get("month") or "").strip()
    if month:
        try:
            start = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
        except ValueError:
            start = None
        if start:
            end = (start + timedelta(days=32)).replace(day=1)
            return {"start": start, "end": end, "label": start.strftime("%B %Y"), "key": f"month={month}",
                    "range": "", "month": month}
    rng = args.get("range") if args.get("range") in RANGES else "30d"
    days = RANGES[rng]
    return {"start": now - timedelta(days=days), "end": now, "label": f"Last {days} days", "key": f"range={rng}",
            "range": rng, "month": ""}


def scope_siems(user, requested: str | None, all_siems: list[dict]) -> list[str] | None:
    """SIEM ids to include: None = all. A requested SIEM the user may not see yields an empty scope."""
    allowed = None if user["role"] == "admin" or user.get("siem_access") is None else list(user["siem_access"])
    if requested:
        if allowed is not None and requested not in allowed:
            return []
        return [requested]
    return allowed


def _params(period, siems, first_siem):
    return {"start": period["start"], "end": period["end"], "siems": siems, "first": first_siem or ""}


_SCOPED = """
    SELECT a.alert_id, COALESCE(a.siem, %(first)s) AS siem, COALESCE(a.count, 1) AS raw, a.rule_name, a.rule_id,
           a.host_name, a.user_name, a.process_executable, a.parent_executable,
           t.verdict, t.severity, t.confidence, t.duration_ms, t.created_at, t.result
    FROM triage_results t JOIN alerts a USING (alert_id)
    WHERE t.created_at >= %(start)s AND t.created_at < %(end)s
      AND (%(siems)s::text[] IS NULL OR COALESCE(a.siem, %(first)s) = ANY(%(siems)s::text[]))"""

_LATEST_FEEDBACK = """
    SELECT DISTINCT ON (alert_id) alert_id, agrees, correct_verdict FROM feedback
    ORDER BY alert_id, created_at DESC"""


# --------------------------------------------------------------------------- report
def report(period, siems, first_siem) -> dict:
    p = _params(period, siems, first_siem)
    with get_connection() as conn:
        totals = conn.execute(f"""
            WITH s AS ({_SCOPED})
            SELECT count(*) AS alerts, COALESCE(sum(raw), 0) AS raw,
                   count(*) FILTER (WHERE verdict = 'True Positive') AS tp,
                   count(*) FILTER (WHERE verdict = 'Needs Human Review') AS review,
                   count(*) FILTER (WHERE verdict = 'Benign Positive') AS bp,
                   count(*) FILTER (WHERE verdict = 'False Positive') AS fp,
                   COALESCE(sum(raw) FILTER (WHERE verdict IN ('Benign Positive', 'False Positive')), 0) AS closed_raw,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) AS median_ms
            FROM s""", p).fetchone()
        fb = conn.execute(f"""
            WITH s AS ({_SCOPED}), f AS ({_LATEST_FEEDBACK})
            SELECT count(*) AS reviewed,
                   count(*) FILTER (WHERE f.agrees) AS agreed,
                   count(*) FILTER (WHERE s.verdict IN ('Benign Positive', 'False Positive')) AS closed_reviewed,
                   count(*) FILTER (WHERE s.verdict IN ('Benign Positive', 'False Positive')
                                    AND (f.agrees OR f.correct_verdict IN ('Benign Positive', 'False Positive')))
                       AS closed_correct
            FROM s JOIN f USING (alert_id)""", p).fetchone()
        tps = conn.execute(f"""
            WITH s AS ({_SCOPED})
            SELECT alert_id, siem, rule_name, host_name, severity, confidence, created_at,
                   left(result->>'summary', 220) AS summary
            FROM s WHERE verdict = 'True Positive' ORDER BY created_at DESC LIMIT 25""", p).fetchall()
        rules = conn.execute(f"""
            WITH s AS ({_SCOPED})
            SELECT rule_name, count(*) AS alerts, sum(raw) AS raw,
                   count(*) FILTER (WHERE verdict IN ('Benign Positive', 'False Positive')) AS closed,
                   count(*) FILTER (WHERE verdict = 'True Positive') AS tp,
                   count(*) FILTER (WHERE verdict = 'Needs Human Review') AS review
            FROM s GROUP BY rule_name ORDER BY sum(raw) DESC, rule_name LIMIT 10""", p).fetchall()
    t = dict(totals)
    closed = t["bp"] + t["fp"]
    t["closed"] = closed
    t["to_person"] = t["tp"] + t["review"]
    t["closed_pct"] = round(100 * closed / t["alerts"]) if t["alerts"] else 0
    t["hours_saved"] = round(t["closed_raw"] * MINUTES_PER_ALERT / 60, 1)
    t["median_min"] = round(t["median_ms"] / 60000, 1) if t["median_ms"] else None
    f = dict(fb)
    f["agreement_pct"] = round(100 * f["agreed"] / f["reviewed"]) if f["reviewed"] else None
    f["closure_accuracy_pct"] = (round(100 * f["closed_correct"] / f["closed_reviewed"])
                                 if f["closed_reviewed"] else None)
    for r in rules:
        r["closed_pct"] = round(100 * r["closed"] / r["alerts"]) if r["alerts"] else 0
    return {"totals": t, "feedback": f, "true_positives": tps, "rules": rules,
            "minutes_per_alert": MINUTES_PER_ALERT}


# --------------------------------------------------------------------------- trends
def trends(siems, first_siem, weeks: int = 12, now=None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    start = (now - timedelta(weeks=weeks)).replace(hour=0, minute=0, second=0, microsecond=0)
    p = _params({"start": start, "end": now}, siems, first_siem)
    with get_connection() as conn:
        rows = conn.execute(f"""
            WITH s AS ({_SCOPED}), f AS ({_LATEST_FEEDBACK})
            SELECT date_trunc('week', s.created_at) AS week, count(*) AS alerts,
                   count(*) FILTER (WHERE verdict = 'True Positive') AS tp,
                   count(*) FILTER (WHERE verdict = 'Needs Human Review') AS review,
                   count(*) FILTER (WHERE verdict IN ('Benign Positive', 'False Positive')) AS closed,
                   count(f.alert_id) AS reviewed, count(*) FILTER (WHERE f.agrees) AS agreed,
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY s.duration_ms) AS median_ms
            FROM s LEFT JOIN f USING (alert_id)
            GROUP BY 1 ORDER BY 1""", p).fetchall()
    out = []
    for r in rows:
        out.append({"week": r["week"], "alerts": r["alerts"], "tp": r["tp"], "review": r["review"],
                    "closed": r["closed"],
                    "agreement_pct": round(100 * r["agreed"] / r["reviewed"]) if r["reviewed"] else None,
                    "median_min": round(r["median_ms"] / 60000, 1) if r["median_ms"] else None})
    return out


# --------------------------------------------------------------------------- rule tuning
def tuning(siems, first_siem, days: int = 30, min_alerts: int = 5, now=None) -> list[dict]:
    """Repeating patterns that Ardea always closed and no analyst disputed: candidates for an Elastic rule
    exception. Patterns of high-impact tactics, or with any True Positive / review / analyst objection, are
    never suggested."""
    now = now or datetime.now(timezone.utc)
    p = _params({"start": now - timedelta(days=days), "end": now}, siems, first_siem)
    p.update(min_alerts=min_alerts, never=list(NEVER_TUNE_TACTICS))
    with get_connection() as conn:
        rows = conn.execute(f"""
            WITH s AS ({_SCOPED}), f AS ({_LATEST_FEEDBACK})
            SELECT s.siem, s.rule_name, max(s.rule_id) AS rule_id, s.process_executable, s.parent_executable,
                   s.user_name, sum(s.raw) AS raw, count(*) AS alerts,
                   count(DISTINCT s.host_name) AS hosts, min(s.host_name) AS a_host,
                   max(s.created_at) AS last_seen,
                   count(f.alert_id) FILTER (WHERE f.agrees) AS confirmed
            FROM s LEFT JOIN f USING (alert_id)
            WHERE s.process_executable IS NOT NULL
            GROUP BY s.siem, s.rule_name, s.process_executable, s.parent_executable, s.user_name
            HAVING sum(s.raw) >= %(min_alerts)s
               AND bool_and(s.verdict IN ('Benign Positive', 'False Positive'))
               AND NOT bool_or(COALESCE(f.agrees = FALSE AND f.correct_verdict NOT IN
                                        ('Benign Positive', 'False Positive'), FALSE))
               AND NOT bool_or(EXISTS (
                   SELECT 1 FROM jsonb_array_elements(COALESCE(s.result->'rule_mitre', '[]'::jsonb)) m
                   WHERE m->>'tactic' = ANY(%(never)s::text[])))
            ORDER BY sum(s.raw) DESC LIMIT 25""", p).fetchall()
    for r in rows:
        r["entries"] = exception_entries(r)
        r["kql"] = " and ".join(f'{e["field"]} : "{_kql_escape(e["value"])}"' for e in r["entries"])
    return rows


def exception_entries(r) -> list[dict]:
    """Elastic rule-exception entries (Exceptions API format), narrowest sensible match."""
    entries = [{"field": "process.executable", "operator": "included", "type": "match",
                "value": r["process_executable"]}]
    if r.get("parent_executable"):
        entries.append({"field": "process.parent.executable", "operator": "included", "type": "match",
                        "value": r["parent_executable"]})
    if r.get("user_name"):
        entries.append({"field": "user.name", "operator": "included", "type": "match", "value": r["user_name"]})
    if r.get("hosts") == 1 and r.get("a_host"):
        entries.append({"field": "host.name", "operator": "included", "type": "match", "value": r["a_host"]})
    return entries


def _kql_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


# --------------------------------------------------------------------------- MSP usage
def usage(month_start: datetime) -> list[dict]:
    end = (month_start + timedelta(days=32)).replace(day=1)
    with get_connection() as conn:
        return conn.execute("""
            SELECT COALESCE(a.siem, '') AS siem, COALESCE(s.name, a.siem, '') AS siem_name,
                   count(*) AS alerts_triaged, COALESCE(sum(a.count), 0) AS raw_alerts,
                   count(*) FILTER (WHERE t.verdict = 'True Positive') AS true_positive,
                   count(*) FILTER (WHERE t.verdict = 'Needs Human Review') AS needs_review,
                   count(*) FILTER (WHERE t.verdict = 'Benign Positive') AS benign_positive,
                   count(*) FILTER (WHERE t.verdict = 'False Positive') AS false_positive
            FROM triage_results t JOIN alerts a USING (alert_id) LEFT JOIN siems s ON s.id = a.siem
            WHERE t.created_at >= %s AND t.created_at < %s
            GROUP BY 1, 2 ORDER BY 2""", (month_start, end)).fetchall()
