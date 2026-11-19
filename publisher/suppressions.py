"""Suppressions (Pro): close a pattern your analysts keep closing, without an investigation.

Suggestions come from analyst feedback, not from the model: a pattern (rule, program, parent program and
account in one SIEM) that analysts called benign or false at least MIN_CONFIRMED times in the last 30 days,
that no analyst ever called a true positive, with no unreviewed True Positive verdict, and whose rule has no
high-impact tactic. An analyst or admin turns a suggestion into a suppression with a reason and an expiry
(at most MAX_DAYS). The worker applies it (worker/suppress.py); every hit is counted and the alert keeps
a verdict that names the suppression. Suppressions can be revoked at any time.
"""
from datetime import datetime, timedelta, timezone

import insights
from db import get_connection

MIN_CONFIRMED = 3
DEFAULT_DAYS = 90
MAX_DAYS = 365
VERDICTS = ("Benign Positive", "False Positive")


class SuppressionError(Exception):
    pass


def suggestions(siems, first_siem, days: int = 30, now=None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    p = insights._params({"start": now - timedelta(days=days), "end": now}, siems, first_siem)
    p.update(min_confirmed=MIN_CONFIRMED, never=list(insights.NEVER_TUNE_TACTICS))
    with get_connection() as conn:
        rows = conn.execute(f"""
            WITH s AS ({insights._SCOPED}), f AS ({insights._LATEST_FEEDBACK}),
            x AS (SELECT s.*, f.alert_id IS NOT NULL AS reviewed,
                         COALESCE((f.agrees AND s.verdict IN ('Benign Positive', 'False Positive'))
                                  OR (NOT f.agrees AND f.correct_verdict IN ('Benign Positive', 'False Positive')),
                                  FALSE) AS benign,
                         COALESCE((f.agrees AND s.verdict = 'True Positive')
                                  OR (NOT f.agrees AND f.correct_verdict = 'True Positive'), FALSE) AS malicious,
                         CASE WHEN f.agrees THEN s.verdict ELSE f.correct_verdict END AS said
                  FROM s LEFT JOIN f USING (alert_id))
            SELECT siem, rule_name, process_executable, parent_executable, user_name,
                   count(*) AS alerts, count(*) FILTER (WHERE benign) AS confirmed,
                   count(*) FILTER (WHERE verdict = 'Needs Human Review') AS reviews,
                   count(DISTINCT host_name) AS hosts, min(host_name) AS a_host, max(created_at) AS last_seen,
                   mode() WITHIN GROUP (ORDER BY said) FILTER (WHERE benign) AS said
            FROM x WHERE process_executable IS NOT NULL
            GROUP BY siem, rule_name, process_executable, parent_executable, user_name
            HAVING count(*) FILTER (WHERE benign) >= %(min_confirmed)s
               AND NOT bool_or(malicious)
               AND NOT bool_or(verdict = 'True Positive' AND NOT reviewed)
               AND NOT bool_or(EXISTS (
                   SELECT 1 FROM jsonb_array_elements(COALESCE(result->'rule_mitre', '[]'::jsonb)) m
                   WHERE m->>'tactic' = ANY(%(never)s::text[])))
            ORDER BY count(*) FILTER (WHERE verdict = 'Needs Human Review') DESC, count(*) DESC
            LIMIT 25""", p).fetchall()
        active = conn.execute("SELECT * FROM suppressions WHERE revoked_at IS NULL AND expires_at > NOW()").fetchall()
    return [r for r in rows if not any(_covers(s, r) for s in active)]


def _same(a, b):
    return (a or "").strip().lower() == (b or "").strip().lower()


def _covers(s, r) -> bool:
    return (s["siem"] in (None, r["siem"]) and s["rule_name"] == r["rule_name"]
            and _same(s["process_executable"], r["process_executable"])
            and _same(s["parent_executable"], r["parent_executable"]) and _same(s["user_name"], r["user_name"]))


def listing(siems) -> list[dict]:
    """Suppressions in these SIEMs (None = all), active first, then the last 50 ended ones."""
    with get_connection() as conn:
        rows = conn.execute("""SELECT *, (revoked_at IS NULL AND expires_at > NOW()) AS active FROM suppressions
                               WHERE %(s)s::text[] IS NULL OR siem IS NULL OR siem = ANY(%(s)s::text[])
                               ORDER BY (revoked_at IS NULL AND expires_at > NOW()) DESC, id DESC LIMIT 200""",
                            {"s": siems}).fetchall()
    active = [r for r in rows if r["active"]]
    return active + [r for r in rows if not r["active"]][:50]


def create(actor: str, form: dict, can_see) -> int:
    rule = (form.get("rule_name") or "").strip()[:300]
    exe = (form.get("process_executable") or "").strip()[:1000]
    siem = (form.get("siem") or "").strip()[:32] or None
    reason = " ".join((form.get("reason") or "").split())[:500]
    verdict = form.get("verdict") or VERDICTS[0]
    if not rule or not exe:
        raise SuppressionError("A suppression needs the rule and the program.")
    if siem is None or not can_see(siem):
        raise SuppressionError("You don't have access to that SIEM.")
    if verdict not in VERDICTS:
        raise SuppressionError("The verdict must be Benign Positive or False Positive.")
    if len(reason) < 5:
        raise SuppressionError("Say why this pattern is safe: the reason is shown on every alert it closes.")
    try:
        days = int(form.get("days") or DEFAULT_DAYS)
    except ValueError:
        days = DEFAULT_DAYS
    days = max(1, min(MAX_DAYS, days))
    host = (form.get("host_name") or "").strip()[:300] or None
    with get_connection() as conn:
        row = conn.execute("""INSERT INTO suppressions (siem, rule_name, process_executable, parent_executable,
                                  user_name, host_name, verdict, reason, created_by, expires_at)
                              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                           (siem, rule, exe, (form.get("parent_executable") or "").strip()[:1000] or None,
                            (form.get("user_name") or "").strip()[:300] or None, host, verdict, reason, actor,
                            datetime.now(timezone.utc) + timedelta(days=days))).fetchone()
        conn.commit()
    return row["id"]


def revoke(sid: int, actor: str, can_see) -> bool:
    with get_connection() as conn:
        s = conn.execute("SELECT siem FROM suppressions WHERE id = %s AND revoked_at IS NULL", (sid,)).fetchone()
        if not s or (s["siem"] and not can_see(s["siem"])):
            return False
        conn.execute("UPDATE suppressions SET revoked_at = NOW(), revoked_by = %s WHERE id = %s", (actor, sid))
        conn.commit()
    return True
