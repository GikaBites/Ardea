"""Daily handover digest (Pro).

At DIGEST_TIME (server time zone) the worker sends one summary of the last 24 hours to the notification
channels: how many alerts came in, how many Ardea closed with evidence and which rules caused most of
them, what still needs a person (true positives and reviews nobody has looked at), incidents with more
than one alert, and SIEMs or watched hosts that went quiet. Sent once a day: report_runs records it.
"""
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

import appsettings
import config
import incidents
import licensing

log = logging.getLogger("digest")
WINDOW = timedelta(hours=24)
LATE = timedelta(hours=3)                 # a worker that was down at DIGEST_TIME still sends within 3 hours
NEEDS_PERSON = ("True Positive", "Needs Human Review")
SEVERITY_RANK = {s: i for i, s in enumerate(("Critical", "High", "Medium", "Low", "Informational"))}


def due(now_local: datetime) -> str | None:
    """The run key if the digest is due now, else None."""
    at = appsettings.env("DIGEST_TIME", "off")
    if at == "off" or len(at) != 5 or not licensing.has("digest"):
        return None
    try:
        hour, minute = int(at[:2]), int(at[3:])
    except ValueError:
        return None
    target = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now_local < target + LATE:
        return f"digest:{now_local:%Y-%m-%d}"
    return None


def _rows(conn, since: datetime) -> list[dict]:
    return conn.execute("""
        SELECT a.alert_id, a.timestamp, a.host_name, a.user_name, a.siem, a.count, a.rule_name,
               t.verdict, t.severity, t.should_escalate, t.result, s.name AS siem_name,
               (EXISTS (SELECT 1 FROM feedback f WHERE f.alert_id = a.alert_id)
                OR EXISTS (SELECT 1 FROM alert_work w WHERE w.alert_id = a.alert_id AND w.status = 'resolved'))
               AS reviewed
        FROM alerts a JOIN triage_results t ON t.alert_id = a.alert_id
        LEFT JOIN siems s ON s.id = a.siem
        WHERE a.timestamp >= %s ORDER BY a.timestamp""", (since,)).fetchall()


def _as_alert(r: dict) -> dict:
    result = r["result"] if isinstance(r["result"], dict) else {}
    mitre = [{"id": str(m.get("technique_id", ""))[:12], "name": str(m.get("name", ""))[:80]}
             for m in (result.get("mitre_techniques") or [])[:5] if isinstance(m, dict)]
    return {"alert_id": r["alert_id"], "timestamp_raw": r["timestamp"], "hostname": r["host_name"] or "unknown host",
            "user": r["user_name"] or "", "siem": r["siem"] or "", "siem_name": r["siem_name"] or r["siem"] or "",
            "verdict": r["verdict"] or "Unknown", "severity": r["severity"] or "Unknown",
            "rule_name": r["rule_name"] or result.get("rule_name") or "Unknown rule",
            "occurrences": r["count"] or 1, "should_escalate": bool(r["should_escalate"]),
            "detail": {"mitre": mitre}, "reviewed": r["reviewed"]}


def build(conn, now: datetime | None = None) -> tuple[str, str, str | None]:
    """(title, body, link) for the last 24 hours."""
    now = now or datetime.now(timezone.utc)
    alerts = [_as_alert(r) for r in _rows(conn, now - WINDOW)]
    verdicts = Counter(a["verdict"] for a in alerts)
    closed = [a for a in alerts if a["verdict"] in ("Benign Positive", "False Positive")]
    open_items = sorted((a for a in alerts if a["verdict"] in NEEDS_PERSON and not a["reviewed"]),
                        key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), a["timestamp_raw"]))
    queue = conn.execute("SELECT count(*) AS n FROM alerts WHERE status IN ('new', 'retry', 'processing')"
                         ).fetchone()["n"]
    multi = len({a["siem"] for a in alerts}) > 1
    where = (lambda a: f"{a['hostname']} ({a['siem_name']})") if multi else (lambda a: a["hostname"])

    lines = [f"Last 24 hours, until {now.astimezone():%d/%m/%Y %H:%M}", "",
             f"Alerts triaged:        {len(alerts)}",
             f"Closed with evidence:  {len(closed)}",
             f"Need a person:         {sum(verdicts[v] for v in NEEDS_PERSON)} "
             f"({verdicts['True Positive']} true positive, {verdicts['Needs Human Review']} for review)",
             f"Still waiting in queue: {queue}"]
    lines += ["", f"WAITING FOR A PERSON ({len(open_items)} not reviewed yet)"]
    if open_items:
        for a in open_items[:12]:
            lines.append(f"  - [{a['severity']}] {a['verdict']}: {a['rule_name']} on {where(a)}, "
                         f"{a['timestamp_raw'].astimezone():%H:%M}")
        if len(open_items) > 12:
            lines.append(f"  … and {len(open_items) - 12} more")
    else:
        lines.append("  Nothing: every alert that needed a person has been reviewed.")

    if licensing.has("incidents"):
        incs = [i for i in incidents.build(alerts) if i["count"] > 1 and i["status"] == "attention"]
        if incs:
            lines += ["", f"INCIDENTS WITH SEVERAL ALERTS ({len(incs)})"]
            for i in incs[:8]:
                lines.append(f"  - [{i['severity']}] {i['title']} on {i['where']}: {i['count']} alerts, "
                             f"{i['start'].astimezone():%H:%M}–{i['end'].astimezone():%H:%M}")

    if closed:
        lines += ["", "CLOSED MOST OFTEN"]
        for rule, n in Counter(a["rule_name"] for a in closed).most_common(5):
            lines.append(f"  - {rule}: {n}")

    quiet = _quiet_sources(conn)
    if quiet:
        lines += ["", "SOURCES THAT WENT QUIET"] + [f"  - {q}" for q in quiet]

    n_open = len(open_items)
    title = (f"Handover {now.astimezone():%d/%m}: {n_open} waiting for a person, {len(closed)} closed"
             if alerts else f"Handover {now.astimezone():%d/%m}: no alerts in the last 24 hours")
    link = None
    if config.ARDEA_PUBLIC_URL:
        link = f"{config.ARDEA_PUBLIC_URL}/incidents" if licensing.has("incidents") else f"{config.ARDEA_PUBLIC_URL}/"
    return title, "\n".join(lines), link


def _quiet_sources(conn) -> list[str]:
    if not conn.execute("SELECT to_regclass('public.source_health') AS t").fetchone()["t"]:
        return []
    out = []
    for r in conn.execute("""SELECT h.siem, h.status, h.detail, h.quiet_hosts, s.name FROM source_health h
                             LEFT JOIN siems s ON s.id = h.siem""").fetchall():
        name = r["name"] or r["siem"]
        if r["status"] != "ok":
            out.append(f"{name}: {r['detail'] or r['status']}")
        for h in r["quiet_hosts"] or []:
            out.append(f"{name}: watched host {h['host']} is quiet")
    return out


def send_now(conn, send=None) -> list[tuple[str, str | None]]:
    """Build and send the digest (the Settings page test button, and run_due). [(channel, error)]."""
    title, body, link = build(conn)
    if send is not None:
        send(title, body, link)
        return [("test", None)]
    import notifier
    return notifier.send_message("digest", title, body, link)


def run_due(conn, now_local: datetime | None = None, send=None) -> str | None:
    """Send today's digest if due. Never raises. Returns the run key sent."""
    key = None
    try:
        key = due(now_local or datetime.now().astimezone())
        if not key or not licensing.has("notifications"):
            return None
        claimed = conn.execute("INSERT INTO report_runs (run_key, status) VALUES (%s, 'sending') "
                               "ON CONFLICT (run_key) DO NOTHING RETURNING run_key", (key,)).fetchone()
        if not claimed:
            return None
        results = send_now(conn, send)
        if not results:
            log.warning("handover digest is on, but no notification channel is set up")
        failed = [f"{c}: {e}" for c, e in results if e]
        if results and len(failed) == len(results):
            raise RuntimeError("; ".join(failed))
        for f in failed:
            log.error("digest via %s", f)
        conn.execute("UPDATE report_runs SET status = 'sent', sent_at = NOW() WHERE run_key = %s", (key,))
        log.info("handover digest sent (%s)", key)
        return key
    except Exception as exc:
        log.error("handover digest failed, will retry: %s", exc)
        try:
            conn.execute("DELETE FROM report_runs WHERE run_key = %s AND status = 'sending'", (key,))
        except Exception:
            pass
        return None
