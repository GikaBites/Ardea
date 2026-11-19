"""Overdue alerts (Pro: assignments). One message per alert when it passes its response deadline.

An alert that needs a person (True Positive, Needs Human Review) is overdue when its deadline (alert time +
SLA_*_MINUTES for its severity) has passed and nobody resolved it (alert_work) or gave feedback on it.
Only alerts that became overdue in the last 24 hours are announced, so switching the feature on does not
send a flood about old alerts. alert_work.overdue_notified_at makes sure each alert is announced once.
"""
import logging
from datetime import datetime, timedelta, timezone

import appsettings
import config
import licensing

log = logging.getLogger("sla")
SLA = {"Critical": ("SLA_CRITICAL_MINUTES", 60), "High": ("SLA_HIGH_MINUTES", 240),
       "Medium": ("SLA_MEDIUM_MINUTES", 1440)}
LOW = ("SLA_LOW_MINUTES", 4320)
RECENT = timedelta(hours=24)


def minutes(severity: str) -> int:
    name, default = SLA.get(severity, LOW)
    try:
        return max(5, int(appsettings.env(name, str(default)) or default))
    except ValueError:
        return default


def overdue(conn, now: datetime) -> list[dict]:
    rows = conn.execute("""
        SELECT a.alert_id, a.timestamp, a.rule_name, a.host_name, a.siem, t.severity, t.verdict,
               w.assignee, s.name AS siem_name
        FROM alerts a JOIN triage_results t ON t.alert_id = a.alert_id
        LEFT JOIN alert_work w ON w.alert_id = a.alert_id
        LEFT JOIN siems s ON s.id = a.siem
        WHERE t.verdict IN ('True Positive', 'Needs Human Review')
          AND a.timestamp >= %s
          AND COALESCE(w.status, 'open') <> 'resolved' AND w.overdue_notified_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM feedback f WHERE f.alert_id = a.alert_id)
        ORDER BY a.timestamp""", (now - timedelta(days=30),)).fetchall()
    out = []
    for r in rows:
        due = r["timestamp"] + timedelta(minutes=minutes(r["severity"] or ""))
        if now - RECENT <= due < now:
            out.append(dict(r, due=due))
    return out


def run_due(conn, now: datetime | None = None, send=None) -> list[str]:
    """Announce newly overdue alerts. Never raises. Returns the alert ids announced."""
    if (not licensing.has("assignments") or appsettings.env("QUEUE_ENABLED", "true").lower() != "true"
            or appsettings.env("OVERDUE_NOTIFY", "true").lower() != "true"):
        return []
    now = now or datetime.now(timezone.utc)
    try:
        items = overdue(conn, now)
        if not items:
            return []
        lines = []
        for r in items[:20]:
            who = f", assigned to {r['assignee']}" if r["assignee"] else ", nobody assigned"
            lines.append(f"  - [{r['severity']}] {r['verdict']}: {r['rule_name']} on {r['host_name'] or '?'}"
                         f"{' (' + (r['siem_name'] or r['siem']) + ')' if r['siem'] else ''}: due "
                         f"{r['due'].astimezone():%d/%m %H:%M}{who}")
        if len(items) > 20:
            lines.append(f"  … and {len(items) - 20} more")
        title = f"{len(items)} alert{'s' if len(items) > 1 else ''} passed the response deadline"
        body = "Not resolved and not reviewed in time:\n" + "\n".join(lines)
        link = f"{config.ARDEA_PUBLIC_URL}/queue" if config.ARDEA_PUBLIC_URL else None
        if send is not None:
            send(title, body, link)
        elif licensing.has("notifications") and config.NOTIFY_CHANNELS:
            import notifier
            for channel, error in notifier.send_message("overdue", title, body, link, urgent=True):
                if error:
                    log.error("overdue message via %s failed: %s", channel, error)
        for r in items:
            conn.execute("""INSERT INTO alert_work (alert_id, overdue_notified_at) VALUES (%s, NOW())
                            ON CONFLICT (alert_id) DO UPDATE SET overdue_notified_at = NOW()""", (r["alert_id"],))
        log.warning("%s", title)
        return [r["alert_id"] for r in items]
    except Exception:
        log.exception("overdue check failed")
        return []
