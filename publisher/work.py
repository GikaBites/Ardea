"""Assignments and response deadlines (Pro).

Every alert that needs a person (True Positive, Needs Human Review) gets a deadline from its severity
(SLA_*_MINUTES on the Settings page, counted from the alert's time) and can be assigned to an analyst,
marked in progress and resolved with a note. An alert an analyst already gave feedback on counts as
handled. The worker sends one message when an alert passes its deadline (worker/sla.py).
Stored in alert_work (current state) and alert_work_log (who did what); nothing about triage changes.
"""
from datetime import datetime, timedelta, timezone

import settings_admin
from db import get_connection

NEEDS_PERSON = ("True Positive", "Needs Human Review")
STATUSES = ("open", "in_progress", "resolved")
STATUS_LABELS = {"open": "Open", "in_progress": "In progress", "resolved": "Resolved"}
SLA_DEFAULTS = {"Critical": ("SLA_CRITICAL_MINUTES", 60), "High": ("SLA_HIGH_MINUTES", 240),
                "Medium": ("SLA_MEDIUM_MINUTES", 1440)}
LOW_DEFAULT = ("SLA_LOW_MINUTES", 4320)
RANGES = {"7d": 7, "30d": 30, "90d": 90}
SEVERITY_RANK = {s: i for i, s in enumerate(("Critical", "High", "Medium", "Low", "Informational"))}


class WorkError(Exception):
    pass


def sla_minutes(severity: str) -> int:
    name, default = SLA_DEFAULTS.get(severity, LOW_DEFAULT)
    try:
        return max(5, int(settings_admin.publisher_value(name, str(default)) or default))
    except ValueError:
        return default


def due_at(alert: dict) -> datetime | None:
    ts = alert.get("timestamp_raw")
    return ts + timedelta(minutes=sla_minutes(alert.get("severity", ""))) if ts else None


def load(alert_ids) -> tuple[dict, set]:
    """(alert_id -> alert_work row, alert ids with analyst feedback) for these alerts."""
    ids = list(alert_ids)
    if not ids:
        return {}, set()
    with get_connection() as conn:
        work = {r["alert_id"]: r for r in conn.execute(
            "SELECT alert_id, assignee, status, note, updated_by, updated_at, resolved_at FROM alert_work "
            "WHERE alert_id = ANY(%s)", (ids,)).fetchall()}
        reviewed = {r["alert_id"] for r in conn.execute(
            "SELECT DISTINCT alert_id FROM feedback WHERE alert_id = ANY(%s)", (ids,)).fetchall()}
    return work, reviewed


def item(alert: dict, work: dict, reviewed: set, now: datetime) -> dict:
    """An alert as the queue and the incident pages show it."""
    w = work.get(alert["alert_id"]) or {}
    handled = w.get("status") == "resolved" or alert["alert_id"] in reviewed
    due = due_at(alert)
    return {"alert": alert, "assignee": w.get("assignee"), "status": w.get("status") or "open",
            "note": w.get("note"), "resolved_at": w.get("resolved_at"), "reviewed": alert["alert_id"] in reviewed,
            "handled": handled, "due": due, "overdue": bool(due and not handled and due < now),
            "minutes_left": int((due - now).total_seconds() // 60) if due and not handled else None,
            "incident": None}


def span(minutes: int) -> str:
    m = abs(minutes)
    return f"{m} min" if m < 60 else (f"{m // 60} h" if m < 2880 else f"{m // 1440} days")


def due_text(i: dict) -> str:
    if i["handled"]:
        return "Resolved" if i["status"] == "resolved" else "Reviewed"
    if i["minutes_left"] is None:
        return ""
    return f"Overdue {span(i['minutes_left'])}" if i["minutes_left"] < 0 else f"Due in {span(i['minutes_left'])}"


def queue(alerts: list[dict], *, who: str = "all", me: str = "", range_key: str = "30d",
          show_handled: bool = False, now: datetime | None = None) -> list[dict]:
    """Alerts that need a person, most urgent first."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=RANGES.get(range_key, 30))
    candidates = [a for a in alerts if a["verdict"] in NEEDS_PERSON and a.get("timestamp_raw")
                  and a["timestamp_raw"] >= since]
    work, reviewed = load(a["alert_id"] for a in candidates)
    items = [item(a, work, reviewed, now) for a in candidates]
    if not show_handled:
        items = [i for i in items if not i["handled"]]
    if who == "mine":
        items = [i for i in items if i["assignee"] == me]
    elif who == "unassigned":
        items = [i for i in items if not i["assignee"]]
    return sorted(items, key=lambda i: (i["handled"], i["due"] or now, SEVERITY_RANK.get(i["alert"]["severity"], 9)))


def assignable_users(siem_id: str | None = None) -> list[str]:
    """Active analysts and admins who may see this SIEM."""
    with get_connection() as conn:
        rows = conn.execute("SELECT username, role, siem_access FROM users WHERE NOT disabled "
                            "AND role IN ('admin', 'analyst') ORDER BY username").fetchall()
    return [r["username"] for r in rows if r["role"] == "admin" or r["siem_access"] is None
            or siem_id is None or siem_id in r["siem_access"]]


def update(alert_ids: list[str], actor: str, action: str, assignee: str | None = None, note: str = "",
           siem_of=None) -> int:
    """take | assign | start | resolve | reopen | unassign, for several alerts at once. Returns how many changed."""
    if action not in ("take", "assign", "start", "resolve", "reopen", "unassign"):
        raise WorkError("Unknown action.")
    note = " ".join(str(note or "").split())[:500]
    if action == "resolve" and not note:
        raise WorkError("Say briefly how it was resolved: the note is kept with the alert.")
    if action == "take":
        assignee = actor
    if action == "assign":
        siems = {siem_of(a) for a in alert_ids} if siem_of else {None}
        allowed = set.intersection(*[set(assignable_users(s)) for s in siems]) if siems else set()
        if assignee not in allowed:
            raise WorkError("That user cannot be assigned: they must be an active analyst or admin who can "
                            "see this SIEM.")
    changed = 0
    with get_connection() as conn:
        for aid in alert_ids[:500]:
            cur = conn.execute("SELECT assignee, status FROM alert_work WHERE alert_id = %s", (aid,)).fetchone()
            new_assignee = (cur or {}).get("assignee")
            new_status = (cur or {}).get("status") or "open"
            if action in ("take", "assign"):
                new_assignee = assignee
            elif action == "unassign":
                new_assignee = None
            elif action == "start":
                new_status, new_assignee = "in_progress", new_assignee or actor
            elif action == "resolve":
                new_status = "resolved"
            elif action == "reopen":
                new_status = "open"
            conn.execute("""INSERT INTO alert_work (alert_id, assignee, status, note, updated_by, updated_at, resolved_at)
                            VALUES (%(a)s, %(who)s, %(st)s, %(note)s, %(by)s, NOW(),
                                    CASE WHEN %(st)s = 'resolved' THEN NOW() END)
                            ON CONFLICT (alert_id) DO UPDATE SET assignee = EXCLUDED.assignee,
                                status = EXCLUDED.status, updated_by = EXCLUDED.updated_by, updated_at = NOW(),
                                note = CASE WHEN %(note)s <> '' THEN EXCLUDED.note ELSE alert_work.note END,
                                resolved_at = CASE WHEN EXCLUDED.status = 'resolved' THEN NOW() END""",
                         {"a": aid, "who": new_assignee, "st": new_status, "note": note, "by": actor})
            what = {"take": "took it", "assign": f"assigned to {new_assignee}", "unassign": "unassigned",
                    "start": "started work", "resolve": f"resolved: {note}", "reopen": "reopened"}[action]
            conn.execute("INSERT INTO alert_work_log (alert_id, actor, action) VALUES (%s, %s, %s)",
                         (aid, actor, what[:600]))
            changed += 1
        conn.commit()
    return changed


def history(alert_ids: list[str], limit: int = 40) -> list[dict]:
    if not alert_ids:
        return []
    with get_connection() as conn:
        return conn.execute("SELECT alert_id, at, actor, action FROM alert_work_log WHERE alert_id = ANY(%s) "
                            "ORDER BY id DESC LIMIT %s", (list(alert_ids), limit)).fetchall()
