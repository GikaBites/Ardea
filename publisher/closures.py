"""Closing incidents (Pro: incidents).

An incident is computed from the alerts each time (incidents.py), so a closure is stored per alert: closing
records every alert of the incident with the outcome and a note. An incident counts as resolved when every
alert in it that needs a person is covered by a closure, or was resolved in the queue or reviewed by an
analyst. A new alert that needs a person and joins the incident later puts it back on the "Need a person"
list. Reopening removes the closure from the incident's alerts. Nothing about triage changes.
"""
from db import get_connection

NEEDS_PERSON = ("True Positive", "Needs Human Review")
OUTCOMES = {"resolved": "Resolved", "false_positive": "False positive", "benign": "Expected activity",
            "duplicate": "Duplicate or already handled", "accepted": "Risk accepted"}


class CloseError(Exception):
    pass


def _needs_person(inc) -> list[str]:
    return [a["alert_id"] for a in inc["alerts"] if a["verdict"] in NEEDS_PERSON or a.get("should_escalate")]


def annotate(incs: list[dict]) -> list[dict]:
    """Copies of these incidents with 'closure', 'reopened' and the status 'resolved' where a person closed
    them. The originals (shared by the alert cache) are not changed."""
    out = [dict(i) for i in incs]
    ids = list({a["alert_id"] for i in out if i["status"] == "attention" for a in i["alerts"]})
    closed, handled = {}, set()
    if ids:
        with get_connection() as conn:
            for r in conn.execute("""SELECT a.alert_id, c.id, c.outcome, c.note, c.closed_by, c.closed_at
                                     FROM incident_closed_alerts a JOIN incident_closures c ON c.id = a.closure_id
                                     WHERE a.alert_id = ANY(%s)""", (ids,)).fetchall():
                closed[r["alert_id"]] = r
            handled = {r["alert_id"] for r in conn.execute(
                "SELECT alert_id FROM alert_work WHERE status = 'resolved' AND alert_id = ANY(%s) "
                "UNION SELECT alert_id FROM feedback WHERE alert_id = ANY(%s)", (ids, ids)).fetchall()}
    for inc in out:
        inc["closure"], inc["reopened"] = None, False
        if inc["status"] != "attention":
            continue
        mine = [closed[a["alert_id"]] for a in inc["alerts"] if a["alert_id"] in closed]
        if mine:
            inc["closure"] = max(mine, key=lambda r: r["closed_at"])
            inc["closure"] = {**inc["closure"], "outcome_label": OUTCOMES.get(inc["closure"]["outcome"],
                                                                              inc["closure"]["outcome"])}
        open_ = [a for a in _needs_person(inc) if a not in closed and a not in handled]
        if not open_:
            inc["status"] = "resolved"
        elif mine:
            inc["reopened"] = True                    # closed before, then a new alert needing a person joined
    return out


def close(incs: list[dict], actor: str, outcome: str, note: str) -> int:
    """Close these incidents. Returns how many. Also resolves their open alerts in the queue when it is on."""
    import work
    note = " ".join(str(note or "").split())[:500]
    if outcome not in OUTCOMES:
        raise CloseError("Choose how the incident ended.")
    if len(note) < 3:
        raise CloseError("Add a short note on how it was closed: it is kept with the incident.")
    n = 0
    with get_connection() as conn:
        for inc in incs:
            cid = conn.execute("""INSERT INTO incident_closures (incident_id, outcome, note, closed_by)
                                  VALUES (%s, %s, %s, %s) RETURNING id""",
                               (inc["id"], outcome, note, actor)).fetchone()["id"]
            for a in inc["alerts"]:
                conn.execute("""INSERT INTO incident_closed_alerts (alert_id, closure_id) VALUES (%s, %s)
                                ON CONFLICT (alert_id) DO UPDATE SET closure_id = EXCLUDED.closure_id""",
                             (a["alert_id"], cid))
                conn.execute("INSERT INTO alert_work_log (alert_id, actor, action) VALUES (%s, %s, %s)",
                             (a["alert_id"], actor, f"closed the incident ({OUTCOMES[outcome]}): {note}"[:600]))
            n += 1
        conn.commit()
    if work.enabled():
        ids = [a for inc in incs for a in _needs_person(inc)]
        if ids:
            work.update(ids, actor, "resolve", note=f"Incident closed ({OUTCOMES[outcome]}): {note}",
                        siem_of=None, log=False)
    return n


def reopen(inc: dict, actor: str) -> bool:
    ids = [a["alert_id"] for a in inc["alerts"]]
    with get_connection() as conn:
        gone = conn.execute("DELETE FROM incident_closed_alerts WHERE alert_id = ANY(%s)", (ids,)).rowcount
        for aid in ids:
            conn.execute("INSERT INTO alert_work_log (alert_id, actor, action) VALUES (%s, %s, 'reopened the incident')",
                         (aid, actor))
        conn.commit()
    import work
    if work.enabled():
        np_ = _needs_person(inc)
        if np_:
            work.update(np_, actor, "reopen", log=False)
    return gone > 0
