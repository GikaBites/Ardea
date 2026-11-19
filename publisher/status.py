"""The status bar: what the worker and the fetcher are doing now, and how many alerts wait.

Read from service_activity (written by the worker and the fetcher, appsettings.activity), the investigation
steps of the alert being investigated, and the alerts queue. Users limited to some SIEMs never see the rule
or host of another SIEM's alert, and count only their own SIEMs' queue.
"""
from datetime import datetime, timezone

from db import get_connection

IDLE_STALE = 180                 # seconds without a heartbeat before an idle worker counts as not responding
FETCH_GRACE = 300                # seconds past the planned next collection
TOOL_WORDS = {"search_host_events": "searching the host's events", "get_process_tree": "reading the process tree",
              "get_auth_events": "reading logons", "get_related_alerts": "looking for related alerts",
              "get_baseline": "checking what is normal", "web_search": "searching the web"}


def _age(ts, now):
    return int((now - ts).total_seconds()) if ts else None


def _worker(conn, row, user, can_see, now):
    if row is None:
        return {"state": "unknown", "level": "warn", "text": "No status yet: the worker has not started with this version"}
    w = {"state": row["state"], "level": "ok", "text": row["detail"] or "", "since": _age(row["started_at"], now)}
    visible = not row["siem"] or can_see(row["siem"])
    if row["state"] in ("investigating", "answering"):
        max_seconds = (row["info"] or {}).get("max_seconds") or 1200
        if not visible:
            w["text"] = "Investigating an alert" if row["state"] == "investigating" else "Answering a question"
        else:
            w["alert_id"] = row["alert_id"]
        if row["state"] == "investigating":
            steps = conn.execute("""SELECT kind, tool_name FROM investigation_steps WHERE alert_id = %s
                                    AND created_at >= %s ORDER BY id""", (row["alert_id"], row["started_at"])).fetchall()
            turns = sum(1 for s in steps if s["kind"] == "llm")
            last = steps[-1] if steps else None
            if last is None:
                phase = "collecting the context"
            elif last["kind"] == "tool":
                phase = TOOL_WORDS.get(last["tool_name"] or "", f"running {last['tool_name']}")
            elif last["kind"] == "final":
                phase = "checking the verdict"
            else:
                phase = "thinking"
            w["phase"] = phase
            w["step"], w["max_steps"] = turns, row["max_steps"] or 8
            w["progress"] = min(0.95, max(turns / max(1, w["max_steps"]), (w["since"] or 0) / max_seconds))
        else:
            w["progress"] = min(0.95, (w["since"] or 0) / max_seconds)
        if (w["since"] or 0) > max_seconds + 300:
            w["level"], w["stuck"] = "bad", True
            w["text"] = f"Possibly stuck: {w['text']}"
    else:
        if row["state"] == "blocked":
            w["level"] = "bad"
        elif row["state"] == "waiting":
            w["level"] = "warn"
        if _age(row["updated_at"], now) > IDLE_STALE:
            w["level"], w["stuck"] = "bad", True
            w["text"] = f"Not responding for {_age(row['updated_at'], now) // 60} min"
    return w


def _fetcher(row, now):
    if row is None:
        return {"state": "unknown", "level": "warn", "text": "No status yet: the fetcher has not started with this version"}
    f = {"state": row["state"], "level": {"error": "bad", "waiting": "warn"}.get(row["state"], "ok"),
         "text": row["detail"] or "", "last": _age(row["updated_at"], now)}
    info = row["info"] or {}
    if info.get("errors") and row["state"] == "idle":
        f["level"] = "warn"
    if row["next_at"]:
        f["next_in"] = int((row["next_at"] - now).total_seconds())
        total = max(1, int((row["next_at"] - row["updated_at"]).total_seconds()))
        f["progress"] = max(0.0, min(1.0, 1 - f["next_in"] / total))
        if f["next_in"] < -FETCH_GRACE:
            f["level"], f["stuck"] = "bad", True
            f["text"] = f"No collection for {(-f['next_in']) // 60 + total // 60} min"
    elif row["state"] == "collecting" and f["last"] > 600:
        f["level"], f["stuck"] = "bad", True
        f["text"] = f"Possibly stuck: {f['text']}"
    return f


def _demo() -> dict:
    """Demo mode has no worker or fetcher: show what a busy afternoon looks like, moving every few seconds."""
    s = int(datetime.now(timezone.utc).timestamp()) % 240
    return {"worker": {"state": "investigating", "level": "ok", "text": "Suspicious Windows Powershell Arguments on srv-app-02",
                       "phase": ("reading the process tree", "checking what is normal", "searching the host's events",
                                 "thinking")[s // 60], "step": 1 + s // 40, "max_steps": 8, "since": s,
                       "progress": min(0.95, s / 260)},
            "fetcher": {"state": "idle", "level": "ok", "text": "2 new alerts in the last collection",
                        "next_in": 180 - s % 180, "progress": (s % 180) / 180},
            "queue": {"waiting": 3, "ready": 3, "later": 0, "processing": 1, "oldest": 420, "eta_minutes": 9},
            "tasks": {"state": "idle", "text": "Waiting for settings tests and questions"}}


def snapshot(user, can_see) -> dict:
    """{'worker': {...}, 'fetcher': {...}, 'queue': {...}} for this user. can_see(siem_id) -> bool."""
    import demo
    if demo.ENABLED:
        return _demo()
    now = datetime.now(timezone.utc)
    restricted = not (user["role"] == "admin" or user.get("siem_access") is None)
    scope = list(user.get("siem_access") or []) if restricted else None
    with get_connection() as conn:
        if not conn.execute("SELECT to_regclass('public.service_activity') AS t").fetchone()["t"]:
            rows = {}
        else:
            rows = {r["service"]: r for r in conn.execute("SELECT * FROM service_activity").fetchall()}
        w = _worker(conn, rows.get("worker"), user, can_see, now)
        q = conn.execute("""SELECT count(*) FILTER (WHERE status = 'new'
                                     OR (status = 'retry' AND COALESCE(next_attempt_at, NOW()) <= NOW())) AS ready,
                                   count(*) FILTER (WHERE status = 'retry' AND next_attempt_at > NOW()) AS later,
                                   count(*) FILTER (WHERE status = 'processing') AS processing,
                                   min(first_seen) FILTER (WHERE status IN ('new', 'retry')) AS oldest
                            FROM alerts WHERE status IN ('new', 'retry', 'processing')
                              AND (%(s)s::text[] IS NULL OR siem = ANY(%(s)s::text[]))""", {"s": scope}).fetchone()
        avg = conn.execute("""SELECT avg(duration_ms) AS ms FROM (SELECT duration_ms FROM triage_results
                              WHERE duration_ms > 0 AND model IS NOT NULL ORDER BY created_at DESC LIMIT 20) t""").fetchone()
    waiting = (q["ready"] or 0) + (q["later"] or 0)
    queue = {"waiting": waiting, "ready": q["ready"] or 0, "later": q["later"] or 0,
             "processing": q["processing"] or 0, "oldest": _age(q["oldest"], now)}
    if waiting and avg and avg["ms"]:
        queue["eta_minutes"] = max(1, round((q["ready"] or 0) * float(avg["ms"]) / 60000))
    t = rows.get("worker-tasks")
    tasks = None
    if t is not None and _age(t["updated_at"], now) < 180:
        tasks = {"state": t["state"], "text": t["detail"] if (not t["siem"] or can_see(t["siem"])) else ""}
    return {"worker": w, "fetcher": _fetcher(rows.get("fetcher"), now), "queue": queue, "tasks": tasks}
