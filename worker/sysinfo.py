"""System health for the Health page, and warnings before things go wrong (every edition).

Every 5 minutes the worker records what only it can see: the AI model Ollama has loaded and the memory it uses,
free disk space, and the database size (table system_health). It also warns the team, at most once a day per
problem, through the notification channels when: the disk is nearly full, the last backup failed or is more than
36 hours old, or the queue holds more than QUEUE_WARN_HOURS of work. Never raises.
"""
import json
import logging
import shutil
from datetime import datetime, timedelta, timezone

import requests

import appsettings
import config

log = logging.getLogger("sysinfo")
DISK_WARN_PERCENT = 10
DISK_WARN_BYTES = 5 * 1024 ** 3
QUEUE_WARN_HOURS = 8
BACKUP_MAX_AGE = timedelta(hours=36)


def _put(conn, name, value):
    conn.execute("""INSERT INTO system_health (name, value, updated_at) VALUES (%s, %s, NOW())
                    ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()""",
                 (name, json.dumps(value, default=str)))


def ollama() -> dict:
    out = {"url_host": (config.LLM_URL or "").split("//")[-1].split("/")[0], "model": config.MODEL}
    try:
        r = requests.get(f"{config.LLM_URL.rstrip('/')}/api/ps", timeout=5)
        r.raise_for_status()
        out["reachable"] = True
        out["loaded"] = [{"name": m.get("name"), "size": m.get("size"), "vram": m.get("size_vram"),
                          "until": m.get("expires_at")} for m in (r.json().get("models") or [])]
        v = requests.get(f"{config.LLM_URL.rstrip('/')}/api/version", timeout=5)
        out["version"] = v.json().get("version") if v.ok else None
    except Exception as exc:
        out["reachable"] = False
        out["error"] = type(exc).__name__
    return out


def disk() -> dict:
    u = shutil.disk_usage("/")
    return {"total": u.total, "free": u.free, "free_percent": round(u.free * 100 / u.total, 1) if u.total else None}


def problems(conn, d: dict, now: datetime) -> list[tuple[str, str]]:
    """[(key, sentence)] of what needs attention now."""
    out = []
    if d.get("free_percent") is not None and (d["free_percent"] < DISK_WARN_PERCENT or d["free"] < DISK_WARN_BYTES):
        out.append(("disk", f"The server's disk is nearly full: {d['free'] / 1024 ** 3:.1f} GB "
                            f"({d['free_percent']}%) free. When it is full, Ardea stops."))
    if appsettings.env("BACKUP_ENABLED", "true").lower() == "true":
        last = conn.execute("SELECT status, finished_at, created_at, detail FROM backup_runs "
                            "WHERE status IN ('ok', 'failed') ORDER BY id DESC LIMIT 1").fetchone()
        last_ok = conn.execute("SELECT max(finished_at) AS t FROM backup_runs WHERE status = 'ok'").fetchone()["t"]
        first = conn.execute("SELECT min(created_at) AS t FROM backup_runs").fetchone()["t"]
        if last and last["status"] == "failed":
            out.append(("backup", f"The last backup failed: {last['detail'] or 'see the backup service log'}."))
        elif last_ok and now - last_ok > BACKUP_MAX_AGE:
            out.append(("backup", f"No backup for {int((now - last_ok).total_seconds() // 3600)} hours. "
                                  "Is the backup service running?"))
        elif not last_ok and first is None:
            pass                                       # the backup service has not run yet (new installation)
    q = conn.execute("""SELECT count(*) AS n FROM alerts WHERE status IN ('new', 'retry')""").fetchone()["n"]
    avg = conn.execute("""SELECT avg(duration_ms) AS ms FROM (SELECT duration_ms FROM triage_results
                          WHERE duration_ms > 0 AND model IS NOT NULL ORDER BY created_at DESC LIMIT 20) t""").fetchone()
    if q and avg and avg["ms"]:
        hours = q * float(avg["ms"]) / 3_600_000
        if hours > QUEUE_WARN_HOURS:
            out.append(("queue", f"{q} alerts are waiting: about {hours:.0f} hours of work at the current speed. "
                                 "Consider ignoring noisy rules, a suppression, or a faster model."))
    return out


def run_due(conn, now: datetime | None = None, send=None) -> list[str]:
    """Record the snapshot and send warnings that are due. Returns the warning keys sent."""
    now = now or datetime.now(timezone.utc)
    try:
        _put(conn, "ollama", ollama())
        d = disk()
        _put(conn, "disk", d)
        _put(conn, "database", conn.execute("SELECT pg_database_size(current_database()) AS b").fetchone())
        found = problems(conn, d, now)
        _put(conn, "problems", [{"key": k, "text": t} for k, t in found])
        row = conn.execute("SELECT value FROM system_health WHERE name = 'warned'").fetchone()
        warned = (row["value"] if row else {}) or {}
        sent = []
        for key, text in found:
            last = warned.get(key)
            if last and now - datetime.fromisoformat(last) < timedelta(hours=24):
                continue
            title = {"disk": "Disk nearly full", "backup": "Backup problem", "queue": "Alerts are piling up"}[key]
            link = f"{config.ARDEA_PUBLIC_URL}/admin/settings/health" if config.ARDEA_PUBLIC_URL else None
            if send is not None:
                send(title, text, link)
            elif config.NOTIFY_CHANNELS:
                import notifier
                for channel, error in notifier.send_message("health", title, text, link, urgent=key == "disk"):
                    if error:
                        log.error("health message via %s failed: %s", channel, error)
            log.warning("%s: %s", title, text)
            warned[key] = now.isoformat()
            sent.append(key)
        for key in list(warned):
            if key not in {k for k, _ in found}:
                warned.pop(key)                       # solved: warn again if it comes back
        _put(conn, "warned", warned)
        return sent
    except Exception:
        log.exception("health snapshot failed")
        return []
