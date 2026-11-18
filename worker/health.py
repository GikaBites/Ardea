"""Silent-source alarm (Pro; watched hosts: MSP).

A quiet SIEM usually means something broke (an agent, a Fleet policy, ingest, a licence, a full disk),
not that all is well, and nobody notices because there are simply no alerts. Every 15 minutes the worker
asks each SIEM, read-only, for the time of its newest event (and, for watched hosts, each host's newest
event). A SIEM with no events for SOURCE_SILENCE_MINUTES, one that cannot be reached twice in a row, or a
watched host quiet for HOST_SILENCE_MINUTES raises a warning: once to the notification channels, and as a
banner in the console until it recovers. Recovery is announced too.
"""
import fnmatch
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import appsettings
import config
import elastic
import licensing

log = logging.getLogger("health")
CHECK_EVERY = 15 * 60
LOOKBACK = "now-7d"
SCHEMA = """CREATE TABLE IF NOT EXISTS source_health (
    siem TEXT PRIMARY KEY,
    checked_at TIMESTAMPTZ, last_event_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'ok',                 -- ok | silent | unreachable
    detail TEXT, failures INT NOT NULL DEFAULT 0,
    quiet_hosts JSONB NOT NULL DEFAULT '[]'::jsonb,    -- [{"host": ..., "last": iso or null}]
    changed_at TIMESTAMPTZ
)"""
_last_run = {"at": 0.0}


def ensure_schema(conn):
    conn.execute(SCHEMA)


def _int(name: str, default: int) -> int:
    try:
        return int(appsettings.env(name, str(default)) or default)
    except ValueError:
        return default


def watch_patterns() -> list[str]:
    raw = appsettings.env("HOST_WATCH", "")
    return [p.strip().lower() for p in raw.replace(",", "\n").splitlines() if p.strip()][:200]


def _ms(value) -> datetime | None:
    return datetime.fromtimestamp(value / 1000, timezone.utc) if isinstance(value, (int, float)) else None


def newest_events(siem, watch: list[str]) -> tuple[datetime | None, dict[str, datetime]]:
    """(newest event time, {host: newest event time}) over the SIEM's event indices. Raises on SIEM errors."""
    newest, hosts = None, {}
    with elastic.use(siem.id):
        for index in siem.events_indices:
            body = {"size": 0, "track_total_hits": False,
                    "query": {"range": {"@timestamp": {"gte": LOOKBACK, "lte": "now+5m"}}},
                    "aggs": {"last": {"max": {"field": "@timestamp"}}}}
            if watch:
                body["aggs"]["hosts"] = {"terms": {"field": "host.name", "size": 5000},
                                         "aggs": {"last": {"max": {"field": "@timestamp"}}}}
            aggs = elastic.search(index, body).get("aggregations") or {}
            t = _ms((aggs.get("last") or {}).get("value"))
            if t and (newest is None or t > newest):
                newest = t
            for b in (aggs.get("hosts") or {}).get("buckets", []):
                ht = _ms((b.get("last") or {}).get("value"))
                name = str(b.get("key", "")).lower()
                if ht and (name not in hosts or ht > hosts[name]):
                    hosts[name] = ht
    return newest, hosts


def quiet_hosts(watch: list[str], hosts: dict[str, datetime], now: datetime, minutes: int) -> list[dict]:
    """Watched hosts with no event for `minutes`. A pattern without * that matches no host at all counts too."""
    out = {}
    for pattern in watch:
        matched = [h for h in hosts if fnmatch.fnmatchcase(h, pattern)]
        for h in matched:
            if now - hosts[h] > timedelta(minutes=minutes):
                out[h] = {"host": h, "last": hosts[h].isoformat()}
        if not matched and not any(c in pattern for c in "*?["):
            out[pattern] = {"host": pattern, "last": None}
    return sorted(out.values(), key=lambda x: x["host"])


def assess(siem, now: datetime, prev: dict | None) -> dict:
    """The new source_health row for one SIEM (not stored yet)."""
    silence = _int("SOURCE_SILENCE_MINUTES", 120)
    watch = watch_patterns() if licensing.has("host_watch") else []
    failures = (prev or {}).get("failures") or 0
    try:
        newest, hosts = newest_events(siem, watch)
    except Exception as exc:
        failures += 1
        detail = f"cannot be reached ({type(exc).__name__})"
        status = "unreachable" if failures >= 2 else (prev or {}).get("status", "ok")
        return {"status": status, "last_event_at": (prev or {}).get("last_event_at"), "failures": failures,
                "detail": detail, "quiet_hosts": (prev or {}).get("quiet_hosts") or []}
    status, detail = "ok", None
    if silence and (newest is None or now - newest > timedelta(minutes=silence)):
        status = "silent"
        detail = "no events in the last 7 days" if newest is None else f"no events since {newest:%d/%m %H:%M} UTC"
    host_min = _int("HOST_SILENCE_MINUTES", 60)
    return {"status": status, "last_event_at": newest, "failures": 0, "detail": detail, "off": not silence,
            "quiet_hosts": quiet_hosts(watch, hosts, now, host_min) if watch else []}


def messages(siem_name: str, prev: dict | None, new: dict) -> list[tuple[str, str, bool]]:
    """(title, body, urgent) for what changed. Nothing when nothing changed."""
    out = []
    old_status = (prev or {}).get("status", "ok")
    if new["status"] != old_status:
        if new["status"] == "silent":
            out.append((f"{siem_name}: no events", f"The SIEM {siem_name} has sent {new['detail']}. Alerts cannot "
                        "fire without events: check the Elastic agents, Fleet policies and ingest pipelines.", True))
        elif new["status"] == "unreachable":
            out.append((f"{siem_name}: cannot be reached", f"The worker {new['detail']} twice in a row. Check the "
                        "cluster, its certificate and the worker's API key. Alerts from it are not collected "
                        "while this lasts.", True))
        elif new["status"] == "ok" and not new.get("off"):             # not when the check was switched off
            newest = f" (newest: {new['last_event_at']:%d/%m %H:%M} UTC)" if new.get("last_event_at") else ""
            out.append((f"{siem_name}: events are arriving again",
                        f"The SIEM {siem_name} is sending events again{newest}.", False))
    before = {h["host"] for h in (prev or {}).get("quiet_hosts") or []}
    after = {h["host"] for h in new["quiet_hosts"]}
    if after - before:
        lines = [f"  - {h['host']}: " + (f"last event {h['last'][:16].replace('T', ' ')} UTC" if h["last"]
                                        else "no events in the last 7 days")
                 for h in new["quiet_hosts"] if h["host"] in after - before]
        out.append((f"{siem_name}: {len(after - before)} watched host(s) went quiet",
                    "These hosts on the watch list stopped sending events:\n" + "\n".join(lines) +
                    "\n\nAn endpoint agent that stops reporting can be a crash, a shutdown, or an attacker "
                    "disabling it.", True))
    if before - after:
        out.append((f"{siem_name}: watched host(s) reporting again",
                    "Sending events again: " + ", ".join(sorted(before - after)), False))
    return out


def _store(conn, siem_id: str, new: dict, changed: bool):
    conn.execute("""INSERT INTO source_health (siem, checked_at, last_event_at, status, detail, failures, quiet_hosts,
                                               changed_at)
                    VALUES (%s, NOW(), %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (siem) DO UPDATE SET checked_at = NOW(), last_event_at = EXCLUDED.last_event_at,
                        status = EXCLUDED.status, detail = EXCLUDED.detail, failures = EXCLUDED.failures,
                        quiet_hosts = EXCLUDED.quiet_hosts,
                        changed_at = CASE WHEN %s THEN NOW() ELSE source_health.changed_at END""",
                 (siem_id, new["last_event_at"], new["status"], new["detail"], new["failures"],
                  json.dumps(new["quiet_hosts"]), changed))


def run_due(conn, now: datetime | None = None, force: bool = False, send=None) -> list[tuple[str, str, bool]]:
    """Check every SIEM when due. Returns the messages sent. Never raises."""
    if not licensing.has("source_health"):
        return []
    if not force and time.monotonic() - _last_run["at"] < CHECK_EVERY:
        return []
    _last_run["at"] = time.monotonic()
    now = now or datetime.now(timezone.utc)
    sent = []
    try:
        ensure_schema(conn)
        prev_rows = {r["siem"]: r for r in conn.execute("SELECT * FROM source_health").fetchall()}
        configured = elastic.configured()
        for siem in configured.values():
            prev = prev_rows.get(siem.id)
            new = assess(siem, now, prev)
            msgs = messages(siem.name, prev, new)
            _store(conn, siem.id, new, bool(msgs))
            for title, body, urgent in msgs:
                (log.warning if urgent else log.info)("%s", title)
                sent.append((title, body, urgent))
                _notify(title, body, urgent, send)
        if prev_rows:
            gone = [s for s in prev_rows if s not in configured]
            if gone:
                conn.execute("DELETE FROM source_health WHERE siem = ANY(%s)", (gone,))
    except Exception:
        log.exception("source health check failed")
    return sent


def _notify(title, body, urgent, send=None):
    if send is not None:
        send(title, body, urgent)
        return
    if not licensing.has("notifications") or not config.NOTIFY_CHANNELS:
        return
    import notifier
    link = f"{config.ARDEA_PUBLIC_URL}/" if config.ARDEA_PUBLIC_URL else None
    for channel, error in notifier.send_message("source_health", title, body, link, urgent):
        if error:
            log.error("source alarm via %s failed: %s", channel, error)
