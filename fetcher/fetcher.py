"""Ardea fetcher: polls Elastic Security alerts from every SIEM in siems/siems.json and enqueues them.

  * one watermark per SIEM (fetcher_siem_state) with an overlap window, so late-indexed alerts are
    not lost and ignored/duplicate alerts still advance the watermark
  * idempotent inserts (ON CONFLICT DO NOTHING): the overlap makes re-reads harmless
  * search_after pagination
  * skips building-block alerts and alerts already closed/acknowledged in Kibana
  * dedup key (rule + host + user + executable + parent + normalised command line) with a
    time-bounded suppression window; duplicates are counted on the first alert
  * one DB connection per cycle, retries with backoff, heartbeat file for the healthcheck
  * one SIEM being down never stops collection from the others
  * alert_id = '<siem id>:<Elastic _id>', so two clusters can never collide
"""
import hashlib
import json
import logging
import os
import pathlib
import re
import time
from datetime import datetime, timedelta, timezone

import requests

import appsettings
import db
import siems as siem_config

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s fetcher %(message)s")
log = logging.getLogger("fetcher")



def _int(name, default):
    """From .env, else the Settings page, else the default. Read each cycle, so changes apply without a restart."""
    try:
        return int(appsettings.env(name, str(default)))
    except ValueError:
        return default


def cooldown() -> int:
    return max(30, _int("FETCH_INTERVAL_SECONDS", 180))


def dedup_window() -> timedelta:
    return timedelta(hours=_int("DEDUP_WINDOW_HOURS", 24))


OVERLAP = timedelta(minutes=_int("FETCH_OVERLAP_MINUTES", 10))
INITIAL_LOOKBACK = timedelta(hours=_int("FETCH_INITIAL_LOOKBACK_HOURS", 12))
PAGE_SIZE = 500
INCIDENT_WINDOW_MIN = _int("INCIDENT_WINDOW_MINUTES", 120)
HEARTBEAT = pathlib.Path("/tmp/heartbeat")
IGNORED_RULES_FILE = pathlib.Path(__file__).with_name("ignored_rules.json")
_MIGRATION_LOCK = 7270020

_sessions: dict[str, requests.Session] = {}


def _session(siem) -> requests.Session:
    s = _sessions.get(siem.id)
    if s is None:
        s = _sessions[siem.id] = requests.Session()
        s.headers.update({"Authorization": f"ApiKey {siem.fetcher_api_key}",     # read-only, alerts index only
                          "Content-Type": "application/json"})
    return s


# --------------------------------------------------------------------------- helpers
def _get(src: dict, dotted: str, default=None):
    """Read ECS fields that may be nested ({"host": {"name": ..}}) or flat ("kibana.alert.x")."""
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


_VOLATILE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"   # GUIDs
    r"|\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"                         # timestamps
    r"|\b\d{5,}\b",                                                         # pids / long numbers
    re.I,
)


def _short(value, n=500):
    """Process fields for the rule-tuning advisor: plain text, bounded."""
    return str(value)[:n] if value not in (None, "") else None


def normalise_cmdline(cmd: str | None) -> str:
    if not cmd:
        return ""
    return _VOLATILE.sub("#", cmd.lower()).strip()


def dedup_key(src: dict) -> str:
    parts = [
        _get(src, "kibana.alert.rule.rule_id") or _get(src, "kibana.alert.rule.name") or "",
        (_get(src, "host.name") or _get(src, "host.hostname") or "").lower(),
        (_first(_get(src, "user.name")) or "").lower(),
        (_get(src, "process.executable") or "").lower(),
        (_get(src, "process.parent.executable") or "").lower(),
        normalise_cmdline(_get(src, "process.command_line")),
        (_get(src, "file.path") or _get(src, "registry.path") or "").lower(),
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def incident_key(src: dict, ts: datetime, siem_id: str = "") -> str:
    """Coarse grouping: same host in the same SIEM within the same time bucket -> same incident candidate."""
    host = (_get(src, "host.name") or _get(src, "host.hostname") or "unknown").lower()
    bucket = int(ts.timestamp() // (INCIDENT_WINDOW_MIN * 60))
    return hashlib.sha1(f"{siem_id}|{host}|{bucket}".encode()).hexdigest()[:16]


def load_ignored_rules() -> dict:
    """ignored_rules.json plus the rules ignored on the Settings page."""
    try:
        rules = json.loads(IGNORED_RULES_FILE.read_text())
    except Exception as exc:  # a broken ignore file must not stop ingestion
        log.error("cannot read ignored_rules.json: %s", exc)
        rules = {}
    return {"ignored": list(rules.get("ignored", [])) + appsettings.lines("IGNORED_RULES"),
            "match": list(rules.get("match", [])) + appsettings.lines("IGNORED_RULES_MATCH")}


def is_rule_ignored(rule_name: str, rules: dict) -> bool:
    if rule_name in rules.get("ignored", []):
        return True
    return any(m in rule_name for m in rules.get("match", []))


# --------------------------------------------------------------------------- elastic
def _search(siem, body: dict, attempt: int = 0) -> dict:
    url = f"{siem.url}/{siem.alerts_index}*/_search?ignore_unavailable=true&allow_no_indices=true"
    try:
        r = _session(siem).post(url, json=body, timeout=30, verify=siem.verify)
        if r.status_code in (429, 502, 503, 504) and attempt < 4:
            raise requests.HTTPError(f"retryable {r.status_code}")
        r.raise_for_status()
        return r.json()
    except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
        if attempt >= 4:
            raise
        delay = min(60, 2 ** attempt * 2)
        log.warning("[%s] elastic error (%s), retry in %ss", siem.id, exc, delay)
        time.sleep(delay)
        return _search(siem, body, attempt + 1)


def fetch_alerts(siem, since: datetime):
    """Yield alert hits with @timestamp >= since, oldest first, paginated."""
    search_after = None
    while True:
        body = {
            "size": PAGE_SIZE,
            "sort": [{"@timestamp": "asc"}, {"kibana.alert.uuid": "asc"}],
            "query": {"bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since.isoformat(), "lt": "now"}}},
                    {"terms": {"kibana.alert.workflow_status": ["open"]}},
                ],
                # building-block alerts are inputs to other rules, not things to triage
                "must_not": [{"exists": {"field": "kibana.alert.building_block_type"}}],
            }},
            "_source": True,
        }
        if search_after:
            body["search_after"] = search_after
        hits = _search(siem, body).get("hits", {}).get("hits", [])
        if not hits:
            return
        yield from hits
        if len(hits) < PAGE_SIZE:
            return
        search_after = hits[-1]["sort"]


# --------------------------------------------------------------------------- db
SCHEMA = """
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS siem TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS process_name TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS process_executable TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parent_executable TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS elastic_id TEXT;
CREATE INDEX IF NOT EXISTS alerts_siem_idx ON alerts (siem, elastic_id);
CREATE TABLE IF NOT EXISTS siems (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kibana_url TEXT, position INT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS fetcher_siem_state (
    siem TEXT PRIMARY KEY, watermark TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
"""


def sync_siems(conn, configured):
    """Schema for multi-SIEM, the siems table for the UI, and alerts from before siems.json assigned to the
    first SIEM: those without a SIEM (older versions) and those of the .env-only SIEM "default" once
    siems.json replaces it (they came from the single Elastic configured then)."""
    first = configured[0].id
    ids = [s.id for s in configured]
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))
        for statement in filter(str.strip, SCHEMA.split(";")):
            cur.execute(statement)
        for pos, s in enumerate(configured):
            cur.execute("""INSERT INTO siems (id, name, kibana_url, position, active) VALUES (%s,%s,%s,%s,TRUE)
                           ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, kibana_url=EXCLUDED.kibana_url,
                               position=EXCLUDED.position, active=TRUE, updated_at=NOW()""",
                        (s.id, s.name, s.kibana_url or None, pos))
        cur.execute("UPDATE siems SET active = FALSE, updated_at = NOW() WHERE NOT (id = ANY(%s)) AND active",
                    ([s.id for s in configured],))
        cur.execute("""UPDATE alerts SET siem = %s, elastic_id = COALESCE(elastic_id, alert_id)
                       WHERE siem IS NULL OR (siem = 'default' AND NOT ('default' = ANY(%s)))""", (first, ids))
        if cur.rowcount:
            log.info("assigned %s alerts from before siems.json to '%s'", cur.rowcount, first)
        if "default" not in ids:
            cur.execute("""UPDATE fetcher_siem_state SET siem = %s WHERE siem = 'default'
                           AND NOT EXISTS (SELECT 1 FROM fetcher_siem_state WHERE siem = %s)""", (first, first))
            cur.execute("DELETE FROM siems WHERE id = 'default'")
    conn.commit()


def get_watermark(cur, siem_id: str, legacy: bool) -> datetime:
    cur.execute("SELECT watermark FROM fetcher_siem_state WHERE siem = %s", (siem_id,))
    row = cur.fetchone()
    if row:
        return row["watermark"]
    if legacy:                                   # the first SIEM continues where the single-SIEM fetcher stopped
        cur.execute("SELECT watermark FROM fetcher_state WHERE id = 1")
        row = cur.fetchone()
        if row:
            return row["watermark"]
    cur.execute("SELECT max(timestamp) AS ts FROM alerts WHERE siem = %s", (siem_id,))
    row = cur.fetchone()
    return row["ts"] if row and row["ts"] else datetime.now(timezone.utc) - INITIAL_LOOKBACK


def set_watermark(cur, siem_id: str, ts: datetime):
    cur.execute("""INSERT INTO fetcher_siem_state (siem, watermark) VALUES (%s, %s)
                   ON CONFLICT (siem) DO UPDATE SET watermark = GREATEST(fetcher_siem_state.watermark,
                                                                        EXCLUDED.watermark),
                                                    updated_at = NOW()""", (siem_id, ts))


def find_recent_duplicate(cur, siem_id: str, key: str, ts: datetime):
    """An alert from the same SIEM with the same dedup key that is queued or was triaged within the window.
    (Same host name in two SIEMs is usually two different machines, so SIEMs never merge.)"""
    cur.execute("""SELECT alert_id FROM alerts
                   WHERE alert_hash = %s AND siem = %s AND timestamp >= %s AND status <> 'failed'
                   ORDER BY timestamp DESC LIMIT 1""", (key, siem_id, ts - dedup_window()))
    return cur.fetchone()


def process_hit(cur, siem, hit: dict, ignored: dict, legacy: bool = False) -> str:
    src = hit.get("_source", {})
    elastic_id = hit.get("_id")
    alert_id = f"{siem.id}:{elastic_id}"
    ts = datetime.fromisoformat(src["@timestamp"].replace("Z", "+00:00"))
    rule_name = _get(src, "kibana.alert.rule.name", "unknown")

    if is_rule_ignored(rule_name, ignored):
        return "ignored"

    # older duplicates of the first SIEM use the bare _id, or 'default:<_id>' (.env-only setup)
    ids = [alert_id, elastic_id, f"default:{elastic_id}"] if legacy else [alert_id]
    cur.execute("SELECT 1 FROM alerts WHERE siem = %s AND elastic_id = %s "
                "UNION ALL SELECT 1 FROM alert_occurrences WHERE alert_id = ANY(%s)", (siem.id, elastic_id, ids))
    if cur.fetchone():
        return "known"            # re-read because of the overlap window

    key = dedup_key(src)
    dup = find_recent_duplicate(cur, siem.id, key, ts)
    if dup:
        cur.execute("INSERT INTO alert_occurrences (alert_id, parent_alert_id, timestamp) "
                    "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", (alert_id, dup["alert_id"], ts))
        cur.execute("UPDATE alerts SET count = count + 1 WHERE alert_id = %s", (dup["alert_id"],))
        return "duplicate"

    cur.execute("""
        INSERT INTO alerts (alert_id, timestamp, first_seen, alert_hash, status,
                            rule_id, rule_name, host_name, user_name, incident_key, siem, elastic_id,
                            process_name, process_executable, parent_executable)
        VALUES (%s, %s, %s, %s, 'new', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (alert_id) DO NOTHING""",
        (alert_id, ts, ts, key,
         _get(src, "kibana.alert.rule.rule_id"), rule_name,
         (_get(src, "host.name") or _get(src, "host.hostname") or "").lower() or None,
         _first(_get(src, "user.name")),
         incident_key(src, ts, siem.id), siem.id, elastic_id,
         _short(_first(_get(src, "process.name"))), _short(_first(_get(src, "process.executable"))),
         _short(_first(_get(src, "process.parent.executable")))))
    return "queued"


def run_siem(conn, siem, ignored: dict, legacy: bool):
    stats = {"queued": 0, "duplicate": 0, "ignored": 0, "known": 0}
    with conn.cursor() as cur:
        since = get_watermark(cur, siem.id, legacy) - OVERLAP
        newest = None
        for hit in fetch_alerts(siem, since):
            stats[process_hit(cur, siem, hit, ignored, legacy)] += 1
            newest = hit["_source"]["@timestamp"]
            if sum(stats.values()) % 200 == 0:
                conn.commit()
        if newest:
            set_watermark(cur, siem.id, datetime.fromisoformat(newest.replace("Z", "+00:00")))
    conn.commit()
    if stats["queued"] or stats["duplicate"]:
        log.info("[%s] cycle: %s", siem.id, stats)
    return stats


_edition = {"tier": None}


def licensed_tier(conn) -> str:
    """The edition from license_state (written by the worker). Community if missing or expired."""
    try:
        row = conn.execute("""SELECT CASE WHEN valid_until > NOW() THEN tier ELSE 'community' END AS tier
                              FROM license_state WHERE id = 1""").fetchone() \
            if conn.execute("SELECT to_regclass('public.license_state') AS t").fetchone()["t"] else None
    except Exception:
        conn.rollback()
        log.exception("cannot read license_state")
        return _edition["tier"] or "community"
    return row["tier"] if row and row["tier"] in ("community", "pro", "msp") else "community"


def licensed_siems(conn, configured):
    """Several SIEMs are an MSP feature. Other editions collect from the FIRST SIEM in siems.json only.
    Alerts already queued from the others are still triaged."""
    tier = licensed_tier(conn)
    if tier != _edition["tier"]:
        _edition["tier"] = tier
        if len(configured) > 1 and tier != "msp":
            log.warning("edition %s: collecting only from '%s'. Collecting from %s SIEMs needs Ardea MSP.",
                        tier.upper(), configured[0].id, len(configured))
        else:
            log.info("edition %s", tier.upper())
    return configured if tier == "msp" else configured[:1]


def run_once(configured) -> tuple[int, int]:
    """One pass over every collected SIEM. Returns (failed, collected); a failing SIEM does not stop the others."""
    ignored = load_ignored_rules()
    failed, new, errors = 0, 0, []
    with db.get_connection() as conn:
        configured = licensed_siems(conn, configured)
        for n, siem in enumerate(configured):
            appsettings.activity(conn, "fetcher", "collecting", f"Collecting alerts from {siem.name}", siem=siem.id,
                                 info={"siem": n + 1, "of": len(configured)}, every=0)
            try:
                new += run_siem(conn, siem, ignored, legacy=(n == 0))["queued"]
            except Exception as exc:
                conn.rollback()
                failed += 1
                errors.append({"siem": siem.id, "name": siem.name, "error": type(exc).__name__})
                log.exception("[%s] fetch failed", siem.id)
        nxt = datetime.now(timezone.utc) + timedelta(seconds=cooldown())
        if failed and failed == len(configured):
            appsettings.activity(conn, "fetcher", "error", "No SIEM could be reached: " +
                                 ", ".join(e["name"] for e in errors), info={"new": 0, "errors": errors},
                                 next_at=nxt, every=0)
        else:
            appsettings.activity(conn, "fetcher", "idle",
                                 f"{new} new alert{'s' if new != 1 else ''} in the last collection" +
                                 (f"; {', '.join(e['name'] for e in errors)} unreachable" if errors else ""),
                                 info={"new": new, "errors": errors, "siems": len(configured)},
                                 next_at=nxt, every=0)
    return failed, len(configured)


def _settings_env() -> dict:
    out = {}
    if siem_config.file_path().is_file():
        out["SIEMS_FILE"] = str(siem_config.file_path())
    if appsettings.from_env("ELASTIC_URL"):
        out["ELASTIC_URL"] = appsettings.from_env("ELASTIC_URL")
    return out


def load_siems() -> list:
    """SIEMs to collect from: siems.json, else the Settings page, else .env. Those without a key are skipped."""
    try:
        configured = siem_config.load(ui_data=appsettings.siems_data())
    except siem_config.SiemConfigError as exc:
        log.error("SIEM configuration: %s", exc)
        return []
    missing = [s.id for s in configured if not s.fetcher_api_key]
    if missing:
        log.error("fetcher API key missing for SIEM(s) %s: skipped", ", ".join(missing))
    configured = [s for s in configured if s.fetcher_api_key]
    if configured:
        log.info("fetcher: every %ss, SIEMs: %s", cooldown(),
                 ", ".join(f"{s.id} ({s.url}/{s.alerts_index})" for s in configured))
    else:
        log.warning("no SIEM configured yet: add one on the Settings page (or siems/siems.json, or ELASTIC_URL)")
    return configured


def _tick(settings) -> bool:
    with db.get_connection() as conn:
        changed = settings.tick(conn)
        conn.commit()
    return changed


def _wait(seconds: float, settings) -> bool:
    """Sleep until the next cycle, but wake up early when the Settings page changes. True if it did."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        time.sleep(min(20.0, max(0.0, end - time.monotonic())))
        try:
            if _tick(settings):
                return True
        except Exception:
            log.exception("cannot read settings")
    return False


def run():
    settings = appsettings.Runtime("fetcher", every=0, extra_env=_settings_env)
    configured, synced, changed = None, False, False
    while True:
        try:
            changed = _tick(settings) or changed
            if changed or configured is None:
                changed = False
                configured, synced = load_siems(), False
                for sess in _sessions.values():
                    sess.close()
                _sessions.clear()
            if configured and not synced:
                with db.get_connection() as conn:
                    sync_siems(conn, configured)
                synced = True
            if configured:
                failed, collected = run_once(configured)
                if failed < collected:
                    HEARTBEAT.touch()              # healthy while at least one collected SIEM is reachable
            else:
                HEARTBEAT.touch()                  # waiting for a SIEM to be configured is not unhealthy
                with db.get_connection() as conn:
                    appsettings.activity(conn, "fetcher", "waiting", "No SIEM with a fetcher API key is configured",
                                         next_at=datetime.now(timezone.utc) + timedelta(seconds=20), every=0)
        except Exception:
            log.exception("fetch cycle failed")
        changed = _wait(cooldown() if configured else 20, settings) or changed


if __name__ == "__main__":
    run()
