"""The playbook pack, installed from the Settings page (Pro / MSP).

Three ways in, one check: every pack must carry a valid Ardea release-key signature before it is used.
  * "Install the latest pack": the publisher queues it; the worker asks the Ardea pack server, which
    hands the newest signed pack to a valid licence (key or offline licence) and to nobody else.
  * Automatic updates: the same request once a day, when ARDEA_PACK_AUTO_UPDATE is on.
  * Upload: an admin uploads a .ardpack file (servers without internet); the publisher stores it as
    'pending' and the worker checks it here.
Installed packs live in the playbook_packs table; sync() hands the verified ones to playbooks.py.
Only the licence key (or the offline licence) and the installed pack version are sent, never alert data.
"""
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import requests

import appsettings
import licensing
import playbooks

log = logging.getLogger("packs")
DEFAULT_SERVER = "https://packs.ardeasecurity.com"
AUTO_EVERY = timedelta(hours=24)
RETRY_AFTER = timedelta(hours=6)
MAX_PACK_BYTES = 2 * 1024 * 1024
_SECTIONS = ("by_rule_id", "by_rule_name", "by_tactic")
_synced = {"at": 0.0}


class PackUnavailable(Exception):
    """The pack could not be fetched or installed; the message is safe to show on the Settings page."""


# --------------------------------------------------------------------------- what the page shows
def summary(payload: dict) -> dict:
    """What the Settings page shows about a pack (rule names and tactics; rule ids only as a count)."""
    return {"version": payload.get("version"), "name": payload.get("name") or "Ardea playbook pack",
            "issued": payload.get("issued"),
            "counts": {s: len(payload.get(s) or {}) for s in _SECTIONS},
            "rule_names": sorted(payload.get("by_rule_name") or {}),
            "tactics": sorted(payload.get("by_tactic") or {})}


def installed_version(conn) -> str | None:
    best = None
    for r in conn.execute("SELECT version FROM playbook_packs WHERE status = 'installed'").fetchall():
        if r["version"] and playbooks.newer(r["version"], best):
            best = r["version"]
    return best


def _audit(conn, actor: str, action: str):
    conn.execute("INSERT INTO settings_audit (actor, name, action) VALUES (%s, 'PLAYBOOK_PACK', %s)",
                 (actor[:80], action[:200]))


def _store(conn, doc: dict, payload: dict, source: str, actor: str) -> bool:
    """Save a verified pack. False if that version is already installed."""
    exists = conn.execute("SELECT 1 FROM playbook_packs WHERE status = 'installed' AND version = %s",
                          (payload["version"],)).fetchone()
    if exists:
        return False
    conn.execute("""INSERT INTO playbook_packs (version, content, source, status, summary, added_by, installed_at)
                    VALUES (%s, %s, %s, 'installed', %s, %s, NOW())""",
                 (payload["version"], json.dumps(doc, ensure_ascii=False), source,
                  json.dumps(summary(payload)), actor))
    _audit(conn, actor, f"installed {payload['version']} ({source})")
    _synced["at"] = 0.0
    return True


# --------------------------------------------------------------------------- the pack server
def _credentials(conn) -> dict:
    """What proves this installation may have the pack: the licence key, else the offline licence."""
    state = conn.execute("SELECT source, instance_id FROM license_state WHERE id = 1").fetchone() or {}
    key = licensing._license_key()
    if state.get("source") == "key" and key:
        return {"license_key": key, "activation_id": state.get("instance_id")}
    offline = licensing.offline_license_doc()
    if state.get("source") == "offline" and offline:
        return {"offline_license": offline}
    raise PackUnavailable("The playbook pack needs an Ardea Pro or MSP licence. Add it on the Licence tab first.")


def _server() -> str:
    return (appsettings.env("ARDEA_PACK_SERVER") or licensing.EDITION.get("pack_server") or DEFAULT_SERVER).rstrip("/")


def fetch_latest(conn) -> tuple[dict | None, str]:
    """(signed pack, server version) from the pack server; pack is None when ours is already the newest."""
    have = installed_version(conn)
    body = dict(_credentials(conn), have=have)
    try:
        r = requests.post(f"{_server()}/v1/pack", json=body, timeout=30, proxies=licensing._proxies(),
                          headers={"Accept": "application/json", "User-Agent": "Ardea"})
    except requests.RequestException as exc:
        raise PackUnavailable(f"The pack server is not reachable ({type(exc).__name__}). If the worker uses a "
                              "proxy, set it on the Licence tab, or upload the pack file instead.") from None
    if len(r.content) > MAX_PACK_BYTES:
        raise PackUnavailable("The pack server sent more data than a pack can be.")
    try:
        data = r.json()
    except ValueError:
        raise PackUnavailable(f"The pack server answered HTTP {r.status_code} without a pack.") from None
    if r.status_code in (401, 402, 403, 404):
        raise PackUnavailable(f"The pack server refused: {str(data.get('error') or r.status_code)[:200]}")
    if r.status_code != 200:
        raise PackUnavailable(f"The pack server answered HTTP {r.status_code}. Try again later.")
    if data.get("up_to_date"):
        return None, str(data.get("version") or have or "")
    if not isinstance(data.get("pack"), dict):
        raise PackUnavailable("The pack server answered without a pack.")
    return data["pack"], str(data.get("version") or "")


def install_latest(conn, actor: str) -> tuple[bool, str]:
    """The "Install the latest pack" button and the daily automatic update. Never raises."""
    try:
        if not licensing.has("playbook_pack"):
            raise PackUnavailable(f"The playbook pack needs Ardea Pro or MSP (this installation runs "
                                  f"{licensing.tier().title()}).")
        doc, version = fetch_latest(conn)
        if doc is None:
            ok, detail = True, f"Pack {version} is installed: it is the newest."
        else:
            try:
                payload = playbooks.load_pack_doc(doc)
            except playbooks.PackError as exc:
                raise PackUnavailable(f"The downloaded pack failed the signature check ({exc}); not installed.") from None
            if _store(conn, doc, payload, "download", actor):
                n = sum(len(payload.get(s) or {}) for s in _SECTIONS)
                ok, detail = True, f"Pack {payload['version']} installed ({n} playbooks). It is used from the next alert."
            else:
                ok, detail = True, f"Pack {payload['version']} is installed: it is the newest."
    except PackUnavailable as exc:
        ok, detail = False, str(exc)
    except Exception as exc:                          # never let a pack problem stop the worker
        log.exception("pack install failed")
        ok, detail = False, f"Installing the pack failed ({type(exc).__name__})."
    conn.execute("""INSERT INTO playbook_pack_state (id, last_check_at, last_ok, last_detail) VALUES (1, NOW(), %s, %s)
                    ON CONFLICT (id) DO UPDATE SET last_check_at = NOW(), last_ok = EXCLUDED.last_ok,
                    last_detail = EXCLUDED.last_detail""", (ok, detail[:400]))
    (log.info if ok else log.warning)("playbook pack: %s", detail)
    return ok, detail


# --------------------------------------------------------------------------- uploads
def check_uploads(conn):
    """Verify packs the publisher stored as 'pending'."""
    for row in conn.execute("SELECT id, content, added_by FROM playbook_packs WHERE status = 'pending' "
                            "ORDER BY id LIMIT 3").fetchall():
        status, detail, version, summ = "rejected", "", None, None
        try:
            if not licensing.has("playbook_pack"):
                raise PackUnavailable(f"needs Ardea Pro or MSP (this installation runs {licensing.tier().title()})")
            payload = playbooks.load_pack_doc(json.loads(row["content"]))
            version, summ = payload["version"], json.dumps(summary(payload))
            dup = conn.execute("SELECT 1 FROM playbook_packs WHERE status = 'installed' AND version = %s",
                               (version,)).fetchone()
            if dup:
                raise PackUnavailable(f"pack {version} is already installed")
            status, detail = "installed", f"Pack {version} installed."
        except (PackUnavailable, playbooks.PackError) as exc:
            detail = f"Not installed: {exc}."
        except (ValueError, TypeError):
            detail = "Not installed: the file is not a signed Ardea pack."
        conn.execute("""UPDATE playbook_packs SET status = %s, detail = %s, version = %s, summary = %s,
                        installed_at = CASE WHEN %s = 'installed' THEN NOW() END WHERE id = %s""",
                     (status, detail, version, summ, status, row["id"]))
        _audit(conn, row["added_by"] or "admin", f"upload {version or '?'}: {status}")
        log.info("uploaded playbook pack %s: %s", version or "?", detail)
        _synced["at"] = 0.0


# --------------------------------------------------------------------------- the worker loop
def auto_update_due(conn, now: datetime | None = None) -> bool:
    if appsettings.env("ARDEA_PACK_AUTO_UPDATE", "true").lower() != "true" or not licensing.has("playbook_pack"):
        return False
    st = conn.execute("SELECT last_check_at, last_ok FROM playbook_pack_state WHERE id = 1").fetchone()
    if not st or not st["last_check_at"]:
        return True
    wait = AUTO_EVERY if st["last_ok"] else RETRY_AFTER
    return (now or datetime.now(timezone.utc)) - st["last_check_at"] >= wait


def sync(conn):
    """Load the installed packs (signature checked again) for playbooks.py."""
    rows = conn.execute("SELECT id, content FROM playbook_packs WHERE status = 'installed' ORDER BY id").fetchall()
    ids = tuple(r["id"] for r in rows)
    if ids == playbooks._db_packs["ids"]:
        return
    payloads = []
    for r in rows:
        try:
            payloads.append(playbooks.load_pack_doc(json.loads(r["content"])))
        except (playbooks.PackError, ValueError) as exc:
            log.error("installed playbook pack #%s ignored: %s", r["id"], exc)
    playbooks.set_db_packs(ids, payloads)


def tick(conn):
    """Called from the worker loop. Cheap when nothing changed; never raises."""
    try:
        check_uploads(conn)
        if time.monotonic() - _synced["at"] > 30:
            sync(conn)
            if auto_update_due(conn):
                install_latest(conn, "automatic update")
                sync(conn)
            _synced["at"] = time.monotonic()
    except Exception:
        log.exception("playbook pack maintenance failed")

