"""Ardea editions: Community (free), Pro and MSP.

What a licence changes, and what it never changes:
  * Triage, every guardrail, the closure review, prompt-injection handling, the audit trail and the
    web UI's security are IDENTICAL in every edition. A missing, expired or unreachable licence never
    stops or weakens triage; it only switches off the convenience features below.
  * Pro: True Positive notifications, the signed playbook pack, eval-case export, SSO sign-in.
  * MSP: everything in Pro, plus collecting from several SIEMs and white-label branding.

Where the licence comes from (first match wins):
  1. an offline licence file (/app/license/ardea.license), signed with the Ardea release key.
     For installations without internet access; issued by hand.
  2. a licence key from the Ardea store (Polar) in ARDEA_LICENSE_KEY or on the Settings page. The worker
     activates it once (one activation per installation) and re-validates it every 24 h (through
     ARDEA_LICENSE_PROXY, or EGRESS_PROXY, if set). Only the key, the store's id and an installation name
     are sent; no alert data ever goes to the licence server.
  3. nothing: Community.

If the licence server cannot be reached, the last good result stays valid for 30 days. If the server
says the key is no longer valid (refunded, subscription ended), the paid features stay on for 72 more
hours so nobody is surprised mid-shift.

The worker is the only service that checks the licence. It writes the result to the license_state
table; the fetcher and the web UI only read it.
"""
import base64
import hashlib
import json
import logging
import os
import pathlib
import time
import uuid
from datetime import datetime, timedelta, timezone

import requests

import appsettings

log = logging.getLogger("licensing")

TIERS = ("community", "pro", "msp")
_RANK = {t: n for n, t in enumerate(TIERS)}
FEATURES = {                     # feature -> lowest edition that has it
    "notifications": "pro",
    "integrations": "pro",           # Slack, Teams, webhook, Jira, TheHive
    "playbook_pack": "pro",
    "eval_export": "pro",
    "sso": "pro",
    "reports": "pro",                # Insights: report + trends, scheduled report e-mails
    "tuning": "pro",                 # rule-tuning advisor
    "csv_export": "pro",
    "retriage": "pro",
    "incidents": "pro",              # related alerts grouped into incidents with one timeline
    "source_health": "pro",          # warning when a SIEM stops sending events
    "digest": "pro",                 # daily handover digest
    "assignments": "pro",            # assign alerts, response deadlines, my queue
    "nis2": "pro",                   # NIS2 report drafts from an incident
    "incident_export": "pro",        # incident export (ZIP) and print view
    "multi_siem": "msp",
    "branding": "msp",
    "customer_reports": "msp",       # per-SIEM scheduled reports
    "customer_routing": "msp",       # per-SIEM notification targets
    "customer_context": "msp",       # per-SIEM environment facts and playbooks
    "usage_export": "msp",
    "host_watch": "msp",             # warning when a watched host goes quiet
}
GRACE_UNREACHABLE = timedelta(days=30)
GRACE_INVALID = timedelta(hours=72)
CHECK_EVERY = timedelta(hours=24)
RETRY_FAILED_CHECK = timedelta(hours=1)
OFFLINE_FILE = pathlib.Path(os.getenv("ARDEA_LICENSE_FILE", "/app/license/ardea.license"))
_LOCK = 7270030

_EDITION_FILE = pathlib.Path(__file__).with_name("edition.json")
EDITION = json.loads(_EDITION_FILE.read_text()) if _EDITION_FILE.is_file() else {}

SCHEMA = """
CREATE TABLE IF NOT EXISTS license_state (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    install_id      TEXT NOT NULL,
    tier            TEXT NOT NULL DEFAULT 'community',
    source          TEXT NOT NULL DEFAULT 'none',
    status          TEXT,
    customer        TEXT,
    product         TEXT,
    key_hash        TEXT,
    instance_id     TEXT,
    expires_at      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    last_ok_at      TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    last_error      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"""

# The edition this process currently runs as. Refreshed from the database by sync().
_state = {"tier": "community", "read_at": 0.0}


class LicenseUnreachable(Exception):
    """Network error, timeout, HTTP 429/5xx: not the customer's fault, keep the last good result."""


class LicenseInvalid(Exception):
    """The licence server (or the signature check) says no."""


# --------------------------------------------------------------------------- edition / features
def effective_tier(row: dict | None, now: datetime | None = None) -> str:
    """The edition a license_state row grants right now."""
    if not row or row.get("tier") not in _RANK:
        return "community"
    valid_until = row.get("valid_until")
    if valid_until is None or valid_until <= (now or datetime.now(timezone.utc)):
        return "community"
    return row["tier"]


def tier() -> str:
    return _state["tier"]


def has(feature: str) -> bool:
    return _RANK[_state["tier"]] >= _RANK[FEATURES[feature]]


def set_tier(value: str):
    """Tests and the eval runner."""
    if value not in _RANK:
        raise ValueError(value)
    _state.update(tier=value, read_at=time.monotonic())


def sync(conn, max_age: float = 60.0) -> str:
    """Re-read license_state at most every max_age seconds. Never raises: a database hiccup keeps
    the edition that was last read."""
    if time.monotonic() - _state["read_at"] < max_age:
        return _state["tier"]
    try:
        row = conn.execute("SELECT * FROM license_state WHERE id = 1").fetchone()
        new = effective_tier(row)
    except Exception:
        log.exception("cannot read license_state")
        return _state["tier"]
    if new != _state["tier"]:
        log.warning("edition is now %s", new.upper())
    _state.update(tier=new, read_at=time.monotonic())
    return new


# --------------------------------------------------------------------------- signatures
def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def signed_message(purpose: str, payload: dict) -> bytes:
    """What the release key signs. The purpose prefix stops a pack signature being reused as a licence."""
    return f"ardea-{purpose}-v1\n".encode() + _canonical(payload)


def verify_signed(doc: dict, purpose: str) -> dict:
    """Return doc['payload'] if doc['signature'] is a valid release-key signature, else raise LicenseInvalid."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key_b64 = EDITION.get("release_public_key") or ""
    if not key_b64:
        raise LicenseInvalid("this build has no release key (run release.py set-key)")
    if not isinstance(doc, dict) or not isinstance(doc.get("payload"), dict):
        raise LicenseInvalid("not a signed Ardea file")
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key_b64))
        public.verify(base64.b64decode(str(doc.get("signature", ""))), signed_message(purpose, doc["payload"]))
    except (InvalidSignature, ValueError):
        raise LicenseInvalid("signature is not valid") from None
    return doc["payload"]


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _offline_text(path: pathlib.Path = None) -> tuple[str, str] | None:
    """(text, where) of the offline licence: the file, else the Settings page. None if there is none."""
    path = path or OFFLINE_FILE
    if path.is_file():
        return path.read_text(), path.name
    if path == OFFLINE_FILE and appsettings.env("ARDEA_LICENSE_OFFLINE"):
        return appsettings.env("ARDEA_LICENSE_OFFLINE"), "the offline licence on the Settings page"
    return None


def offline_license_doc() -> dict | None:
    """The signed offline licence as stored (signature not checked here), for the pack server."""
    found = _offline_text()
    try:
        return json.loads(found[0]) if found else None
    except (OSError, json.JSONDecodeError):
        return None


def read_offline_license(path: pathlib.Path = None) -> dict | None:
    """The offline licence's payload, None if there is no file. Raises LicenseInvalid if it is bad."""
    found = _offline_text(path)
    if found is None:
        return None
    text, where = found
    try:
        doc = json.loads(text)
    except (OSError, json.JSONDecodeError):
        raise LicenseInvalid(f"{where} is not readable JSON") from None
    payload = verify_signed(doc, "license")
    if payload.get("tier") not in ("pro", "msp"):
        raise LicenseInvalid("offline licence has no valid tier")
    try:
        expires = _parse_time(payload.get("expires"))
    except ValueError:
        raise LicenseInvalid("offline licence has a bad expiry date") from None
    if expires is None:
        raise LicenseInvalid("offline licence has no expiry date")
    payload["_expires"] = expires
    return payload


# --------------------------------------------------------------------------- Polar (online licence keys)
# Polar is the reseller (merchant of record) and issues the licence keys. edition.json pins which Polar
# organisation and which licence-key benefits are Ardea editions; release.py set-store writes it.
POLAR_API = {"production": "https://api.polar.sh", "sandbox": "https://sandbox-api.polar.sh"}
PRODUCT_NAMES = {"pro": "Ardea Pro", "msp": "Ardea MSP"}


def _proxies():
    proxy = appsettings.env("ARDEA_LICENSE_PROXY") or appsettings.env("EGRESS_PROXY")
    return {"https": proxy, "http": proxy} if proxy else None


def _polar() -> tuple[str, dict]:
    cfg = EDITION.get("polar") or {}
    if not cfg.get("organization_id") or not cfg.get("benefits"):
        raise LicenseInvalid("this build has no store configured (run release.py set-store)")
    base = POLAR_API.get(cfg.get("environment") or "production")
    if base is None:
        raise LicenseInvalid("this build has an unknown licence server configured")
    return base, cfg


def _call(path: str, data: dict) -> tuple[int, dict]:
    """POST to the licence server. Raises LicenseUnreachable for network errors, 429 and 5xx."""
    base, _ = _polar()
    try:
        r = requests.post(f"{base}{path}", json=data, headers={"Accept": "application/json"},
                          timeout=15, proxies=_proxies())
    except requests.RequestException as exc:
        raise LicenseUnreachable(f"licence server not reachable ({type(exc).__name__})") from None
    if r.status_code == 429 or r.status_code >= 500:
        raise LicenseUnreachable(f"licence server answered HTTP {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        raise LicenseUnreachable(f"licence server answered HTTP {r.status_code} without JSON") from None
    if not isinstance(body, dict):
        raise LicenseUnreachable("unexpected answer from the licence server")
    return r.status_code, body


def _detail(body: dict) -> str:
    d = body.get("detail")
    if isinstance(d, list) and d:
        d = d[0].get("msg") if isinstance(d[0], dict) else d[0]
    return str(d or body.get("error") or "")[:160]


def interpret(lk: dict, activation_id: str | None) -> dict:
    """Map a Polar licence key to an edition, or raise LicenseInvalid."""
    _, cfg = _polar()
    status = str(lk.get("status") or "")
    if status != "granted":
        raise LicenseInvalid(f"licence key is {status or 'not active'}")
    if lk.get("organization_id") and str(lk["organization_id"]) != str(cfg["organization_id"]):
        raise LicenseInvalid("this key is not an Ardea licence")
    tier_name = (cfg.get("benefits") or {}).get(str(lk.get("benefit_id")))
    if tier_name not in ("pro", "msp"):
        raise LicenseInvalid("this key is for a product that is not an Ardea edition")
    customer = lk.get("customer") or {}
    return {"tier": tier_name, "status": "active",
            "customer": str(customer.get("name") or customer.get("email") or "")[:120] or None,
            "product": PRODUCT_NAMES[tier_name], "expires_at": _parse_time(lk.get("expires_at")),
            "instance_id": activation_id}


def check_key(key: str, activation_id: str | None, label: str) -> dict:
    """Activate the key for this installation (first time) or validate it (afterwards).
    Raises LicenseUnreachable or LicenseInvalid."""
    _, cfg = _polar()
    org = str(cfg["organization_id"])
    if not activation_id:
        status, body = _call("/v1/customer-portal/license-keys/activate",
                             {"key": key, "organization_id": org, "label": label[:100]})
        if status in (200, 201):
            return interpret(body.get("license_key") or {}, str(body.get("id") or "") or None)
        detail = _detail(body)
        if status == 404:
            raise LicenseInvalid("licence key not found")
        if "activation" not in detail.lower() or "limit" in detail.lower():
            if "limit" in detail.lower():
                raise LicenseInvalid("this key is already in use on another installation: free it in your "
                                     "customer portal, then check again")
            raise LicenseInvalid(detail or f"licence key not accepted (HTTP {status})")
        # a key without activation limits cannot be activated: validate it as it is
    payload = {"key": key, "organization_id": org}
    if activation_id:
        payload["activation_id"] = activation_id
    status, body = _call("/v1/customer-portal/license-keys/validate", payload)
    if status == 404:
        raise LicenseInvalid("this installation's activation was removed, or the key does not exist"
                             if activation_id else "licence key not found")
    if status != 200:
        raise LicenseInvalid(_detail(body) or f"licence key not accepted (HTTP {status})")
    return interpret(body, activation_id)


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def _license_key() -> str:
    return appsettings.env("ARDEA_LICENSE_KEY")


# --------------------------------------------------------------------------- refresh (worker only)
def ensure_schema(conn):
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK,))
        conn.execute(SCHEMA)
        conn.execute("INSERT INTO license_state (id, install_id) VALUES (1, %s) ON CONFLICT (id) DO NOTHING",
                     (uuid.uuid4().hex,))


def _update(conn, **fields):
    cols = ", ".join(f"{k} = %({k})s" for k in fields)
    conn.execute(f"UPDATE license_state SET {cols}, updated_at = NOW() WHERE id = 1", fields)


def refresh(conn, force: bool = False) -> dict:
    """Check the licence if it is due (or forced) and store the result. Never raises."""
    try:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK,))       # one worker checks at a time
            _refresh(conn, force)
    except Exception:
        log.exception("licence check failed")
    _state["read_at"] = 0.0
    sync(conn)
    return conn.execute("SELECT * FROM license_state WHERE id = 1").fetchone()


def _refresh(conn, force: bool):
    now = datetime.now(timezone.utc)
    row = conn.execute("SELECT * FROM license_state WHERE id = 1").fetchone()

    # 1. offline licence file
    try:
        offline = read_offline_license()
    except LicenseInvalid as exc:
        offline = None
        log.error("offline licence ignored: %s", exc)
        offline_error = f"offline licence: {exc}"
    else:
        offline_error = None
    if offline:
        _update(conn, tier=offline["tier"], source="offline", status="active",
                customer=str(offline.get("customer") or "")[:120] or None, product=f"{offline['tier']} (offline)",
                key_hash=None, instance_id=row["instance_id"], expires_at=offline["_expires"],
                valid_until=offline["_expires"], last_ok_at=now, last_checked_at=now, last_error=None)
        return

    # 2. licence key (Polar)
    key = _license_key()
    if not key:
        _update(conn, tier="community", source="none", status=None, customer=None, product=None, key_hash=None,
                expires_at=None, valid_until=None, last_checked_at=now, last_error=offline_error)
        return
    key_hash = _key_hash(key)
    same_key = row["key_hash"] == key_hash
    last = row["last_checked_at"]
    due = (not same_key or force or last is None
           or now - last > (CHECK_EVERY if row["last_error"] is None else RETRY_FAILED_CHECK))
    if not due:
        return
    try:
        info = check_key(key, row["instance_id"] if same_key else None, f"Ardea {row['install_id'][:12]}")
    except LicenseUnreachable as exc:
        log.warning("licence check postponed: %s", exc)
        fields = {"last_checked_at": now, "last_error": str(exc)}
        if not same_key:                       # a new key that was never confirmed grants nothing yet
            fields.update(tier="community", source="key", status="unverified", key_hash=key_hash,
                          instance_id=None, valid_until=None, customer=None, product=None, expires_at=None)
        _update(conn, **fields)
        return
    except LicenseInvalid as exc:
        log.error("licence key not accepted: %s", exc)
        keep = row["valid_until"] if same_key and row["valid_until"] and row["source"] == "key" else None
        _update(conn, source="key", status="invalid", key_hash=key_hash,
                # an installation removed in the customer portal is activated again on the next check
                instance_id=None if not same_key or "activation" in str(exc).lower() else row["instance_id"],
                valid_until=min(keep, now + GRACE_INVALID) if keep else None,
                last_checked_at=now, last_error=str(exc))
        if not same_key:
            _update(conn, tier="community")
        return

    valid_until = now + GRACE_UNREACHABLE
    if info["expires_at"]:
        valid_until = min(valid_until, info["expires_at"])
    _update(conn, tier=info["tier"], source="key", status="active", customer=info["customer"],
            product=info["product"], key_hash=key_hash, instance_id=info["instance_id"],
            expires_at=info["expires_at"], valid_until=valid_until, last_ok_at=now, last_checked_at=now,
            last_error=None)
    if not same_key or row["tier"] != info["tier"]:
        log.warning("licence accepted: %s (%s)", info["tier"].upper(), info["product"])


if __name__ == "__main__":      # `docker compose exec worker python licensing.py` -> check now and show the result
    import db
    logging.basicConfig(level="INFO")
    with db.get_connection() as c:
        ensure_schema(c)
        r = refresh(c, force=True)
    print(f"edition:     {effective_tier(r).upper()}")
    for k in ("source", "status", "product", "customer", "valid_until", "last_ok_at", "last_error"):
        print(f"{k + ':':13}{r[k] if r[k] is not None else '-'}")
