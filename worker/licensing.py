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
  2. a Lemon Squeezy licence key in ARDEA_LICENSE_KEY. The worker activates it once (one activation
     per installation) and re-validates it every 24 h (through ARDEA_LICENSE_PROXY, or EGRESS_PROXY, if set). Only the key and an
     installation name are sent; no alert data ever goes to the licence server.
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
    "multi_siem": "msp",
    "branding": "msp",
    "customer_reports": "msp",       # per-SIEM scheduled reports
    "customer_routing": "msp",       # per-SIEM notification targets
    "customer_context": "msp",       # per-SIEM environment facts and playbooks
    "usage_export": "msp",
}
GRACE_UNREACHABLE = timedelta(days=30)
GRACE_INVALID = timedelta(hours=72)
CHECK_EVERY = timedelta(hours=24)
RETRY_FAILED_CHECK = timedelta(hours=1)
API = "https://api.lemonsqueezy.com/v1/licenses"
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


def read_offline_license(path: pathlib.Path = None) -> dict | None:
    """The offline licence's payload, None if there is no file. Raises LicenseInvalid if it is bad."""
    path = path or OFFLINE_FILE
    if path.is_file():
        text, where = path.read_text(), path.name
    elif path == OFFLINE_FILE and appsettings.env("ARDEA_LICENSE_OFFLINE"):
        text, where = appsettings.env("ARDEA_LICENSE_OFFLINE"), "the offline licence on the Settings page"
    else:
        return None
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


# --------------------------------------------------------------------------- Lemon Squeezy
def _proxies():
    proxy = appsettings.env("ARDEA_LICENSE_PROXY") or appsettings.env("EGRESS_PROXY")
    return {"https": proxy, "http": proxy} if proxy else None


def _call(endpoint: str, data: dict) -> dict:
    try:
        r = requests.post(f"{API}/{endpoint}", data=data, headers={"Accept": "application/json"},
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
    body["_http_status"] = r.status_code
    return body


def interpret(body: dict, ok_field: str) -> dict:
    """Map a Lemon Squeezy activate/validate answer to an edition, or raise LicenseInvalid."""
    lk = body.get("license_key") or {}
    meta = body.get("meta") or {}
    if not body.get(ok_field):
        raise LicenseInvalid(str(body.get("error") or "licence key is not valid")[:200])
    if lk.get("status") != "active":
        raise LicenseInvalid(f"licence key is {lk.get('status') or 'not active'}")
    ls = EDITION.get("lemonsqueezy") or {}
    if not ls.get("store_id"):
        raise LicenseInvalid("this build has no store configured (run release.py set-store)")
    if str(meta.get("store_id")) != str(ls["store_id"]):
        raise LicenseInvalid("this key is not an Ardea licence")
    tier_name = (ls.get("products") or {}).get(str(meta.get("product_id")))
    if tier_name not in ("pro", "msp"):
        raise LicenseInvalid("this key is for a product that is not an Ardea edition")
    return {"tier": tier_name, "status": "active",
            "customer": str(meta.get("customer_name") or meta.get("customer_email") or "")[:120] or None,
            "product": str(meta.get("variant_name") or meta.get("product_name") or tier_name)[:120],
            "expires_at": _parse_time(lk.get("expires_at")),
            "instance_id": (body.get("instance") or {}).get("id")}


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

    # 2. Lemon Squeezy key
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
        if same_key and row["instance_id"]:
            info = interpret(_call("validate", {"license_key": key, "instance_id": row["instance_id"]}), "valid")
            info["instance_id"] = info["instance_id"] or row["instance_id"]
        else:
            info = interpret(_call("activate", {"license_key": key,
                                                "instance_name": f"Ardea {row['install_id'][:12]}"}),
                             "activated")
    except LicenseUnreachable as exc:
        log.warning("licence check postponed: %s", exc)
        fields = {"last_checked_at": now, "last_error": str(exc)}
        if not same_key:                       # a new key that was never confirmed grants nothing yet
            fields.update(tier="community", source="lemonsqueezy", status="unverified", key_hash=key_hash,
                          instance_id=None, valid_until=None, customer=None, product=None, expires_at=None)
        _update(conn, **fields)
        return
    except LicenseInvalid as exc:
        log.error("licence key not accepted: %s", exc)
        keep = row["valid_until"] if same_key and row["valid_until"] and row["source"] == "lemonsqueezy" else None
        _update(conn, source="lemonsqueezy", status="invalid", key_hash=key_hash,
                # an installation removed in the customer portal is activated again on the next check
                instance_id=None if not same_key or "instance" in str(exc).lower() else row["instance_id"],
                valid_until=min(keep, now + GRACE_INVALID) if keep else None,
                last_checked_at=now, last_error=str(exc))
        if not same_key:
            _update(conn, tier="community")
        return

    valid_until = now + GRACE_UNREACHABLE
    if info["expires_at"]:
        valid_until = min(valid_until, info["expires_at"])
    _update(conn, tier=info["tier"], source="lemonsqueezy", status="active", customer=info["customer"],
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
