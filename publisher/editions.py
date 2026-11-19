"""The Ardea edition for the web UI. The worker checks the licence and writes license_state; the UI
only reads it (cached for 30 s). Same feature map as worker/licensing.py.

Security features (sign-in, roles, lockout, per-user SIEM restrictions, CSRF, CSP) are never edition
dependent: a lapsed licence only switches off SSO sign-in (local passwords keep working) and branding.
"""
import logging
import time

from db import get_connection

log = logging.getLogger("ardea.editions")
TIERS = ("community", "pro", "msp")
_RANK = {t: n for n, t in enumerate(TIERS)}
FEATURES = {                     # same map as worker/licensing.py
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
    "ask": "pro",                    # ask a follow-up question about an alert
    "suppressions": "pro",           # suppressions suggested from analyst feedback
    "multi_siem": "msp",
    "branding": "msp",
    "customer_reports": "msp",       # per-SIEM scheduled reports
    "customer_routing": "msp",       # per-SIEM notification targets
    "customer_context": "msp",       # per-SIEM environment facts and playbooks
    "usage_export": "msp",
    "host_watch": "msp",             # warning when a watched host goes quiet
    "templates": "msp",              # settings templates applied across customer SIEMs
}
_cache = {"at": 0.0, "state": None}


def state(max_age: float = 30.0) -> dict:
    """license_state plus 'edition' (what it grants now). Community if the table or row is missing."""
    if _cache["state"] is not None and time.monotonic() - _cache["at"] < max_age:
        return _cache["state"]
    import demo
    if demo.ENABLED:                     # sample data only: every feature on, nothing to protect
        return {"edition": demo.EDITION, "tier": demo.EDITION, "source": "demo", "status": "demo"}
    result = {"edition": "community", "source": "none"}
    try:
        with get_connection() as conn:
            if conn.execute("SELECT to_regclass('public.license_state') AS t").fetchone()["t"]:
                row = conn.execute("""SELECT *, CASE WHEN valid_until > NOW() THEN tier ELSE 'community' END
                                             AS edition FROM license_state WHERE id = 1""").fetchone()
                if row:
                    result = dict(row)
                    if result["edition"] not in _RANK:
                        result["edition"] = "community"
    except Exception:
        log.exception("cannot read license_state")
        if _cache["state"] is not None:
            return _cache["state"]
    _cache.update(at=time.monotonic(), state=result)
    return result


def edition() -> str:
    return state()["edition"]


def has(feature: str) -> bool:
    return _RANK[edition()] >= _RANK[FEATURES[feature]]


def reset_cache():
    _cache.update(at=0.0, state=None)
