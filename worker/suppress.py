"""Suppressions (Pro): patterns your analysts closed again and again are closed without an investigation.

A suppression is created by an analyst or admin on Insights -> Suppressions, usually from a suggestion. It
matches one rule plus the exact program, parent program and account (and optionally one host) in one SIEM,
and it always expires. A matching alert gets the suppression's verdict without the model, with the
suppression named in the summary, so it stays visible and auditable. Never applied when the alert carries a
high-impact tactic (credential access, lateral movement, impact, exfiltration) or text that tries to
instruct the model: those are always investigated.
"""
import logging
from datetime import datetime, timezone

import licensing

log = logging.getLogger("suppress")
PROTECTED_TACTICS = {"Credential Access", "Lateral Movement", "Impact", "Exfiltration"}


def _same(a, b) -> bool:
    return (a or "").strip().lower() == (b or "").strip().lower()


def find(conn, row: dict) -> dict | None:
    """The active suppression matching this alert row, or None."""
    if not licensing.has("suppressions") or not row.get("process_executable"):
        return None
    try:
        rows = conn.execute("""SELECT * FROM suppressions WHERE revoked_at IS NULL AND expires_at > NOW()
                               AND rule_name = %s AND (siem IS NOT DISTINCT FROM %s)""",
                            (row.get("rule_name"), row.get("siem"))).fetchall()
    except Exception:
        log.exception("cannot read suppressions")
        return None
    for s in rows:
        if (_same(s["process_executable"], row.get("process_executable"))
                and _same(s["parent_executable"], row.get("parent_executable"))
                and _same(s["user_name"], row.get("user_name"))
                and (s["host_name"] is None or _same(s["host_name"], row.get("host_name")))):
            return s
    return None


def blocked(ctx: dict) -> str | None:
    """Why this alert must be investigated even though a suppression matches, or None."""
    tactics = {m.get("tactic") for m in ctx["rule"].get("mitre") or []}
    if tactics & PROTECTED_TACTICS:
        return f"high-impact tactic ({', '.join(sorted(tactics & PROTECTED_TACTICS))})"
    if ctx.get("injection_markers"):
        return "the alert contains text that tries to instruct the model"
    return None


def verdict(s: dict) -> dict:
    expires = s["expires_at"].astimezone(timezone.utc).strftime("%d/%m/%Y")
    return {
        "verdict": s["verdict"], "severity": "Low", "confidence": 100,
        "summary": (f"Closed by suppression #{s['id']} without an investigation: {s['reason']} "
                    f"(created by {s['created_by'] or 'an analyst'}, expires {expires})."),
        "malicious_hypothesis": "", "benign_hypothesis": s["reason"], "key_findings": [], "information_gaps": [],
        "mitre_techniques": [], "recommended_actions": [], "should_escalate": False,
        "prompt_injection_suspected": False,
        "investigation": {"stop_reason": "suppressed", "suppression_id": s["id"],
                          "guardrails_applied": [f"suppression #{s['id']} matched rule, program, parent and account"]},
    }


def record_hit(conn, s: dict):
    conn.execute("UPDATE suppressions SET hits = hits + 1, last_hit_at = %s WHERE id = %s",
                 (datetime.now(timezone.utc), s["id"]))
