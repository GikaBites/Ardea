"""Flood guard: when one rule fires again and again with the same program, investigate a few, reuse the rest.

A "pattern" is the same SIEM, rule, program and parent program (the host and account may differ, which is
what a burst across many machines looks like). When at least FLOOD_SAMPLE alerts of the pattern were fully
investigated in the last FLOOD_WINDOW_HOURS and every one of them got the same verdict, the next alert of the
pattern gets that verdict without the model, with the investigated alerts named in its summary.

Never reused:
  * a True Positive (every host of a real attack is investigated);
  * when any alert of the pattern was a True Positive, or an analyst disagreed with one of its verdicts;
  * a closing verdict (Benign / False Positive) below the confidence needed to close;
  * alerts with a high-impact tactic (credential access, lateral movement, impact, exfiltration) or with text
    that tries to instruct the model;
  * alerts without a program (nothing to compare).
Every FLOOD_RECHECK_EVERY reused alerts, one is investigated in full again, so a pattern that changes is noticed.
"""
import logging
from datetime import timedelta

import appsettings
import config

log = logging.getLogger("flood")
PROTECTED_TACTICS = {"Credential Access", "Lateral Movement", "Impact", "Exfiltration"}
REUSABLE = ("Benign Positive", "False Positive", "Needs Human Review")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(appsettings.env(name, str(default)) or default)))
    except ValueError:
        return default


def enabled() -> bool:
    return appsettings.env("FLOOD_GUARD", "true").strip().lower() == "true"


def blocked(ctx: dict) -> str | None:
    tactics = {m.get("tactic") for m in ctx["rule"].get("mitre") or []}
    if tactics & PROTECTED_TACTICS:
        return "high-impact tactic"
    if ctx.get("injection_markers"):
        return "text that tries to instruct the model"
    return None


def find(conn, row: dict) -> dict | None:
    """{'verdict': .., 'samples': [...], 'base': result} to reuse for this alert, or None to investigate."""
    if not enabled() or not row.get("process_executable"):
        return None
    sample = _int("FLOOD_SAMPLE", 3, 2, 20)
    window = timedelta(hours=_int("FLOOD_WINDOW_HOURS", 6, 1, 72))
    recheck = _int("FLOOD_RECHECK_EVERY", 25, 5, 500)
    rows = conn.execute("""
        SELECT a.alert_id, a.host_name, t.verdict, t.confidence, t.result, t.model, t.created_at,
               EXISTS (SELECT 1 FROM feedback f WHERE f.alert_id = a.alert_id AND NOT f.agrees) AS disputed,
               EXISTS (SELECT 1 FROM feedback f WHERE f.alert_id = a.alert_id AND f.correct_verdict = 'True Positive')
                   AS called_tp
        FROM alerts a JOIN triage_results t ON t.alert_id = a.alert_id
        WHERE a.siem IS NOT DISTINCT FROM %(siem)s AND a.rule_name = %(rule)s
          AND a.process_executable = %(exe)s AND a.parent_executable IS NOT DISTINCT FROM %(parent)s
          AND t.created_at > NOW() - %(window)s AND a.alert_id <> %(id)s
        ORDER BY t.created_at DESC LIMIT 200""",
        {"siem": row.get("siem"), "rule": row.get("rule_name"), "exe": row["process_executable"],
         "parent": row.get("parent_executable"), "window": window, "id": row["alert_id"]}).fetchall()
    if not rows or any(r["verdict"] == "True Positive" or r["disputed"] or r["called_tp"] for r in rows):
        return None
    full = [r for r in rows if r["model"] and (r["result"] or {}).get("investigation", {}).get("stop_reason")
            not in ("flood_reused", "suppressed")]
    if len(full) < sample:
        return None
    full_ids = {r["alert_id"] for r in full}
    since_last_full = 0
    for r in rows:                                   # newest first: reused ones since the newest full one
        if r["alert_id"] in full_ids:
            break
        since_last_full += 1
    if since_last_full >= recheck:
        log.info("flood %s: %s reused since the last full investigation, investigating this one",
                 row.get("rule_name"), since_last_full)
        return None
    recent = full[:sample]
    verdicts = {r["verdict"] for r in recent}
    if len(verdicts) != 1:
        return None
    verdict = verdicts.pop()
    if verdict not in REUSABLE:
        return None
    if verdict != "Needs Human Review" and min(r["confidence"] or 0 for r in recent) < config.MIN_CONFIDENCE_TO_CLOSE:
        return None
    return {"verdict": verdict, "samples": recent, "base": recent[0]["result"] or {}, "reused_before": since_last_full}


def verdict(found: dict) -> dict:
    base, samples = found["base"], found["samples"]
    ids = ", ".join(s["alert_id"].split(":")[-1][:12] for s in samples)
    hosts = sorted({s["host_name"] for s in samples if s["host_name"]})
    conf = min(int(s["confidence"] or 0) for s in samples)
    summary = (f"Part of a burst: the same rule, program and parent program were investigated {len(samples)} times "
               f"in the last hours{' (on ' + ', '.join(hosts[:4]) + ')' if hosts else ''} and every time the verdict "
               f"was {found['verdict']}, so it was reused without a new investigation (alerts {ids}). "
               f"Earlier finding: {base.get('summary') or ''}")
    return {
        "verdict": found["verdict"], "severity": base.get("severity") or "Low", "confidence": conf,
        "summary": summary[:2000], "malicious_hypothesis": base.get("malicious_hypothesis", ""),
        "benign_hypothesis": base.get("benign_hypothesis", ""), "key_findings": [],
        "information_gaps": ["This alert itself was not investigated; open an investigated alert of the burst "
                             "for the evidence."],
        "mitre_techniques": base.get("mitre_techniques") or [], "recommended_actions": base.get("recommended_actions") or [],
        "should_escalate": False, "prompt_injection_suspected": False,
        "investigation": {"stop_reason": "flood_reused", "reused_from": [s["alert_id"] for s in samples],
                          "guardrails_applied": [f"flood guard: same verdict on {len(samples)} investigated alerts "
                                                 "of this pattern"]},
    }
