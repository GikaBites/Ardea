"""Final verdict schema (what the model must produce) + deterministic post-validation."""
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

import config

Verdict = Literal["True Positive", "Benign Positive", "False Positive", "Needs Human Review"]
Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]


class Finding(BaseModel):
    claim: str = Field(..., max_length=400, description="One factual statement.")
    stance: Literal["suspicious", "benign", "neutral"]
    evidence_ids: list[str] = Field(..., description="IDs like 'ALERT', 'E1', 'E2' that support the claim.")


class MitreRef(BaseModel):
    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(..., max_length=120)


class Action(BaseModel):
    action: str = Field(..., max_length=300)
    priority: Literal["immediate", "soon", "routine"]


_LIMITS = {"summary": 600, "malicious_hypothesis": 400, "benign_hypothesis": 400}
_LIST_LIMITS = {"key_findings": 10, "information_gaps": 6, "mitre_techniques": 5, "recommended_actions": 6}


def _tidy(data):
    """Trim over-long text and lists instead of rejecting the whole verdict (small models overshoot)."""
    if not isinstance(data, dict):
        return data
    for k, n in _LIMITS.items():
        if isinstance(data.get(k), str):
            data[k] = data[k][:n]
    for k, n in _LIST_LIMITS.items():
        if isinstance(data.get(k), list):
            data[k] = data[k][:n]
    for f in data.get("key_findings") or []:
        if isinstance(f, dict) and isinstance(f.get("claim"), str):
            f["claim"] = f["claim"][:400]
        if isinstance(f, dict) and isinstance(f.get("evidence_ids"), str):
            f["evidence_ids"] = [f["evidence_ids"]]
    for a in data.get("recommended_actions") or []:
        if isinstance(a, dict) and isinstance(a.get("action"), str):
            a["action"] = a["action"][:300]
    if isinstance(data.get("mitre_techniques"), list):
        import re as _re
        data["mitre_techniques"] = [m for m in data["mitre_techniques"] if isinstance(m, dict)
                                    and _re.match(r"^T\d{4}(\.\d{3})?$", str(m.get("technique_id", "")))]
        for m in data["mitre_techniques"]:
            if isinstance(m.get("name"), str):
                m["name"] = m["name"][:120]
    if isinstance(data.get("information_gaps"), list):
        data["information_gaps"] = [str(g)[:300] for g in data["information_gaps"]]
    if isinstance(data.get("confidence"), (int, float)):
        data["confidence"] = max(0, min(100, int(data["confidence"])))
    return data


class ModelVerdict(BaseModel):
    """Exactly what the LLM fills in. A simplified copy is passed to Ollama as `format=`."""

    @model_validator(mode="before")
    @classmethod
    def _pre(cls, data):
        return _tidy(data)

    verdict: Verdict
    severity: Severity
    confidence: int = Field(..., ge=0, le=100)
    summary: str = Field(..., max_length=600, description="2-3 sentences for the analyst.")
    malicious_hypothesis: str = Field(..., max_length=400, description="Best-case attacker explanation.")
    benign_hypothesis: str = Field(..., max_length=400, description="Best-case legitimate explanation.")
    key_findings: list[Finding] = Field(..., min_length=1, max_length=10)
    information_gaps: list[str] = Field(default_factory=list, max_length=6)
    mitre_techniques: list[MitreRef] = Field(default_factory=list, max_length=5)
    recommended_actions: list[Action] = Field(default_factory=list, max_length=6)
    should_escalate: bool
    prompt_injection_suspected: bool

    @field_validator("key_findings")
    @classmethod
    def _non_empty_evidence(cls, v):
        for f in v:
            if not f.evidence_ids:
                raise ValueError("every finding needs at least one evidence id")
        return v


# Constraints that llama.cpp grammars handle badly: maxLength:600 expands into ~600 nested grammar
# rules per field, which makes Ollama return HTTP 500 (or decode very slowly). We keep them in
# pydantic for validation, but send the model a schema with only types, enums and required keys.
_GRAMMAR_UNSAFE = {"maxLength", "minLength", "pattern", "maxItems", "minItems", "maximum", "minimum",
                   "description", "title"}


def _strip(node):
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if k not in _GRAMMAR_UNSAFE}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def json_schema() -> dict:
    """Grammar-friendly schema for Ollama's `format=`; full validation happens in pydantic."""
    return _strip(ModelVerdict.model_json_schema())


class ReviewFact(BaseModel):
    fact: str = Field(..., max_length=400)
    evidence_ids: list[str]


class ClosureReview(BaseModel):
    """Output of the adversarial closure review (kept tiny: ~10-20 s of generation on CPU)."""

    @model_validator(mode="before")
    @classmethod
    def _pre(cls, data):
        if isinstance(data, dict):
            facts = data.get("unexplained_facts")
            if isinstance(facts, list):
                data["unexplained_facts"] = facts[:5]
                for f in data["unexplained_facts"]:
                    if isinstance(f, dict) and isinstance(f.get("fact"), str):
                        f["fact"] = f["fact"][:400]
                    if isinstance(f, dict) and isinstance(f.get("evidence_ids"), str):
                        f["evidence_ids"] = [f["evidence_ids"]]
        return data

    unexplained_facts: list[ReviewFact] = Field(default_factory=list)
    uphold_closure: bool


def closure_review_schema() -> dict:
    return _strip(ClosureReview.model_json_schema())


CLOSING = ("False Positive", "Benign Positive")


def apply_guardrails(v: ModelVerdict, valid_evidence_ids: set[str], *, injection_markers: list[str],
                     playbook: dict, budget_exhausted: bool, history: list[dict] | None = None,
                     closure_review: dict | None = None,
                     context_overflow: bool = False) -> tuple[dict, list[str]]:
    """Deterministic rules the model cannot override. Returns (final dict, list of guardrail notes)."""
    notes = []
    out = v.model_dump()

    # 1. Citations must point to evidence that actually exists.
    kept = []
    for f in out["key_findings"]:
        good = [e for e in f["evidence_ids"] if e in valid_evidence_ids]
        if not good:
            notes.append(f"dropped uncited/invalid finding: {f['claim'][:80]}")
            continue
        f["evidence_ids"] = good
        kept.append(f)
    out["key_findings"] = kept
    if not kept and out["verdict"] != "Needs Human Review":
        notes.append("no finding had valid evidence -> Needs Human Review")
        out["verdict"] = "Needs Human Review"

    closing = out["verdict"] in ("False Positive", "Benign Positive")

    # 2. Low-confidence closures go to a human (missing a TP costs far more than a review).
    if closing and out["confidence"] < config.MIN_CONFIDENCE_TO_CLOSE:
        notes.append(f"confidence {out['confidence']} < {config.MIN_CONFIDENCE_TO_CLOSE} for a closing verdict")
        out["verdict"] = "Needs Human Review"

    # 3. Any sign of prompt injection: never auto-close.
    if injection_markers or out["prompt_injection_suspected"]:
        out["prompt_injection_suspected"] = True
        if out["verdict"] in ("False Positive", "Benign Positive"):
            notes.append("prompt-injection markers present -> cannot auto-close")
            out["verdict"] = "Needs Human Review"

    # 4. Rule-level policy from the playbook.
    if playbook.get("never_auto_close") and out["verdict"] in ("False Positive", "Benign Positive"):
        notes.append("playbook forbids auto-closing this rule")
        out["verdict"] = "Needs Human Review"

    # 5. Ran out of budget and still wants to close with weak support -> review.
    if budget_exhausted and closing and len(kept) < 2:
        notes.append("investigation budget exhausted with thin evidence")
        out["verdict"] = "Needs Human Review"

    # 6. An analyst already called a similar alert malicious: a human decides this one too.
    for h in history or []:
        if (h.get("analyst_verdict") == "True Positive" and h.get("match") in ("same pattern", "same host")
                and out["verdict"] in CLOSING):
            notes.append(f"analyst marked a similar alert ({h['match']}) True Positive -> cannot auto-close")
            out["verdict"] = "Needs Human Review"
            break

    # 7. The adversarial closure review found facts the benign story does not explain (or failed).
    if closure_review is not None and out["verdict"] in CLOSING:
        cited = [f for f in closure_review.get("unexplained_facts", [])
                 if any(e in valid_evidence_ids for e in f.get("evidence_ids", []))]
        if cited or not closure_review.get("uphold_closure"):
            reason = "; ".join(f["fact"][:120] for f in cited[:3]) or closure_review.get("error") or \
                "reviewer did not uphold the closure"
            notes.append(f"closure review -> Needs Human Review: {reason}")
            out["verdict"] = "Needs Human Review"
            out["information_gaps"] = (out["information_gaps"] +
                                       [f"Unexplained: {f['fact'][:280]}" for f in cited])[:6]

    # 8. The prompt overflowed num_ctx, so the model may not have seen its own rules.
    if context_overflow and out["verdict"] in CLOSING:
        notes.append("context window overflowed -> cannot auto-close")
        out["verdict"] = "Needs Human Review"

    # 9. Escalation is derived, not trusted.
    out["should_escalate"] = (out["verdict"] in ("True Positive", "Needs Human Review")
                              or out["severity"] in ("Critical", "High") and out["verdict"] != "False Positive")
    return out, notes


def fallback_verdict(reason: str) -> dict:
    """Used when the model fails completely. Always visible in the UI, never silent."""
    return {
        "verdict": "Needs Human Review", "severity": "Medium", "confidence": 0,
        "summary": f"Automated triage failed: {reason}. Please triage manually.",
        "malicious_hypothesis": "", "benign_hypothesis": "",
        "key_findings": [], "information_gaps": [reason], "mitre_techniques": [],
        "recommended_actions": [{"action": "Triage this alert manually in Kibana.", "priority": "soon"}],
        "should_escalate": True, "prompt_injection_suspected": False,
    }
