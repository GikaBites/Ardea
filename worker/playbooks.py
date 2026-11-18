"""Load playbooks.yaml (+ the signed playbook pack) and resolve the playbook and pre-LLM enrichment plan.

Two sources, merged per rule:
  * playbooks.yaml: your own playbooks, environment context and default. Always used, every edition.
  * the Ardea playbook pack (Pro / MSP), signed with the Ardea release key: installed from the Settings
    page (downloaded from the pack server or uploaded; packs.py keeps them in the database), or *.ardpack
    files in /app/packs. Playbook guidance is shown to the model as operator text, so an unsigned or
    modified pack is never loaded. The newest valid pack is used.
A playbook in playbooks.yaml always wins over the pack's playbook for the same rule id, rule name or tactic.

MSP: per-SIEM overrides. siems.json "context" adds environment facts for that SIEM's alerts, and
/app/siems/<siem id>.playbooks.yaml (same layout as playbooks.yaml) wins over both for that SIEM.
"""
import json
import logging
import os
import pathlib
import re

import yaml

import licensing

log = logging.getLogger("playbooks")
_PATH = pathlib.Path(__file__).with_name("playbooks.yaml")
PACKS_DIR = pathlib.Path(os.getenv("ARDEA_PACKS_DIR", "/app/packs"))
_cache = {"mtime": None, "data": {}}
_pack_cache = {"key": None, "pack": None}
_db_packs = {"ids": (), "packs": []}                # verified payloads from the playbook_packs table (packs.sync)
SIEMS_DIR = pathlib.Path(os.getenv("ARDEA_SIEMS_DIR", "/app/siems"))
_siem_cache: dict = {}
_SECTIONS = ("by_rule_id", "by_rule_name", "by_tactic")
_PLAYBOOK_KEYS = {"enrichment", "guidance", "never_auto_close"}


def _load() -> dict:
    mtime = _PATH.stat().st_mtime
    if _cache["mtime"] != mtime:                   # hot-reload when the file changes
        _cache["data"] = yaml.safe_load(_PATH.read_text()) or {}
        _cache["mtime"] = mtime
    return _cache["data"]


# --------------------------------------------------------------------------- playbook pack
class PackError(Exception):
    pass


def _version_key(version: str):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", str(version)))


def validate_pack(payload: dict) -> dict:
    """Structural check of a (signature-verified) pack. Raises PackError."""
    import siem_tools                              # late import: siem_tools pulls in the Elastic client

    if not isinstance(payload.get("version"), str) or not payload["version"]:
        raise PackError("pack has no version")
    for section in _SECTIONS:
        books = payload.get(section, {})
        if not isinstance(books, dict):
            raise PackError(f"{section} is not a mapping")
        for name, pb in books.items():
            if not isinstance(pb, dict) or set(pb) - _PLAYBOOK_KEYS:
                raise PackError(f"{section}/{name}: unknown keys {sorted(set(pb) - _PLAYBOOK_KEYS)}")
            if not isinstance(pb.get("guidance", ""), str) or not isinstance(pb.get("never_auto_close", False), bool):
                raise PackError(f"{section}/{name}: bad guidance or never_auto_close")
            for step in pb.get("enrichment", []) or []:
                if not isinstance(step, dict) or step.get("tool") not in siem_tools.TOOL_FUNCS:
                    raise PackError(f"{section}/{name}: unknown enrichment tool {step!r:.80}")
                if not isinstance(step.get("args", {}), dict) or not all(
                        isinstance(v, (str, int, bool)) for v in step.get("args", {}).values()):
                    raise PackError(f"{section}/{name}: enrichment args must be plain values")
    return payload


def load_pack_file(path: pathlib.Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        raise PackError("not readable JSON") from None
    return load_pack_doc(doc)


def load_pack_doc(doc) -> dict:
    """The payload of a signed pack document, after the signature and structure checks. Raises PackError."""
    try:
        payload = licensing.verify_signed(doc, "pack")
    except licensing.LicenseInvalid as exc:
        raise PackError(str(exc)) from None
    return validate_pack(payload)


def set_db_packs(ids: tuple, payloads: list[dict]):
    """packs.sync: the verified packs installed from the Settings page."""
    _db_packs.update(ids=tuple(ids), packs=list(payloads))


def newer(a: str, b: str | None) -> bool:
    """Is pack version a newer than b?"""
    return b is None or _version_key(a) > _version_key(b)


def current_pack() -> dict | None:
    """The newest valid pack (Settings page or PACKS_DIR), or None. Only for Pro / MSP."""
    files = sorted(PACKS_DIR.glob("*.ardpack")) if PACKS_DIR.is_dir() else []
    key = (licensing.has("playbook_pack"), tuple((f.name, f.stat().st_mtime) for f in files), _db_packs["ids"])
    if key == _pack_cache["key"]:
        return _pack_cache["pack"]
    best = None
    if (files or _db_packs["packs"]) and not key[0]:
        log.warning("a playbook pack is installed, but it needs Ardea Pro or MSP (edition: %s): not loaded",
                    licensing.tier())
    elif files or _db_packs["packs"]:
        candidates = list(_db_packs["packs"])
        for f in files:
            try:
                candidates.append(load_pack_file(f))
            except PackError as exc:
                log.error("playbook pack %s rejected: %s", f.name, exc)
        for pack in candidates:
            if best is None or newer(pack["version"], best["version"]):
                best = pack
        if best:
            log.info("playbook pack %s loaded (%s rules)", best["version"],
                     sum(len(best.get(s, {})) for s in _SECTIONS))
    _pack_cache.update(key=key, pack=best)
    return best


# --------------------------------------------------------------------------- per-SIEM overrides (MSP)
def siem_overrides(siem_id) -> tuple[dict, list[str]]:
    """(playbooks from <siem>.playbooks.yaml, extra context facts) for one SIEM. Empty without MSP."""
    if not siem_id or not licensing.has("customer_context"):
        return {}, []
    import elastic                                   # late import: elastic pulls in the SIEM client
    siem = elastic.configured().get(siem_id)
    facts = list(siem.context) if siem else []
    path = SIEMS_DIR / f"{siem_id}.playbooks.yaml"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}, facts
    cached = _siem_cache.get(siem_id)
    if not cached or cached[0] != mtime:
        try:
            data = yaml.safe_load(path.read_text()) or {}
            validate_pack(dict(data, version="siem"))
            cached = (mtime, data)
        except Exception as exc:                     # a broken override must never stop triage
            log.error("%s ignored: %s", path.name, exc)
            cached = (mtime, {})
        _siem_cache[siem_id] = cached
    data = cached[1]
    return data, facts + [str(c) for c in (data.get("context") or [])]


# --------------------------------------------------------------------------- resolve
def _lookup(section: str, name, local: dict, pack: dict | None, overlay: dict | None = None):
    """(playbook, source): the SIEM's own playbooks, then playbooks.yaml, then the pack."""
    if name is None:
        return None, None
    pb = ((overlay or {}).get(section) or {}).get(name)
    if pb:
        return pb, "siem playbooks"
    pb = (local.get(section) or {}).get(name)
    if pb:
        return pb, "playbooks.yaml"
    pb = ((pack or {}).get(section) or {}).get(name)
    if pb:
        return pb, f"pack {pack['version']}"
    return None, None


def resolve(ctx: dict) -> dict:
    data = _load()
    try:
        pack = current_pack()
    except Exception:                               # a pack problem must never stop triage
        log.exception("playbook pack could not be loaded")
        pack = None
    try:
        overlay, siem_facts = siem_overrides(ctx.get("siem"))
    except Exception:
        log.exception("per-SIEM playbooks could not be loaded")
        overlay, siem_facts = {}, []
    rule = ctx["rule"]
    default = data.get("default", {})
    pb, source = _lookup("by_rule_id", rule.get("rule_id"), data, pack, overlay)
    if not pb:
        pb, source = _lookup("by_rule_name", rule.get("name"), data, pack, overlay)
    tactic_pb, tactic_source = {}, None
    for m in rule.get("mitre", []):
        found, found_source = _lookup("by_tactic", m.get("tactic"), data, pack, overlay)
        if found:
            tactic_pb, tactic_source = found, found_source
            break
    merged = {
        "enrichment": (pb or {}).get("enrichment") or default.get("enrichment", []),
        "guidance": "\n".join(x for x in [(pb or {}).get("guidance"), tactic_pb.get("guidance"),
                                           None if pb else default.get("guidance")] if x),
        # a tactic marked never_auto_close in playbooks.yaml stays so, whatever a pack or SIEM file says
        "never_auto_close": bool((pb or {}).get("never_auto_close") or tactic_pb.get("never_auto_close")
                                 or any(((data.get("by_tactic") or {}).get(m.get("tactic")) or {})
                                        .get("never_auto_close") for m in rule.get("mitre", []))),
        "context": list(data.get("context", []) or []) + siem_facts,
        "matched": "rule" if pb else ("tactic" if tactic_pb else "default"),
        "source": source or tactic_source or "playbooks.yaml",
    }
    return merged


_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def render_enrichment(plan: list[dict], fields: dict) -> list[tuple[str, dict]]:
    """Fill placeholders; skip a step if any placeholder has no value in this alert."""
    out = []
    for step in plan:
        args, ok = {}, True
        for k, v in (step.get("args") or {}).items():
            if isinstance(v, str):
                names = _PLACEHOLDER.findall(v)
                if any(not fields.get(n) for n in names):
                    ok = False
                    break
                v = _PLACEHOLDER.sub(lambda m: str(fields[m.group(1)]), v)
            args[k] = v
        if ok:
            out.append((step["tool"], args))
    return out
