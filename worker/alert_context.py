"""Turn a raw Elastic Security alert into a compact, token-cheap, injection-hardened context.

  * keeps the fields that matter for triage: kibana.alert.reason, rule description, MITRE mapping,
    risk score, the rule's own investigation guide, event.*, process/file/network/registry fields
    and winlog.event_data highlights (IntegrityLevel, ParentUser, LogonType ...)
  * drops noise (agent ids, ecs, data_stream, duplicated winlog fields, raw message)
  * renders as flat "field: value" lines (fewer tokens than indented JSON)
  * extracts entities (host, user, IPs, hashes, process ids...) used to scope tool calls
"""
import ipaddress
import json
import re

# Prefix allowlist (flattened ECS keys). Order matters only for readability of the output.
KEEP_PREFIXES = (
    "@timestamp", "kibana.alert.original_time", "kibana.alert.reason", "kibana.alert.severity",
    "kibana.alert.risk_score", "kibana.alert.rule.name", "kibana.alert.rule.rule_id",
    "kibana.alert.rule.description", "kibana.alert.rule.type", "kibana.alert.rule.tags",
    "event.action", "event.category", "event.type", "event.code", "event.dataset", "event.outcome",
    "host.name", "host.hostname", "host.os.name", "host.ip",
    "user.", "group.", "process.", "file.", "registry.", "dll.", "network.", "source.", "destination.",
    "dns.", "url.", "tls.", "http.", "powershell.", "service.", "threat.", "email.",
    "winlog.event_data.", "winlog.channel", "winlog.user.name", "related.",
)
DROP_PREFIXES = (
    "process.pe.file_version", "process.args", "process.parent.args", "process.Ext.ancestry",
    "winlog.event_data.Company", "winlog.event_data.Description", "winlog.event_data.Product",
    "winlog.event_data.FileVersion", "winlog.event_data.LogonGuid", "winlog.event_data.Hashes",
    "kibana.alert.rule.tags",   # rendered separately (filtered)
)
MAX_VALUE_CHARS = 600
SCRIPT_HEAD, SCRIPT_TAIL = 1500, 400
RULE_NOTE_MAX = 1200

# Strings an attacker could use to break out of our data delimiters.
_DELIM = re.compile(r"</?\s*(untrusted_data|system|assistant|user|tool)[^>]*>", re.I)
# Heuristic prompt-injection markers. Detection only — we never rely on the model to resist.
INJECTION_PATTERNS = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts)|disregard (the )?(system|previous)"
    r"|you are now|new instructions|system prompt|as an ai|classify (this|it) as (benign|false positive)"
    r"|mark (this|it) as (benign|false positive)|do not escalate|this is a (test|authorized) alert"
    r"|<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>",
    re.I,
)


def flatten(d: dict, prefix: str = ""):
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from flatten(v, key + ".")
        else:
            yield key, v


def neutralise(text: str) -> str:
    """Make attacker text unable to close our <untrusted_data> wrapper or fake chat roles."""
    text = _DELIM.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
    return text.replace("<|", "‹|").replace("|>", "|›")


def _render_value(key: str, value) -> str:
    if isinstance(value, list):
        value = ", ".join(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
                          for v in value[:20])
    value = str(value)
    if key.endswith("script_block_text") and len(value) > SCRIPT_HEAD + SCRIPT_TAIL:
        cut = len(value) - SCRIPT_HEAD - SCRIPT_TAIL
        value = f"{value[:SCRIPT_HEAD]}\n…[{cut} chars omitted]…\n{value[-SCRIPT_TAIL:]}"
    elif len(value) > MAX_VALUE_CHARS:
        value = value[:MAX_VALUE_CHARS] + f"…[+{len(value) - MAX_VALUE_CHARS} chars]"
    return neutralise(value)


def _rule_note_excerpt(note: str | None) -> str:
    """Keep only 'Possible investigation steps' + 'False positive analysis' of Elastic's guide."""
    if not note:
        return ""
    keep, out = False, []
    for line in note.splitlines():
        if line.startswith("### "):
            keep = any(s in line.lower() for s in ("investigation steps", "false positive"))
        if keep:
            out.append(line)
    text = "\n".join(out).strip() or note
    return text[:RULE_NOTE_MAX]


def _mitre(src: dict) -> list[dict]:
    out = []
    for t in src.get("kibana.alert.rule.threat") or []:
        tactic = (t.get("tactic") or {})
        for tech in t.get("technique") or [{}]:
            out.append({"tactic": tactic.get("name"), "tactic_id": tactic.get("id"),
                        "technique": tech.get("name"), "technique_id": tech.get("id"),
                        "subtechniques": [s.get("id") for s in tech.get("subtechnique") or []]})
    return out


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_SERVICE_BINARY = re.compile(r"^.*?\.(exe|sys|dll)\b", re.I)


_DRIVE = re.compile(r"^([A-Za-z]):\\?$")


def _drive_letter(value) -> str | None:
    """'D:\\' or 'D:' (as Windows records a newly mounted drive) -> 'D:\\'."""
    for v in value if isinstance(value, list) else [value]:
        m = _DRIVE.match(str(v or "").strip())
        if m:
            return f"{m.group(1).upper()}:\\"
    return None


def service_executable(service_file_name) -> str | None:
    """Program path of a Windows service from its ImagePath / ServiceFileName, without arguments:
    '"C:\\Program Files\\X\\svc.exe" -k a' -> 'C:\\Program Files\\X\\svc.exe'."""
    if isinstance(service_file_name, list):
        service_file_name = service_file_name[0] if service_file_name else None
    value = str(service_file_name or "").strip()
    if not value:
        return None
    if value.startswith('"'):
        end = value.find('"', 1)
        return value[1:end] if end > 1 else None
    m = _SERVICE_BINARY.match(value)
    return m.group(0) if m else value.split()[0]


def extract_entities(flat: dict) -> dict:
    """Entities the agent may pivot on. Tool calls on entities NOT in this set (or in later
    evidence) are refused — this stops injected text steering queries to arbitrary data."""
    def vals(*keys):
        out = []
        for k in keys:
            v = flat.get(k)
            if v is None:
                continue
            out.extend(v if isinstance(v, list) else [v])
        return [str(x) for x in out if x not in (None, "", "-")]

    ips = vals("host.ip", "source.ip", "destination.ip", "client.ip", "server.ip",
               "winlog.event_data.IpAddress", "related.ip")
    return {
        "hosts": sorted({h.lower() for h in vals("host.name", "host.hostname", "winlog.computer_name")}),
        "users": sorted({u for u in vals("user.name", "related.user", "user.target.name",
                                         "winlog.event_data.TargetUserName", "winlog.event_data.SubjectUserName")
                         if not u.endswith("$")}),
        "ips_internal": sorted({i for i in ips if not is_public_ip(i)}),
        "ips_public": sorted({i for i in ips if is_public_ip(i)}),
        "hashes": sorted({h.lower() for h in vals("process.hash.md5", "process.hash.sha1", "process.hash.sha256",
                                                    "file.hash.sha256", "file.hash.md5", "dll.hash.sha256",
                                                    "related.hash") if HASH_RE.match(h)}),
        "domains": sorted({d.lower() for d in vals("dns.question.name", "destination.domain", "url.domain",
                                                     "related.hosts")}),
        "process_entity_ids": sorted(set(vals("process.entity_id", "process.parent.entity_id"))),
        "executables": sorted(set(vals("process.executable", "process.parent.executable"))
                              | ({svc} if (svc := service_executable(flat.get("winlog.event_data.ServiceFileName")
                                                                    or flat.get("service.executable"))) else set())),
        "process_names": sorted({p.lower() for p in vals("process.name", "process.parent.name")}),
    }


def build_context(raw_alert: dict, occurrences: int = 1) -> dict:
    src = raw_alert.get("_source", {})
    flat = dict(flatten(src))

    lines = []
    for key in sorted(flat):
        if not key.startswith(KEEP_PREFIXES) or key.startswith(DROP_PREFIXES):
            continue
        value = flat[key]
        if value in (None, "", [], "-"):
            continue
        lines.append(f"{key}: {_render_value(key, value)}")

    tags = [t for t in flat.get("kibana.alert.rule.tags") or [] if t.startswith(("Tactic:", "OS:", "Domain:"))]
    rule = {
        "name": flat.get("kibana.alert.rule.name"),
        "rule_id": flat.get("kibana.alert.rule.rule_id"),
        "type": flat.get("kibana.alert.rule.type"),
        "severity": flat.get("kibana.alert.severity"),
        "risk_score": flat.get("kibana.alert.risk_score"),
        "tags": tags,
        "mitre": _mitre(src),
        "investigation_guide": neutralise(_rule_note_excerpt(flat.get("kibana.alert.rule.note"))),
    }
    text_blob = "\n".join(lines)
    return {
        "alert_id": raw_alert.get("_id"),
        "event_time": flat.get("kibana.alert.original_time") or flat.get("@timestamp"),
        "rule": rule,
        "fields_text": text_blob,
        "occurrences": occurrences,
        "entities": extract_entities(flat),
        "injection_markers": sorted({m.group(0).lower() for m in INJECTION_PATTERNS.finditer(text_blob)}),
        "kibana_url": flat.get("kibana.alert.url"),
        "service_executable": service_executable(flat.get("winlog.event_data.ServiceFileName")
                                                 or flat.get("service.executable")),
        "removable_drive": _drive_letter(flat.get("registry.data.strings")),
        "hostname": flat.get("host.hostname") or flat.get("host.name"),
    }
