"""Tool definitions passed to the model (OpenAI/Ollama function-calling format).

Guidelines followed for small local models:
  * few tools (7), each with one job and a verb-first name
  * every description says WHEN to use it and what it returns
  * flat parameters, enums wherever possible, no nested objects, sensible defaults
"""


def _fn(name, description, properties, required):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required}}}


TOOLS = [
    _fn("get_process_tree",
        "Get the ancestors (parent, grandparent...) and the direct children of a process. Use when "
        "you need to know what launched the alerting process or what it spawned. Input is a "
        "process entity id exactly as shown in the alert or earlier evidence (e.g. the value of "
        "process.entity_id or process.parent.entity_id).",
        {"process_entity_id": {"type": "string", "description": "process.entity_id value, e.g. {AAAAAAAA-...}"},
         "depth_up": {"type": "integer", "description": "How many ancestor levels (1-6). Default 4."}},
        ["process_entity_id"]),

    _fn("get_baseline",
        "Measure how NORMAL something is: how often an executable, process name, SHA256 or exact "
        "command line ran over the last N days, on how many hosts, by which users and parents. "
        "Use this FIRST when deciding if activity is routine automation or new and unusual.",
        {"field": {"type": "string", "enum": ["process.executable", "process.name",
                                              "process.hash.sha256", "process.command_line"]},
         "value": {"type": "string", "description": "Exact value copied from the alert/evidence."},
         "host": {"type": "string", "description": "Optional host.name to restrict to one host. Omit for fleet-wide."},
         "days": {"type": "integer", "description": "Look-back days, 1-30. Default 30."}},
        ["field", "value"]),

    _fn("search_host_events",
        "List events of ONE category on ONE host in a time window around the alert, grouped into "
        "patterns with counts. Use to see what else happened on the host (other processes, network "
        "connections, DNS, file or registry changes, logons).",
        {"host": {"type": "string", "description": "host.name from the alert."},
         "category": {"type": "string", "enum": ["process", "network", "dns", "file", "registry", "authentication"]},
         "minutes_before": {"type": "integer", "description": "Minutes before alert time (max 4320). Default 30."},
         "minutes_after": {"type": "integer", "description": "Minutes after alert time (max 4320). Default 30."},
         "process_name": {"type": "string", "description": "Optional filter, e.g. powershell.exe"},
         "user": {"type": "string", "description": "Optional user.name filter."},
         "path_prefix": {"type": "string", "description": "Optional, category file or process only: keep "
                                                          "paths starting with this, e.g. 'E:\\' for a USB drive."}},
        ["host", "category"]),

    _fn("get_auth_events",
        "Summarise logon successes and failures for a user (optionally on one host): logon types, "
        "source IPs, outcomes. Use for credential-access, lateral-movement or suspicious-account alerts.",
        {"user": {"type": "string"},
         "host": {"type": "string", "description": "Optional host.name."},
         "hours_before": {"type": "integer", "description": "0-72. Default 24."},
         "hours_after": {"type": "integer", "description": "0-24. Default 2."}},
        ["user"]),

    _fn("get_related_alerts",
        "List other security alerts (rule name, count, severity, tactics, status) for the same host, "
        "user or file hash around this alert. Use to spot multi-stage activity.",
        {"entity_type": {"type": "string", "enum": ["host", "user", "hash"]},
         "value": {"type": "string"},
         "hours_before": {"type": "integer", "description": "0-72. Default 48."},
         "hours_after": {"type": "integer", "description": "0-24. Default 6."}},
        ["entity_type", "value"]),

    _fn("web_search",
        "Search the public internet for threat intelligence or documentation. You can ONLY search a "
        "typed public indicator or a generic technique description. NEVER include hostnames, "
        "usernames, internal IPs, internal domains or file paths — such queries are rejected. "
        "Use for: reputation of a public IP/domain/hash, CVE details, what a known binary or "
        "command-line flag does, MITRE technique details.",
        {"kind": {"type": "string", "enum": ["ip", "domain", "hash", "cve", "mitre", "filename",
                                             "command_pattern", "error_text"]},
         "value": {"type": "string", "description": "The indicator, or for command_pattern a short generic "
                                                     "description such as 'forfiles /c cmd /c del'."},
         "context": {"type": "string", "description": "Optional 1-4 generic words, e.g. 'malware reputation'."}},
        ["kind", "value"]),

    _fn("finish_investigation",
        "Call this when you have enough evidence to decide, or when more tool calls will not help. "
        "After this you will be asked for the final structured verdict.",
        {"reason": {"type": "string", "description": "One sentence: why you are done."}},
        ["reason"]),
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


def web_search_enabled() -> bool:
    import config
    return config.WEB_SEARCH_PROVIDER not in ("", "disabled") and bool(config.WEB_SEARCH_KINDS)


def active_tools() -> list[dict]:
    """Tools actually offered to the model. A tool that can only ever fail (web search while it is
    disabled) wastes CPU-minutes of generation and tool budget, so it is not offered at all.
    The list is stable for a deployment, which keeps Ollama's prompt-prefix cache valid."""
    import copy
    import config
    out = []
    for t in TOOLS:
        if t["function"]["name"] == "web_search":
            if not web_search_enabled():
                continue
            t = copy.deepcopy(t)
            kinds = t["function"]["parameters"]["properties"]["kind"]
            kinds["enum"] = [k for k in kinds["enum"] if k in config.WEB_SEARCH_KINDS]
        out.append(t)
    return out


def active_tool_names() -> set[str]:
    return {t["function"]["name"] for t in active_tools()}
