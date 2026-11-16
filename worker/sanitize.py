"""Outbound query sanitiser — the ONLY gate between internal data and the internet.

Design: the model cannot send free text. It sends a typed request
    {"kind": "ip"|"domain"|"hash"|"cve"|"mitre"|"filename"|"command_pattern"|"error_text", "value": ..., "context": ...}
and each kind has a strict validator. Anything that looks internal is REJECTED (not silently
redacted — redaction still leaks structure, and a rejection teaches the model to rephrase).

This runs in code, after the model, so a prompt injection cannot talk its way past it.
"""
import ipaddress
import re

import config

MAX_QUERY_CHARS = 160
MAX_CONTEXT_WORDS = 6

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$|^TA\d{4}$", re.I)
HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
FILENAME_RE = re.compile(r"^[\w\-. ]{1,80}\.(exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|hta|msi|scr|lnk|jar|py|sh|elf|so|dmg|app)$", re.I)

# Things that must never leave the network, whatever the kind.
SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|apikey|api_key|bearer|authorization)\s*[:=]"),
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),                          # long base64 blobs
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                  # AWS key id
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),           # JWT
    re.compile(r"\bS-1-5-21-\d+-\d+-\d+(-\d+)?\b"),                       # domain SIDs
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),                              # e-mail addresses
    re.compile(r"\\\\[\w.$-]+\\"),                                         # UNC paths \\server\
    re.compile(r"(?i)[a-z]:\\users\\[^\\\s]+"),                            # user profile paths
    re.compile(r"(?i)/home/[^/\s]+|/Users/[^/\s]+"),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),  # GUIDs
]
IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f:]{6,}:[0-9a-f]{1,4}\b", re.I)
GENERIC_CONTEXT_WORDS = {
    "malware", "malicious", "legitimate", "benign", "ioc", "threat", "intel", "report", "abuse",
    "reputation", "c2", "phishing", "ransomware", "vulnerability", "exploit", "lolbin", "lolbas",
    "windows", "linux", "macos", "process", "command", "persistence", "technique", "microsoft",
    "documentation", "detection", "sigma", "what", "is", "used", "by", "attack", "apt", "campaign",
    "false", "positive", "known", "software", "vendor", "signed", "driver", "service", "scheduled",
    "task", "registry", "powershell", "backup", "update", "installer", "admin", "tool",
}


class BlockedQuery(Exception):
    """Message is shown to the model so it can rephrase."""


def _sensitive_tokens(entities: dict) -> set[str]:
    """Internal identifiers taken from the alert itself: hostnames, usernames, internal IPs."""
    toks = set(config.SENSITIVE_TERMS)
    for key in ("hosts", "users", "ips_internal"):
        for v in entities.get(key, []):
            v = v.lower()
            toks.add(v)
            toks.update(p for p in re.split(r"[\\/@.\s_-]", v) if len(p) >= 4)  # DOMAIN\user, fqdn parts
    return {t for t in toks if t}


def _check_common(text: str, entities: dict):
    low = text.lower()
    no_hashes = re.sub(r"\b[a-f0-9]{32,64}\b", " ", text, flags=re.I)   # hashes are allowed IOCs
    if len(text) > MAX_QUERY_CHARS:
        raise BlockedQuery(f"query longer than {MAX_QUERY_CHARS} chars")
    for pat in SECRET_PATTERNS:
        if pat.search(no_hashes):
            raise BlockedQuery("query contains a credential, e-mail, SID, GUID, UNC or user-profile path")
    for tok in _sensitive_tokens(entities):
        if re.search(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])", low):
            raise BlockedQuery("query contains an internal hostname, username or internal IP")
    for dom in config.INTERNAL_DOMAINS:
        d = re.escape(dom)
        # as a suffix of any name (x.corp, host.example.com) ...
        if re.search(rf"[a-z0-9-]\.{d}(?![a-z0-9-])", low):
            raise BlockedQuery("query contains an internal domain")
        # ... or standalone, but only for multi-label domains (so the word 'local' is fine)
        if "." in dom and re.search(rf"(?<![a-z0-9.-]){d}(?![a-z0-9-])", low):
            raise BlockedQuery("query contains an internal domain")
    for ip in IP_IN_TEXT.findall(text):
        try:
            if not ipaddress.ip_address(ip).is_global:
                raise BlockedQuery("query contains a private/internal IP address")
        except ValueError:
            continue


def _context_words(context: str | None) -> str:
    if not context:
        return ""
    words = [w for w in re.findall(r"[a-z0-9]+", context.lower()) if w in GENERIC_CONTEXT_WORDS]
    return " ".join(words[:MAX_CONTEXT_WORDS])


def build_query(kind: str, value: str, context: str | None, entities: dict) -> str:
    """Return the exact string that will be sent to the search provider, or raise BlockedQuery."""
    value = (value or "").strip().strip('"\'')
    if not value:
        raise BlockedQuery("empty value")
    if kind not in config.WEB_SEARCH_KINDS:
        raise BlockedQuery(f"search kind '{kind}' is not enabled here; allowed: {config.WEB_SEARCH_KINDS}")

    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise BlockedQuery("not a valid IP address")
        if not ip.is_global:
            raise BlockedQuery("private/internal IPs are never searched externally")
        core = f'"{ip}"'
    elif kind == "domain":
        value = value.lower().rstrip(".")
        if not DOMAIN_RE.match(value):
            raise BlockedQuery("not a valid public domain name")
        core = f'"{value}"'
    elif kind == "hash":
        if not HASH_RE.match(value):
            raise BlockedQuery("not an MD5/SHA1/SHA256 hash")
        core = value.lower()
    elif kind == "cve":
        if not CVE_RE.match(value):
            raise BlockedQuery("not a CVE id")
        core = value.upper()
    elif kind == "mitre":
        if not MITRE_RE.match(value):
            raise BlockedQuery("not a MITRE ATT&CK id (e.g. T1202, T1053.005)")
        core = f"MITRE ATT&CK {value.upper()}"
    elif kind == "filename":
        name = re.split(r"[\\/]", value)[-1]          # basename only — never a full path
        if not FILENAME_RE.match(name):
            raise BlockedQuery("filename must be a bare executable/script name like 'forfiles.exe'")
        core = f'"{name}"'
    elif kind in ("command_pattern", "error_text"):
        # Generic technique text only: strip paths/quotes, require it to be short.
        text = re.sub(r"\"[^\"]*[\\/][^\"]*\"", " ", value)   # drop quoted paths ("C:\\a b\\c")
        text = re.sub(r"\S*\\\S*", " ", text)                    # drop any token with a backslash
        text = re.sub(r"(/[\w.-]+){2,}", " ", text)              # drop unix paths
        text = re.sub(r"[\"'`]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text.split()) > 12:
            raise BlockedQuery("command_pattern must be ≤12 words — keep only the generic flags/verbs")
        core = text
    else:
        raise BlockedQuery(f"unknown kind '{kind}'")

    query = f"{core} {_context_words(context)}".strip()
    _check_common(query, entities)
    return query
