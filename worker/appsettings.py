"""Settings that admins change in the web UI (Settings page), shared by the worker, fetcher and publisher.
Keep worker/appsettings.py, fetcher/appsettings.py and publisher/appsettings.py identical.

Where a value comes from, first match wins:
  1. the container's environment (.env): shown read-only in the UI, so file-managed installs keep working
  2. the app_settings table (written by the publisher when an admin saves the Settings page)
  3. the default in the code

Secrets (API keys, passwords, webhook URLs) are sealed with the public half of an X25519 key pair. The
private half lives only in the worker and fetcher (volume /app/keys), so the web UI can store a secret but
never read one back: a compromised publisher cannot recover them. A secret that belongs to a host (an
Elastic API key, an SMTP password) is bound to that host: change the host and the old secret no longer
decrypts, so it can never be sent to a new address without being entered again.
"""
import base64
import hashlib
import json
import logging
import os
import pathlib
import re
import time
from dataclasses import dataclass

# --------------------------------------------------------------------------- the settings
GROUPS = [
    ("licence", "Licence"),
    ("siems", "SIEMs (Elastic)"),
    ("ai", "AI model"),
    ("notifications", "Alerts to your team"),
    ("triage", "How alerts are handled"),
    ("websearch", "Web search"),
    ("playbooks", "Playbook pack"),
    ("deadlines", "Queue and deadlines"),
    ("monitoring", "Monitoring and daily digest"),
    ("reports", "Reports and branding"),
    ("nis2", "NIS2 details"),
    ("backups", "Backups"),
]


@dataclass(frozen=True)
class Field:
    name: str
    group: str
    label: str
    kind: str = "text"            # text | url | int | bool | choice | multi | list | emails | email | lines | secret | pem
    help: str = ""
    default: str = ""
    options: tuple = ()           # choice / multi: (value, label) pairs
    bind: str = ""                # secret: the setting whose value the secret is bound to (a host or URL)
    feature: str = ""             # editions feature that makes it take effect ("" = every edition)
    services: tuple = ("worker",)
    min: int | None = None
    max: int | None = None
    advanced: bool = False        # Settings page: under "Advanced", closed by default
    show_if: str = ""             # Settings page: only shown when another setting has a value, e.g. "X=y|z"
    example: str = ""             # Settings page: placeholder text

    @property
    def secret(self) -> bool:
        return self.kind == "secret"


_CHANNELS = (("smtp", "E-mail"), ("ntfy", "ntfy"), ("slack", "Slack"), ("teams", "Microsoft Teams"),
             ("webhook", "Webhook"), ("jira", "Jira"), ("thehive", "TheHive"))
_SEVERITIES = tuple((s, s) for s in ("Informational", "Low", "Medium", "High", "Critical"))
_VERDICTS = tuple((v, v) for v in ("True Positive", "Needs Human Review", "Benign Positive", "False Positive"))

FIELDS = [
    # Licence
    Field("ARDEA_LICENSE_KEY", "licence", "Licence key", "secret",
          "The key from your purchase e-mail. Leave it empty to use the free Community edition.",
          example="Paste your licence key"),
    Field("ARDEA_LICENSE_OFFLINE", "licence", "Offline licence file", "lines",
          "Only for servers that cannot reach the internet. Open the ardea.license file we sent you and paste "
          "everything in it here. You need either a key or a file, not both."),
    Field("ARDEA_LICENSE_PROXY", "licence", "Proxy for the licence check", "url",
          "Only if this server reaches the internet through a proxy.", advanced=True,
          example="http://egress-proxy:3128"),
    # Playbook pack (Pro / MSP)
    Field("ARDEA_PACK_AUTO_UPDATE", "playbooks", "Install new packs automatically", "bool",
          "Once a day Ardea checks for a newer pack and installs it. Only your licence key is sent.", "true",
          feature="playbook_pack"),
    Field("ARDEA_PACK_SERVER", "playbooks", "Pack server", "url",
          "Do not change this unless support asks you to.", "https://packs.ardeasecurity.com",
          feature="playbook_pack", advanced=True),
    # AI model
    Field("LLM_URL", "ai", "Where Ollama runs", "url",
          "The address of the computer running Ollama, with port 11434. If Ollama runs on this same server, use "
          "http://host.docker.internal:11434.", "http://ollama:11434", example="http://192.168.1.50:11434"),
    Field("LLM_MODEL", "ai", "Model name", "text",
          "Type it exactly as the command \"ollama list\" shows it on that computer. Use \"Test the connection\" "
          "below to see the installed models.", "qwen3:14b"),
    Field("LLM_THINK", "ai", "Reasoning", "choice",
          "Some models think before answering. That is better but slow without a graphics card.",
          "", (("", "Model default"), ("false", "Off"), ("true", "On"), ("low", "Low (gpt-oss)"),
               ("medium", "Medium (gpt-oss)"), ("high", "High (gpt-oss)")), advanced=True),
    Field("LLM_NUM_CTX", "ai", "Memory for one investigation (tokens)", "int",
          "16384 without a graphics card, 24576 with one. Higher needs more memory.", "24576",
          min=4096, max=262144, advanced=True),
    Field("LLM_TIMEOUT_SECONDS", "ai", "Give up on one model answer after (seconds)", "int", "", "900",
          min=30, max=7200, advanced=True),
    Field("LLM_NUM_THREAD", "ai", "CPU threads", "int", "Only for servers without a graphics card. 0 = automatic.",
          "0", min=0, max=512, advanced=True),
    Field("LLM_KEEP_ALIVE", "ai", "Keep the model loaded", "text",
          "-1 keeps it in memory all the time (fastest). Or a time such as 24h.", "-1", advanced=True),
    # Triage
    Field("MIN_CONFIDENCE_TO_CLOSE", "triage", "Close an alert by itself only when at least this sure (%)", "int",
          "If Ardea thinks an alert is harmless but is less sure than this, a person checks it instead. 70 is a "
          "good start; higher sends more alerts to people.", "70", min=50, max=100),
    Field("VERIFY_CLOSURES", "triage", "Double-check before closing an alert", "bool",
          "Ardea takes a second, sceptical look before it closes any alert by itself. Keep this on.", "true"),
    Field("IGNORED_RULES", "triage", "Never look at alerts from these rules", "lines",
          "One rule name per line, exactly as in Kibana. These alerts are not collected at all.",
          services=("fetcher",)),
    Field("IGNORED_RULES_MATCH", "triage", "Never look at rules whose name contains", "lines",
          "One piece of text per line, for example a vendor name.", services=("fetcher",)),
    Field("FLOOD_GUARD", "triage", "Handle bursts quickly", "bool",
          "When one rule fires on many computers with the same program, Ardea investigates the first few. If they "
          "all get the same verdict, the rest reuse it instead of waiting hours in the queue. Real attacks (True "
          "Positives) and high-impact alerts are always investigated one by one.", "true"),
    Field("FLOOD_SAMPLE", "triage", "Burst: investigate this many first", "int", "", "3", min=2, max=20,
          advanced=True, show_if="FLOOD_GUARD=true"),
    Field("FLOOD_WINDOW_HOURS", "triage", "Burst: look back this many hours", "int", "", "6", min=1, max=72,
          advanced=True, show_if="FLOOD_GUARD=true"),
    Field("FLOOD_RECHECK_EVERY", "triage", "Burst: fully investigate again every", "int",
          "After this many reused verdicts, one alert is investigated in full again.", "25", min=5, max=500,
          advanced=True, show_if="FLOOD_GUARD=true"),
    Field("FEEDBACK_EXAMPLES", "triage", "Past analyst corrections shown to the model", "int",
          "How many similar alerts your analysts corrected are shown as examples. 0 = none.", "3",
          min=0, max=10, advanced=True),
    Field("AGENT_MAX_STEPS", "triage", "Most thinking steps per alert", "int", "", "8", min=2, max=20, advanced=True),
    Field("AGENT_MAX_TOOL_CALLS", "triage", "Most SIEM searches per alert", "int", "", "10", min=1, max=30,
          advanced=True),
    Field("AGENT_MAX_WALL_SECONDS", "triage", "Most time per alert (seconds)", "int", "", "1200", min=60, max=7200,
          advanced=True),
    Field("FETCH_INTERVAL_SECONDS", "triage", "Look for new alerts every (seconds)", "int", "", "180",
          min=30, max=3600, services=("fetcher",), advanced=True),
    Field("DEDUP_WINDOW_HOURS", "triage", "Treat identical alerts as one within (hours)", "int",
          "Repeats of the same alert are counted on the first one instead of being investigated again. 0 = off.",
          "24", min=0, max=168, services=("fetcher",), advanced=True),
    # Web search
    Field("WEB_SEARCH_PROVIDER", "websearch", "Search the web with", "choice",
          "Optional. Lets Ardea look up public things such as an IP address, a domain or a file hash. Nothing "
          "about your hosts, users or customers is ever sent.", "disabled",
          (("disabled", "Off"), ("searxng", "SearXNG (free, your own)"), ("brave", "Brave Search (API key)"),
           ("google_cse", "Google (API key)"))),
    Field("SEARXNG_URL", "websearch", "SearXNG address", "url", show_if="WEB_SEARCH_PROVIDER=searxng",
          example="http://searxng:8080"),
    Field("BRAVE_API_KEY", "websearch", "Brave API key", "secret", show_if="WEB_SEARCH_PROVIDER=brave"),
    Field("GOOGLE_API_KEY", "websearch", "Google API key", "secret", show_if="WEB_SEARCH_PROVIDER=google_cse"),
    Field("GOOGLE_CSE_ID", "websearch", "Google search engine ID", "text", show_if="WEB_SEARCH_PROVIDER=google_cse"),
    Field("INTERNAL_DOMAINS", "websearch", "Your internal domain names", "list",
          "Never searched for. Separate them with commas.", "local,lan,corp,internal,intra",
          show_if="WEB_SEARCH_PROVIDER=searxng|brave|google_cse"),
    Field("SENSITIVE_TERMS", "websearch", "Words that must never leave your network", "list",
          "Customer or project names. Separate them with commas.",
          show_if="WEB_SEARCH_PROVIDER=searxng|brave|google_cse", example="acme, project-falcon"),
    Field("WEB_SEARCH_DRY_RUN", "websearch", "Practice mode", "bool",
          "Write down what would be searched, but send nothing. Useful for the first week.", "false", advanced=True),
    Field("WEB_SEARCH_KINDS", "websearch", "What may be searched", "list",
          "Separate with commas: ip, domain, hash, cve, mitre, filename (riskier: command_pattern, error_text).",
          "ip,domain,hash,cve,mitre,filename", advanced=True),
    # Notifications
    Field("NOTIFY_CHANNELS", "notifications", "Send alerts by", "multi", "", "", _CHANNELS, feature="notifications"),
    Field("NOTIFY_VERDICTS", "notifications", "Tell the team about", "multi",
          "Usually only True Positives: real attacks.", "True Positive", _VERDICTS),
    Field("NOTIFY_MIN_SEVERITY", "notifications", "Only from this severity up", "choice", "", "Informational",
          _SEVERITIES),
    Field("ARDEA_PUBLIC_URL", "notifications", "The address of this console", "url",
          "So that messages can link back here.", example="https://ardea.example.com"),
    Field("NOTIFY_DETAIL", "notifications", "How much to put in a message", "choice",
          "\"Minimal\" sends only the verdict and a link: no host or user names leave your network.", "full",
          (("full", "Full summary"), ("minimal", "Minimal: verdict and link")), advanced=True),
    Field("SMTP_HOST", "notifications", "Mail server", "text", show_if="NOTIFY_CHANNELS=smtp",
          example="smtp.office365.com"),
    Field("SMTP_PORT", "notifications", "Port", "int", "587 in most cases.", "587", min=1, max=65535,
          show_if="NOTIFY_CHANNELS=smtp"),
    Field("SMTP_SECURITY", "notifications", "Encryption", "choice", "STARTTLS with port 587, SSL/TLS with port 465.",
          "starttls", (("starttls", "STARTTLS"), ("ssl", "SSL/TLS"), ("none", "None")), show_if="NOTIFY_CHANNELS=smtp"),
    Field("SMTP_USER", "notifications", "Sign in as", "text", "Leave empty if the server needs no sign-in.",
          show_if="NOTIFY_CHANNELS=smtp", example="ardea@example.com"),
    Field("SMTP_PASSWORD", "notifications", "Mail password", "secret", bind="SMTP_HOST",
          show_if="NOTIFY_CHANNELS=smtp"),
    Field("SMTP_FROM", "notifications", "Send from", "email", show_if="NOTIFY_CHANNELS=smtp",
          example="ardea@example.com"),
    Field("SMTP_TO", "notifications", "Send to (your team)", "emails", "Separate addresses with commas.",
          show_if="NOTIFY_CHANNELS=smtp", example="soc@example.com"),
    Field("NTFY_URL", "notifications", "ntfy server", "url", "", "https://ntfy.sh", show_if="NOTIFY_CHANNELS=ntfy"),
    Field("NTFY_TOPIC", "notifications", "Topic", "text", "Subscribe to this topic in the ntfy phone app.",
          show_if="NOTIFY_CHANNELS=ntfy"),
    Field("NTFY_TOKEN", "notifications", "Access token", "secret", "Only for a protected topic.", bind="NTFY_URL",
          show_if="NOTIFY_CHANNELS=ntfy"),
    Field("SLACK_WEBHOOK_URL", "notifications", "Slack webhook address", "secret",
          "In Slack: Apps → Incoming WebHooks → Add to a channel, then copy the address.", feature="integrations",
          show_if="NOTIFY_CHANNELS=slack"),
    Field("TEAMS_WEBHOOK_URL", "notifications", "Teams webhook address", "secret",
          "In Teams: Workflows → \"Post to a channel when a webhook request is received\", then copy the address.",
          feature="integrations", show_if="NOTIFY_CHANNELS=teams"),
    Field("WEBHOOK_URL", "notifications", "Webhook address", "url", "Ardea sends a JSON message to it.",
          feature="integrations", show_if="NOTIFY_CHANNELS=webhook"),
    Field("WEBHOOK_SECRET", "notifications", "Signing secret", "secret", "Optional. Lets the receiver check that "
          "the message came from Ardea.", bind="WEBHOOK_URL", feature="integrations", show_if="NOTIFY_CHANNELS=webhook"),
    Field("JIRA_URL", "notifications", "Jira address", "url", feature="integrations", show_if="NOTIFY_CHANNELS=jira",
          example="https://yourcompany.atlassian.net"),
    Field("JIRA_USER", "notifications", "Jira user (e-mail)", "text", feature="integrations",
          show_if="NOTIFY_CHANNELS=jira"),
    Field("JIRA_API_TOKEN", "notifications", "Jira API token", "secret", bind="JIRA_URL", feature="integrations",
          show_if="NOTIFY_CHANNELS=jira"),
    Field("JIRA_PROJECT", "notifications", "Project key", "text", feature="integrations",
          show_if="NOTIFY_CHANNELS=jira", example="SEC"),
    Field("JIRA_ISSUE_TYPE", "notifications", "Issue type", "text", "", "Task", feature="integrations",
          show_if="NOTIFY_CHANNELS=jira"),
    Field("THEHIVE_URL", "notifications", "TheHive address", "url", feature="integrations",
          show_if="NOTIFY_CHANNELS=thehive"),
    Field("THEHIVE_API_KEY", "notifications", "TheHive API key", "secret", bind="THEHIVE_URL",
          feature="integrations", show_if="NOTIFY_CHANNELS=thehive"),
    Field("NOTIFY_PROXY", "notifications", "Proxy for Slack, Teams and Jira", "url",
          "Only if this server reaches the internet through a proxy.", advanced=True),
    # Queue and deadlines (Pro)
    Field("QUEUE_ENABLED", "deadlines", "Use the queue", "bool",
          "The Queue page lets your team assign alerts and see deadlines. Turn it off if you do not need it: "
          "nothing is deleted.", "true", feature="assignments", services=("worker", "publisher")),
    Field("SLA_CRITICAL_MINUTES", "deadlines", "Critical alerts: handle within (minutes)", "int",
          "Counted from the alert's time. 60 = 1 hour.", "60",
          min=5, max=43200, feature="assignments", services=("worker", "publisher"), show_if="QUEUE_ENABLED=true"),
    Field("SLA_HIGH_MINUTES", "deadlines", "High alerts: handle within (minutes)", "int", "240 = 4 hours.", "240",
          min=5, max=43200, feature="assignments", services=("worker", "publisher"), show_if="QUEUE_ENABLED=true"),
    Field("SLA_MEDIUM_MINUTES", "deadlines", "Medium alerts: handle within (minutes)", "int", "1440 = 1 day.", "1440",
          min=5, max=43200, feature="assignments", services=("worker", "publisher"), show_if="QUEUE_ENABLED=true"),
    Field("SLA_LOW_MINUTES", "deadlines", "Other alerts: handle within (minutes)", "int", "4320 = 3 days.", "4320",
          min=5, max=43200, feature="assignments", services=("worker", "publisher"), show_if="QUEUE_ENABLED=true"),
    Field("OVERDUE_NOTIFY", "deadlines", "Tell the team when an alert is late", "bool",
          "One message, through \"Alerts to your team\", when an alert passes its deadline.",
          "true", feature="assignments", show_if="QUEUE_ENABLED=true"),
    # NIS2 report drafts (Pro): filled into the drafts, publisher only
    Field("NIS2_ENTITY", "nis2", "Your organisation's legal name", "text", "As registered with the authority.",
          feature="nis2", services=("publisher",)),
    Field("NIS2_SECTOR", "nis2", "Sector and entity type", "text", "For example: Digital infrastructure, important entity.",
          feature="nis2", services=("publisher",)),
    Field("NIS2_CONTACT", "nis2", "Contact person for incident reports", "text", "Name, phone and e-mail.",
          feature="nis2", services=("publisher",)),
    Field("NIS2_AUTHORITY", "nis2", "Who receives your reports", "text",
          "Your national CSIRT or authority, for example CSIRT-CY / Digital Security Authority.",
          feature="nis2", services=("publisher",)),
    # Monitoring and digest
    Field("SOURCE_SILENCE_MINUTES", "monitoring", "Warn me when a SIEM goes quiet for (minutes)", "int",
          "If a SIEM sends no events for this long, something is broken and alerts cannot fire. You get a "
          "message and a red banner. 0 = never warn.", "120", min=0, max=10080, feature="source_health"),
    Field("HOST_WATCH", "monitoring", "Important computers that must never go quiet", "lines",
          "One name per line. * matches anything, so dc-* means every computer whose name starts with dc-.",
          feature="host_watch", example="dc-*\nsrv-sql-01"),
    Field("HOST_SILENCE_MINUTES", "monitoring", "Warn me when one of them is quiet for (minutes)", "int",
          "", "60", min=15, max=10080, feature="host_watch"),
    Field("DIGEST_TIME", "monitoring", "Daily summary for the team", "choice",
          "Once a day: what came in, what Ardea closed and why, and what still needs a person. Sent through "
          "\"Alerts to your team\".", "off",
          (("off", "Off"),) + tuple((f"{h:02d}:00", f"Every day at {h:02d}:00") for h in range(24)),
          feature="digest"),
    # Backups (the "backup" service reads them straight from the database)
    Field("BACKUP_ENABLED", "backups", "Back up every night", "bool",
          "Saves the whole database and the key that opens your saved passwords into the backups folder next to "
          "docker-compose.yml. Copy that folder to another computer or a NAS now and then.", "true",
          services=("backup",)),
    Field("BACKUP_TIME", "backups", "At", "choice", "In the server's time zone.", "02:00",
          tuple((f"{h:02d}:00", f"{h:02d}:00") for h in range(24)), services=("backup",), show_if="BACKUP_ENABLED=true"),
    Field("BACKUP_KEEP_DAYS", "backups", "Keep backups for (days)", "int", "Older backups are deleted.", "14",
          min=1, max=365, services=("backup",), show_if="BACKUP_ENABLED=true"),
    # Reports and branding
    Field("ARDEA_REPORTS", "reports", "E-mail a management report", "choice",
          "A one-page summary: alerts handled, time saved, real attacks found.", "off",
          (("off", "Off"), ("weekly", "Every Monday"), ("monthly", "On the 1st of every month")), feature="reports"),
    Field("ARDEA_REPORT_TO", "reports", "Send the report to", "emails",
          "Separate addresses with commas. Empty = your team's addresses from \"Alerts to your team\". "
          "It uses the mail server set there.", feature="reports", show_if="ARDEA_REPORTS=weekly|monthly",
          example="manager@example.com"),
    Field("ARDEA_MINUTES_PER_ALERT", "reports", "Minutes a person needs for one alert", "int",
          "Used to estimate the time Ardea saves you.", "10", min=1, max=240, services=("worker", "publisher")),
    Field("ARDEA_BRAND_NAME", "reports", "Your company name", "text",
          "Shown instead of \"Ardea\" in the console and in reports.", feature="branding",
          services=("worker", "publisher")),
]
BY_NAME = {f.name: f for f in FIELDS}

SIEMS_KEY = "SIEMS"                       # the SIEM list (no secrets), JSON
SIEM_TEMPLATES_KEY = "SIEM_TEMPLATES"     # MSP: settings templates for customer SIEMs (no secrets), JSON
BRAND_LOGO_KEY = "BRAND_LOGO"             # data: URI of the uploaded logo (publisher only)
SIEM_SECRETS = ("fetcher_api_key", "worker_api_key")
SIEM_NOTIFY_SECRETS = ("slack_webhook_url", "teams_webhook_url", "webhook_url", "webhook_secret")
SIEM_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def siem_secret_name(siem_id: str, key: str) -> str:
    return f"SIEM.{siem_id}.{key}"


def secret_bind(name: str, siem_url: str | None = None) -> str:
    """What a secret is bound to: '' for unbound secrets."""
    if name.startswith("SIEM."):
        return siem_url or ""
    f = BY_NAME.get(name)
    return f.bind if f else ""


# --------------------------------------------------------------------------- schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS app_settings (
    name        TEXT PRIMARY KEY,
    value       TEXT NOT NULL,                 -- plain value, or a sealed secret ('v1:...')
    secret      BOOLEAN NOT NULL DEFAULT FALSE,
    hint        TEXT,                          -- last 4 characters of a secret, for the UI
    kid         TEXT,                          -- which key sealed it
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS settings_meta (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), public_key TEXT NOT NULL, kid TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS settings_env (       -- which settings each service has from .env (values of secrets never)
    service TEXT NOT NULL, name TEXT NOT NULL, value TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (service, name)
);
CREATE TABLE IF NOT EXISTS settings_status (    -- per service: settings version applied, secrets it could not open
    service TEXT PRIMARY KEY, version TEXT, problems JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS settings_audit (
    id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT NOW(), actor TEXT, ip TEXT,
    name TEXT NOT NULL, action TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS playbook_packs (    -- signed playbook packs added from the Settings page
    id BIGSERIAL PRIMARY KEY, version TEXT, content TEXT NOT NULL,
    source TEXT NOT NULL,                       -- download | upload
    status TEXT NOT NULL DEFAULT 'pending',     -- pending (upload, not checked yet) | installed | rejected
    detail TEXT, summary JSONB, added_by TEXT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), installed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS playbook_pack_state (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), last_check_at TIMESTAMPTZ, last_ok BOOLEAN, last_detail TEXT
);
CREATE TABLE IF NOT EXISTS alert_work (           -- who handles an alert that needs a person (Pro)
    alert_id TEXT PRIMARY KEY, assignee TEXT,
    status TEXT NOT NULL DEFAULT 'open',        -- open | in_progress | resolved
    note TEXT, updated_by TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), resolved_at TIMESTAMPTZ,
    overdue_notified_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS alert_work_log (
    id BIGSERIAL PRIMARY KEY, alert_id TEXT NOT NULL, at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT, action TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_questions (      -- "Ask about this alert" (Pro)
    id BIGSERIAL PRIMARY KEY, alert_id TEXT NOT NULL, asked_by TEXT, question TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',      -- queued | running | done | failed
    answer TEXT, cited JSONB, steps JSONB, note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS alert_questions_alert_idx ON alert_questions (alert_id, id);
CREATE TABLE IF NOT EXISTS suppressions (         -- patterns closed without investigation (Pro)
    id BIGSERIAL PRIMARY KEY, siem TEXT, rule_name TEXT NOT NULL,
    process_executable TEXT NOT NULL, parent_executable TEXT, user_name TEXT,
    host_name TEXT,                             -- NULL = any host
    verdict TEXT NOT NULL DEFAULT 'Benign Positive', reason TEXT NOT NULL,
    created_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
    revoked_by TEXT, revoked_at TIMESTAMPTZ, hits INT NOT NULL DEFAULT 0, last_hit_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS incident_closures (      -- incidents closed by an analyst (Pro: incidents)
    id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL, outcome TEXT NOT NULL, note TEXT NOT NULL,
    closed_by TEXT NOT NULL, closed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS incident_closed_alerts (  -- which alerts a closure covered (deleted on reopen)
    alert_id TEXT PRIMARY KEY, closure_id BIGINT NOT NULL REFERENCES incident_closures(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS backup_runs (            -- nightly and on-demand backups (the "backup" service)
    id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'manual', status TEXT NOT NULL DEFAULT 'requested',
    requested_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ, file TEXT, bytes BIGINT, detail TEXT
);
CREATE TABLE IF NOT EXISTS system_health (          -- snapshots the worker writes for the Health page
    name TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS service_activity (    -- what the worker and the fetcher are doing now (status bar)
    service TEXT PRIMARY KEY, state TEXT NOT NULL, detail TEXT, alert_id TEXT, siem TEXT,
    max_steps INT, info JSONB, next_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS settings_tests (
    id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL, requested_by TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), status TEXT NOT NULL DEFAULT 'queued',
    detail TEXT, finished_at TIMESTAMPTZ
);
"""
_SCHEMA_LOCK = 7310555


def ensure_schema(execute):
    """`execute(sql)` runs one statement (psycopg conn.execute or a SQLAlchemy wrapper)."""
    execute(f"SELECT pg_advisory_xact_lock({_SCHEMA_LOCK})")
    for statement in filter(str.strip, SCHEMA.split(";")):
        execute(statement)


# --------------------------------------------------------------------------- sealing secrets
def _kid(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def _aad(name: str, bound: str) -> bytes:
    return f"ardea-setting-v1|{name}|{bound}".encode()


def _derive(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=b"ardea-settings-v1").derive(shared)


def seal(public_b64: str, name: str, plaintext: str, bound: str = "") -> str:
    """Encrypt a secret for the worker and fetcher. Needs only the public key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    recipient_raw = base64.b64decode(public_b64)
    recipient = X25519PublicKey.from_public_bytes(recipient_raw)
    eph = X25519PrivateKey.generate()
    eph_raw = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _derive(eph.exchange(recipient), eph_raw, recipient_raw)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), _aad(name, bound))
    return "v1:" + base64.b64encode(eph_raw + nonce + ct).decode()


def unseal(private_key, name: str, token: str, bound: str = "") -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    if not token.startswith("v1:"):
        raise ValueError("unknown format")
    raw = base64.b64decode(token[3:])
    eph_raw, nonce, ct = raw[:32], raw[32:44], raw[44:]
    recipient_raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _derive(private_key.exchange(X25519PublicKey.from_public_bytes(eph_raw)), eph_raw, recipient_raw)
    return AESGCM(key).decrypt(nonce, ct, _aad(name, bound)).decode()


KEY_FILE = pathlib.Path(os.getenv("ARDEA_SETTINGS_KEY_FILE", "/app/keys/settings.key"))


def load_or_create_key(path: pathlib.Path = None):
    """The private key (worker and fetcher only). Created once; whichever service starts first makes it."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    path = path or KEY_FILE
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                        serialization.NoEncryption())
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass                                    # the other service won the race
        else:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
    return X25519PrivateKey.from_private_bytes(path.read_bytes()[:32])


def public_b64(private_key) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), _kid(raw)


# --------------------------------------------------------------------------- reading (all services)
def _clean(v) -> str:
    v = (v or "").strip() if isinstance(v, str) else ("" if v is None else str(v))
    return "" if v.startswith("#") else v           # Compose turns `KEY=   # comment` into '# comment'


OVERLAY: dict[str, str] = {}                        # values from the database, secrets already opened
PROBLEMS: dict[str, str] = {}                       # secrets that could not be opened, and why
_state = {"version": None}


def from_env(name: str) -> str:
    return _clean(os.getenv(name))


def env(name: str, default: str = "") -> str:
    """The value of a setting: .env first, then the Settings page, then the default."""
    return from_env(name) or _clean(OVERLAY.get(name)) or default


def _rows(fetchall):
    return {r["name"]: r for r in fetchall("SELECT name, value, secret, kid, updated_at FROM app_settings")}


def version_of(fetchone) -> str:
    r = fetchone("SELECT count(*) AS n, max(updated_at) AS t FROM app_settings")
    return f"{r['n']}:{r['t']}"


def refresh(conn, private_key=None, force: bool = False) -> bool:
    """Load the Settings page values into OVERLAY. Returns True when they changed. Psycopg connection, dict rows."""
    def fetchone(q):
        return conn.execute(q).fetchone()

    def fetchall(q):
        return conn.execute(q).fetchall()
    if not fetchone("SELECT to_regclass('public.app_settings') AS t")["t"]:
        return False
    version = version_of(fetchone)
    if version == _state["version"] and not force:
        return False
    rows = _rows(fetchall)
    plain = {n: r["value"] for n, r in rows.items() if not r["secret"]}
    opened, problems = {}, {}
    siem_urls = {}
    try:
        for s in json.loads(plain.get(SIEMS_KEY) or "[]"):
            siem_urls[str(s.get("id"))] = str(s.get("url") or "").rstrip("/")
    except (ValueError, TypeError, AttributeError):
        problems[SIEMS_KEY] = "the SIEM list is not valid"
    kid = public_b64(private_key)[1] if private_key else None
    for name, r in rows.items():
        if not r["secret"]:
            continue
        if private_key is None:
            continue                                  # the publisher never opens secrets
        if r["kid"] and r["kid"] != kid:
            problems[name] = "saved with a different key: enter it again"
            continue
        if name.startswith("SIEM."):
            bound = siem_urls.get(name.split(".")[1], "")
        else:
            bind = secret_bind(name)
            bound = (from_env(bind) or _clean(plain.get(bind)) or BY_NAME[bind].default) if bind else ""
        try:
            opened[name] = unseal(private_key, name, r["value"], bound)
        except Exception:
            problems[name] = ("its host or URL changed since it was saved: enter it again" if bound
                              else "cannot be opened: enter it again")
    OVERLAY.clear()
    OVERLAY.update(plain)
    OVERLAY.update(opened)
    PROBLEMS.clear()
    PROBLEMS.update(problems)
    _state["version"] = version
    return True


def lines(name: str) -> list[str]:
    return [x.strip() for x in env(name).splitlines() if x.strip()]


_CA_DIR = pathlib.Path(os.getenv("ARDEA_CA_DIR", "/tmp/ardea-ca"))


def siems_data() -> dict | None:
    """The SIEM list from the Settings page, with secrets filled in, in siems.json's format. None if unset."""
    try:
        items = json.loads(OVERLAY.get(SIEMS_KEY) or "null")
    except ValueError:
        return None
    if not isinstance(items, list) or not items:
        return None
    out = []
    for s in items:
        if not isinstance(s, dict):
            continue
        s = dict(s)
        sid = str(s.get("id", ""))
        for k in SIEM_SECRETS:
            s[k] = OVERLAY.get(siem_secret_name(sid, k), "")
        notify = dict(s.get("notify") or {})
        for k in SIEM_NOTIFY_SECRETS:
            v = OVERLAY.get(siem_secret_name(sid, "notify." + k))
            if v:
                notify[k] = v
        s["notify"] = notify
        pem = str(s.pop("ca_pem", "") or "")
        if pem.strip() and SIEM_ID_RE.match(sid):
            _CA_DIR.mkdir(parents=True, exist_ok=True)
            p = _CA_DIR / f"{sid}.pem"
            if not p.is_file() or p.read_text() != pem:
                p.write_text(pem)
            s["ca_cert"] = str(p)
        out.append(s)
    return {"siems": out}


def report(conn, service: str, extra_env: dict | None = None):
    """Tell the UI which settings this service has from .env (names; values only if not secret), and which
    secrets it could not open. Psycopg connection."""
    names = [f.name for f in FIELDS if service in f.services]
    found = {n: (None if BY_NAME[n].secret else from_env(n)) for n in names if from_env(n)}
    found.update(extra_env or {})
    sig = json.dumps([service, sorted(found.items()), _state["version"], sorted(PROBLEMS.items())])
    if _reported.get(service) == sig:
        return
    with conn.transaction():
        conn.execute("DELETE FROM settings_env WHERE service = %s", (service,))
        for n, v in found.items():
            conn.execute("INSERT INTO settings_env (service, name, value) VALUES (%s, %s, %s)", (service, n, v))
        conn.execute("""INSERT INTO settings_status (service, version, problems, updated_at) VALUES (%s, %s, %s, NOW())
                        ON CONFLICT (service) DO UPDATE SET version = EXCLUDED.version, problems = EXCLUDED.problems,
                                                            updated_at = NOW()""",
                     (service, _state["version"], json.dumps(PROBLEMS)))
    _reported[service] = sig


_reported: dict[str, str] = {}
_activity: dict[str, tuple] = {}


def activity(conn, service: str, state: str, detail: str = "", *, alert_id=None, siem=None, max_steps=None,
             info=None, next_at=None, every: float = 30.0):
    """Record what this service is doing, for the status bar. Written when it changes, otherwise at most every
    `every` seconds (that doubles as a heartbeat). Never raises. started_at resets when the state or the alert
    changes. Psycopg connection; commits if it is not in autocommit."""
    import time as _t
    key = (state, detail, alert_id, siem, json.dumps(info, sort_keys=True, default=str))
    last = _activity.get(service)
    if last and last[0] == key and _t.monotonic() - last[1] < every:
        return
    try:
        conn.execute("""INSERT INTO service_activity (service, state, detail, alert_id, siem, max_steps, info, next_at,
                                                      started_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT (service) DO UPDATE SET
                            started_at = CASE WHEN service_activity.state = EXCLUDED.state
                                               AND service_activity.alert_id IS NOT DISTINCT FROM EXCLUDED.alert_id
                                              THEN service_activity.started_at ELSE NOW() END,
                            state = EXCLUDED.state, detail = EXCLUDED.detail, alert_id = EXCLUDED.alert_id,
                            siem = EXCLUDED.siem, max_steps = EXCLUDED.max_steps, info = EXCLUDED.info,
                            next_at = EXCLUDED.next_at, updated_at = NOW()""",
                     (service, state, (detail or "")[:300], alert_id, siem, max_steps,
                      json.dumps(info, default=str) if info is not None else None, next_at))
        if not conn.autocommit:
            conn.commit()
        _activity[service] = (key, _t.monotonic())
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def publish_key(conn, private_key):
    pub, kid = public_b64(private_key)
    conn.execute("""INSERT INTO settings_meta (id, public_key, kid) VALUES (1, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET public_key = EXCLUDED.public_key, kid = EXCLUDED.kid,
                                                   updated_at = NOW()
                    WHERE settings_meta.kid <> EXCLUDED.kid""", (pub, kid))


class Runtime:
    """What the worker and fetcher run: key, schema, periodic refresh. `tick(conn)` -> True when values changed."""

    def __init__(self, service: str, every: float = 20.0, extra_env=None):
        self.service, self.every, self.extra_env = service, every, extra_env or (lambda: {})
        self.key = None
        self.ready = False
        self.last = 0.0

    def tick(self, conn, force: bool = False) -> bool:
        if not force and time.monotonic() - self.last < self.every:
            return False
        self.last = time.monotonic()
        if not self.ready:
            with conn.transaction():
                ensure_schema(conn.execute)
            try:
                self.key = load_or_create_key()
            except OSError as exc:                  # no writable /app/keys volume: secrets from the UI stay off
                self.key = None
                logging.getLogger("settings").error(
                    "cannot create or read %s (%s): secrets saved on the Settings page cannot be used", KEY_FILE, exc)
            if self.key is not None:
                with conn.transaction():
                    publish_key(conn, self.key)
            self.ready = True
        changed = refresh(conn, self.key, force=force)
        report(conn, self.service, self.extra_env())
        return changed
