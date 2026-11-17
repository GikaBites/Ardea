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
    ("siems", "SIEMs"),
    ("ai", "AI model"),
    ("triage", "Triage"),
    ("websearch", "Web search"),
    ("notifications", "Notifications"),
    ("reports", "Reports and branding"),
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
          "From your purchase e-mail. Leave empty for the free Community edition."),
    Field("ARDEA_LICENSE_OFFLINE", "licence", "Offline licence file", "lines",
          "For servers without internet access: paste the contents of the ardea.license file we sent you."),
    Field("ARDEA_LICENSE_PROXY", "licence", "Proxy for the licence check", "url",
          "Only if the worker reaches the internet through a proxy, e.g. http://egress-proxy:3128."),
    # AI model
    Field("LLM_URL", "ai", "Ollama URL", "url", "Where Ollama listens, e.g. http://192.168.1.50:11434.",
          "http://ollama:11434"),
    Field("LLM_MODEL", "ai", "Model", "text", "Exactly as `ollama list` shows it.", "qwen3:14b"),
    Field("LLM_THINK", "ai", "Reasoning", "choice", "Hybrid models (qwen3) reason by default, which is slow on CPU.",
          "", (("", "Model default"), ("false", "Off"), ("true", "On"), ("low", "Low (gpt-oss)"),
               ("medium", "Medium (gpt-oss)"), ("high", "High (gpt-oss)"))),
    Field("LLM_NUM_CTX", "ai", "Context window (tokens)", "int", "", "24576", min=4096, max=262144),
    Field("LLM_TIMEOUT_SECONDS", "ai", "Timeout per model call (seconds)", "int", "", "900", min=30, max=7200),
    Field("LLM_NUM_THREAD", "ai", "CPU threads", "int", "0 = Ollama's default. Only for CPU-only servers.", "0",
          min=0, max=512),
    Field("LLM_KEEP_ALIVE", "ai", "Keep model loaded", "text", "-1 = always, or a duration such as 24h.", "-1"),
    # Triage
    Field("MIN_CONFIDENCE_TO_CLOSE", "triage", "Minimum confidence to close an alert (%)", "int",
          "Benign or false positive verdicts below this go to a person.", "70", min=50, max=100),
    Field("VERIFY_CLOSURES", "triage", "Second look before closing", "bool",
          "A sceptical second pass before any alert is closed automatically. Recommended.", "true"),
    Field("FEEDBACK_EXAMPLES", "triage", "Analyst feedback shown to the model", "int",
          "Similar alerts your analysts corrected, shown as examples. 0 = off.", "3", min=0, max=10),
    Field("AGENT_MAX_STEPS", "triage", "Investigation steps", "int", "", "8", min=2, max=20),
    Field("AGENT_MAX_TOOL_CALLS", "triage", "SIEM queries per alert", "int", "", "10", min=1, max=30),
    Field("AGENT_MAX_WALL_SECONDS", "triage", "Time limit per alert (seconds)", "int", "", "1200", min=60, max=7200),
    Field("IGNORED_RULES", "triage", "Ignore these rules (exact names)", "lines",
          "One rule name per line. Alerts from these rules are never triaged.", services=("fetcher",)),
    Field("IGNORED_RULES_MATCH", "triage", "Ignore rules whose name contains", "lines",
          "One text per line, e.g. a vendor name.", services=("fetcher",)),
    Field("FETCH_INTERVAL_SECONDS", "triage", "Check for new alerts every (seconds)", "int", "", "180",
          min=30, max=3600, services=("fetcher",)),
    Field("DEDUP_WINDOW_HOURS", "triage", "Merge identical alerts within (hours)", "int", "", "24",
          min=0, max=168, services=("fetcher",)),
    # Web search
    Field("WEB_SEARCH_PROVIDER", "websearch", "Provider", "choice",
          "Only public indicators (IPs, domains, hashes, CVEs) pass the outbound filter.", "disabled",
          (("disabled", "Off"), ("searxng", "SearXNG"), ("brave", "Brave Search"), ("google_cse", "Google"))),
    Field("WEB_SEARCH_DRY_RUN", "websearch", "Dry run", "bool",
          "Log the queries but send nothing. Use it for a week before going live.", "false"),
    Field("WEB_SEARCH_KINDS", "websearch", "Allowed query kinds", "list",
          "Comma-separated: ip, domain, hash, cve, mitre, filename (and the riskier command_pattern, error_text).",
          "ip,domain,hash,cve,mitre,filename"),
    Field("SEARXNG_URL", "websearch", "SearXNG URL", "url"),
    Field("BRAVE_API_KEY", "websearch", "Brave API key", "secret"),
    Field("GOOGLE_API_KEY", "websearch", "Google API key", "secret"),
    Field("GOOGLE_CSE_ID", "websearch", "Google search engine ID", "text"),
    Field("INTERNAL_DOMAINS", "websearch", "Your internal domains", "list",
          "Never searched for. Comma-separated.", "local,lan,corp,internal,intra"),
    Field("SENSITIVE_TERMS", "websearch", "Sensitive words", "list",
          "Customer or project names that must never leave your network. Comma-separated."),
    # Notifications
    Field("NOTIFY_CHANNELS", "notifications", "Send verdicts to", "multi",
          "Every channel needs Ardea Pro or MSP.", "", _CHANNELS,
          feature="notifications"),
    Field("NOTIFY_VERDICTS", "notifications", "Verdicts that notify", "multi", "", "True Positive", _VERDICTS),
    Field("NOTIFY_MIN_SEVERITY", "notifications", "Minimum severity", "choice", "", "Informational", _SEVERITIES),
    Field("NOTIFY_DETAIL", "notifications", "Detail", "choice",
          "Minimal sends only the verdict and a link: nothing about the host or user leaves.", "full",
          (("full", "Full summary"), ("minimal", "Minimal: verdict and link"))),
    Field("ARDEA_PUBLIC_URL", "notifications", "Ardea web address", "url",
          "Used for links in notifications and reports, e.g. https://ardea.example.com."),
    Field("SMTP_HOST", "notifications", "SMTP server", "text"),
    Field("SMTP_PORT", "notifications", "SMTP port", "int", "", "587", min=1, max=65535),
    Field("SMTP_SECURITY", "notifications", "SMTP encryption", "choice", "", "starttls",
          (("starttls", "STARTTLS"), ("ssl", "SSL/TLS"), ("none", "None"))),
    Field("SMTP_USER", "notifications", "SMTP user", "text"),
    Field("SMTP_PASSWORD", "notifications", "SMTP password", "secret", bind="SMTP_HOST"),
    Field("SMTP_FROM", "notifications", "From address", "email"),
    Field("SMTP_TO", "notifications", "To addresses", "emails", "Comma-separated."),
    Field("NTFY_URL", "notifications", "ntfy server", "url", "", "https://ntfy.sh"),
    Field("NTFY_TOPIC", "notifications", "ntfy topic", "text"),
    Field("NTFY_TOKEN", "notifications", "ntfy access token", "secret", bind="NTFY_URL"),
    Field("SLACK_WEBHOOK_URL", "notifications", "Slack webhook URL", "secret", feature="integrations"),
    Field("TEAMS_WEBHOOK_URL", "notifications", "Teams webhook URL", "secret", feature="integrations"),
    Field("WEBHOOK_URL", "notifications", "Webhook URL", "url", feature="integrations"),
    Field("WEBHOOK_SECRET", "notifications", "Webhook signing secret", "secret", bind="WEBHOOK_URL",
          feature="integrations"),
    Field("JIRA_URL", "notifications", "Jira URL", "url", feature="integrations"),
    Field("JIRA_USER", "notifications", "Jira user (e-mail)", "text", feature="integrations"),
    Field("JIRA_API_TOKEN", "notifications", "Jira API token", "secret", bind="JIRA_URL", feature="integrations"),
    Field("JIRA_PROJECT", "notifications", "Jira project key", "text", feature="integrations"),
    Field("JIRA_ISSUE_TYPE", "notifications", "Jira issue type", "text", "", "Task", feature="integrations"),
    Field("THEHIVE_URL", "notifications", "TheHive URL", "url", feature="integrations"),
    Field("THEHIVE_API_KEY", "notifications", "TheHive API key", "secret", bind="THEHIVE_URL",
          feature="integrations"),
    Field("NOTIFY_PROXY", "notifications", "Proxy for notifications", "url",
          "Only if the worker reaches Slack, Teams or Jira through a proxy."),
    # Reports and branding
    Field("ARDEA_REPORTS", "reports", "Scheduled report e-mail", "choice", "", "off",
          (("off", "Off"), ("weekly", "Weekly, on Monday"), ("monthly", "Monthly, on the 1st")), feature="reports"),
    Field("ARDEA_REPORT_TO", "reports", "Report recipients", "emails", "Comma-separated. Empty = the To addresses.",
          feature="reports"),
    Field("ARDEA_MINUTES_PER_ALERT", "reports", "Minutes an analyst spends per alert", "int",
          "For the time-saved estimate in Insights.", "10", min=1, max=240, services=("worker", "publisher")),
    Field("ARDEA_BRAND_NAME", "reports", "Your brand name", "text", "Shown instead of Ardea in the console and reports.",
          feature="branding", services=("worker", "publisher")),
]
BY_NAME = {f.name: f for f in FIELDS}

SIEMS_KEY = "SIEMS"                       # the SIEM list (no secrets), JSON
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
