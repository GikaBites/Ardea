"""Support bundle: one archive with Ardea's logs, versions and health, with every secret removed.

Made by ./support-bundle.sh on the Docker host. That script collects what only the host can see (container
logs, `docker compose ps`, Docker and git versions, .env, siems/siems.json) into a tar stream and pipes it
into this module inside the worker container:

    tar -cf - -C raw . | docker compose exec -T worker python support_bundle.py > ardea-support.tar.gz

Here we add what only the worker can see (health tables, licence state, settings), remove secrets and write
a .tar.gz to stdout. Nothing is sent anywhere: the person decides whether to e-mail the file.

Secrets are removed in two ways:
  1. Known values. Every value of a secret setting (from .env, the environment, siems.json and the sealed
     secrets on the Settings page, opened with the worker's key) is replaced wherever it appears.
  2. Patterns. Things that look like secrets even when we do not know the value: Authorization headers,
     "password=...", passwords in URLs, private keys, sealed values, webhook addresses and common token formats.
Before the archive is written, every file is checked again for every known value. If one is still there,
no archive is made (exit 3).
"""
import io
import json
import os
import pathlib
import platform
import re
import sys
import tarfile
from datetime import datetime, timezone
from urllib.parse import quote

MASK = "[REDACTED]"
MAX_MEMBER = 200 * 1024 * 1024          # bytes read from one input file
MIN_SECRET_LEN = 4                      # shorter "secrets" (e.g. "1") would blank out half the logs

# Setting names that hold secrets, whatever the setting is called.
SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|PASS\b|PWD|SECRET|TOKEN(?!S)|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|LICEN[CS]E_KEY|"
    r"WEBHOOK|COOKIE|SALT|SIGNING|AUTH(?!OR))", re.I)
NOT_SECRET_VALUES = {"true", "false", "yes", "no", "none", "null", "on", "off"}
NOT_SECRET_NAMES = {"PWD", "OLDPWD"}   # the shell's working directory, not a password
_KEEP = r"(?!\[REDACTED|\((?:secret|empty)\b)"   # do not mask a mask, or settings.txt's "(secret, set)"

_KV_WORDS = (r"password|passwd|pwd|pass(?![a-z])|secret|token(?!s)|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
             r"licen[cs]e[_-]?key|client[_-]?secret|webhook[_-]?(?:url|secret)|cookie|auth[_-]?token|"
             r"x-api-key|session[_-]?id(?![a-z])")
PATTERNS = [
    # private keys and certificates' keys
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
     "-----BEGIN PRIVATE KEY-----" + MASK + "-----END PRIVATE KEY-----"),
    # Authorization: Bearer xyz / ApiKey xyz / Basic xyz (headers, curl lines, Python reprs)
    (re.compile(r"(?i)((?:proxy-)?authorization['\"]?\s*[:=]\s*['\"]?)(?:(bearer|apikey|basic|token|sharedaccesssignature)\s+)?"
                + _KEEP + r"[^\s'\",}]+"),
     lambda m: m.group(1) + (m.group(2) + " " if m.group(2) else "") + MASK),
    (re.compile(r"(?i)\b(bearer|apikey|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), lambda m: m.group(1) + " " + MASK),
    # https://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@'\"]+:[^/\s@'\"]+@"), r"\1" + MASK + "@"),
    # password=..., "api_key": "...", token: ..., SMTP_PASSWORD=...
    (re.compile(r"(?i)(\b[\w.-]*(?:" + _KV_WORDS + r")[\w.-]*['\"]?\s*[:=]\s*['\"]?)" + _KEEP + r"([^\s'\",;&}\]]+)"),
     lambda m: m.group(1) + MASK),
    # "Temporary password: x", "one-time password for 'admin': x"
    (re.compile(r"(?i)(\bpassword\b[^:\n=]{0,40}:\s*)" + _KEEP + r"(\S+)"), lambda m: m.group(1) + MASK),
    # query strings: ?token=..&key=..&sig=..
    (re.compile(r"(?i)([?&](?:key|token|sig|signature|code|secret|apikey|api_key|access_token)=)[^&\s'\"]+"),
     r"\1" + MASK),
    # webhook addresses: the path is the secret
    (re.compile(r"(?i)(https?://hooks\.slack\.com/)[^\s'\"<>]+"), r"\1" + MASK),
    (re.compile(r"(?i)(https?://[\w.-]*(?:webhook\.office\.com|logic\.azure\.com|powerplatform\.com|"
                r"discord(?:app)?\.com/api/webhooks)[^\s/'\"<>]*/)[^\s'\"<>]+"), r"\1" + MASK),
    # values sealed by the Settings page
    (re.compile(r"\bv1:[A-Za-z0-9+/=]{24,}"), "v1:" + MASK),
    # common token formats
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),                       # Slack
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), MASK),                         # GitHub
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), MASK),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), MASK),                           # GitLab
    (re.compile(r"\btk_[A-Za-z0-9]{20,}"), MASK),                                # ntfy
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),                        # AWS access key id
    (re.compile(r"\bpolar_[a-z]{2,4}_[A-Za-z0-9]{20,}"), MASK),                  # Polar tokens
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), MASK),                              # API keys of many LLM services
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),   # JWT
]


# --------------------------------------------------------------------------- redaction
def is_secret_name(name: str) -> bool:
    import appsettings
    f = appsettings.BY_NAME.get(name)
    return name not in NOT_SECRET_NAMES and bool((f and f.secret) or SECRET_NAME.search(name or ""))


def _variants(value: str) -> set[str]:
    out = {value, quote(value, safe=""), json.dumps(value)[1:-1]}
    return {v for v in out if len(v) >= MIN_SECRET_LEN}


class Redactor:
    def __init__(self, secrets: dict[str, str] | None = None):
        self.secrets: dict[str, str] = {}       # value -> name it came from
        self.count = 0
        for name, value in (secrets or {}).items():
            self.add(name, value)

    def add(self, name: str, value) -> None:
        if not isinstance(value, str):
            return
        value = value.strip()
        if len(value) < MIN_SECRET_LEN or value.lower() in NOT_SECRET_VALUES:
            return
        for v in _variants(value):
            self.secrets.setdefault(v, name)

    def text(self, s: str) -> str:
        for value in sorted(self.secrets, key=len, reverse=True):     # longest first: a key inside a URL
            if value in s:
                self.count += s.count(value)
                s = s.replace(value, f"[REDACTED:{self.secrets[value]}]" if self.secrets[value] else MASK)
        for rx, repl in PATTERNS:
            s, n = rx.subn(repl, s)
            self.count += n
        return s

    def leaks(self, s: str) -> list[str]:
        """Names of known secrets still in s (should always be empty)."""
        return sorted({name for value, name in self.secrets.items() if value in s})


# --------------------------------------------------------------------------- input from the host
def parse_env(text: str) -> dict[str, str]:
    """KEY=value lines of a .env file (comments, blank lines and `export ` allowed; quotes removed)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            out[k] = v
    return out


def _walk_secrets(obj, add, path=""):
    """Every value under a secret-looking key in a JSON document (siems.json)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            if isinstance(v, str) and SECRET_NAME.search(str(k)):
                add(p, v)
            else:
                _walk_secrets(v, add, p)
    elif isinstance(obj, list):
        for n, v in enumerate(obj):
            _walk_secrets(v, add, f"{path}[{n}]")


def _mask_json(obj, red: "Redactor"):
    """A JSON document with values under secret-looking keys masked and every string redacted. Done on the
    structure, not on the JSON text, so the result is still valid JSON."""
    if isinstance(obj, dict):
        return {k: ((MASK if v not in ("", None) else v) if SECRET_NAME.search(str(k)) and not isinstance(v, (dict, list))
                    else _mask_json(v, red)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_json(v, red) for v in obj]
    if isinstance(obj, str):
        return red.text(obj)
    return obj


def read_input(stream) -> dict[str, bytes]:
    files = {}
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
            for m in tar:
                if not m.isfile():
                    continue
                name = m.name
                while name.startswith("./"):
                    name = name[2:]
                parts = pathlib.PurePosixPath(name).parts
                if not name or name.startswith("/") or ".." in parts:
                    continue
                files[name] = tar.extractfile(m).read(MAX_MEMBER)
    except tarfile.ReadError:
        pass                                        # nothing piped in: bundle with the worker's view only
    return files


# --------------------------------------------------------------------------- what the worker sees
def _key():
    import appsettings
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        if appsettings.KEY_FILE.is_file():
            return X25519PrivateKey.from_private_bytes(appsettings.KEY_FILE.read_bytes()[:32])
    except Exception:
        pass
    return None


def _rows(conn, sql, params=()):
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except Exception as exc:                        # missing table on an old install, etc.
        return [{"error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"}]


def collect_db(conn, red: Redactor, key=None) -> tuple[dict, list[str]]:
    """Health data for the bundle, and lines for settings.txt. Adds every Settings page secret to `red`."""
    import appsettings
    stored = {r["name"]: r for r in _rows(conn, "SELECT name, value, secret, hint, updated_at FROM app_settings")
              if "name" in r}
    appsettings.refresh(conn, key, force=True)
    for name, r in stored.items():
        if r["secret"]:
            red.add(name, appsettings.OVERLAY.get(name, ""))
            red.add(name, r["value"])               # the sealed text itself
    health = {
        "system_health": _rows(conn, "SELECT name, value, updated_at FROM system_health ORDER BY name"),
        "backup_runs": _rows(conn, "SELECT id, kind, status, created_at, started_at, finished_at, file, bytes, detail "
                                   "FROM backup_runs ORDER BY id DESC LIMIT 30"),
        "service_activity": _rows(conn, "SELECT service, state, detail, siem, info, next_at, started_at, updated_at "
                                        "FROM service_activity ORDER BY service"),
        "settings_status": _rows(conn, "SELECT service, version, problems, updated_at FROM settings_status"),
        "licence": _rows(conn, "SELECT tier, source, status, product, expires_at, valid_until, last_ok_at, "
                               "last_checked_at, last_error, updated_at FROM license_state"),
        "alerts_by_status": _rows(conn, "SELECT status, count(*) AS n FROM alerts GROUP BY status ORDER BY status"),
        "results_last_24h": _rows(conn, "SELECT r.verdict, count(*) AS n, "
                                        "round(avg(r.duration_ms) / 1000.0) AS avg_seconds FROM triage_results r "
                                        "WHERE r.created_at > NOW() - interval '24 hours' GROUP BY 1 ORDER BY 1"),
        "siems": _rows(conn, "SELECT id, name, kibana_url, active, updated_at FROM siems ORDER BY position, id"),
        "database": _rows(conn, "SELECT version() AS postgres, pg_database_size(current_database()) AS bytes"),
        "settings_problems": dict(appsettings.PROBLEMS),
    }
    lines = []
    for name in sorted(stored):
        r = stored[name]
        if r["secret"]:
            lines.append(f"{name} = (secret, set on the Settings page)")
        else:
            lines.append(f"{name} = {r['value']}")
    return health, lines


def settings_txt(env_file: dict[str, str], page_lines: list[str] | None) -> str:
    out = ["# Settings. Secrets are never shown: only whether they are set.", "", "## .env"]
    for k in sorted(env_file):
        v = env_file[k]
        if is_secret_name(k):
            out.append(f"{k} = {'(secret, set)' if v else '(empty)'}")
        else:
            out.append(f"{k} = {v}")
    if page_lines is None:
        page_lines = ["(the database could not be read)"]
    out += ["", "## Settings page"] + (page_lines or ["(nothing saved on the Settings page)"])
    return "\n".join(out) + "\n"


def worker_versions() -> str:
    lines = [f"python {platform.python_version()}"]
    try:
        import config
        lines.append(f"prompt version {config.PROMPT_VERSION}")
        lines.append(f"model {config.MODEL}")
    except Exception:
        pass
    try:
        from importlib import metadata
        for pkg in ("psycopg", "requests", "ollama", "pydantic", "PyYAML", "cryptography"):
            try:
                lines.append(f"{pkg} {metadata.version(pkg)}")
            except metadata.PackageNotFoundError:
                pass
    except Exception:
        pass
    try:
        import licensing
        lines.append(f"edition {licensing.tier()}")
    except Exception:
        pass
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- the bundle
README = """Ardea support bundle, made {when}.

What is inside:
  versions.txt      Ardea, Docker, Python and package versions
  system.txt        the server: operating system, memory, disk
  compose-ps.txt    which containers run, and their health
  settings.txt      setting names and plain values; secrets only as "set" or "empty"
  health.json       System health, backups, licence state, queue size, what each service is doing
  siems.json        your SIEM list, with its keys removed (only if you use siems/siems.json)
  logs/             the last {hours} hours of each container's log

Passwords, API keys, tokens, webhook addresses, sealed settings and .env secrets were replaced with
[REDACTED] ({count} replacements). The logs can still contain names of your computers, users and alerts.
Please read the files before you send them, and remove anything you do not want to share.
"""


def build(inputs: dict[str, bytes], conn=None, key=None, extra_secrets: dict | None = None,
          now: datetime | None = None) -> tuple[bytes, Redactor]:
    """The .tar.gz bytes. Raises RuntimeError if a known secret would still be in it."""
    now = now or datetime.now(timezone.utc)
    red = Redactor()
    env_file = parse_env(inputs.get("env", b"").decode("utf-8", "replace"))
    for k, v in {**os.environ, **env_file, **(extra_secrets or {})}.items():
        if is_secret_name(k):
            red.add(k, v)
    siems_doc = None
    if "siems.json" in inputs:
        try:
            siems_doc = json.loads(inputs["siems.json"])
            _walk_secrets(siems_doc, red.add)
        except ValueError:
            siems_doc = {"error": "siems.json is not valid JSON"}
    if key is not None:
        try:
            from cryptography.hazmat.primitives import serialization
            import base64
            raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
            red.add("settings key", base64.b64encode(raw).decode())
            red.add("settings key", raw.hex())
        except Exception:
            pass
    health, page_lines = {"error": "the database could not be read"}, None
    if conn is not None:
        try:
            health, page_lines = collect_db(conn, red, key)
        except Exception as exc:
            health, page_lines = {"error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"}, None

    out: dict[str, str] = {}
    host_versions = inputs.get("versions.txt", b"").decode("utf-8", "replace")
    out["versions.txt"] = host_versions + "\n# inside the worker\n" + worker_versions()
    for name in ("system.txt", "compose-ps.txt"):
        if name in inputs:
            out[name] = inputs[name].decode("utf-8", "replace")
    out["settings.txt"] = settings_txt(env_file, page_lines)
    for name, data in sorted(inputs.items()):
        if name.startswith("logs/") and name.endswith(".log"):
            out[name] = data.decode("utf-8", "replace")
    # Never pass through anything else from the input (the raw .env above all).

    out = {name: red.text(text) for name, text in out.items()}
    health = json.loads(json.dumps(health, default=str))
    out["health.json"] = json.dumps(_mask_json(health, red), indent=2) + "\n"
    if siems_doc is not None:
        out["siems.json"] = json.dumps(_mask_json(siems_doc, red), indent=2) + "\n"
    hours = (inputs.get("log-hours", b"72").decode().strip() or "72")
    out["README.txt"] = README.format(when=now.strftime("%Y-%m-%d %H:%M UTC"), hours=hours, count=red.count)

    leaked = {name: red.leaks(text) for name, text in out.items()}
    leaked = {k: v for k, v in leaked.items() if v}
    if leaked:
        raise RuntimeError("a secret is still in " + ", ".join(f"{f} ({', '.join(n)})" for f, n in leaked.items()))

    top = "ardea-support-" + now.strftime("%Y-%m-%d_%H%M")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in sorted(out.items()):
            data = text.encode()
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size, info.mtime, info.mode = len(data), int(now.timestamp()), 0o600
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue(), red


def main() -> int:
    inputs = read_input(sys.stdin.buffer)
    conn = None
    try:
        import db
        conn = db.get_connection()
    except Exception as exc:
        print(f"support bundle: the database could not be read ({type(exc).__name__}); continuing without it",
              file=sys.stderr)
    try:
        data, red = build(inputs, conn, _key())
    except RuntimeError as exc:
        print(f"support bundle: stopped, nothing written: {exc}", file=sys.stderr)
        return 3
    finally:
        if conn is not None:
            conn.close()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    print(f"support bundle: {len(data)} bytes, {red.count} secrets removed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
