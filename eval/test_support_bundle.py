"""Support bundle (worker/support_bundle.py): every secret is removed, useful information is kept.

The first tests need nothing. The last one needs a real Postgres (EMPTY *_test database) and checks that
secrets sealed on the Settings page are opened with the worker's key and removed from the logs too.
"""
import io
import json
import os
import pathlib
import tarfile
from datetime import datetime, timezone

import pytest

import appsettings
import support_bundle as sb

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 20, 9, 30, tzinfo=timezone.utc)

ENV = """# Ardea settings
TZ=Asia/Nicosia
POSTGRES_DB=ArdeaDB
POSTGRES_USER=admin
POSTGRES_PASSWORD=pg-Very-Secret-91
ELASTIC_URL=https://elastic.lan:9200
ELASTIC_WORKER_API_KEY="d29ya2VyOmtleS1zZWNyZXQtMTIz"
export SMTP_PASSWORD='mail pass 7'
NTFY_TOKEN=tk_abcdefghijklmnopqrstuvwxyz123
ARDEA_LICENSE_KEY=ARDEA-1111-2222-3333-4444
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX
WEBHOOK_SECRET=whsec-shh-0042
LLM_URL=http://10.0.0.5:11434
LLM_MODEL=qwen3:14b
LLM_MAX_TOKENS=4096
BACKUP_ENABLED=true
"""
ENV_SECRETS = ["pg-Very-Secret-91", "d29ya2VyOmtleS1zZWNyZXQtMTIz", "mail pass 7", "tk_abcdefghijklmnopqrstuvwxyz123",
               "ARDEA-1111-2222-3333-4444", "T000/B000/XXXXXXXXXXXXXXXX", "whsec-shh-0042"]

SIEMS = {"siems": [{"id": "hq", "name": "Head office", "url": "https://elastic-hq.lan:9200",
                    "worker_api_key": "siem-worker-key-0001", "fetcher_api_key": "siem-fetcher-key-0002",
                    "notify": {"teams_webhook_url": "https://acme.webhook.office.com/webhookb2/abc/IncomingWebhook/def"}}]}
SIEM_SECRETS = ["siem-worker-key-0001", "siem-fetcher-key-0002", "webhookb2/abc/IncomingWebhook/def"]

LOG = """2026-11-20T02:00:01Z worker  | INFO investigating alert a-17 on host WS-042 (user j.smith)
2026-11-20T02:00:02Z worker  | DEBUG POST https://elastic.lan:9200/_search headers={'Authorization': 'ApiKey d29ya2VyOmtleS1zZWNyZXQtMTIz'}
2026-11-20T02:00:03Z worker  | ERROR smtp login failed for alerts@acme.example with password=mail pass 7
2026-11-20T02:00:04Z worker  | WARNING ntfy https://ntfy.sh/acme returned 401 for token tk_abcdefghijklmnopqrstuvwxyz123
2026-11-20T02:00:05Z worker  | ERROR db: connection to postgresql://admin:pg-Very-Secret-91@db:5432/ArdeaDB failed
2026-11-20T02:00:06Z worker  | INFO slack post to https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX failed (404)
2026-11-20T02:00:07Z worker  | DEBUG teams https://acme.webhook.office.com/webhookb2/abc/IncomingWebhook/def
2026-11-20T02:00:08Z worker  | DEBUG unknown secret: Authorization: Bearer abcDEF1234567890ghijklmnop
2026-11-20T02:00:09Z worker  | DEBUG {"api_key": "never-seen-before-1", "client_secret": "never-seen-before-2"}
2026-11-20T02:00:10Z worker  | DEBUG sealed v1:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk=
2026-11-20T02:00:11Z worker  | DEBUG cert -----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC
-----END PRIVATE KEY-----
2026-11-20T02:00:12Z worker  | INFO licence ARDEA-1111-2222-3333-4444 checked: ok
2026-11-20T02:00:13Z worker  | INFO verdict False Positive, 812 tokens, sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
"""
PUBLISHER_LOG = "2026-11-20T01:00:00Z publisher | Temporary password: Xy7-qq-91-zz (one-time)\n"
UNKNOWN = ["abcDEF1234567890ghijklmnop", "never-seen-before-1", "never-seen-before-2",
           "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk=", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC",
           "Xy7-qq-91-zz"]


def _inputs(**extra):
    files = {"env": ENV.encode(), "siems.json": json.dumps(SIEMS).encode(), "logs/worker.log": LOG.encode(),
             "logs/publisher.log": PUBLISHER_LOG.encode(), "versions.txt": b"# Ardea\nversion v1.0.0\n",
             "system.txt": b"# Operating system\nLinux 6.8 x86_64\n", "compose-ps.txt": b"Ardea_worker  Up (healthy)\n",
             "log-hours": b"24\n"}
    files.update(extra)
    return files


def _unpack(data: bytes) -> dict[str, str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {m.name.split("/", 1)[1]: tar.extractfile(m).read().decode() for m in tar if m.isfile()}


@pytest.fixture(autouse=True)
def _clean_environ(monkeypatch):
    for k in list(os.environ):
        if sb.is_secret_name(k) and k != "POSTGRES_PASSWORD":
            monkeypatch.delenv(k, raising=False)


def test_bundle_has_no_secret_and_keeps_what_support_needs():
    data, red = sb.build(_inputs(), now=NOW)
    files = _unpack(data)
    assert set(files) >= {"README.txt", "versions.txt", "system.txt", "compose-ps.txt", "settings.txt",
                          "health.json", "siems.json", "logs/worker.log", "logs/publisher.log"}
    assert "env" not in files                                     # the raw .env never goes in
    everything = "\n".join(files.values())
    for secret in ENV_SECRETS + SIEM_SECRETS + UNKNOWN:
        assert secret not in everything, secret
    log = files["logs/worker.log"]
    # what support needs is still there
    for kept in ("host WS-042", "alert a-17", "https://elastic.lan:9200/_search", "returned 401", "@db:5432/ArdeaDB",
                 "812 tokens", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                 "[REDACTED:SLACK_WEBHOOK_URL] failed (404)", "DEBUG teams [REDACTED"):
        assert kept in log, kept
    assert "[REDACTED:SMTP_PASSWORD]" in log and "[REDACTED:ARDEA_LICENSE_KEY]" in log
    assert "Temporary password: [REDACTED]" in files["logs/publisher.log"]
    assert "version v1.0.0" in files["versions.txt"] and "inside the worker" in files["versions.txt"]
    assert "last 24 hours" in files["README.txt"] and red.count > 10


def test_settings_file_shows_names_and_plain_values_only():
    files = _unpack(sb.build(_inputs(), now=NOW)[0])
    s = files["settings.txt"]
    assert "POSTGRES_PASSWORD = (secret, set)" in s
    assert "SMTP_PASSWORD = (secret, set)" in s
    assert "SLACK_WEBHOOK_URL = (secret, set)" in s
    assert "LLM_MODEL = qwen3:14b" in s and "LLM_URL = http://10.0.0.5:11434" in s
    assert "LLM_MAX_TOKENS = 4096" in s                         # "tokens" is not a secret
    assert "BACKUP_ENABLED = true" in s
    siems = json.loads(files["siems.json"])["siems"][0]
    assert siems["worker_api_key"] == sb.MASK and siems["notify"]["teams_webhook_url"] == sb.MASK
    assert siems["url"] == "https://elastic-hq.lan:9200" and siems["name"] == "Head office"


def test_secrets_from_the_environment_and_variants_are_removed(monkeypatch):
    monkeypatch.setenv("JIRA_API_TOKEN", "jira/tok+en=42")
    log = "jira said 401 for jira%2Ftok%2Ben%3D42 and {\"t\": \"jira/tok+en=42\"}\n"
    files = _unpack(sb.build(_inputs(**{"logs/worker.log": log.encode()}), now=NOW)[0])
    assert "jira/tok+en=42" not in files["logs/worker.log"]
    assert "jira%2Ftok%2Ben%3D42" not in files["logs/worker.log"]
    assert "jira said 401" in files["logs/worker.log"]


def test_no_bundle_when_a_secret_would_remain(monkeypatch):
    monkeypatch.setattr(sb, "PATTERNS", [])
    red_text = sb.Redactor.text
    monkeypatch.setattr(sb.Redactor, "text", lambda self, s: s if "smtp login" in s else red_text(self, s))
    with pytest.raises(RuntimeError, match="SMTP_PASSWORD"):
        sb.build(_inputs(), now=NOW)


def test_redactor_does_not_blank_short_or_boolean_values():
    red = sb.Redactor({"A_TOKEN": "1", "B_SECRET": "true", "C_PASSWORD": "abc"})
    assert red.secrets == {}
    assert red.text("retry 1 of 3, enabled=true") == "retry 1 of 3, enabled=true"


@pytest.mark.parametrize("text, gone, kept", [
    ("curl -H 'Authorization: Basic YWRtaW46aHVudGVyMg=='", "YWRtaW46aHVudGVyMg==", "Authorization: Basic"),
    ("GET https://bob:hunter2@proxy.lan:3128/", "hunter2", "proxy.lan:3128"),
    ("url=https://api.example/x?token=abc123secret&page=2", "abc123secret", "page=2"),
    ("post https://x.webhook.office.com/webhookb2/aa-bb/IncomingWebhook/cc-dd ok", "aa-bb", "https://x.webhook.office.com/"),
    ("post https://hooks.slack.com/services/T1/B2/abcdef ok", "T1/B2/abcdef", "https://hooks.slack.com/"),
    ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij", "slack"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLXZhbHVl", "eyJzdWIiOiIxMjM0In0", "jwt"),
    ("AWS AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", "used"),
    ("SEARXNG_SECRET: 9f9f9f9f9f", "9f9f9f9f9f", "SEARXNG_SECRET"),
    ("tests passed: 12", None, "tests passed: 12"),
    ("SESSION_IDLE_MINUTES=480", None, "SESSION_IDLE_MINUTES=480"),
    ("author=j.smith", None, "author=j.smith"),
])
def test_patterns(text, gone, kept):
    out = sb.Redactor().text(text)
    if gone:
        assert gone not in out
    assert kept in out


def test_parse_env():
    env = sb.parse_env("A=1\n# c\n\nexport B = 'two words'\nC=\"x=y\"\nbad line\n9X=no\n")
    assert env == {"A": "1", "B": "two words", "C": "x=y"}


def test_input_without_tar_still_makes_a_bundle():
    assert sb.read_input(io.BytesIO(b"")) == {}
    files = _unpack(sb.build({}, now=NOW)[0])
    assert "README.txt" in files and "the database could not be read" in files["health.json"]


def test_unsafe_paths_in_input_are_ignored():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in ("./logs/ok.log", "../evil.log"):
            info = tarfile.TarInfo(name)
            info.size = 2
            tar.addfile(info, io.BytesIO(b"hi"))
    buf.seek(0)
    assert sb.read_input(buf) == {"logs/ok.log": b"hi"}


# --------------------------------------------------------------------------- with a database
@pytest.mark.skipif(not os.environ.get("POSTGRES_DB", "").endswith("_test"),
                    reason="set POSTGRES_DB to an empty database ending in _test")
def test_sealed_settings_page_secrets_are_removed(tmp_path, monkeypatch):
    import db
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    conn = db.get_connection()
    try:
        if not conn.execute("SELECT to_regclass('public.alerts') AS t").fetchone()["t"]:
            conn.execute((ROOT / "db" / "init.sql").read_text())
        with conn.transaction():
            appsettings.ensure_schema(conn.execute)
        conn.execute("DELETE FROM app_settings")
        conn.execute("DELETE FROM backup_runs")
        key = X25519PrivateKey.generate()
        pub, kid = appsettings.public_b64(key)
        sealed = appsettings.seal(pub, "BRAVE_API_KEY", "brave-key-from-ui-77")
        conn.execute("INSERT INTO app_settings (name, value, secret, hint, kid) VALUES (%s, %s, TRUE, '..77', %s)",
                     ("BRAVE_API_KEY", sealed, kid))
        conn.execute("INSERT INTO app_settings (name, value, secret) VALUES ('WEB_SEARCH_PROVIDER', 'brave', FALSE)")
        conn.execute("INSERT INTO backup_runs (kind, status, finished_at, file, detail) "
                     "VALUES ('scheduled', 'ok', NOW(), 'ardea-2026-11-20_0200.dump', 'Database saved.')")
        log = f"brave said 403 for X-Subscription-Token brave-key-from-ui-77\nstored {sealed}\n"
        files = _unpack(sb.build(_inputs(**{"logs/worker.log": log.encode()}), conn, key, now=NOW)[0])
        everything = "\n".join(files.values())
        assert "brave-key-from-ui-77" not in everything
        assert sealed not in everything and sealed[3:40] not in everything
        assert "[REDACTED:BRAVE_API_KEY]" in files["logs/worker.log"]
        assert "BRAVE_API_KEY = (secret, set on the Settings page)" in files["settings.txt"]
        assert "WEB_SEARCH_PROVIDER = brave" in files["settings.txt"]
        health = json.loads(files["health.json"])
        assert health["backup_runs"][0]["file"] == "ardea-2026-11-20_0200.dump"
        assert "alerts_by_status" in health and "licence" in health
    finally:
        conn.execute("DELETE FROM app_settings WHERE name IN ('BRAVE_API_KEY', 'WEB_SEARCH_PROVIDER')")
        conn.close()
