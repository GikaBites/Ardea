"""Settings page, worker side: sealed secrets, precedence, hot reload, SIEMs from the UI, test buttons."""
import filecmp
import importlib
import importlib.util
import json
import pathlib
import sys

import pytest

import appsettings as A
import config
import licensing
import settings_tests
import siems

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def key(tmp_path):
    return A.load_or_create_key(tmp_path / "settings.key")


@pytest.fixture(autouse=True)
def _clean_overlay():
    saved = dict(A.OVERLAY)
    yield
    A.OVERLAY.clear()
    A.OVERLAY.update(saved)
    A.PROBLEMS.clear()
    importlib.reload(config)


def test_shared_modules_are_identical():
    for name in ("appsettings.py", "siems.py"):
        assert filecmp.cmp(ROOT / "worker" / name, ROOT / "fetcher" / name, shallow=False), name
        assert filecmp.cmp(ROOT / "worker" / name, ROOT / "publisher" / name, shallow=False), name
    assert filecmp.cmp(ROOT / "worker" / "incidents.py", ROOT / "publisher" / "incidents.py", shallow=False)


def test_every_field_is_well_formed():
    groups = {g for g, _ in A.GROUPS}
    for f in A.FIELDS:
        assert f.group in groups, f.name
        if f.bind:
            assert f.secret and f.bind in A.BY_NAME and not A.BY_NAME[f.bind].secret, f.name
        if f.kind in ("choice", "multi"):
            assert f.options, f.name
        if f.default and f.kind == "choice":
            assert f.default in {o[0] for o in f.options}, f.name


def test_seal_roundtrip_and_binding(key):
    pub, _ = A.public_b64(key)
    token = A.seal(pub, "SMTP_PASSWORD", "hunter2-long-password", "smtp.example.com")
    assert token.startswith("v1:") and "hunter2" not in token
    assert A.unseal(key, "SMTP_PASSWORD", token, "smtp.example.com") == "hunter2-long-password"
    with pytest.raises(Exception):                       # host changed: the old password no longer opens
        A.unseal(key, "SMTP_PASSWORD", token, "evil.example.com")
    with pytest.raises(Exception):                       # a ciphertext moved to another setting does not open
        A.unseal(key, "JIRA_API_TOKEN", token, "smtp.example.com")


def test_key_is_created_once_and_private(tmp_path):
    k1 = A.load_or_create_key(tmp_path / "k")
    k2 = A.load_or_create_key(tmp_path / "k")
    assert A.public_b64(k1) == A.public_b64(k2)
    assert oct((tmp_path / "k").stat().st_mode)[-3:] == "600"


def test_env_wins_over_settings_page_over_default(monkeypatch):
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert A.env("LLM_MODEL", "d") == "d"
    A.OVERLAY["LLM_MODEL"] = "from-ui"
    assert A.env("LLM_MODEL", "d") == "from-ui"
    monkeypatch.setenv("LLM_MODEL", "from-env")
    assert A.env("LLM_MODEL", "d") == "from-env"
    monkeypatch.setenv("LLM_MODEL", "   # a comment")       # Compose quirk: a comment is unset
    assert A.env("LLM_MODEL", "d") == "from-ui"


def test_config_reload_applies_settings(monkeypatch):
    for n in ("LLM_MODEL", "MIN_CONFIDENCE_TO_CLOSE", "NOTIFY_CHANNELS"):
        monkeypatch.delenv(n, raising=False)
    A.OVERLAY.update({"LLM_MODEL": "gpt-oss:20b", "MIN_CONFIDENCE_TO_CLOSE": "85", "NOTIFY_CHANNELS": "smtp,slack"})
    importlib.reload(config)
    assert config.MODEL == "gpt-oss:20b" and config.MIN_CONFIDENCE_TO_CLOSE == 85
    assert config.NOTIFY_CHANNELS == ["smtp", "slack"]


class FakeConn:
    """Just enough of a psycopg connection for appsettings.refresh."""

    def __init__(self, rows):
        self.rows = rows

    def execute(self, q, params=None):
        rows = self.rows

        class R:
            def fetchone(self_inner):
                if "to_regclass" in q:
                    return {"t": "app_settings"}
                return {"n": len(rows), "t": json.dumps(sorted(rows))}

            def fetchall(self_inner):
                return [{"name": n, **r} for n, r in rows.items()]
        return R()


def _row(value, secret=False, kid=None):
    return {"value": value, "secret": secret, "kid": kid, "updated_at": None}


def test_refresh_opens_secrets_and_reports_what_it_cannot(key, monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    pub, kid = A.public_b64(key)
    siem_list = [{"id": "hq", "name": "HQ", "url": "https://es-hq:9200"}]
    rows = {
        "SMTP_HOST": _row("mail.example.com"),
        "SMTP_PASSWORD": _row(A.seal(pub, "SMTP_PASSWORD", "pw-1234567890", "old.example.com"), True, kid),
        "SLACK_WEBHOOK_URL": _row(A.seal(pub, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"), True, kid),
        "NTFY_TOKEN": _row(A.seal(pub, "NTFY_TOKEN", "tok", "https://ntfy.sh"), True, kid),   # bound to the default
        "JIRA_API_TOKEN": _row("v1:AAAA", True, "otherkeyid"),
        A.SIEMS_KEY: _row(json.dumps(siem_list)),
        "SIEM.hq.worker_api_key": _row(A.seal(pub, "SIEM.hq.worker_api_key", "wk", "https://es-hq:9200"), True, kid),
    }
    assert A.refresh(FakeConn(rows), key) is True
    assert A.OVERLAY["SLACK_WEBHOOK_URL"] == "https://hooks.slack.com/x"
    assert A.OVERLAY["NTFY_TOKEN"] == "tok"
    assert A.OVERLAY["SIEM.hq.worker_api_key"] == "wk"
    assert "SMTP_PASSWORD" not in A.OVERLAY and "host or URL changed" in A.PROBLEMS["SMTP_PASSWORD"]
    assert "different key" in A.PROBLEMS["JIRA_API_TOKEN"]
    assert A.refresh(FakeConn(rows), key) is False                     # same version: nothing to do
    publisher_view = dict(A.OVERLAY)
    A.refresh(FakeConn(rows), None, force=True)                        # the publisher: no key, no secrets
    assert "SLACK_WEBHOOK_URL" not in A.OVERLAY and publisher_view["SMTP_HOST"] == A.OVERLAY["SMTP_HOST"]


def test_siems_from_settings_page(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "_CA_DIR", tmp_path / "ca")
    A.OVERLAY.update({
        A.SIEMS_KEY: json.dumps([{"id": "hq", "name": "HQ", "url": "https://es-hq:9200",
                                  "ca_pem": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
                                  "notify": {"smtp_to": ["soc@customer.example"]}}]),
        "SIEM.hq.fetcher_api_key": "fk", "SIEM.hq.worker_api_key": "wk",
        "SIEM.hq.notify.slack_webhook_url": "https://hooks.slack.com/c"})
    data = A.siems_data()
    [s] = siems.load(path=str(tmp_path / "missing.json"), ui_data=data)
    assert (s.id, s.fetcher_api_key, s.worker_api_key) == ("hq", "fk", "wk")
    assert s.notify == {"smtp_to": ("soc@customer.example",), "slack_webhook_url": "https://hooks.slack.com/c"}
    assert pathlib.Path(s.ca_cert).read_text().startswith("-----BEGIN CERTIFICATE-----")
    f = tmp_path / "siems.json"                                        # siems.json on the server wins
    f.write_text(json.dumps({"siems": [{"id": "file", "url": "https://es-file:9200"}]}))
    assert [x.id for x in siems.load(path=str(f), ui_data=data)] == ["file"]


def test_licence_key_and_offline_licence_from_settings_page(monkeypatch, tmp_path):
    monkeypatch.delenv("ARDEA_LICENSE_KEY", raising=False)
    A.OVERLAY["ARDEA_LICENSE_KEY"] = "KEY-FROM-UI"
    assert licensing._license_key() == "KEY-FROM-UI"
    monkeypatch.setattr(licensing, "OFFLINE_FILE", tmp_path / "missing.license")
    A.OVERLAY["ARDEA_LICENSE_OFFLINE"] = "not json"
    with pytest.raises(licensing.LicenseInvalid, match="Settings page"):
        licensing.read_offline_license()


def test_fetcher_ignores_rules_from_settings_page(monkeypatch):
    fetcher_dir = str(ROOT / "fetcher")
    spec = importlib.util.spec_from_file_location("tz_fetcher_settings", ROOT / "fetcher" / "fetcher.py")
    sys.path.insert(0, fetcher_dir)
    saved = {m: sys.modules.pop(m) for m in ("db", "siems") if m in sys.modules}
    try:
        fetcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fetcher)
    finally:
        sys.path.remove(fetcher_dir)
        sys.modules.update(saved)
    fetcher.appsettings.OVERLAY.update({"IGNORED_RULES": "Noisy Rule\n", "IGNORED_RULES_MATCH": "Vendor X\n",
                                        "FETCH_INTERVAL_SECONDS": "10"})
    rules = fetcher.load_ignored_rules()
    assert fetcher.is_rule_ignored("Noisy Rule", rules) and fetcher.is_rule_ignored("Vendor X agent alert", rules)
    assert not fetcher.is_rule_ignored("Credential Dumping", rules)
    assert fetcher.cooldown() == 30                                    # never faster than 30 s


def test_test_results_never_contain_secrets(monkeypatch):
    A.OVERLAY.update({"SMTP_PASSWORD": "S3cr3t-Passw0rd", "SIEM.hq.worker_api_key": "abcdKEY123"})
    out = settings_tests._scrub("login failed for S3cr3t-Passw0rd with abcdKEY123 at https://es-hq:9200/_search")
    assert "S3cr3t" not in out and "abcdKEY123" not in out and "es-hq" not in out


class QueueConn:
    def __init__(self, kinds):
        self.queue = list(kinds)
        self.done = {}

    def execute(self, q, params=None):
        conn = self

        class R:
            def fetchone(self_inner):
                if "RETURNING id, kind" in q:
                    if not conn.queue:
                        return None
                    kind = conn.queue.pop(0)
                    return {"id": len(conn.done) + 1, "kind": kind}
                return None
        if q.startswith("UPDATE settings_tests SET status = %s"):
            self.done[params[2]] = (params[0], params[1])
        return R()


def test_unknown_test_kinds_are_refused_and_missing_siem_explained(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "OVERLAY", {})
    monkeypatch.setenv("SIEMS_FILE", str(tmp_path / "none.json"))
    for n in ("ELASTIC_URL",):
        monkeypatch.delenv(n, raising=False)
    conn = QueueConn(["rm -rf", "siem:nope"])
    settings_tests.run_pending(conn)
    assert conn.done[1] == ("failed", "Unknown test.")
    assert conn.done[2][0] == "failed" and "not saved yet" in conn.done[2][1]


def test_compose_no_longer_hides_settings_behind_defaults():
    """A ${X:-default} in docker-compose.yml would always be 'set in .env' and lock the Settings page."""
    text = (ROOT / "docker-compose.yml").read_text()
    for f in A.FIELDS:
        assert f"{f.name}: ${{{f.name}:-}}" in text or f"{f.name}:" not in text, f.name
    assert "settings_keys:/app/keys" in text


def test_notifications_use_the_msp_brand(monkeypatch):
    import notifier
    monkeypatch.setenv("ARDEA_BRAND_NAME", "Acme SOC")
    p = notifier.build_payload({"alert_id": "a", "verdict": "True Positive", "severity": "High", "confidence": 90,
                                "rule_name": "R", "hostname": "h", "summary": "s"})
    licensing.set_tier("pro")
    assert notifier._subject(p).startswith("[Ardea]")
    licensing.set_tier("msp")
    assert notifier._subject(p).startswith("[Acme SOC]")
