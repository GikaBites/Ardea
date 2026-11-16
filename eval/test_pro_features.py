"""Pro / MSP features in the worker: integrations, per-SIEM routing, per-SIEM playbooks, report e-mails.
No model, database or network needed."""
import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest

import config
import elastic
import licensing
import notifier
import playbooks
import reports
import siems
from alert_context import build_context

FINAL = {"alert_id": "hq:a1", "verdict": "True Positive", "severity": "High", "confidence": 91,
         "rule_name": "Suspicious MS Office Child Process", "hostname": "ws-07", "siem": "hq",
         "summary": "Click <https://evil.example|here> & [see](https://evil.example) ```code```",
         "key_findings": [{"claim": "encoded PowerShell", "stance": "suspicious"}]}


class Capture:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        resp = type("R", (), {})()
        resp.status_code = self.status
        def raise_for_status():
            if self.status >= 400:
                import requests
                err = requests.HTTPError("boom " + url)
                err.response = resp
                raise err
        resp.raise_for_status = raise_for_status
        return resp


@pytest.fixture
def post(monkeypatch):
    cap = Capture()
    monkeypatch.setattr(notifier.requests, "post", cap)
    return cap


@pytest.fixture
def routed_siems(monkeypatch):
    configured = {s.id: s for s in siems.parse({"siems": [
        {"id": "hq", "name": "Head office", "url": "https://e1:9200", "worker_api_key": "k"},
        {"id": "acme", "name": "Acme Ltd", "url": "https://e2:9200", "worker_api_key": "k",
         "context": ["Acme backups run as svc.acmebackup"],
         "notify": {"smtp_to": ["soc@acme.example"], "slack_webhook_url": "https://hooks.slack.example/acme",
                    "webhook_url": "https://hooks.acme.example/in", "webhook_secret": "s3cret"},
         "report_to": ["boss@acme.example"]}]})}
    monkeypatch.setattr(elastic, "_SIEMS", configured)
    return configured


def payload(**over):
    return notifier.build_payload({**FINAL, **over})


# --------------------------------------------------------------------------- channels
def test_slack_escapes_untrusted_text(post, monkeypatch):
    monkeypatch.setattr(config, "ARDEA_PUBLIC_URL", "https://ardea.example")
    notifier.send_slack(payload(), {"slack_webhook_url": "https://hooks.slack.example/x"})
    url, kw = post.calls[0]
    text = kw["json"]["blocks"][1]["text"]["text"]
    assert "<https://evil" not in text and "&lt;https://evil.example|here&gt;" in text and "&amp;" in text
    assert text.startswith("```") and text.count("```") == 2           # alert text cannot close the fence
    assert kw["json"]["blocks"][2]["elements"][0]["url"].startswith("https://ardea.example")


def test_teams_breaks_markdown_links(post):
    notifier.send_teams(payload(), {"teams_webhook_url": "https://teams.example/hook"})
    card = post.calls[0][1]["json"]["attachments"][0]["content"]
    assert "](" not in json.dumps(card["body"])


def test_webhook_is_hmac_signed(post):
    notifier.send_webhook(payload(), {"webhook_url": "https://h.example/in", "webhook_secret": "s3cret"})
    _, kw = post.calls[0]
    expected = "sha256=" + hmac.new(b"s3cret", kw["data"], hashlib.sha256).hexdigest()
    assert kw["headers"]["X-Ardea-Signature"] == expected
    assert json.loads(kw["data"])["event"] == "ardea.verdict"


def test_jira_issue(post, monkeypatch):
    for k, v in {"JIRA_URL": "https://acme.atlassian.net/", "JIRA_USER": "bot@acme.example",
                 "JIRA_API_TOKEN": "tok", "JIRA_PROJECT": "SOC"}.items():
        monkeypatch.setenv(k, v)
    notifier.send_jira(payload())
    url, kw = post.calls[0]
    assert url == "https://acme.atlassian.net/rest/api/3/issue" and kw["auth"] == ("bot@acme.example", "tok")
    fields = kw["json"]["fields"]
    assert fields["project"] == {"key": "SOC"} and fields["labels"] == ["ardea", "true-positive"]
    assert fields["description"]["type"] == "doc"


def test_thehive_alert_and_duplicate_is_ok(monkeypatch):
    monkeypatch.setenv("THEHIVE_URL", "https://hive.example")
    monkeypatch.setenv("THEHIVE_API_KEY", "key")
    cap = Capture(status=409)                                 # already sent: not an error
    monkeypatch.setattr(notifier.requests, "post", cap)
    notifier.send_thehive(payload())
    alert = cap.calls[0][1]["json"]
    assert alert["sourceRef"] == "hq:a1" and alert["severity"] == 3
    assert alert["description"].count("```") == 2


def test_errors_never_leak_the_webhook_url(monkeypatch):
    monkeypatch.setattr(notifier.requests, "post", Capture(status=500))
    with pytest.raises(notifier.NotifyError) as err:
        notifier.send_slack(payload(), {"slack_webhook_url": "https://hooks.slack.example/T000/SECRET"})
    assert "SECRET" not in str(err.value) and "HTTP 500" in str(err.value)


# --------------------------------------------------------------------------- routing + gates
def test_channels_by_edition(monkeypatch, routed_siems):
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", ["smtp", "slack"])
    licensing.set_tier("community")
    assert notifier.build_notifications({**FINAL, "siem": "acme"}) == []
    licensing.set_tier("pro")
    assert [c for c, _ in notifier.build_notifications({**FINAL, "siem": "acme"})] == ["smtp", "slack"]
    licensing.set_tier("msp")
    assert [c for c, _ in notifier.build_notifications({**FINAL, "siem": "acme"})] == \
        ["smtp", "slack", "smtp@acme", "slack@acme", "webhook@acme"]
    assert [c for c, _ in notifier.build_notifications({**FINAL, "siem": "hq"})] == ["smtp", "slack"]


def test_routing_works_without_global_channels(monkeypatch, routed_siems):
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", [])
    licensing.set_tier("msp")
    assert [c for c, _ in notifier.build_notifications({**FINAL, "siem": "acme"})][0] == "smtp@acme"
    assert notifier.build_notifications({**FINAL, "siem": "acme", "verdict": "Benign Positive"}) == []


def test_resolve_looks_up_secrets_at_send_time(routed_siems):
    sender, target = notifier.resolve("webhook@acme")
    assert sender is notifier.send_webhook and target["webhook_secret"] == "s3cret"
    assert notifier.resolve("slack") == (notifier.send_slack, None)
    with pytest.raises(notifier.NotifyError):
        notifier.resolve("slack@gone")
    with pytest.raises(notifier.NotifyError):
        notifier.resolve("carrierpigeon")


def test_outbox_never_stores_destinations(routed_siems, monkeypatch):
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", [])
    licensing.set_tier("msp")
    stored = json.dumps(notifier.build_notifications({**FINAL, "siem": "acme"}))
    assert "hooks.acme.example" not in stored and "s3cret" not in stored and "soc@acme" not in stored


# --------------------------------------------------------------------------- per-SIEM playbooks
def _alert(rule_id, name, tactic):
    return {"_id": "a1", "_source": {
        "@timestamp": "2026-11-04T07:34:21.759Z", "kibana.alert.rule.rule_id": rule_id,
        "kibana.alert.rule.name": name, "host": {"name": "ws01"},
        "kibana.alert.rule.threat": [{"tactic": {"name": tactic}, "technique": []}]}}


def test_siem_context_and_playbooks_for_msp(tmp_path, monkeypatch, routed_siems):
    monkeypatch.setattr(playbooks, "SIEMS_DIR", tmp_path)
    playbooks._siem_cache.clear()
    (tmp_path / "acme.playbooks.yaml").write_text(
        "context: ['Acme scanner is 10.9.0.5']\n"
        "by_rule_id:\n  r-1:\n    guidance: ACME GUIDANCE\n"
        "by_tactic:\n  Credential Access:\n    never_auto_close: false\n    guidance: acme says fine\n")
    ctx = build_context(_alert("r-1", "x", "Execution"))
    ctx["siem"] = "acme"
    licensing.set_tier("pro")
    pb = playbooks.resolve(ctx)
    assert "ACME" not in pb["guidance"] and not any("Acme" in c for c in pb["context"])
    licensing.set_tier("msp")
    pb = playbooks.resolve(ctx)
    assert pb["guidance"].startswith("ACME GUIDANCE") and pb["source"] == "siem playbooks"
    assert "Acme backups run as svc.acmebackup" in pb["context"] and "Acme scanner is 10.9.0.5" in pb["context"]
    # a SIEM file cannot relax a never_auto_close tactic from playbooks.yaml
    ctx2 = build_context(_alert("r-2", "y", "Credential Access"))
    ctx2["siem"] = "acme"
    assert playbooks.resolve(ctx2)["never_auto_close"] is True


def test_broken_siem_playbooks_never_stop_triage(tmp_path, monkeypatch, routed_siems):
    monkeypatch.setattr(playbooks, "SIEMS_DIR", tmp_path)
    playbooks._siem_cache.clear()
    (tmp_path / "acme.playbooks.yaml").write_text("by_rule_id:\n  r-1:\n    enrichment: [{tool: rm_rf}]\n")
    licensing.set_tier("msp")
    ctx = build_context(_alert("r-1", "x", "Execution"))
    ctx["siem"] = "acme"
    assert playbooks.resolve(ctx)["source"] == "playbooks.yaml"


def test_siems_json_validation():
    with pytest.raises(siems.SiemConfigError):
        siems.parse({"siems": [{"id": "a", "url": "https://e:9200", "report_to": ["not-an-email"]}]})
    with pytest.raises(siems.SiemConfigError):
        siems.parse({"siems": [{"id": "a", "url": "https://e:9200", "notify": {"slack_webhook_url": "ftp://x"}}]})


# --------------------------------------------------------------------------- report e-mails
def test_due_periods():
    now = datetime(2026, 11, 4, 9, 0, tzinfo=timezone.utc)          # a Wednesday
    w = reports.due_period("weekly", now)
    assert w["key"] == "weekly:2026-W44" and w["start"] == datetime(2026, 10, 26, tzinfo=timezone.utc)
    m = reports.due_period("monthly", now)
    assert m["key"] == "monthly:2026-10" and m["label"] == "October 2026"
    assert reports.due_period("off", now) is None


def test_render_respects_minimal_detail(monkeypatch):
    s = {"alerts": 10, "raw": 14, "tp": 1, "review": 2, "closed": 7, "closed_raw": 11,
         "rules": [{"rule_name": "Whoami", "raw": 6}],
         "true_positives": [{"rule_name": "Office child", "host_name": "ws-07", "severity": "High",
                             "created_at": datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)}]}
    period = reports.due_period("monthly", datetime(2026, 11, 1, tzinfo=timezone.utc))
    subject, body = reports.render(s, period, "Acme SOC", "Acme Ltd", 10)
    assert subject.startswith("[Acme SOC] Report October 2026 · Acme Ltd: 14 alerts, 70% closed")
    assert "ws-07" in body and "about 1.8 h" in body
    monkeypatch.setattr(config, "NOTIFY_DETAIL", "minimal")
    assert "ws-07" not in reports.render(s, period, "Ardea", None, 10)[1]


class FakeConn:
    def __init__(self):
        self.runs = set()

    def execute(self, sql, params=None):
        rows = []
        if sql.startswith("INSERT INTO report_runs"):
            key = params[0]
            rows = [] if key in self.runs else [{"run_key": key}]
            self.runs.add(key)
        elif sql.startswith("DELETE FROM report_runs"):
            self.runs.discard(params[0])
        elif "count(*) AS alerts" in sql:
            rows = [{"alerts": 3, "raw": 3, "tp": 0, "review": 1, "closed": 2, "closed_raw": 2}]
        return type("R", (), {"fetchone": lambda _s: rows[0] if rows else None, "fetchall": lambda _s: []})()


def test_reports_sent_once_per_period_and_per_customer(monkeypatch, routed_siems):
    monkeypatch.setenv("ARDEA_REPORTS", "monthly")
    monkeypatch.setenv("ARDEA_REPORT_TO", "manager@hq.example")
    conn, outbox = FakeConn(), []
    now = datetime(2026, 11, 1, 6, 0, tzinfo=timezone.utc)
    licensing.set_tier("community")
    assert reports.run_due(conn, now, send=lambda *a: outbox.append(a)) == []
    licensing.set_tier("pro")
    assert reports.run_due(conn, now, send=lambda *a: outbox.append(a)) == ["monthly:2026-10:all"]
    assert reports.run_due(conn, now, send=lambda *a: outbox.append(a)) == []          # never twice
    licensing.set_tier("msp")
    assert reports.run_due(conn, now, send=lambda *a: outbox.append(a)) == ["monthly:2026-10:acme"]
    assert outbox[-1][2] == ["boss@acme.example"] and "Acme Ltd" in outbox[-1][0]


def test_failed_report_is_retried(monkeypatch, routed_siems):
    monkeypatch.setenv("ARDEA_REPORTS", "weekly")
    monkeypatch.setenv("ARDEA_REPORT_TO", "manager@hq.example")
    licensing.set_tier("pro")
    conn = FakeConn()

    def fail(*a):
        raise notifier.NotifyError("smtp down")
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    assert reports.run_due(conn, now, send=fail) == []
    assert reports.run_due(conn, now, send=lambda *a: None) == ["weekly:2026-W44:all"]
