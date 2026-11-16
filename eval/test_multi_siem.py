"""Multi-SIEM: config parsing, per-SIEM routing of every Elastic call, Kibana link allowlist per SIEM."""
import json

import pytest

import elastic
import notifier
import siem_tools
import siems
import config


# --------------------------------------------------------------------------- siems.json parsing
def _cfg(*items):
    return {"siems": list(items)}


GOOD = {"id": "hq", "url": "https://es:9200/"}


def test_parse_defaults():
    [s] = siems.parse(_cfg(GOOD))
    assert s.url == "https://es:9200" and s.name == "hq"
    assert s.alerts_index == siems.DEFAULT_ALERTS_INDEX and s.events_indices == ("logs-*",)
    assert s.verify is True                                   # never verify=False
    assert "secret" not in repr(siems.parse(_cfg({**GOOD, "worker_api_key": "secret"}))[0])   # keys never logged


def test_parse_events_list_and_disabled():
    out = siems.parse(_cfg({**GOOD, "events_indices": ["logs-a*", " logs-b* "]},
                           {"id": "old", "url": "https://x", "enabled": False}))
    assert [s.id for s in out] == ["hq"] and out[0].events_indices == ("logs-a*", "logs-b*")


@pytest.mark.parametrize("bad, msg", [
    ({"siems": {}}, "must look like"),
    (_cfg({"id": "HQ", "url": "https://x"}), "id must be"),
    (_cfg({"id": "a b", "url": "https://x"}), "id must be"),
    (_cfg({"id": "hq", "url": "es:9200"}), "url must start"),
    (_cfg(GOOD, GOOD), "used twice"),
    (_cfg({**GOOD, "events_indices": ""}), "events_indices"),
])
def test_parse_rejects(bad, msg):
    with pytest.raises(siems.SiemConfigError, match=msg):
        siems.parse(bad)


def test_load_file_and_env_fallback(tmp_path, monkeypatch):
    f = tmp_path / "siems.json"
    f.write_text(json.dumps(_cfg(GOOD)))
    assert [s.id for s in siems.load(str(f))] == ["hq"]
    f.write_text("{not json")
    with pytest.raises(siems.SiemConfigError, match="not valid JSON"):
        siems.load(str(f))
    # no file: the old single-Elastic settings still work
    monkeypatch.setenv("ELASTIC_URL", "https://old-es:9200")
    monkeypatch.setenv("ELASTIC_WORKER_API_KEY", "wk")
    monkeypatch.setenv("KIBANA_BASE_URL", "# not set")
    [s] = siems.load(str(tmp_path / "missing.json"))
    assert (s.id, s.url, s.worker_api_key, s.kibana_url) == ("default", "https://old-es:9200", "wk", "")
    monkeypatch.delenv("ELASTIC_URL")
    assert siems.load(str(tmp_path / "missing.json")) == []


# --------------------------------------------------------------------------- routing
class _Resp:
    status_code = 200

    def __init__(self, data=None):
        self._data = data or {"hits": {"hits": [], "total": {"value": 0}}}

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


@pytest.fixture
def sent(monkeypatch):
    calls = []

    class FakeSession:
        def __init__(self):
            self.headers = {}

        def post(self, url, json=None, timeout=None, verify=None):
            calls.append({"url": url, "auth": self.headers.get("Authorization"), "body": json})
            return _Resp()

    monkeypatch.setattr(elastic.requests, "Session", FakeSession)
    monkeypatch.setattr(elastic, "_sessions", {})
    return calls


def test_default_siem_outside_investigation(sent):
    assert elastic.current_id() == "hq"
    elastic.search("logs-*", {"size": 0})
    assert sent[0]["url"].startswith("https://elastic-hq.example:9200/logs-*/_search")
    assert sent[0]["auth"] == "ApiKey k1"


def test_use_routes_every_call_to_that_siem(sent):
    scope = siem_tools.InvestigationScope({"hosts": ["ws01"]}, "2026-11-04T07:34:21Z")
    with elastic.use("branch"):
        elastic.fetch_alert("abc")
        siem_tools.search_host_events(scope, "ws01", "process")
        siem_tools.get_related_alerts(scope, "host", "ws01")
    assert all(c["url"].startswith("https://elastic-br.example:9200/") for c in sent)
    assert all(c["auth"] == "ApiKey k2" for c in sent)
    assert "/logs-endpoint*/_search" in sent[1]["url"]                   # branch's first events index
    assert f"/{siems.DEFAULT_ALERTS_INDEX}/_search" in sent[2]["url"]
    assert elastic.current_id() == "hq"                                   # restored after the block


def test_index_allowlist_is_per_siem(sent):
    with elastic.use("branch"):
        with pytest.raises(elastic.SiemError, match="not allowed"):
            elastic.search("logs-*", {})                                  # hq's index, not branch's
        elastic.search("logs-windows*", {})
    assert len(sent) == 1


def test_unknown_siem_is_refused(sent):
    with pytest.raises(elastic.SiemError, match="not configured"):
        with elastic.use("gone"):
            pass
    assert not sent


# --------------------------------------------------------------------------- notifications
@pytest.fixture
def notify(monkeypatch):
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", ["smtp"])
    monkeypatch.setattr(config, "NOTIFY_VERDICTS", ["True Positive"])
    monkeypatch.setattr(config, "NOTIFY_MIN_SEVERITY", "Low")
    monkeypatch.setattr(config, "NOTIFY_DETAIL", "full")


FINAL = {"alert_id": "branch:abc", "verdict": "True Positive", "severity": "High", "confidence": 90,
         "rule_name": "Rule", "hostname": "ws01", "siem": "branch", "siem_name": "Branch"}


def test_kibana_link_only_for_the_alerts_own_siem(notify):
    ok = dict(FINAL, alert_url="https://kibana-br.example/app/security/alerts/abc")
    [(_, p)] = notifier.build_notifications(ok)
    assert p["kibana_url"] == ok["alert_url"] and p["siem"] == "Branch"
    other = dict(FINAL, alert_url="https://kibana-hq.example:5601/app/security/alerts/abc")
    [(_, p)] = notifier.build_notifications(other)
    assert p["kibana_url"] is None                                        # another SIEM's Kibana


def test_siem_shown_in_message(notify):
    [(_, p)] = notifier.build_notifications(FINAL)
    assert notifier._subject(p).startswith("[Ardea] [Branch] True Positive")
    assert "SIEM:       Branch" in notifier._body(p)


# --------------------------------------------------------------------------- worker
def test_alert_of_removed_siem_gets_a_visible_verdict(monkeypatch):
    import worker
    stored = []
    monkeypatch.setattr(worker.db, "store_result", lambda conn, aid, final, meta, *a: stored.append((aid, final)))
    row = {"alert_id": "gone:abc", "siem": "gone", "elastic_id": "abc", "rule_name": "R", "host_name": "h",
           "count": 1}
    worker.process(None, None, row)
    [(aid, final)] = stored
    assert aid == "gone:abc" and final["verdict"] == "Needs Human Review"
    assert "no longer configured" in final["summary"] and final["siem"] == "gone"


def test_old_alert_without_siem_uses_first_siem(monkeypatch, sent):
    import worker
    stored = []
    monkeypatch.setattr(worker.db, "store_result", lambda conn, aid, final, meta, *a: stored.append(final))
    worker.process(None, None, {"alert_id": "plainid", "siem": None, "elastic_id": None, "rule_name": "R",
                                "host_name": "h", "count": 1})
    assert sent[0]["url"].startswith("https://elastic-hq.example:9200/")   # fetched by its bare _id from hq
    assert sent[0]["body"]["query"] == {"ids": {"values": ["plainid"]}}
    assert stored[0]["siem"] == "hq" and "no longer found" in stored[0]["summary"]
