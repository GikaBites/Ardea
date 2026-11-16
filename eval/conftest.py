"""Pin config for the model-free tests so they don't depend on the developer's environment."""
import pathlib

import pytest

import harness  # noqa: F401  (puts worker/ on sys.path)
import config
import elastic
import licensing
import playbooks
import siems

TEST_SIEMS = {s.id: s for s in siems.parse({"siems": [
    {"id": "hq", "name": "Head office", "url": "https://elastic-hq.example:9200", "worker_api_key": "k1",
     "kibana_url": "https://kibana-hq.example:5601"},
    {"id": "branch", "name": "Branch", "url": "https://elastic-br.example:9200", "worker_api_key": "k2",
     "kibana_url": "https://kibana-br.example", "events_indices": "logs-endpoint*,logs-windows*"},
]})}


@pytest.fixture(autouse=True)
def _test_config(monkeypatch):
    monkeypatch.setattr(config, "WEB_SEARCH_PROVIDER", "brave")
    monkeypatch.setattr(config, "WEB_SEARCH_DRY_RUN", False)
    monkeypatch.setattr(config, "WEB_SEARCH_KINDS",
                        ["ip", "domain", "hash", "cve", "mitre", "filename", "command_pattern", "error_text"])
    monkeypatch.setattr(config, "VERIFY_CLOSURES", False)
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", [])
    monkeypatch.setattr(elastic, "_SIEMS", TEST_SIEMS)
    monkeypatch.setattr(elastic, "_DEFAULT", "hq")
    # Existing tests exercise every feature; the edition tests (test_editions.py) switch tiers themselves.
    licensing.set_tier("msp")
    monkeypatch.setattr(playbooks, "PACKS_DIR", pathlib.Path("/nonexistent-ardea-packs"))
    playbooks._pack_cache.update(key=None, pack=None)
