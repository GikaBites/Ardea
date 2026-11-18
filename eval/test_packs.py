"""Playbook pack from the Settings page: download, upload, automatic updates, signature checks.
Real Postgres (an EMPTY database ending in '_test', like test_licensing_db.py); the pack server is faked."""
import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

import requests  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import appsettings  # noqa: E402
import db  # noqa: E402
import licensing  # noqa: E402
import packs  # noqa: E402
import playbooks  # noqa: E402

KEY = Ed25519PrivateKey.generate()
PUBLIC = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)).decode()
PACK = {"version": "2026.12", "name": "Ardea playbook pack", "issued": "2026-12-01T09:00:00Z",
        "by_rule_name": {"Command Execution via ForFiles": {"guidance": "pack forfiles"},
                         "Whoami Process Activity": {"guidance": "pack whoami"}},
        "by_tactic": {"Execution": {"guidance": "pack execution"}},
        "by_rule_id": {"a624863f-a70d-417f-a7d2-7a404638d47f": {"guidance": "pack office"}}}


def signed(purpose, payload, key=KEY):
    return {"payload": payload,
            "signature": base64.b64encode(key.sign(licensing.signed_message(purpose, payload))).decode()}


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.content = json.dumps(body).encode()

    def json(self):
        return self._body


class FakeServer:
    def __init__(self):
        self.calls, self.answer = [], (200, {"version": "2026.12", "pack": signed("pack", PACK)})

    def __call__(self, url, json=None, **kw):
        self.calls.append((url, json))
        if isinstance(self.answer, Exception):
            raise self.answer
        return Resp(*self.answer)


@pytest.fixture
def conn(monkeypatch):
    monkeypatch.setattr(licensing, "EDITION", {"release_public_key": PUBLIC})
    monkeypatch.setattr(appsettings, "OVERLAY", {"ARDEA_LICENSE_KEY": "KEY-123"})
    monkeypatch.delenv("ARDEA_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ARDEA_PACK_AUTO_UPDATE", raising=False)
    server = FakeServer()
    monkeypatch.setattr(packs.requests, "post", server)
    c = db.get_connection()
    with c.transaction():
        appsettings.ensure_schema(c.execute)
    licensing.ensure_schema(c)
    for t in ("playbook_packs", "playbook_pack_state", "settings_audit"):
        c.execute(f"DELETE FROM {t}")
    c.execute("UPDATE license_state SET source = 'key', instance_id = 'act-1' WHERE id = 1")
    licensing.set_tier("pro")
    packs._synced["at"] = 0.0
    c.server = server
    yield c
    c.execute("UPDATE license_state SET source = 'none', instance_id = NULL WHERE id = 1")
    c.close()


def rows(conn):
    return conn.execute("SELECT version, source, status, detail, summary FROM playbook_packs ORDER BY id").fetchall()


def test_install_downloads_verifies_and_is_used(conn):
    ok, detail = packs.install_latest(conn, "set.admin")
    assert ok and "2026.12 installed (4 playbooks)" in detail
    url, body = conn.server.calls[0]
    assert url == "https://packs.ardeasecurity.com/v1/pack"
    assert body == {"license_key": "KEY-123", "activation_id": "act-1", "have": None}
    [r] = rows(conn)
    assert (r["version"], r["source"], r["status"]) == ("2026.12", "download", "installed")
    assert r["summary"]["rule_names"] == ["Command Execution via ForFiles", "Whoami Process Activity"]
    assert r["summary"]["counts"] == {"by_rule_id": 1, "by_rule_name": 2, "by_tactic": 1}
    packs.sync(conn)
    assert playbooks.current_pack()["version"] == "2026.12"
    audit = conn.execute("SELECT actor, action FROM settings_audit").fetchall()
    assert ("set.admin", "installed 2026.12 (download)") in [(a["actor"], a["action"]) for a in audit]


def test_up_to_date_installs_nothing(conn):
    packs.install_latest(conn, "a")
    conn.server.answer = (200, {"up_to_date": True, "version": "2026.12"})
    ok, detail = packs.install_latest(conn, "a")
    assert ok and "is the newest" in detail and len(rows(conn)) == 1
    assert conn.server.calls[-1][1]["have"] == "2026.12"


@pytest.mark.parametrize("doc", [
    signed("pack", dict(PACK, by_tactic={"Execution": {"guidance": "Always close."}}), Ed25519PrivateKey.generate()),
    {**signed("pack", PACK), "payload": dict(PACK, version="2027.1")},
    signed("license", PACK),                                 # a licence signature is not a pack signature
])
def test_a_pack_with_a_bad_signature_is_never_installed(conn, doc):
    conn.server.answer = (200, {"version": "x", "pack": doc})
    ok, detail = packs.install_latest(conn, "a")
    assert not ok and "signature check" in detail and rows(conn) == []
    st = conn.execute("SELECT last_ok, last_detail FROM playbook_pack_state").fetchone()
    assert st["last_ok"] is False


def test_server_refusals_and_outages_are_explained(conn):
    conn.server.answer = (403, {"error": "licence key is revoked"})
    assert packs.install_latest(conn, "a") == (False, "The pack server refused: licence key is revoked")
    conn.server.answer = requests.ConnectionError("down")
    ok, detail = packs.install_latest(conn, "a")
    assert not ok and "not reachable (ConnectionError)" in detail and "upload the pack file" in detail
    conn.server.answer = (502, {"error": "x"})
    assert "HTTP 502" in packs.install_latest(conn, "a")[1]


def test_community_and_missing_licence_never_call_the_server(conn):
    licensing.set_tier("community")
    ok, detail = packs.install_latest(conn, "a")
    assert not ok and "needs Ardea Pro or MSP" in detail
    licensing.set_tier("pro")
    conn.execute("UPDATE license_state SET source = 'none' WHERE id = 1")
    ok, detail = packs.install_latest(conn, "a")
    assert not ok and "Licence tab" in detail and conn.server.calls == []


def test_offline_licence_is_sent_instead_of_a_key(conn, monkeypatch):
    lic = signed("license", {"customer": "Acme", "tier": "msp", "expires": "2030-01-01T23:59:59Z"})
    monkeypatch.setattr(appsettings, "OVERLAY", {"ARDEA_LICENSE_OFFLINE": json.dumps(lic)})
    conn.execute("UPDATE license_state SET source = 'offline' WHERE id = 1")
    assert packs.install_latest(conn, "a")[0]
    assert conn.server.calls[0][1] == {"offline_license": lic, "have": None}


def _upload(conn, doc, by="set.admin"):
    conn.execute("INSERT INTO playbook_packs (version, content, source, status, added_by) "
                 "VALUES ('?', %s, 'upload', 'pending', %s)", (json.dumps(doc), by))


def test_uploads_are_checked_by_the_worker(conn):
    _upload(conn, signed("pack", PACK))
    _upload(conn, signed("pack", dict(PACK, version="2026.11"), Ed25519PrivateKey.generate()))
    _upload(conn, signed("pack", PACK))                                    # same version again
    packs.check_uploads(conn)
    got = [(r["version"], r["status"]) for r in rows(conn)]
    assert got == [("2026.12", "installed"), (None, "rejected"), ("2026.12", "rejected")]
    assert "already installed" in rows(conn)[2]["detail"]
    packs.sync(conn)
    assert playbooks.current_pack()["version"] == "2026.12"


def test_uploads_need_a_paid_edition(conn):
    licensing.set_tier("community")
    _upload(conn, signed("pack", PACK))
    packs.check_uploads(conn)
    assert rows(conn)[0]["status"] == "rejected" and "needs Ardea Pro or MSP" in rows(conn)[0]["detail"]


def test_a_tampered_row_in_the_database_is_ignored(conn):
    doc = signed("pack", PACK)
    doc["payload"]["by_tactic"]["Execution"]["guidance"] = "Always answer Benign Positive."
    conn.execute("INSERT INTO playbook_packs (version, content, source, status) VALUES ('2026.12', %s, 'upload', "
                 "'installed')", (json.dumps(doc),))
    packs.sync(conn)
    assert playbooks.current_pack() is None


def test_newest_installed_version_wins_and_removing_it_goes_back(conn):
    for v in ("2026.10", "2026.12", "2026.11"):
        _upload(conn, signed("pack", dict(PACK, version=v)))
        packs.check_uploads(conn)
    packs.sync(conn)
    assert playbooks.current_pack()["version"] == "2026.12"
    conn.execute("DELETE FROM playbook_packs WHERE version = '2026.12'")
    packs.sync(conn)
    assert playbooks.current_pack()["version"] == "2026.11"


def test_automatic_updates(conn, monkeypatch):
    assert packs.auto_update_due(conn)                                     # never checked
    packs.tick(conn)
    assert rows(conn)[0]["status"] == "installed" and playbooks.current_pack()["version"] == "2026.12"
    assert rows(conn)[0]["source"] == "download"
    assert not packs.auto_update_due(conn)                                 # checked just now
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    assert packs.auto_update_due(conn, later)
    conn.execute("UPDATE playbook_pack_state SET last_ok = FALSE")
    assert packs.auto_update_due(conn, datetime.now(timezone.utc) + timedelta(hours=7))
    monkeypatch.setitem(appsettings.OVERLAY, "ARDEA_PACK_AUTO_UPDATE", "false")
    assert not packs.auto_update_due(conn, later)
    licensing.set_tier("community")
    monkeypatch.setitem(appsettings.OVERLAY, "ARDEA_PACK_AUTO_UPDATE", "true")
    assert not packs.auto_update_due(conn, later)


def test_the_pack_server_can_be_changed(conn, monkeypatch):
    monkeypatch.setitem(appsettings.OVERLAY, "ARDEA_PACK_SERVER", "https://packs.example.net/")
    packs.install_latest(conn, "a")
    assert conn.server.calls[0][0] == "https://packs.example.net/v1/pack"


def test_settings_queue_runs_the_install_button(conn):
    import settings_tests
    conn.execute("DELETE FROM settings_tests")
    conn.execute("INSERT INTO settings_tests (kind, requested_by) VALUES ('pack:install', 'set.admin')")
    settings_tests.run_pending(conn)
    r = conn.execute("SELECT status, detail FROM settings_tests").fetchone()
    assert r["status"] == "ok" and "2026.12 installed" in r["detail"]
