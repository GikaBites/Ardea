"""The licence check state machine against a real Postgres (the licence server is faked).

Needs an EMPTY throwaway database whose name ends in '_test' (POSTGRES_* like publisher/tests).
"""
import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import db  # noqa: E402
import licensing  # noqa: E402

KEY = Ed25519PrivateKey.generate()
PUBLIC = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)).decode()


def polar_key(status="granted", benefit="ben-pro"):
    return {"organization_id": "org-ardea", "status": status, "benefit_id": benefit, "expires_at": None,
            "customer": {"name": "Acme", "email": "it@acme.example"}}


class FakeServer:
    def __init__(self):
        self.calls, self.mode = [], "ok"

    def __call__(self, path, data):
        self.calls.append((path.rsplit("/", 1)[-1], dict(data)))
        if self.mode == "down":
            raise licensing.LicenseUnreachable("licence server not reachable (ConnectTimeout)")
        if self.mode == "expired":
            return 200, polar_key(status="revoked")
        if path.endswith("/activate"):
            return 200, {"id": "act-1", "license_key": polar_key()}
        return 200, polar_key()


@pytest.fixture
def conn(monkeypatch, tmp_path):
    monkeypatch.setattr(licensing, "EDITION", {"release_public_key": PUBLIC,
                                               "polar": {"organization_id": "org-ardea", "benefits": {"ben-pro": "pro"}}})
    monkeypatch.setattr(licensing, "OFFLINE_FILE", tmp_path / "ardea.license")
    server = FakeServer()
    monkeypatch.setattr(licensing, "_call", server)
    c = db.get_connection()
    c.execute("DROP TABLE IF EXISTS license_state")
    licensing.ensure_schema(c)
    c.server = server
    yield c
    c.execute("DROP TABLE IF EXISTS license_state")
    licensing.ensure_schema(c)
    c.close()


def row(c):
    return c.execute("SELECT * FROM license_state").fetchone()


def test_no_key_is_community(conn, monkeypatch):
    monkeypatch.delenv("ARDEA_LICENSE_KEY", raising=False)
    r = licensing.refresh(conn)
    assert licensing.effective_tier(r) == "community" and licensing.tier() == "community"
    assert conn.server.calls == []


def test_activate_then_daily_validate(conn, monkeypatch):
    monkeypatch.setenv("ARDEA_LICENSE_KEY", "KEY-1")
    r = licensing.refresh(conn)
    assert licensing.effective_tier(r) == "pro" and licensing.tier() == "pro"
    assert conn.server.calls[0][0] == "activate" and conn.server.calls[0][1]["label"].startswith("Ardea ")
    assert r["instance_id"] == "act-1" and r["customer"] == "Acme" and r["last_error"] is None
    assert timedelta(days=29) < r["valid_until"] - datetime.now(timezone.utc) <= timedelta(days=30)
    licensing.refresh(conn)                                     # not due yet: no call
    assert len(conn.server.calls) == 1
    licensing.refresh(conn, force=True)
    assert conn.server.calls[-1] == ("validate", {"key": "KEY-1", "organization_id": "org-ardea",
                                                  "activation_id": "act-1"})


def test_server_down_keeps_the_last_good_result(conn, monkeypatch):
    monkeypatch.setenv("ARDEA_LICENSE_KEY", "KEY-1")
    good = licensing.refresh(conn)
    conn.server.mode = "down"
    r = licensing.refresh(conn, force=True)
    assert licensing.effective_tier(r) == "pro" and r["valid_until"] == good["valid_until"]
    assert "not reachable" in r["last_error"]
    # ... until the 30-day grace runs out
    conn.execute("UPDATE license_state SET valid_until = NOW() - interval '1 second'")
    licensing.refresh(conn, force=True)
    assert licensing.tier() == "community"


def test_ended_licence_keeps_features_72_hours_then_stops(conn, monkeypatch):
    monkeypatch.setenv("ARDEA_LICENSE_KEY", "KEY-1")
    licensing.refresh(conn)
    conn.server.mode = "expired"
    r = licensing.refresh(conn, force=True)
    left = r["valid_until"] - datetime.now(timezone.utc)
    assert licensing.effective_tier(r) == "pro" and timedelta(hours=71) < left <= timedelta(hours=72)
    assert r["status"] == "invalid" and "revoked" in r["last_error"]
    r2 = licensing.refresh(conn, force=True)                    # a second "no" never extends the grace
    assert r2["valid_until"] <= r["valid_until"]


def test_new_key_grants_nothing_until_confirmed(conn, monkeypatch):
    monkeypatch.setenv("ARDEA_LICENSE_KEY", "KEY-1")
    licensing.refresh(conn)
    monkeypatch.setenv("ARDEA_LICENSE_KEY", "KEY-2")
    conn.server.mode = "down"
    r = licensing.refresh(conn)
    assert licensing.effective_tier(r) == "community" and r["status"] == "unverified"
    conn.server.mode = "ok"
    r = licensing.refresh(conn)                                 # failed checks are retried within the hour
    conn.execute("UPDATE license_state SET last_checked_at = NOW() - interval '2 hours'")
    r = licensing.refresh(conn)
    assert licensing.effective_tier(r) == "pro" and conn.server.calls[-1][0] == "activate"


def test_offline_licence_wins(conn, monkeypatch):
    monkeypatch.setenv("ARDEA_LICENSE_KEY", "")
    payload = {"customer": "Air-gapped Ltd", "tier": "msp", "expires": "2030-01-01T00:00:00Z"}
    sig = base64.b64encode(KEY.sign(licensing.signed_message("license", payload))).decode()
    licensing.OFFLINE_FILE.write_text(json.dumps({"payload": payload, "signature": sig}))
    r = licensing.refresh(conn)
    assert licensing.effective_tier(r) == "msp" and r["source"] == "offline" and conn.server.calls == []
