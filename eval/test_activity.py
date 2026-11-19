"""Status bar heartbeat (appsettings.activity): written on change, throttled otherwise, never raises."""
import os
import pathlib

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

import appsettings  # noqa: E402
import db  # noqa: E402

INIT_SQL = pathlib.Path(__file__).resolve().parents[1] / "db" / "init.sql"


def test_activity_written_on_change_and_throttled():
    c = db.get_connection()
    if not c.execute("SELECT to_regclass('public.alerts') AS t").fetchone()["t"]:
        c.execute(INIT_SQL.read_text())
    with c.transaction():
        appsettings.ensure_schema(c.execute)
    c.execute("DELETE FROM service_activity")
    appsettings._activity.clear()
    appsettings.activity(c, "worker", "idle", "Waiting for new alerts")
    first = c.execute("SELECT * FROM service_activity WHERE service = 'worker'").fetchone()
    appsettings.activity(c, "worker", "idle", "Waiting for new alerts")          # throttled: no write
    assert c.execute("SELECT updated_at FROM service_activity").fetchone()["updated_at"] == first["updated_at"]
    appsettings.activity(c, "worker", "investigating", "Rule on host", alert_id="a1", max_steps=8)
    row = c.execute("SELECT * FROM service_activity WHERE service = 'worker'").fetchone()
    assert row["state"] == "investigating" and row["alert_id"] == "a1" and row["started_at"] >= first["started_at"]
    c.close()
    appsettings.activity(c, "worker", "idle", "closed connection")             # never raises
