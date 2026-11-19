"""Health page snapshot and the once-a-day warnings (disk, backup, queue). Real Postgres (EMPTY *_test database)."""
import os
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

import appsettings  # noqa: E402
import db  # noqa: E402
import sysinfo  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def conn(monkeypatch):
    c = db.get_connection()
    if not c.execute("SELECT to_regclass('public.alerts') AS t").fetchone()["t"]:
        c.execute((ROOT / "db" / "init.sql").read_text())
    with c.transaction():
        appsettings.ensure_schema(c.execute)
    for t in ("system_health", "backup_runs", "triage_results", "alerts"):
        c.execute(f"DELETE FROM {t}")
    monkeypatch.setattr(sysinfo, "ollama", lambda: {"reachable": False, "error": "ConnectError"})
    yield c
    c.close()


def test_warnings_once_a_day_and_again_after_fixed(conn, monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(sysinfo, "disk", lambda: {"total": 100 * 2 ** 30, "free": 3 * 2 ** 30, "free_percent": 3.0})
    conn.execute("INSERT INTO backup_runs (kind, status, finished_at, detail) VALUES ('scheduled', 'failed', NOW(), 'disk full')")
    sent = []
    assert sorted(sysinfo.run_due(conn, now, send=lambda *a: sent.append(a))) == ["backup", "disk"]
    assert "disk full" in [s for s in sent if s[0] == "Backup problem"][0][1]
    assert sysinfo.run_due(conn, now + timedelta(hours=1), send=lambda *a: sent.append(a)) == []   # not twice a day
    assert sysinfo.run_due(conn, now + timedelta(hours=25), send=lambda *a: sent.append(a)) != []
    monkeypatch.setattr(sysinfo, "disk", lambda: {"total": 100 * 2 ** 30, "free": 60 * 2 ** 30, "free_percent": 60.0})
    conn.execute("INSERT INTO backup_runs (kind, status, finished_at) VALUES ('manual', 'ok', NOW())")
    assert sysinfo.run_due(conn, now + timedelta(hours=26), send=lambda *a: None) == []
    row = conn.execute("SELECT value FROM system_health WHERE name = 'problems'").fetchone()
    assert row["value"] == []
    assert conn.execute("SELECT value FROM system_health WHERE name = 'ollama'").fetchone()["value"]["reachable"] is False


def test_queue_warning(conn, monkeypatch):
    monkeypatch.setattr(sysinfo, "disk", lambda: {"total": 100, "free": 90 * 2 ** 30, "free_percent": 90.0})
    for n in range(30):
        conn.execute("INSERT INTO alerts (alert_id, timestamp, status) VALUES (%s, NOW(), 'new')", (f"q{n}",))
    conn.execute("INSERT INTO alerts (alert_id, timestamp, status) VALUES ('d1', NOW(), 'done')")
    conn.execute("INSERT INTO triage_results (alert_id, response, result, duration_ms, model) "
                 "VALUES ('d1', '{}', '{}', 1200000, 'm')")                       # 20 minutes per alert
    assert sysinfo.run_due(conn, send=lambda *a: None) == ["queue"]                  # 30 x 20 min = 10 h
