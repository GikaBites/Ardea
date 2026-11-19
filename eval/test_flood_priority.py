"""Flood guard (reuse a burst's verdict), the urgency order of the queue, and the worker-tasks hand-off.
Real Postgres (EMPTY database ending in '_test')."""
import importlib.util
import json
import os
import pathlib

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

import appsettings  # noqa: E402
import db  # noqa: E402
import flood  # noqa: E402
import worker  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXE, PARENT = r"C:\Program Files\RMM\agent.exe", r"C:\Windows\System32\services.exe"
RULE = "Multiple Remote Management Tool Vendors on Same Host"


@pytest.fixture
def conn():
    c = db.get_connection()
    if not c.execute("SELECT to_regclass('public.alerts') AS t").fetchone()["t"]:
        c.execute((ROOT / "db" / "init.sql").read_text())
    db.ensure_schema(c)
    with c.transaction():
        appsettings.ensure_schema(c.execute)
    for t in ("feedback", "investigation_steps", "triage_results", "notifications", "alert_occurrences",
              "service_activity", "alerts"):
        c.execute(f"DELETE FROM {t}")
    yield c
    c.close()


def add(c, n, verdict=None, conf=85, model="m", reused=False, exe=EXE, rule=RULE, priority=50, waited_min=0):
    aid = f"hq:f{n}"
    c.execute("""INSERT INTO alerts (alert_id, timestamp, status, siem, rule_name, host_name, process_executable,
                                     parent_executable, priority, inserted_at)
                 VALUES (%s, NOW(), %s, 'hq', %s, %s, %s, %s, %s, NOW() - make_interval(mins => %s))""",
              (aid, "done" if verdict else "new", rule, f"host-{n}", exe, PARENT, priority, waited_min))
    if verdict:
        res = {"verdict": verdict, "severity": "Low", "confidence": conf, "summary": f"RMM agent {n}",
               "investigation": {"stop_reason": "flood_reused" if reused else "final"}}
        c.execute("""INSERT INTO triage_results (alert_id, response, result, verdict, confidence, model)
                     VALUES (%s, '{}', %s, %s, %s, %s)""", (aid, json.dumps(res), verdict, conf, None if reused else model))
    return {"alert_id": aid, "siem": "hq", "rule_name": rule, "process_executable": exe, "parent_executable": PARENT}


def test_burst_reuses_after_three_identical_verdicts(conn):
    for n in range(2):
        add(conn, n, "Benign Positive")
    assert flood.find(conn, add(conn, 90)) is None                   # only two investigated so far
    add(conn, 2, "Benign Positive")
    found = flood.find(conn, add(conn, 91))
    assert found and found["verdict"] == "Benign Positive" and len(found["samples"]) == 3
    v = flood.verdict(found)
    assert v["investigation"]["stop_reason"] == "flood_reused" and "Part of a burst" in v["summary"]
    assert flood.find(conn, add(conn, 92, exe=r"C:\other.exe")) is None   # another program: investigated


@pytest.mark.parametrize("spoil", ["true_positive", "dispute", "mixed", "low_confidence"])
def test_burst_is_not_reused_when_unsafe(conn, spoil):
    for n in range(3):
        add(conn, n, "Benign Positive", conf=60 if spoil == "low_confidence" else 85)
    if spoil == "true_positive":
        add(conn, 3, "True Positive")
    elif spoil == "dispute":
        conn.execute("INSERT INTO feedback (alert_id, analyst, agrees, correct_verdict) "
                     "VALUES ('hq:f0', 'ann', FALSE, 'Needs Human Review')")
    elif spoil == "mixed":
        add(conn, 3, "False Positive")
    assert flood.find(conn, add(conn, 99)) is None


def test_burst_review_verdicts_reused_and_recheck(conn, monkeypatch):
    for n in range(3):
        add(conn, n, "Needs Human Review", conf=40)
    assert flood.find(conn, add(conn, 50))["verdict"] == "Needs Human Review"
    monkeypatch.setitem(appsettings.OVERLAY, "FLOOD_RECHECK_EVERY", "5")
    for n in range(5):
        add(conn, 10 + n, "Needs Human Review", reused=True)
    assert flood.find(conn, add(conn, 51)) is None                    # 5 reused in a row: investigate one again
    monkeypatch.setitem(appsettings.OVERLAY, "FLOOD_GUARD", "false")
    monkeypatch.setitem(appsettings.OVERLAY, "FLOOD_RECHECK_EVERY", "25")
    assert flood.find(conn, add(conn, 52)) is None                    # switched off


def test_protected_tactics_and_injection_block():
    assert flood.blocked({"rule": {"mitre": [{"tactic": "Lateral Movement"}]}}) == "high-impact tactic"
    assert flood.blocked({"rule": {"mitre": []}, "injection_markers": ["ignore previous"]})
    assert flood.blocked({"rule": {"mitre": [{"tactic": "Execution"}]}}) is None


def test_queue_takes_the_most_urgent_first_and_never_starves(conn):
    add(conn, 1, rule="Low noisy rule", priority=21)
    add(conn, 2, rule="Credential dump", priority=119)
    add(conn, 3, rule="Medium", priority=47)
    assert db.claim_next_alert(conn)["alert_id"] == "hq:f2"
    assert db.claim_next_alert(conn)["alert_id"] == "hq:f3"
    add(conn, 4, rule="Old low", priority=21, waited_min=200)          # waited 200 min: 21 + 40 > 47
    add(conn, 5, rule="Fresh medium", priority=47)
    assert db.claim_next_alert(conn)["alert_id"] == "hq:f4"


def test_fetcher_priority_from_risk_and_tactic():
    spec = importlib.util.spec_from_file_location("fetcher_mod", ROOT / "fetcher" / "fetcher.py")
    if spec is None:
        pytest.skip("fetcher not importable")
    import sys
    sys.path.insert(0, str(ROOT / "fetcher"))
    try:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    assert mod.priority({"kibana.alert.risk_score": 73}) == 73
    assert mod.priority({"kibana.alert.severity": "critical"}) == 99
    assert mod.priority({"kibana.alert.risk_score": 47,
                         "kibana.alert.rule.threat": [{"tactic": {"name": "Credential Access"}}]}) == 67
    assert mod.priority({}) == 47


def test_main_worker_leaves_side_tasks_to_worker_tasks(conn):
    worker._tasks_seen.update(at=-1e9, alive=False)
    assert worker.tasks_worker_alive(conn) is False
    appsettings._activity.clear()
    appsettings.activity(conn, "worker-tasks", "idle", "Waiting")
    worker._tasks_seen.update(at=-1e9)
    assert worker.tasks_worker_alive(conn) is True
    conn.execute("UPDATE service_activity SET updated_at = NOW() - interval '10 minutes'")
    worker._tasks_seen.update(at=-1e9)
    assert worker.tasks_worker_alive(conn) is False


def test_worker_reuses_the_burst_verdict_without_the_model(conn, monkeypatch):
    import contextlib
    import elastic
    for n in range(3):
        add(conn, n, "Benign Positive")
    row = add(conn, 7)
    conn.execute("UPDATE alerts SET status = 'processing' WHERE alert_id = 'hq:f7'")
    raw = {"_id": "f7", "_source": {"@timestamp": "2026-11-20T02:00:00Z", "kibana.alert.original_time": "2026-11-20T02:00:00Z",
                                     "kibana.alert.rule.name": RULE, "host": {"name": "host-7"},
                                     "process": {"name": "agent.exe", "executable": EXE, "parent": {"executable": PARENT}}}}
    monkeypatch.setattr(elastic, "configured", lambda: {"hq": {}})
    monkeypatch.setattr(elastic, "use", lambda _s: contextlib.nullcontext())
    monkeypatch.setattr(elastic, "fetch_alert", lambda _id: raw)
    monkeypatch.setattr(worker.notifier, "build_notifications", lambda *a, **k: [])

    class NoLLM:
        def chat(self, **kw):
            raise AssertionError("the model must not be called for a reused burst verdict")

    worker.process(conn, NoLLM(), {**row, "attempts": 1, "count": 1, "rule_id": None, "host_name": "host-7",
                                   "user_name": None, "alert_hash": None, "incident_key": None, "elastic_id": "f7"})
    res = conn.execute("SELECT result FROM triage_results WHERE alert_id = 'hq:f7'").fetchone()["result"]
    assert res["verdict"] == "Benign Positive" and res["investigation"]["stop_reason"] == "flood_reused"
    assert set(res["investigation"]["reused_from"]) == {"hq:f0", "hq:f1", "hq:f2"}
