"""Ask about this alert: answered from stored evidence plus a few read-only queries, never touching the
alert's own trail. Real Postgres (EMPTY database ending in '_test'); the model and the SIEM are faked."""
import json
import os
import pathlib

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

import agent  # noqa: E402
import appsettings  # noqa: E402
import ask  # noqa: E402
import db  # noqa: E402
import elastic  # noqa: E402
import licensing  # noqa: E402
import siem_tools  # noqa: E402

INIT_SQL = pathlib.Path(__file__).resolve().parents[1] / "db" / "init.sql"
RAW = {"_id": "a1", "_source": {"@timestamp": "2026-11-18T09:00:00Z", "kibana.alert.original_time": "2026-11-18T09:00:00Z",
                                 "kibana.alert.rule.name": "Whoami Process Activity",
                                 "host": {"name": "ws01"}, "user": {"name": "bob"},
                                 "process": {"name": "whoami.exe", "command_line": "whoami /all"}}}


class FakeLLM:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def chat(self, **kw):
        self.calls.append(kw)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return {"message": r, "done_reason": "stop", "prompt_eval_count": 500}


@pytest.fixture
def conn(monkeypatch):
    c = db.get_connection()
    if not c.execute("SELECT to_regclass('public.alerts') AS t").fetchone()["t"]:
        c.execute(INIT_SQL.read_text())
    with c.transaction():
        appsettings.ensure_schema(c.execute)
    for t in ("alert_questions", "tool_cache", "investigation_steps", "triage_results", "alert_work", "feedback",
              "notifications", "alert_occurrences", "alerts"):
        c.execute(f"DELETE FROM {t}")
    c.execute("INSERT INTO alerts (alert_id, timestamp, status, siem, elastic_id, host_name, user_name) "
              "VALUES ('hq:a1', '2026-11-18T09:00:00Z', 'done', 'hq', 'a1', 'ws01', 'bob')")
    c.execute("INSERT INTO triage_results (alert_id, response, result, verdict) VALUES ('hq:a1', '{}', %s, 'Needs Human Review')",
              (json.dumps({"verdict": "Needs Human Review", "severity": "Medium", "confidence": 60,
                           "summary": "whoami by bob", "key_findings": [{"claim": "new for bob", "stance": "suspicious",
                                                                         "evidence_ids": ["E1"]}]}),))
    c.execute("""INSERT INTO investigation_steps (alert_id, run_id, step, kind, tool_name, arguments, status,
                                                  evidence_id, result)
                 VALUES ('hq:a1', 'run1', 1, 'enrichment', 'get_baseline', %s, 'ok', 'E1', %s)""",
              (json.dumps({"field": "process.name"}), json.dumps({"days_seen": 0, "hosts": ["srv-db"]})))
    monkeypatch.setattr(elastic, "fetch_alert", lambda _id: RAW)
    licensing.set_tier("pro")
    yield c
    c.close()


def queue(conn, text="Did bob log on to other hosts?"):
    return conn.execute("INSERT INTO alert_questions (alert_id, asked_by, question) VALUES ('hq:a1', 'maria', %s) "
                        "RETURNING id", (text,)).fetchone()["id"]


def test_question_answered_with_a_new_query_and_checked_citations(conn, monkeypatch):
    seen = []

    def fake_events(scope, host, category, **kw):
        seen.append((host, category))
        return {"events": [{"host.name": "srv-db", "user.name": "bob", "event.action": "logged-in"}]}
    monkeypatch.setitem(siem_tools.TOOL_FUNCS, "search_host_events", fake_events)
    llm = FakeLLM([
        {"content": "", "tool_calls": [{"function": {"name": "search_host_events",
                                                     "arguments": {"host": "ws01", "category": "authentication"}}}]},
        {"content": "Yes: bob logged on to srv-db (Q1). The baseline had never seen this (E1). See also E9."},
    ])
    qid = queue(conn)
    before = conn.execute("SELECT count(*) AS n FROM investigation_steps").fetchone()["n"]
    assert ask.run_pending(conn, llm) is True
    q = conn.execute("SELECT * FROM alert_questions WHERE id = %s", (qid,)).fetchone()
    assert q["status"] == "done" and seen == [("ws01", "authentication")]
    assert "(Q1)" in q["answer"] and "(E1)" in q["answer"] and "E9" not in q["answer"] and "unsupported" in q["answer"]
    assert q["cited"] == ["Q1", "E1"] and "E9" in q["note"]
    assert q["steps"][-1]["evidence"][0]["id"] == "Q1"
    assert conn.execute("SELECT count(*) AS n FROM investigation_steps").fetchone()["n"] == before  # trail untouched
    prompt = llm.calls[0]["messages"][1]["content"]
    assert 'evidence_id="E1"' in prompt and "Did bob log on to other hosts?" in prompt
    assert {t["function"]["name"] for t in llm.calls[0]["tools"]} <= set(siem_tools.TOOL_FUNCS)  # no web, no finish
    assert ask.run_pending(conn, llm) is False                                 # nothing left


def test_scope_rules_still_apply(conn, monkeypatch):
    monkeypatch.setattr(elastic, "search", lambda *a, **k: {"hits": {"hits": [], "total": {"value": 0}}})
    llm = FakeLLM([
        {"content": "", "tool_calls": [{"function": {"name": "search_host_events",
                                                     "arguments": {"host": "dc-evil", "category": "process"}}}]},
        {"content": "I could not check that host."},
    ])
    qid = queue(conn)
    ask.run_pending(conn, llm)
    tool_msg = [m for m in llm.calls[1]["messages"] if m["role"] == "tool"][-1]["content"]
    assert "does not appear in the alert" in tool_msg
    assert conn.execute("SELECT status FROM alert_questions WHERE id = %s", (qid,)).fetchone()["status"] == "done"


def test_an_ollama_outage_puts_the_question_back(conn):
    qid = queue(conn)
    assert ask.run_pending(conn, FakeLLM([agent.LLMUnavailable("down")])) is False
    assert conn.execute("SELECT status FROM alert_questions WHERE id = %s", (qid,)).fetchone()["status"] == "queued"


def test_a_deleted_alert_document_is_answered_from_stored_evidence(conn, monkeypatch):
    monkeypatch.setattr(elastic, "fetch_alert", lambda _id: None)
    llm = FakeLLM([{"content": "From the stored evidence only: the baseline saw nothing (E1)."}])
    qid = queue(conn)
    ask.run_pending(conn, llm)
    assert "tools" not in llm.calls[0]
    assert conn.execute("SELECT answer FROM alert_questions WHERE id = %s", (qid,)).fetchone()["answer"].endswith("(E1).")
