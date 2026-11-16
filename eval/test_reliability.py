"""Model-free tests: LLM outages, truncation, closure review, analyst history, web search
exposure, notifications and settings parsing."""
import json
import pathlib

import pytest

from harness import MemoryDB, install_fixtures, load_case

import config
import notifier
import playbooks
import sanitize
from agent import Investigation, LLMUnavailable
from alert_context import build_context
from tool_schemas import active_tool_names

CASE = load_case(pathlib.Path(__file__).parent / "samples" / "cases" / "forfiles_backup_benign.json")
GOOD = {"verdict": "Benign Positive", "severity": "Informational", "confidence": 88,
        "summary": "Daily backup cleanup.", "malicious_hypothesis": "evidence wiping",
        "benign_hypothesis": "retention job",
        "key_findings": [{"claim": "ran daily for 30 days", "stance": "benign", "evidence_ids": ["E2"]},
                         {"claim": "parent is a scheduled .bat", "stance": "benign", "evidence_ids": ["E1"]}],
        "should_escalate": False, "prompt_injection_suspected": False}
FINISH = {"message": {"content": "", "tool_calls": [{"function": {"name": "finish_investigation",
                                                                  "arguments": {"reason": "enough"}}}]}}


def msg(obj, **extra):
    return {"message": {"content": obj if isinstance(obj, str) else json.dumps(obj)}, **extra}


class FakeLLM:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def chat(self, **kw):
        self.calls.append(kw)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def run(script, history=None):
    mem = MemoryDB().install()
    install_fixtures(CASE["fixtures"])
    ctx = build_context(CASE["alert"])
    llm = FakeLLM(script)
    final, _ = Investigation(None, llm, "t", ctx, playbooks.resolve(ctx), history=history).run()
    return final, mem, llm


# ----------------------------------------------------------------- LLM outage != verdict
def test_connection_error_in_finalize_requeues_instead_of_fallback_verdict():
    with pytest.raises(LLMUnavailable):
        run([FINISH, ConnectionError("Failed to connect to Ollama")])


def test_connection_error_in_tool_loop_requeues():
    with pytest.raises(LLMUnavailable):
        run([ConnectionError("Failed to connect to Ollama")])


# ----------------------------------------------------------------- truncation
def test_truncated_final_output_is_retried():
    final, mem, llm = run([FINISH, msg(GOOD, done_reason="length"), msg(GOOD)])
    errors = [s.get("error") or "" for s in mem.steps if s["kind"] == "final" and s["status"] == "error"]
    assert any("cut off" in e for e in errors)
    assert final["verdict"] == "Benign Positive"


def test_context_overflow_blocks_auto_close():
    final, *_ = run([FINISH, msg(GOOD, prompt_eval_count=config.NUM_CTX)])
    assert final["verdict"] == "Needs Human Review"
    assert any("context window" in n for n in final["investigation"]["guardrails_applied"])


# ----------------------------------------------------------------- closure review
@pytest.fixture
def verify(monkeypatch):
    monkeypatch.setattr(config, "VERIFY_CLOSURES", True)


def test_closure_review_upheld_keeps_closure(verify):
    final, mem, llm = run([FINISH, msg(GOOD), msg({"unexplained_facts": [], "uphold_closure": True})])
    assert final["verdict"] == "Benign Positive"
    assert any(s["kind"] == "review" and s["status"] == "ok" for s in mem.steps)
    assert llm.calls[-1]["options"]["num_predict"] == 500          # short output: cheap on CPU


def test_closure_review_with_cited_fact_downgrades(verify):
    review = {"unexplained_facts": [{"fact": "parent is WINWORD.EXE", "evidence_ids": ["E1"]}],
              "uphold_closure": True}      # even if it says 'uphold', a cited fact wins
    final, *_ = run([FINISH, msg(GOOD), msg(review)])
    assert final["verdict"] == "Needs Human Review"
    assert any("WINWORD" in g for g in final["information_gaps"])


def test_closure_review_uncited_fact_is_ignored(verify):
    review = {"unexplained_facts": [{"fact": "an attacker could do this", "evidence_ids": ["E77"]}],
              "uphold_closure": True}
    final, *_ = run([FINISH, msg(GOOD), msg(review)])
    assert final["verdict"] == "Benign Positive"


def test_closure_review_fails_closed(verify):
    final, *_ = run([FINISH, msg(GOOD), msg("{bad"), msg("{bad")])
    assert final["verdict"] == "Needs Human Review"


def test_closure_review_skipped_for_true_positive(verify):
    tp = dict(GOOD, verdict="True Positive", severity="High")
    final, mem, llm = run([FINISH, msg(tp)])
    assert final["verdict"] == "True Positive"
    assert not any(s["kind"] == "review" for s in mem.steps)


# ----------------------------------------------------------------- analyst history
HIST_TP = [{"match": "same pattern", "date": "2026-10-01", "analyst_verdict": "True Positive",
            "model_verdict": "Benign Positive", "comment": "this was the red team", "summary": "x"}]


def test_history_is_shown_to_model_and_tp_history_blocks_close():
    final, mem, llm = run([FINISH, msg(GOOD)], history=HIST_TP)
    user_msg = llm.calls[0]["messages"][1]["content"]
    assert "<analyst_history>" in user_msg and "this was the red team" in user_msg
    assert final["verdict"] == "Needs Human Review"


def test_benign_history_does_not_force_review():
    hist = [dict(HIST_TP[0], analyst_verdict="Benign Positive")]
    final, *_ = run([FINISH, msg(GOOD)], history=hist)
    assert final["verdict"] == "Benign Positive"


# ----------------------------------------------------------------- web search exposure
def test_disabled_web_search_is_not_offered(monkeypatch):
    monkeypatch.setattr(config, "WEB_SEARCH_PROVIDER", "disabled")
    assert "web_search" not in active_tool_names()
    call = {"message": {"content": "", "tool_calls": [{"function": {
        "name": "web_search", "arguments": {"kind": "ip", "value": "8.8.8.8"}}}]}}
    final, mem, llm = run([call, FINISH, msg(GOOD)])
    assert all(t["function"]["name"] != "web_search" for t in llm.calls[0]["tools"])
    assert ("web_search", "error") in [(s.get("tool_name"), s["status"]) for s in mem.steps]
    assert "NOT available" in llm.calls[0]["messages"][1]["content"]


def test_dry_run_logs_but_sends_nothing(monkeypatch):
    monkeypatch.setattr(config, "WEB_SEARCH_DRY_RUN", True)
    import websearch
    monkeypatch.setattr(websearch, "search", lambda *a, **k: pytest.fail("dry run must not send"))
    call = {"message": {"content": "", "tool_calls": [{"function": {
        "name": "web_search", "arguments": {"kind": "ip", "value": "8.8.8.8"}}}]}}
    final, mem, _ = run([call, FINISH, msg(GOOD)])
    assert mem.outbound == [{"query": '"8.8.8.8"', "status": "dry_run"}]


def test_free_text_kinds_off_by_default(monkeypatch):
    monkeypatch.setattr(config, "WEB_SEARCH_KINDS", config._list("X", "ip,domain,hash,cve,mitre,filename"))
    with pytest.raises(sanitize.BlockedQuery):
        sanitize.build_query("command_pattern", "forfiles /c cmd", None, {})
    from tool_schemas import active_tools
    ws = [t for t in active_tools() if t["function"]["name"] == "web_search"][0]
    assert "command_pattern" not in ws["function"]["parameters"]["properties"]["kind"]["enum"]


# ----------------------------------------------------------------- notifications
TP_FINAL = {"alert_id": "abc123", "verdict": "True Positive", "severity": "High", "confidence": 81,
            "rule_name": "Evil\r\nBcc: attacker@example.com", "hostname": "fs01",
            "alert_url": "javascript:alert(1)", "summary": "Word spawned forfiles\x1b[31m",
            "key_findings": [{"claim": "benign bit", "stance": "benign"},
                             {"claim": "WINWORD -> forfiles", "stance": "suspicious"}],
            "recommended_actions": [{"action": "Isolate host", "priority": "immediate"}],
            "mitre_techniques": [{"technique_id": "T1202", "name": "Indirect Command Execution"}]}


@pytest.fixture
def notify(monkeypatch):
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", ["smtp"])
    monkeypatch.setattr(config, "NOTIFY_VERDICTS", ["True Positive"])
    monkeypatch.setattr(config, "NOTIFY_MIN_SEVERITY", "Medium")
    monkeypatch.setattr(config, "NOTIFY_DETAIL", "full")
    monkeypatch.setattr(config, "ARDEA_PUBLIC_URL", "https://ardea.example")


def test_notify_policy(notify):
    assert notifier.should_notify(TP_FINAL)
    assert not notifier.should_notify(dict(TP_FINAL, verdict="Benign Positive"))
    assert not notifier.should_notify(dict(TP_FINAL, severity="Low"))


def test_payload_is_sanitised(notify):
    [(channel, p)] = notifier.build_notifications(TP_FINAL, "jdoe")
    assert channel == "smtp"
    assert "\n" not in p["rule_name"] and "\r" not in p["rule_name"]
    assert p["kibana_url"] is None                                 # javascript: URL dropped
    assert "\x1b" not in p["summary"]
    assert p["findings"][0].startswith("[suspicious]")             # suspicious first
    assert p["ardea_url"] == "https://ardea.example/?q=abc123"


def test_minimal_mode_omits_internal_details(notify, monkeypatch):
    monkeypatch.setattr(config, "NOTIFY_DETAIL", "minimal")
    p = notifier.build_payload(TP_FINAL, "jdoe")
    assert "hostname" not in p and "user" not in p and "summary" not in p
    assert "fs01" not in notifier._body(p)


def test_smtp_message_is_plain_text(notify, monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["host"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context): sent["tls"] = True
        def login(self, u, pw): sent["login"] = u
        def send_message(self, m): sent["msg"] = m

    monkeypatch.setattr(notifier.smtplib, "SMTP", FakeSMTP)
    for k, v in {"SMTP_HOST": "mail.example", "SMTP_FROM": "tz@example.com", "SMTP_TO": "soc@example.com",
                 "SMTP_USER": "tz", "SMTP_PASSWORD": "pw"}.items():
        monkeypatch.setenv(k, v)
    notifier.send_smtp(notifier.build_payload(TP_FINAL, "jdoe"))
    m = sent["msg"]
    assert sent["tls"] and m.get_content_type() == "text/plain"
    assert m["Bcc"] is None and "attacker" not in m["To"]
    assert m["Subject"].startswith("[Ardea] True Positive (High)")


def test_delivery_retries_and_never_raises(notify, monkeypatch):
    marks = []
    rows = [{"id": 1, "alert_id": "a", "channel": "smtp", "attempts": 0, "payload": {}}]
    monkeypatch.setattr(notifier.db, "pending_notifications", lambda conn: rows)
    monkeypatch.setattr(notifier.db, "mark_notification",
                        lambda conn, nid, ok, err=None, attempts=0: marks.append((nid, ok, err)) or "pending")

    def boom(p, target=None):
        raise notifier.NotifyError("SMTP down")
    monkeypatch.setitem(notifier.SENDERS, "smtp", boom)
    notifier.deliver_pending(None)
    assert marks == [(1, False, "SMTP down")]
    monkeypatch.setitem(notifier.SENDERS, "smtp", lambda p, target=None: None)
    notifier.deliver_pending(None)
    assert marks[-1] == (1, True, None)


def test_keep_alive_is_numeric_for_ollama(monkeypatch):
    import importlib
    monkeypatch.setenv("LLM_KEEP_ALIVE", "-1")
    assert importlib.reload(config).LLM_KEEP_ALIVE == -1          # "-1" string -> HTTP 400 from Ollama
    monkeypatch.setenv("LLM_KEEP_ALIVE", "24h")
    assert importlib.reload(config).LLM_KEEP_ALIVE == "24h"
    monkeypatch.delenv("LLM_KEEP_ALIVE")
    importlib.reload(config)


def test_ollama_silently_dropping_messages_is_detected():
    # 2nd call: more text than the 1st, but Ollama reports FEWER prompt tokens -> it dropped messages
    call = {"message": {"content": "", "tool_calls": [{"function": {
        "name": "get_related_alerts", "arguments": {"entity_type": "host", "value": "fs01", "hours_before": 1}}}]},
        "prompt_eval_count": 6000}
    final, *_ = run([call, dict(FINISH, prompt_eval_count=2500), msg(GOOD, prompt_eval_count=2600)])
    assert final["verdict"] == "Needs Human Review"
    assert any("context window" in n for n in final["investigation"]["guardrails_applied"])


def test_normal_growth_is_not_overflow():
    call = {"message": {"content": "", "tool_calls": [{"function": {
        "name": "get_related_alerts", "arguments": {"entity_type": "host", "value": "fs01", "hours_before": 1}}}]},
        "prompt_eval_count": 3000}
    final, *_ = run([call, dict(FINISH, prompt_eval_count=3200), msg(GOOD, prompt_eval_count=3400)])
    assert final["verdict"] == "Benign Positive"


# ----------------------------------------------------------------- connectivity and settings
def test_connect_timeout_counts_as_ollama_unavailable():
    import httpx
    with pytest.raises(LLMUnavailable):
        run([httpx.ConnectTimeout("[Errno 110] Connection timed out")])


def test_env_ignores_compose_inline_comments(monkeypatch):
    monkeypatch.setenv("TZ_TEST_LIST", "# smtp, ntfy, or smtp,ntfy")   # what Compose makes of `KEY=  # ...`
    assert config._list("TZ_TEST_LIST", "") == []
    assert config.env("TZ_TEST_LIST", "dflt") == "dflt"
    monkeypatch.setenv("TZ_TEST_LIST", "  smtp,ntfy ")
    assert config._list("TZ_TEST_LIST") == ["smtp", "ntfy"]
    monkeypatch.setenv("TZ_TEST_INT", "# 30 seconds")
    assert config._int("TZ_TEST_INT", 30) == 30


@pytest.mark.parametrize("raw,expected", [("", None), ("false", False), ("true", True), ("high", "high"),
                                          ("# comment", None)])
def test_llm_think_tristate(monkeypatch, raw, expected):
    import importlib
    monkeypatch.setenv("LLM_THINK", raw)
    assert importlib.reload(config).LLM_THINK == expected
    monkeypatch.delenv("LLM_THINK")
    importlib.reload(config)


def test_think_false_is_sent_and_empty_is_not(monkeypatch):
    monkeypatch.setattr(config, "LLM_THINK", False)
    _, _, llm = run([FINISH, msg(GOOD)])
    assert llm.calls[0]["think"] is False
    monkeypatch.setattr(config, "LLM_THINK", None)
    _, _, llm = run([FINISH, msg(GOOD)])
    assert "think" not in llm.calls[0]


# ----------------------------------------------------------------- playbooks
@pytest.mark.parametrize("raw,expected", [
    ('"C:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe" -user_path "C:\\x"',
     "C:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe"),
    ("C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\KUnelevate.exe", "C:\\Users\\bob\\AppData\\Local\\Temp\\KUnelevate.exe"),
    ("\\SystemRoot\\System32\\drivers\\evil.sys", "\\SystemRoot\\System32\\drivers\\evil.sys"),
    ("%COMSPEC% /c echo x > \\\\.\\pipe\\y", "%COMSPEC%"),
    ("", None),
])
def test_service_executable(raw, expected):
    from alert_context import service_executable
    assert service_executable(raw) == expected


def _alert(rule_id, name, tactic, fields):
    src = {"@timestamp": "2026-11-04T07:34:21.759Z", "kibana.alert.rule.rule_id": rule_id,
           "kibana.alert.rule.name": name, "host": {"name": "ws01"},
           "kibana.alert.rule.threat": [{"tactic": {"name": tactic}, "technique": []}], **fields}
    return {"_id": "a1", "_source": src}


def test_service_playbook_baselines_the_service_program():
    from playbooks import render_enrichment
    from agent import _enrichment_fields
    import siem_tools
    ctx = build_context(_alert("da87eee1-129c-4661-a7aa-57d0b9645fad", "Suspicious Service was Installed in the System",
                               "Persistence", {"winlog": {"event_data": {
                                   "ServiceFileName": '"C:\\Program Files\\Zoom\\CptService.exe" -user_path x'}}}))
    pb = playbooks.resolve(ctx)
    plan = render_enrichment(pb["enrichment"], _enrichment_fields(ctx))
    assert pb["matched"] == "rule"
    assert ("get_baseline", {"field": "process.executable", "value": "C:\\Program Files\\Zoom\\CptService.exe",
                             "days": 30}) in plan
    # the service program is an entity, so the model may also query it itself
    siem_tools.InvestigationScope(ctx["entities"], ctx["event_time"]).allow(
        "c:\\program files\\zoom\\cptservice.exe", "process.executable")


@pytest.mark.parametrize("rule_id,name,tactic,fields,tools", [
    ("0859355c-0f08-4b43-8ff5-7d2a4789fc08", "First Time Seen Removable Device", "Exfiltration",
     {"process": {"name": "WUDFHost.exe", "entity_id": "{X}"}, "registry": {"data": {"strings": ["D:\\"]}}},
     ["get_related_alerts", "search_host_events", "search_host_events"]),
    ("6e1a2cc4-d260-11ed-8829-f661ea17fbcc", "First Time Seen Commonly Abused Remote Access Tool Execution",
     "Command and Control", {"process": {"name": "AnyDesk.exe", "entity_id": "{6884CE3D-DF95}"}},
     ["get_process_tree", "get_baseline", "get_related_alerts"]),
])
def test_new_rule_playbooks_render(rule_id, name, tactic, fields, tools):
    from playbooks import render_enrichment
    from agent import _enrichment_fields
    ctx = build_context(_alert(rule_id, name, tactic, fields))
    pb = playbooks.resolve(ctx)
    assert pb["matched"] == "rule" and pb["guidance"]
    assert [t for t, _ in render_enrichment(pb["enrichment"], _enrichment_fields(ctx))] == tools


def test_path_prefix_filter_and_drive_placeholder(monkeypatch):
    import siem_tools, elastic
    from alert_context import _drive_letter
    assert _drive_letter(["D:\\"]) == "D:\\" and _drive_letter("e:") == "E:\\" and _drive_letter("C:\\Windows") is None
    sent = {}
    monkeypatch.setattr(elastic, "search", lambda index, body: sent.update(body) or {"hits": {"hits": [], "total": {"value": 0}}})
    scope = siem_tools.InvestigationScope({"hosts": ["ws01"]}, "2026-11-04T07:34:21Z")
    siem_tools.search_host_events(scope, "ws01", "file", path_prefix="D:\\")
    assert {"prefix": {"file.path": {"value": "D:\\", "case_insensitive": True}}} in sent["query"]["bool"]["filter"]
    with pytest.raises(siem_tools.ToolInputError):
        siem_tools.search_host_events(scope, "ws01", "network", path_prefix="D:\\")
