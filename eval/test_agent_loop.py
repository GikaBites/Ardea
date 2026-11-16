"""Agent-loop mechanics with a scripted fake LLM (no model needed)."""
import json
import pathlib

from harness import MemoryDB, install_fixtures, load_case

import playbooks
from ollama import ResponseError
from agent import Investigation
from alert_context import build_context

CASE = load_case(pathlib.Path(__file__).parent / "samples" / "cases" / "forfiles_backup_benign.json")
GOOD = {"verdict": "Benign Positive", "severity": "Informational", "confidence": 88,
        "summary": "Daily backup cleanup.", "malicious_hypothesis": "evidence wiping",
        "benign_hypothesis": "retention job",
        "key_findings": [{"claim": "ran daily for 30 days", "stance": "benign", "evidence_ids": ["E2"]},
                         {"claim": "parent is a scheduled .bat", "stance": "benign", "evidence_ids": ["E1", "E99"]},
                         {"claim": "made-up fact", "stance": "benign", "evidence_ids": ["E42"]}],
        "should_escalate": False, "prompt_injection_suspected": False}


def call(name, **args):
    return {"message": {"content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}}


class FakeLLM:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def chat(self, **kw):
        self.calls.append(kw)
        return self.script.pop(0)


def run(script):
    mem = MemoryDB().install()
    install_fixtures(CASE["fixtures"])
    ctx = build_context(CASE["alert"])
    llm = FakeLLM(script)
    final, meta = Investigation(None, llm, "t", ctx, playbooks.resolve(ctx)).run()
    return final, mem, llm


def test_full_loop_with_duplicate_block_and_schema_retry():
    cmd = 'forfiles  -p "C:\\SQL Backups\\Automatic" -s -m *.* /D -3 /C "cmd /c del @path"'
    final, mem, llm = run([
        call("get_baseline", field="process.command_line", value=cmd, host="fs01", days=30),  # dup of E2
        call("web_search", kind="command_pattern", value="fs01 forfiles"),                    # leak -> blocked
        call("search_host_events", host="evil-host-not-in-alert", category="process"),                 # out of scope
        {"message": {"content": '<tool_call>{"name": "finish_investigation", "arguments": {"reason": "enough"}}</tool_call>'}},
        {"message": {"content": "{not json"}},                                                           # schema retry
        {"message": {"content": json.dumps(GOOD)}},
    ])
    statuses = [(s["kind"], s.get("tool_name"), s["status"]) for s in mem.steps]
    assert ("enrichment", "get_process_tree", "ok") in statuses
    assert ("tool", "get_baseline", "duplicate") in statuses
    assert ("tool", "web_search", "blocked") in statuses
    assert ("tool", "search_host_events", "error") in statuses
    assert mem.outbound == []                                   # nothing left the network
    assert final["verdict"] == "Benign Positive"
    assert [f["evidence_ids"] for f in final["key_findings"]] == [["E2"], ["E1"]]   # bad ids stripped
    assert any("dropped uncited" in n for n in final["investigation"]["guardrails_applied"])
    fmt = llm.calls[-1]["format"]
    # tools stay in the final call: same prompt prefix -> Ollama KV-cache hit (big win on CPU)
    assert llm.calls[-1]["tools"] == llm.calls[0]["tools"] and "verdict" in fmt["properties"]
    assert all(c["options"]["seed"] == llm.calls[0]["options"]["seed"] for c in llm.calls)
    assert "maxLength" not in json.dumps(fmt) and "pattern" not in json.dumps(fmt)   # grammar-safe


def test_budget_and_fallback():
    loop = [call("get_related_alerts", entity_type="host", value="fs01", hours_before=i) for i in range(20)]
    bad = [{"message": {"content": "nope"}}] * 3
    final, mem, _ = run(loop[:8] + bad)
    assert final["verdict"] == "Needs Human Review" and final["should_escalate"]
    assert "budget" in final["investigation"]["stop_reason"] or "loop" in final["investigation"]["stop_reason"]


class SchemaRejectingLLM(FakeLLM):
    """Mimics Ollama returning HTTP 500 when given a JSON-schema `format`."""
    def chat(self, **kw):
        if isinstance(kw.get("format"), dict):
            self.calls.append(kw)
            raise ResponseError("model runner failed", 500)
        return super().chat(**kw)


def test_schema_500_falls_back_to_json_mode():
    mem = MemoryDB().install()
    install_fixtures(CASE["fixtures"])
    ctx = build_context(CASE["alert"])
    long = dict(GOOD, summary="x" * 2000)                       # over-long text is trimmed, not fatal
    llm = SchemaRejectingLLM([call("finish_investigation", reason="ok"), {"message": {"content": json.dumps(long)}}])
    final, _ = Investigation(None, llm, "t", ctx, playbooks.resolve(ctx)).run()
    assert final["verdict"] == "Benign Positive" and len(final["summary"]) == 600
    assert llm.calls[-1]["format"] == "json"
