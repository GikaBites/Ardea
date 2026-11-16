"""Shared test/eval plumbing: run the real Investigation with an in-memory DB and replayed tool
results, so evaluations are deterministic, need no Postgres, and never touch the real SIEM/web."""
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

import db            # noqa: E402  (worker modules)
import siem_tools    # noqa: E402
import websearch     # noqa: E402


class MemoryDB:
    """Replaces the DB functions the agent uses. Collects the audit trail and outbound queries."""

    def __init__(self):
        self.steps, self.outbound, self.cache = [], [], {}

    def install(self):
        db.log_step = lambda conn, alert_id, run_id, step, kind, **kw: self.steps.append(
            {"step": step, "kind": kind, **kw})
        db.cache_get = lambda conn, key: copy.deepcopy(self.cache.get(key))
        db.cache_put = lambda conn, key, tool, result, ttl: self.cache.__setitem__(key, copy.deepcopy(result))
        db.outbound_counts = lambda conn: (0, 0)
        db.log_outbound = lambda conn, alert_id, provider, query, status: self.outbound.append(
            {"query": query, "status": status})
        return self


def install_fixtures(fixtures: dict):
    """fixtures = {"get_baseline": [{"match": {"field": "process.command_line"}, "result": {...}}, ...],
                   "web_search": [{"match": {}, "result": {...}}]}
    First entry whose `match` keys equal the call's args wins; no match -> empty result."""
    def make(name, real):
        def fake(scope, **args):
            # keep the real scope rules so replays exercise the same guardrails
            for key in ("host", "user", "process_entity_id"):
                if args.get(key):
                    scope.allow(args[key], key)
            if args.get("value") and args.get("field") != "process.command_line":
                scope.allow(args["value"], "value")
            for entry in fixtures.get(name, []):
                if all(str(args.get(k)) == str(v) for k, v in (entry.get("match") or {}).items()):
                    res = copy.deepcopy(entry["result"])
                    scope.harvest([res] if isinstance(res, dict) else [])
                    return res
            return {"total_events": 0, "note": "no matching events (replay fixture)"}
        return fake

    for name, real in list(siem_tools.TOOL_FUNCS.items()):
        siem_tools.TOOL_FUNCS[name] = make(name, real)
    websearch.search = lambda query, n=8: copy.deepcopy(
        (fixtures.get("web_search") or [{"result": {"results": [], "result_count": 0,
                                                    "note": "no results (replay)"}}])[0]["result"])


def load_case(path: pathlib.Path) -> dict:
    case = json.loads(path.read_text())
    if "alert_file" in case:
        case["alert"] = json.loads((path.parent / case["alert_file"]).read_text())
    for patch in case.get("alert_patch", []):           # dotted-key overrides on _source
        src = case["alert"].setdefault("_source", {})
        if patch["key"] in src:
            src[patch["key"]] = patch["value"]
            continue
        cur = src
        parts = patch["key"].split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = patch["value"]
    return case
