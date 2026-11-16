"""Parameterised, read-only SIEM investigation tools.

Why templates instead of letting the model write KQL/ES|QL:
  * a 14B local model writes syntactically wrong / semantically loose queries often
  * free-form query text built from alert fields is an injection vector
  * templates let us enforce index allowlists, time windows, size caps and field projection,
    and return pre-aggregated, compact results that fit the context window
Values are only ever placed inside term/terms/range clauses (never parsed as query syntax).
"""
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import config
import elastic
from alert_context import flatten, is_public_ip, neutralise

VALUE_RE = re.compile(r"^[\w.\-\\/:{}@$ ()\[\]~#+=,&'%]{1,512}$")   # sane field value charset


class ToolInputError(Exception):
    """Bad arguments — the message is returned to the model so it can correct itself."""


# --------------------------------------------------------------------------- context
class InvestigationScope:
    """Entities the model is allowed to pivot on: those in the alert plus those that appeared
    in earlier tool results. Prevents injected text from steering queries elsewhere."""

    def __init__(self, entities: dict, event_time: str):
        self.anchor = _parse_ts(event_time)
        self.known: set[str] = set()
        for vals in entities.values():
            self.known.update(str(v).lower() for v in vals)

    def allow(self, value: str, what: str):
        if value is None:
            return
        if str(value).lower() not in self.known:
            raise ToolInputError(f"{what} '{value}' does not appear in the alert or in earlier evidence; "
                                 f"pivot only on entities you have seen")

    def harvest(self, docs: list[dict]):
        for d in docs:
            for k in ("host.name", "user.name", "process.entity_id", "process.parent.entity_id",
                      "process.executable", "process.parent.executable", "process.name",
                      "process.hash.sha256", "process.hash.md5", "source.ip", "destination.ip",
                      "destination.domain", "dns.question.name", "file.hash.sha256"):
                v = d.get(k)
                for x in (v if isinstance(v, list) else [v]):
                    if x:
                        self.known.add(str(x).lower())


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.now(timezone.utc)


def _clean_value(value, what: str) -> str:
    if value is None or str(value).strip() == "":
        raise ToolInputError(f"{what} is required")
    value = str(value).strip()
    if not VALUE_RE.match(value):
        raise ToolInputError(f"{what} contains unsupported characters")
    return value


def _clamp(n, lo, hi, what):
    try:
        n = int(n)
    except (TypeError, ValueError):
        raise ToolInputError(f"{what} must be an integer")
    return max(lo, min(hi, n))


def _window(scope, before_min, after_min):
    max_min = config.SIEM_MAX_WINDOW_HOURS * 60
    b = _clamp(before_min, 0, max_min, "minutes_before")
    a = _clamp(after_min, 0, max_min, "minutes_after")
    return {"range": {"@timestamp": {"gte": (scope.anchor - timedelta(minutes=b)).isoformat(),
                                     "lte": (scope.anchor + timedelta(minutes=a)).isoformat()}}}


def _term(field, value):
    return {"term": {field: {"value": value, "case_insensitive": True}}}


def _host_filter(host):
    return {"bool": {"should": [_term("host.name", host), _term("host.hostname", host)],
                     "minimum_should_match": 1}}


def _flat_hits(data, fields):
    out = []
    for h in data.get("hits", {}).get("hits", []):
        flat = dict(flatten(h.get("_source", {})))
        out.append({f: flat.get(f) for f in fields if flat.get(f) not in (None, "", [])})
    return out


def _shorten(row: dict, max_len=300):
    return {k: neutralise(str(v)[:max_len]) if isinstance(v, str) else v for k, v in row.items()}


def _group(rows, key_fields, time_field="@timestamp", limit=None):
    """Collapse identical rows -> {..., count, first, last}. Turns 500 events into ~10 lines."""
    limit = limit or config.SIEM_MAX_ROWS
    groups = {}
    for r in rows:
        k = tuple(str(r.get(f)) for f in key_fields)
        g = groups.setdefault(k, {**{f: r.get(f) for f in key_fields if r.get(f) is not None},
                                  "count": 0, "first": r.get(time_field), "last": r.get(time_field)})
        g["count"] += 1
        t = r.get(time_field)
        if t:
            g["first"] = min(g["first"] or t, t)
            g["last"] = max(g["last"] or t, t)
    ordered = sorted(groups.values(), key=lambda g: -g["count"])
    return [_shorten(g) for g in ordered[:limit]], len(ordered)


def _total(data):
    t = data.get("hits", {}).get("total", {})
    return t.get("value", 0) if isinstance(t, dict) else t


def _events_index():
    return elastic.events_index()           # of the SIEM the alert under investigation came from


# --------------------------------------------------------------------------- tools
PROC_FIELDS = ["@timestamp", "host.name", "user.name", "process.name", "process.executable",
               "process.command_line", "process.entity_id", "process.parent.entity_id",
               "process.parent.name", "process.parent.command_line", "process.hash.sha256",
               "process.code_signature.subject_name", "process.code_signature.trusted",
               "winlog.event_data.IntegrityLevel"]


def get_process_tree(scope: InvestigationScope, process_entity_id: str, depth_up: int = 4):
    """Ancestors (up to depth_up) and direct children of a process, by entity id."""
    pid = _clean_value(process_entity_id, "process_entity_id")
    scope.allow(pid, "process_entity_id")
    depth_up = _clamp(depth_up, 1, 6, "depth_up")
    window = _window(scope, 24 * 60, 24 * 60)
    base = [window, {"terms": {"event.type": ["start"]}}, {"terms": {"event.category": ["process"]}}]

    ancestors, current = [], pid
    for _ in range(depth_up + 1):
        data = elastic.search(_events_index(), {
            "size": 1, "_source": PROC_FIELDS,
            "query": {"bool": {"filter": base + [{"term": {"process.entity_id": current}}]}}})
        rows = _flat_hits(data, PROC_FIELDS)
        if not rows:
            break
        ancestors.append(_shorten(rows[0]))
        current = rows[0].get("process.parent.entity_id")
        if not current:
            break

    data = elastic.search(_events_index(), {
        "size": 100, "_source": PROC_FIELDS, "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": base + [{"term": {"process.parent.entity_id": pid}}]}}})
    child_rows = _flat_hits(data, PROC_FIELDS)
    children, distinct = _group(child_rows, ["process.name", "process.command_line", "user.name"])
    scope.harvest(ancestors + child_rows)
    return {
        "process": ancestors[0] if ancestors else None,
        "ancestors_oldest_last": ancestors[1:],
        "children": children,
        "children_total": _total(data),
        "children_distinct": distinct,
        "note": None if ancestors else "start event not found in window (process may predate retention "
                                       "or Sysmon/Defend did not log it)",
    }


CATEGORY_FIELDS = {
    "process": PROC_FIELDS,
    "network": ["@timestamp", "process.name", "process.entity_id", "source.ip", "source.port",
                "destination.ip", "destination.port", "destination.domain", "network.direction",
                "network.transport", "user.name"],
    "dns": ["@timestamp", "process.name", "dns.question.name", "dns.resolved_ip", "user.name"],
    "file": ["@timestamp", "process.name", "file.path", "event.action", "file.hash.sha256", "user.name"],
    "registry": ["@timestamp", "process.name", "registry.path", "registry.data.strings", "event.action",
                 "user.name"],
    "authentication": ["@timestamp", "event.code", "event.outcome", "user.name", "source.ip",
                       "winlog.event_data.LogonType", "winlog.logon.type", "winlog.event_data.WorkstationName",
                       "process.name"],
}
GROUP_KEYS = {
    "process": ["process.name", "process.command_line", "process.parent.name", "user.name"],
    "network": ["process.name", "destination.ip", "destination.port", "destination.domain"],
    "dns": ["process.name", "dns.question.name"],
    "file": ["process.name", "event.action", "file.path"],
    "registry": ["process.name", "event.action", "registry.path", "registry.data.strings"],
    "authentication": ["event.code", "event.outcome", "user.name", "source.ip", "winlog.event_data.LogonType"],
}


PATH_PREFIX_FIELDS = {"file": "file.path", "process": "process.executable"}


def search_host_events(scope: InvestigationScope, host: str, category: str,
                       minutes_before: int = 30, minutes_after: int = 30,
                       process_name: str | None = None, user: str | None = None,
                       path_prefix: str | None = None):
    """Events of one category on one host around the alert time, grouped and counted.
    path_prefix (file and process only) keeps events whose file.path / process.executable starts with
    it, e.g. a drive letter, so one location's activity is not drowned in profile noise."""
    host = _clean_value(host, "host")
    scope.allow(host, "host")
    if category not in CATEGORY_FIELDS:
        raise ToolInputError(f"category must be one of {sorted(CATEGORY_FIELDS)}")
    filters = [_window(scope, minutes_before, minutes_after), _host_filter(host),
               {"terms": {"event.category": [category]}}]
    if process_name:
        filters.append(_term("process.name", _clean_value(process_name, "process_name")))
    if user:
        user = _clean_value(user, "user")
        scope.allow(user, "user")
        filters.append(_term("user.name", user))
    if path_prefix:
        field = PATH_PREFIX_FIELDS.get(category)
        if not field:
            raise ToolInputError(f"path_prefix only works with category {sorted(PATH_PREFIX_FIELDS)}")
        prefix = _clean_value(path_prefix, "path_prefix")
        if len(prefix) < 3:
            raise ToolInputError("path_prefix must be at least a drive letter with backslash, e.g. 'E:\\'")
        filters.append({"prefix": {field: {"value": prefix, "case_insensitive": True}}})
    fields = CATEGORY_FIELDS[category]
    data = elastic.search(_events_index(), {
        "size": 500, "_source": fields, "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": filters}}})
    rows = _flat_hits(data, fields)
    scope.harvest(rows)
    groups, distinct = _group(rows, GROUP_KEYS[category])
    result = {"total_events": _total(data), "distinct_patterns": distinct, "patterns": groups,
              "partial": bool(data.get("_partial"))}
    if category == "network":
        result["public_destinations"] = sorted({r["destination.ip"] for r in rows
                                                if r.get("destination.ip") and is_public_ip(r["destination.ip"])})[:20]
    return result


def get_baseline(scope: InvestigationScope, field: str, value: str, host: str | None = None, days: int = 30):
    """How common is this executable / process name / hash / exact command line?
    Answers 'is this normal here?' — usually the single most useful FP-vs-TP pivot."""
    allowed = {"process.executable": "process.executable", "process.name": "process.name",
               "process.hash.sha256": "process.hash.sha256", "process.command_line": "process.command_line"}
    if field not in allowed:
        raise ToolInputError(f"field must be one of {sorted(allowed)}")
    value = _clean_value(value, "value")
    if field != "process.command_line":
        scope.allow(value, field)
    days = _clamp(days, 1, config.SIEM_MAX_BASELINE_DAYS, "days")
    filters = [{"range": {"@timestamp": {"gte": (scope.anchor - timedelta(days=days)).isoformat(),
                                         "lte": (scope.anchor + timedelta(hours=1)).isoformat()}}},
               {"terms": {"event.category": ["process"]}}, {"terms": {"event.type": ["start"]}},
               _term(allowed[field], value)]
    if host:
        host = _clean_value(host, "host")
        scope.allow(host, "host")
        filters.append(_host_filter(host))
    data = elastic.search(_events_index(), {
        "size": 0, "query": {"bool": {"filter": filters}},
        "aggs": {
            "hosts": {"cardinality": {"field": "host.name"}},
            "top_hosts": {"terms": {"field": "host.name", "size": 5}},
            "top_users": {"terms": {"field": "user.name", "size": 5}},
            "top_parents": {"terms": {"field": "process.parent.executable", "size": 5}},
            "top_cmdlines": {"terms": {"field": "process.command_line", "size": 5}},
            "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
            "per_day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day",
                                           "min_doc_count": 1}},
        }})
    aggs = data.get("aggregations", {})

    def buckets(name):
        return [{"value": neutralise(str(b["key"])[:300]), "count": b["doc_count"]}
                for b in aggs.get(name, {}).get("buckets", [])]
    per_day = aggs.get("per_day", {}).get("buckets", [])
    return {
        "scope": f"host={host}" if host else "all hosts",
        "days": days,
        "total_executions": _total(data),
        "distinct_hosts": aggs.get("hosts", {}).get("value"),
        "days_with_activity": len(per_day),
        "first_seen": aggs.get("first", {}).get("value_as_string"),
        "last_seen": aggs.get("last", {}).get("value_as_string"),
        "top_hosts": buckets("top_hosts"), "top_users": buckets("top_users"),
        "top_parents": buckets("top_parents"), "top_command_lines": buckets("top_cmdlines"),
        "interpretation_hint": "Regular daily activity over many days with the same parent/user suggests "
                               "automation; first_seen close to the alert time suggests something new.",
    }


def get_auth_events(scope: InvestigationScope, user: str, host: str | None = None, hours_before: int = 24,
                    hours_after: int = 2):
    """Logon successes/failures for a user (optionally on one host), aggregated."""
    user = _clean_value(user, "user")
    scope.allow(user, "user")
    filters = [_window(scope, _clamp(hours_before, 0, 72, "hours_before") * 60,
                       _clamp(hours_after, 0, 24, "hours_after") * 60),
               {"terms": {"event.category": ["authentication"]}}, _term("user.name", user)]
    if host:
        host = _clean_value(host, "host")
        scope.allow(host, "host")
        filters.append(_host_filter(host))
    fields = CATEGORY_FIELDS["authentication"] + ["host.name"]
    data = elastic.search(_events_index(), {"size": 500, "_source": fields,
                                            "query": {"bool": {"filter": filters}}})
    rows = _flat_hits(data, fields)
    scope.harvest(rows)
    groups, distinct = _group(rows, ["host.name", "event.outcome", "winlog.event_data.LogonType", "source.ip"])
    outcomes = Counter(r.get("event.outcome", "unknown") for r in rows)
    return {"total": _total(data), "outcomes": dict(outcomes), "distinct_patterns": distinct,
            "patterns": groups,
            "public_source_ips": sorted({r["source.ip"] for r in rows
                                         if r.get("source.ip") and is_public_ip(r["source.ip"])})[:20]}


def get_related_alerts(scope: InvestigationScope, entity_type: str, value: str, hours_before: int = 48,
                       hours_after: int = 6):
    """Other Elastic Security alerts (same SIEM) for the same host/user/hash around this alert."""
    fields = {"host": "host.name", "user": "user.name", "hash": "process.hash.sha256"}
    if entity_type not in fields:
        raise ToolInputError("entity_type must be host, user or hash")
    value = _clean_value(value, "value")
    scope.allow(value, entity_type)
    flt = _host_filter(value) if entity_type == "host" else _term(fields[entity_type], value)
    data = elastic.search(elastic.alerts_index(), {
        "size": 0,
        "query": {"bool": {"filter": [
            _window(scope, _clamp(hours_before, 0, 72, "hours_before") * 60,
                    _clamp(hours_after, 0, 24, "hours_after") * 60), flt]}},
        "aggs": {"rules": {"terms": {"field": "kibana.alert.rule.name", "size": 15},
                           "aggs": {"sev": {"terms": {"field": "kibana.alert.severity", "size": 1}},
                                    "first": {"min": {"field": "@timestamp"}},
                                    "last": {"max": {"field": "@timestamp"}},
                                    "status": {"terms": {"field": "kibana.alert.workflow_status", "size": 3}},
                                    "tactics": {"terms": {"field": "kibana.alert.rule.threat.tactic.name",
                                                          "size": 3}}}}}})
    rules = []
    for b in data.get("aggregations", {}).get("rules", {}).get("buckets", []):
        rules.append({"rule": neutralise(b["key"]), "count": b["doc_count"],
                      "severity": (b["sev"]["buckets"] or [{"key": "?"}])[0]["key"],
                      "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string"),
                      "workflow_status": [s["key"] for s in b["status"]["buckets"]],
                      "tactics": [t["key"] for t in b["tactics"]["buckets"]]})
    return {"total_alerts": _total(data), "distinct_rules": len(rules), "rules": rules,
            "note": "includes the alert under investigation itself"}


TOOL_FUNCS = {
    "get_process_tree": get_process_tree,
    "search_host_events": search_host_events,
    "get_baseline": get_baseline,
    "get_auth_events": get_auth_events,
    "get_related_alerts": get_related_alerts,
}
