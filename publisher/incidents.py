"""Incidents (Pro): related alerts grouped into one incident with one timeline.

Two alerts belong to the same incident when they come from the same SIEM and share a host or a user
account, and the second arrives within WINDOW of the previous alert on that host or account. Chains
are followed, so a burst on one host that moves to a second host through the same account is one
incident. Built from the triaged alerts on every page view: nothing is stored and nothing about triage
changes. Service and machine accounts are ignored for linking, or every alert would join one incident.
"""
import hashlib
from collections import Counter
from datetime import datetime, timedelta, timezone

WINDOW = timedelta(minutes=60)
NEEDS_PERSON = ("True Positive", "Needs Human Review")
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
_NOT_A_PERSON = {"", "-", "n/a", "unknown", "unknown host", "system", "local service", "network service",
                 "nt authority\\system", "root", "anonymous logon", "dwm-1", "umfd-0", "umfd-1"}
RANGES = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}


def _linkable(kind: str, value: str) -> bool:
    v = (value or "").strip().lower()
    if v in _NOT_A_PERSON:
        return False
    if kind == "user" and (v.endswith("$") or v.startswith(("dwm-", "umfd-"))):   # machine and window-manager accounts
        return False
    return True


class _Groups:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, i):
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def join(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _worst(severities) -> str:
    known = [s for s in severities if s in _SEV_RANK]
    return min(known, key=_SEV_RANK.get) if known else "Unknown"


def incident_id(first_alert_id: str) -> str:
    return "inc-" + hashlib.sha256(first_alert_id.encode()).hexdigest()[:12]


def _summary(members: list[dict]) -> dict:
    members = sorted(members, key=lambda a: a["timestamp_raw"])
    verdicts = Counter(a["verdict"] for a in members)
    hosts = Counter(a["hostname"] for a in members if _linkable("host", a["hostname"]))
    users = Counter(a["user"] for a in members if _linkable("user", a.get("user", "")))
    rules = Counter(a["rule_name"] for a in members)
    attention = any(a["verdict"] in NEEDS_PERSON or a.get("should_escalate") for a in members)
    flagged = [a for a in members if a["verdict"] in NEEDS_PERSON]
    severity = _worst([a["severity"] for a in (flagged or members)])
    lead = min(flagged or members, key=lambda a: (_SEV_RANK.get(a["severity"], 9), a["timestamp_raw"]))
    techniques, seen = [], set()
    for a in members:
        for m in (a.get("detail") or {}).get("mitre", []):
            if m.get("id") and m["id"] not in seen:
                seen.add(m["id"])
                techniques.append(m)
    host_list = [h for h, _ in hosts.most_common()]
    title = lead["rule_name"]
    where = host_list[0] if host_list else lead["hostname"]
    if len(host_list) > 1:
        where += f" and {len(host_list) - 1} more host{'s' if len(host_list) > 2 else ''}"
    start, end = members[0]["timestamp_raw"], members[-1]["timestamp_raw"]
    return {
        "id": incident_id(members[0]["alert_id"]),
        "title": title, "where": where,
        "siem": members[0]["siem"], "siem_name": members[0].get("siem_name") or members[0]["siem"],
        "status": "attention" if attention else "closed",
        "severity": severity,
        "start": start, "end": end,
        "minutes": max(1, round((end - start).total_seconds() / 60)) if start and end else 0,
        "count": len(members),
        "occurrences": sum(int(a.get("occurrences") or 1) for a in members),
        "verdicts": dict(verdicts),
        "needs_person": sum(verdicts[v] for v in NEEDS_PERSON),
        "hosts": host_list, "users": [u for u, _ in users.most_common()],
        "rules": rules.most_common(),
        "techniques": techniques[:12],
        "alerts": members,
    }


def build(alerts: list[dict], window: timedelta = WINDOW) -> list[dict]:
    """All incidents in these alerts (each alert in exactly one), newest first."""
    items = sorted((a for a in alerts if a.get("timestamp_raw")), key=lambda a: a["timestamp_raw"])
    groups = _Groups(len(items))
    last: dict[tuple, tuple[int, datetime]] = {}
    for i, a in enumerate(items):
        for kind, value in (("host", a.get("hostname", "")), ("user", a.get("user", ""))):
            if not _linkable(kind, value):
                continue
            key = (a.get("siem"), kind, value.strip().lower())
            prev = last.get(key)
            if prev and a["timestamp_raw"] - prev[1] <= window:
                groups.join(prev[0], i)
            last[key] = (i, a["timestamp_raw"])
    members: dict[int, list[dict]] = {}
    for i, a in enumerate(items):
        members.setdefault(groups.find(i), []).append(a)
    incidents = [_summary(m) for m in members.values()]
    return sorted(incidents, key=lambda x: x["end"], reverse=True)


def select(incidents: list[dict], *, range_key: str = "7d", status: str = "attention", siem: str = "",
           min_alerts: int = 2, now: datetime | None = None) -> list[dict]:
    """What the Incidents page lists. Single alerts are left out by default: the alert list has those."""
    since = (now or datetime.now(timezone.utc)) - timedelta(hours=RANGES.get(range_key, RANGES["7d"]))
    out = []
    for inc in incidents:
        if inc["end"] < since or inc["count"] < min_alerts:
            continue
        if status == "attention" and inc["status"] != "attention":
            continue
        if siem and inc["siem"] != siem:
            continue
        out.append(inc)
    return out


def find(incidents: list[dict], inc_id: str) -> dict | None:
    return next((i for i in incidents if i["id"] == inc_id), None)


def alert_index(incidents: list[dict]) -> dict[str, tuple[str, int]]:
    """alert_id -> (incident id, alerts in it), for incidents with more than one alert."""
    return {a["alert_id"]: (inc["id"], inc["count"]) for inc in incidents if inc["count"] > 1
            for a in inc["alerts"]}
