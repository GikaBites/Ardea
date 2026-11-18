"""Incident grouping (pure logic, no database)."""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import incidents  # noqa: E402

T0 = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)


def alert(n, minutes, host="ws-01", user="alice", siem="hq", verdict="Benign Positive", severity="Low",
          rule="Rule A", mitre=()):
    return {"alert_id": f"{siem}:{n}", "timestamp_raw": T0 + timedelta(minutes=minutes), "hostname": host,
            "user": user, "siem": siem, "siem_name": siem.upper(), "verdict": verdict, "severity": severity,
            "rule_name": rule, "occurrences": 1, "should_escalate": False,
            "detail": {"mitre": [{"id": m, "name": m} for m in mitre], "summary": f"s{n}"}}


def groups(alerts):
    return sorted(sorted(a["alert_id"] for a in inc["alerts"]) for inc in incidents.build(alerts))


def test_same_host_within_the_window_is_one_incident_and_a_gap_splits_it():
    got = groups([alert(1, 0), alert(2, 30, user=""), alert(3, 85, user=""), alert(4, 200, user="")])
    assert got == [["hq:1", "hq:2", "hq:3"], ["hq:4"]]                  # 85-30 <= 60, 200-85 > 60


def test_an_account_links_hosts_and_chains_are_followed():
    got = groups([alert(1, 0, host="ws-01", user="bob"), alert(2, 20, host="srv-db", user="bob"),
                  alert(3, 50, host="srv-db", user=""), alert(4, 55, host="ws-99", user="carol")])
    assert got == [["hq:1", "hq:2", "hq:3"], ["hq:4"]]


def test_service_and_machine_accounts_never_link_alerts():
    for account in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "WS-01$", "", "-", "LOCAL SERVICE", "DWM-3"):
        assert len(groups([alert(1, 0, host="a", user=account), alert(2, 5, host="b", user=account)])) == 2, account


def test_different_siems_are_never_mixed():
    assert len(groups([alert(1, 0, siem="hq"), alert(2, 1, siem="branch")])) == 2


def test_summary_status_severity_and_title():
    [inc] = incidents.build([alert(1, 0, rule="Noise"), alert(2, 10, verdict="True Positive", severity="High",
                                                                  rule="Mimikatz", host="ws-02", mitre=("T1003",)),
                             alert(3, 20, verdict="Needs Human Review", severity="Medium", host="ws-02")])
    assert inc["status"] == "attention" and inc["severity"] == "High" and inc["title"] == "Mimikatz"
    assert inc["where"] == "ws-02 and 1 more host" and inc["users"] == ["alice"] and inc["needs_person"] == 2
    assert inc["verdicts"] == {"Benign Positive": 1, "True Positive": 1, "Needs Human Review": 1}
    assert inc["minutes"] == 20 and inc["techniques"] == [{"id": "T1003", "name": "T1003"}]
    assert [a["alert_id"] for a in inc["alerts"]] == ["hq:1", "hq:2", "hq:3"]          # timeline order
    assert inc["id"] == incidents.incident_id("hq:1")


def test_closed_incident_and_select():
    built = incidents.build([alert(1, 0), alert(2, 1), alert(3, 500, host="x", user="y")])
    now = T0 + timedelta(hours=10)
    assert [i["count"] for i in incidents.select(built, status="all", now=now)] == [2]   # singles left out
    assert incidents.select(built, status="attention", now=now) == []
    assert incidents.select(built, status="all", now=T0 + timedelta(days=9)) == []      # older than 7 days
    assert len(incidents.select(built, status="all", range_key="30d", now=T0 + timedelta(days=9))) == 1
    idx = incidents.alert_index(built)
    assert idx["hq:1"] == idx["hq:2"] and idx["hq:1"][1] == 2 and "hq:3" not in idx
