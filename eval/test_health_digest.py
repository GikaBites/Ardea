"""Silent-source alarm and daily handover digest, against a real Postgres (EMPTY database ending in '_test')."""
import json
import os
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

import appsettings  # noqa: E402
import db  # noqa: E402
import digest  # noqa: E402
import elastic  # noqa: E402
import health  # noqa: E402
import licensing  # noqa: E402
import settings_tests  # noqa: E402

NOW = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
INIT_SQL = pathlib.Path(__file__).resolve().parents[1] / "db" / "init.sql"


@pytest.fixture
def conn(monkeypatch):
    monkeypatch.setattr(appsettings, "OVERLAY", {})
    for n in ("SOURCE_SILENCE_MINUTES", "HOST_WATCH", "HOST_SILENCE_MINUTES", "DIGEST_TIME"):
        monkeypatch.delenv(n, raising=False)
    c = db.get_connection()
    if not c.execute("SELECT to_regclass('public.alerts') AS t").fetchone()["t"]:
        c.execute(INIT_SQL.read_text())
    health.ensure_schema(c)
    with c.transaction():
        appsettings.ensure_schema(c.execute)
    c.execute("INSERT INTO siems (id, name) VALUES ('hq', 'Head office'), ('branch', 'Branch') ON CONFLICT DO NOTHING")
    for t in ("source_health", "report_runs", "feedback", "notifications", "investigation_steps", "triage_results",
              "alert_occurrences", "alerts"):
        c.execute(f"DELETE FROM {t}")
    licensing.set_tier("pro")
    yield c
    c.close()


class FakeSiem:
    """newest_events stand-in: what each SIEM would answer."""
    def __init__(self):
        self.answers = {}

    def __call__(self, siem, watch):
        a = self.answers.get(siem.id, (NOW - timedelta(minutes=5), {}))
        if isinstance(a, Exception):
            raise a
        return a


@pytest.fixture
def fake(monkeypatch):
    f = FakeSiem()
    monkeypatch.setattr(health, "newest_events", f)
    return f


def run(conn):
    return [t for t, _, _ in health.run_due(conn, now=NOW, force=True, send=lambda *a: None)]


def test_a_silent_siem_warns_once_and_recovery_is_announced(conn, fake):
    assert run(conn) == []
    fake.answers["hq"] = (NOW - timedelta(hours=3), {})
    assert run(conn) == ["Head office: no events"]
    row = conn.execute("SELECT status, detail FROM source_health WHERE siem = 'hq'").fetchone()
    assert row["status"] == "silent" and "no events since 18/11 06:00" in row["detail"]
    assert run(conn) == []                                                   # no repeat while it lasts
    fake.answers["hq"] = (NOW - timedelta(minutes=1), {})
    assert run(conn) == ["Head office: events are arriving again"]


def test_no_events_at_all_and_threshold_off(conn, fake, monkeypatch):
    fake.answers["branch"] = (None, {})
    assert run(conn) == ["Branch: no events"]
    assert "last 7 days" in conn.execute("SELECT detail FROM source_health WHERE siem='branch'").fetchone()["detail"]
    monkeypatch.setitem(appsettings.OVERLAY, "SOURCE_SILENCE_MINUTES", "0")
    assert run(conn) == []                                                   # switched off: no "recovered" message
    assert conn.execute("SELECT status FROM source_health WHERE siem='branch'").fetchone()["status"] == "ok"


def test_unreachable_needs_two_failures_in_a_row(conn, fake):
    fake.answers["hq"] = ConnectionError("down")
    assert run(conn) == []
    assert run(conn) == ["Head office: cannot be reached"]
    assert "ConnectionError" in conn.execute("SELECT detail FROM source_health WHERE siem='hq'").fetchone()["detail"]


def test_watched_hosts_need_msp(conn, fake, monkeypatch):
    monkeypatch.setitem(appsettings.OVERLAY, "HOST_WATCH", "dc-*\nsrv-sql-01\nws-*")
    fake.answers["hq"] = (NOW, {"dc-01": NOW - timedelta(hours=2), "dc-02": NOW, "ws-77": NOW - timedelta(days=2)})
    assert run(conn) == []                                                   # Pro: hosts are not watched
    licensing.set_tier("msp")
    titles = run(conn)
    assert titles == ["Head office: 3 watched host(s) went quiet", "Branch: 1 watched host(s) went quiet"]
    quiet = conn.execute("SELECT quiet_hosts FROM source_health WHERE siem='hq'").fetchone()["quiet_hosts"]
    assert [h["host"] for h in quiet] == ["dc-01", "srv-sql-01", "ws-77"] and quiet[1]["last"] is None
    fake.answers["hq"] = (NOW, {"dc-01": NOW, "dc-02": NOW, "ws-77": NOW, "srv-sql-01": NOW})
    assert run(conn) == ["Head office: watched host(s) reporting again"]       # branch still lacks srv-sql-01


def test_newest_events_reads_every_events_index(monkeypatch):
    calls = []

    def search(index, body):
        calls.append((index, body))
        ms = {"logs-endpoint*": 1_700_000_000_000, "logs-windows*": 1_700_000_600_000}[index]
        return {"aggregations": {"last": {"value": ms},
                                 "hosts": {"buckets": [{"key": "DC-01", "last": {"value": ms}}]}}}
    monkeypatch.setattr(elastic, "search", search)
    newest, hosts = health.newest_events(elastic.configured()["branch"], ["dc-*"])
    assert [c[0] for c in calls] == ["logs-endpoint*", "logs-windows*"]
    assert newest == datetime.fromtimestamp(1_700_000_600, timezone.utc) and hosts == {"dc-01": newest}
    assert calls[0][1]["size"] == 0 and "hosts" in calls[0][1]["aggs"]
    health.newest_events(elastic.configured()["branch"], [])
    assert "hosts" not in calls[-1][1]["aggs"]                               # no host list without a watch list


def test_community_never_checks(conn, fake):
    licensing.set_tier("community")
    fake.answers["hq"] = ConnectionError("x")
    assert health.run_due(conn, now=NOW, force=True) == []


# --------------------------------------------------------------------------- digest
def add(conn, n, verdict, severity="Low", minutes_ago=60, host="ws-01", user="alice", rule="Rule A", reviewed=False,
        siem="hq"):
    aid = f"{siem}:d{n}"
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    conn.execute("""INSERT INTO alerts (alert_id, timestamp, status, rule_name, host_name, user_name, siem, count)
                    VALUES (%s, %s, 'done', %s, %s, %s, %s, 1)""", (aid, ts, rule, host, user, siem))
    conn.execute("""INSERT INTO triage_results (alert_id, response, result, verdict, severity, should_escalate)
                    VALUES (%s, '{}', %s, %s, %s, %s)""",
                 (aid, json.dumps({"mitre_techniques": [{"technique_id": "T1059", "name": "Scripting"}]}),
                  verdict, severity, verdict == "True Positive"))
    if reviewed:
        conn.execute("INSERT INTO feedback (alert_id, analyst, agrees) VALUES (%s, 'bob', TRUE)", (aid,))


def test_digest_due_window(monkeypatch):
    licensing.set_tier("pro")
    monkeypatch.setattr(appsettings, "OVERLAY", {"DIGEST_TIME": "08:00"})
    monkeypatch.delenv("DIGEST_TIME", raising=False)
    day = datetime(2026, 11, 18, tzinfo=timezone(timedelta(hours=2)))
    assert digest.due(day.replace(hour=7, minute=59)) is None
    assert digest.due(day.replace(hour=8, minute=4)) == "digest:2026-11-18"
    assert digest.due(day.replace(hour=11, minute=30)) is None                  # more than 3 hours late
    licensing.set_tier("community")
    assert digest.due(day.replace(hour=8, minute=4)) is None
    licensing.set_tier("pro")
    appsettings.OVERLAY["DIGEST_TIME"] = "off"
    assert digest.due(day.replace(hour=8, minute=4)) is None


def test_digest_content(conn):
    for n in range(5):
        add(conn, n, "Benign Positive", rule="Backup job", minutes_ago=300 + n)
    add(conn, 5, "False Positive", rule="Updater", host="ws-09", user="")
    add(conn, 6, "True Positive", "High", minutes_ago=50, rule="Mimikatz", host="ws-02")
    add(conn, 7, "Needs Human Review", "Medium", minutes_ago=40, rule="Odd PowerShell", host="ws-02")
    add(conn, 8, "Needs Human Review", "Low", minutes_ago=30, rule="Reviewed already", host="ws-50", user="x",
        reviewed=True)
    add(conn, 9, "True Positive", "Critical", minutes_ago=60 * 30, rule="Too old")
    conn.execute("INSERT INTO source_health (siem, status, detail) VALUES ('branch', 'silent', 'no events since x')")
    title, body, _ = digest.build(conn)
    assert title.endswith(": 2 waiting for a person, 6 closed")
    assert "Alerts triaged:        9" in body and "Closed with evidence:  6" in body
    assert body.index("[High] True Positive: Mimikatz on ws-02") < body.index("[Medium] Needs Human Review: Odd")
    assert "Reviewed already" not in body and "Too old" not in body
    assert "Backup job: 5" in body and "Branch: no events since x" in body
    assert "INCIDENTS WITH SEVERAL ALERTS (1)" in body and "Mimikatz on ws-02" in body


def test_digest_is_sent_once_a_day(conn, monkeypatch):
    monkeypatch.setitem(appsettings.OVERLAY, "DIGEST_TIME", "08:00")
    add(conn, 1, "True Positive", "High")
    sent = []
    when = datetime.now().astimezone().replace(hour=8, minute=10)
    assert digest.run_due(conn, when, send=lambda *a: sent.append(a)) == f"digest:{when:%Y-%m-%d}"
    assert digest.run_due(conn, when, send=lambda *a: sent.append(a)) is None
    assert len(sent) == 1 and "1 waiting for a person" in sent[0][0]


def test_digest_button_explains_missing_channels(conn, monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_CHANNELS", [])
    conn.execute("DELETE FROM settings_tests")
    conn.execute("INSERT INTO settings_tests (kind, requested_by) VALUES ('digest', 'a'), ('health', 'a')")
    monkeypatch.setattr(health, "newest_events", lambda siem, watch: (datetime.now(timezone.utc), {}))
    settings_tests.run_pending(conn)
    rows = conn.execute("SELECT kind, status, detail FROM settings_tests ORDER BY id").fetchall()
    assert rows[0]["status"] == "failed" and "No notification channel" in rows[0]["detail"]
    assert rows[1]["status"] == "ok" and "Head office: OK" in rows[1]["detail"]


# --------------------------------------------------------------------------- overdue alerts
def test_overdue_alerts_are_announced_once(conn):
    import sla
    conn.execute("DELETE FROM alert_work")
    add(conn, 1, "True Positive", "High", minutes_ago=5 * 60)               # due 4 h after: 1 h overdue
    add(conn, 2, "Needs Human Review", "Critical", minutes_ago=3 * 24 * 60)  # overdue for days: not announced
    add(conn, 3, "True Positive", "High", minutes_ago=6 * 60, reviewed=True)
    add(conn, 4, "Needs Human Review", "Medium", minutes_ago=60)            # due in 23 h
    add(conn, 5, "True Positive", "Critical", minutes_ago=90)               # due 60 min: overdue
    add(conn, 6, "Benign Positive", "Low", minutes_ago=5 * 24 * 60)
    conn.execute("INSERT INTO alert_work (alert_id, status) VALUES ('hq:d5', 'resolved')")
    sent = []
    assert sla.run_due(conn, send=lambda *a: sent.append(a)) == ["hq:d1"]
    assert sent[0][0] == "1 alert passed the response deadline" and "nobody assigned" in sent[0][1]
    assert sla.run_due(conn, send=lambda *a: sent.append(a)) == [] and len(sent) == 1
    licensing.set_tier("community")
    add(conn, 7, "True Positive", "High", minutes_ago=5 * 60)
    assert sla.run_due(conn, send=lambda *a: sent.append(a)) == []


def test_sla_minutes_follow_the_settings(monkeypatch):
    import sla
    monkeypatch.setattr(appsettings, "OVERLAY", {"SLA_HIGH_MINUTES": "30"})
    monkeypatch.delenv("SLA_HIGH_MINUTES", raising=False)
    assert sla.minutes("High") == 30 and sla.minutes("Critical") == 60 and sla.minutes("Informational") == 4320


def test_no_overdue_messages_when_the_queue_is_off(conn, monkeypatch):
    import sla
    conn.execute("DELETE FROM alert_work")
    add(conn, 1, "True Positive", "High", minutes_ago=5 * 60)
    monkeypatch.setitem(appsettings.OVERLAY, "QUEUE_ENABLED", "false")
    assert sla.run_due(conn, send=lambda *a: None) == []
