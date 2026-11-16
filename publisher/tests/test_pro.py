"""Pro / MSP pages against a real Postgres: Insights, tuning advisor, CSV export, re-triage, usage export.
Same throwaway '_test' database as test_auth.py; uses its own SIEM id 'tpro' so other tests are unaffected."""
import csv
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app as app_module  # noqa: E402
import auth  # noqa: E402
import editions  # noqa: E402
from sqlalchemy import text  # noqa: E402

BASE = "https://localhost"
NOW = datetime.now(timezone.utc)


def set_license(tier):
    with auth.engine.begin() as c:
        c.execute(text("INSERT INTO license_state (id, install_id) VALUES (1, 'test') ON CONFLICT (id) DO NOTHING"))
        c.execute(text("UPDATE license_state SET tier = :t, valid_until = NOW() + interval '30 days' WHERE id = 1"),
                  {"t": tier})
    editions.reset_cache()
    app_module._cache["at"] = 0


def add_alert(n, verdict, rule="Whoami Process Activity", exe=r"C:\Windows\System32\whoami.exe",
              parent=r"C:\Windows\System32\cmd.exe", user="helpdesk1", host="ws-it-03", tactic="Discovery",
              siem="tpro", days_ago=1, count=1):
    aid = f"{siem}:p{n}"
    ts = NOW - timedelta(days=days_ago, minutes=n)
    res = {"verdict": verdict, "severity": "High" if verdict == "True Positive" else "Low", "confidence": 88,
           "summary": f"summary {n}", "rule_name": rule, "hostname": host, "alert_id": aid,
           "rule_mitre": [{"tactic": tactic, "technique_id": "T1", "technique": "x"}],
           "investigation": {"duration_ms": 120000}}
    with auth.engine.begin() as c:
        c.execute(text("""INSERT INTO alerts (alert_id, timestamp, first_seen, status, rule_name, host_name, user_name,
                                              siem, elastic_id, count, process_executable, parent_executable)
                          VALUES (:a, :ts, :ts, 'done', :r, :h, :u, :s, :e, :c, :x, :p)"""),
                  {"a": aid, "ts": ts, "r": rule, "h": host, "u": user, "s": siem, "e": f"p{n}", "c": count,
                   "x": exe, "p": parent})
        c.execute(text("""INSERT INTO triage_results (alert_id, response, result, verdict, severity, confidence,
                                                      duration_ms, created_at)
                          VALUES (:a, :resp, CAST(:resj AS jsonb), :v, :sev, 88, 120000, :ts)"""),
                  {"a": aid, "resp": json.dumps(res), "resj": json.dumps(res), "v": verdict, "sev": res["severity"], "ts": ts})
    return aid


def user(name, role, siems=None):
    with auth.engine.begin() as c:
        if not c.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": name}).first():
            auth.create_user("test", name, role, None, siems)
    return name


@pytest.fixture(scope="module", autouse=True)
def seeded():
    with auth.engine.begin() as c:
        c.execute(text("INSERT INTO siems (id, name, position) VALUES ('tpro', 'Pro Test', 9), ('tother', 'Other', 10) "
                       "ON CONFLICT DO NOTHING"))
    for n in range(6):
        add_alert(n, "Benign Positive")                                    # tunable pattern, 6 alerts
    for n in range(6, 12):
        add_alert(n, "Benign Positive", rule="LSASS Memory Dump", exe=r"C:\Tools\procdump.exe",
                  tactic="Credential Access")                                # never suggested
    for n in range(12, 17):
        add_alert(n, "Benign Positive", rule="Service Install", exe=r"C:\svc\x.exe")
    add_alert(17, "True Positive", rule="Service Install", exe=r"C:\svc\x.exe")   # spoils that pattern
    add_alert(18, "True Positive", rule="=HYPERLINK(\"https://evil\",\"x\")", exe=r"C:\a.exe")
    add_alert(19, "Needs Human Review", rule="Odd", exe=r"C:\b.exe", count=3)
    add_alert(20, "Benign Positive", siem="tother", rule="Other customer rule")
    yield


def sso_client(name, monkeypatch):
    monkeypatch.setattr(app_module, "SSO_ENABLED", True)
    c = app_module.app.test_client()
    c.get("/", base_url=BASE, headers={app_module.SSO_HEADER: name})
    return c


def get(c, path, name):
    return c.get(path, base_url=BASE, headers={app_module.SSO_HEADER: name})


def post(c, path, name):
    html = get(c, "/", name).get_data(as_text=True)
    import re
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    return c.post(path, base_url=BASE, headers={app_module.SSO_HEADER: name, "Origin": BASE, "X-CSRF-Token": csrf})


def test_community_sees_what_pro_adds(monkeypatch):
    set_license("pro")                        # SSO itself needs Pro: sign in first, then drop to Community
    name = user("pro.admin", "admin")
    c = sso_client(name, monkeypatch)
    set_license("community")
    monkeypatch.setattr(editions, "has", lambda f: f == "sso")
    html = get(c, "/insights/report", name).get_data(as_text=True)
    assert "The report your manager asks for" in html and "PRO feature" in html
    assert get(c, "/api/alerts.csv", name).status_code == 403
    assert post(c, "/api/alerts/tpro:p0/retriage", name).status_code == 403


def test_report_numbers(monkeypatch):
    set_license("pro")
    name = user("pro.admin", "admin")
    c = sso_client(name, monkeypatch)
    html = get(c, "/insights/report?range=7d&siem=tpro", name).get_data(as_text=True)
    # 20 alerts in tpro (22 raw: one alert counted 3 times), 17 closed, 1 review, 2 true positives
    assert "<b>22</b>" in html and "20 after merging duplicates" in html
    assert "<b>85%</b>" in html and "17 with cited evidence" in html
    assert "1 for review, 2 true positives" in html
    assert "Other customer rule" not in html


def test_tuning_suggests_only_safe_patterns(monkeypatch):
    set_license("pro")
    name = user("pro.analyst", "analyst")
    c = sso_client(name, monkeypatch)
    html = get(c, "/insights/tuning?siem=tpro", name).get_data(as_text=True)
    assert "Whoami Process Activity" in html and r"C:\\Windows\\System32\\whoami.exe" in html
    assert "LSASS Memory Dump" not in html                 # credential access: never
    assert "Service Install" not in html                   # a true positive in the pattern: never
    assert '&#34;field&#34;: &#34;host.name&#34;' in html  # one host -> host added to the exception


def test_viewer_cannot_open_tuning(monkeypatch):
    set_license("pro")
    name = user("pro.viewer", "viewer")
    c = sso_client(name, monkeypatch)
    assert get(c, "/insights/tuning", name).status_code == 403
    assert get(c, "/insights/report", name).status_code == 200


def test_restricted_user_only_sees_own_siem(monkeypatch):
    set_license("pro")
    name = user("cust.viewer", "viewer", ["tother"])
    c = sso_client(name, monkeypatch)
    html = get(c, "/insights/report?range=7d", name).get_data(as_text=True)
    assert "Whoami" not in html and "Other customer rule" in html
    assert "have access to that SIEM" in get(c, "/insights/report?siem=tpro", name).get_data(as_text=True)


def test_csv_export_neutralises_formulas(monkeypatch):
    set_license("pro")
    name = user("pro.admin", "admin")
    c = sso_client(name, monkeypatch)
    r = get(c, "/api/alerts.csv?siem=tpro", name)
    assert r.status_code == 200 and r.mimetype == "text/csv"
    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    rules = [row[2] for row in rows[1:]]
    assert "'=HYPERLINK(\"https://evil\",\"x\")" in rules
    assert not any(cell.startswith("=") for row in rows for cell in row)


def test_retriage(monkeypatch):
    set_license("pro")
    name = user("pro.analyst", "analyst")
    c = sso_client(name, monkeypatch)
    assert post(c, "/api/alerts/tpro:p1/retriage", name).status_code == 200
    with auth.engine.begin() as conn:
        row = conn.execute(text("SELECT status, attempts FROM alerts WHERE alert_id = 'tpro:p1'")).mappings().first()
    assert row["status"] == "retry" and row["attempts"] == 0
    assert post(c, "/api/alerts/tpro:p1/retriage", name).status_code == 409
    viewer = user("pro.viewer", "viewer")
    cv = sso_client(viewer, monkeypatch)
    assert post(cv, "/api/alerts/tpro:p2/retriage", viewer).status_code == 403


def test_usage_export_needs_msp_and_admin(monkeypatch):
    set_license("pro")
    name = user("pro.admin", "admin")
    c = sso_client(name, monkeypatch)
    month = NOW.strftime("%Y-%m")
    assert get(c, f"/admin/usage.csv?month={month}", name).status_code == 403
    set_license("msp")
    r = get(c, f"/admin/usage.csv?month={month}", name)
    assert r.status_code == 200
    rows = {row[1]: row for row in csv.reader(io.StringIO(r.get_data(as_text=True)))}
    assert rows["tother"][3] == "1"
    analyst = user("pro.analyst", "analyst")
    assert get(sso_client(analyst, monkeypatch), "/admin/usage.csv", analyst).status_code == 403
    set_license("community")
