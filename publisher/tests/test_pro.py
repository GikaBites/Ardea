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


# --------------------------------------------------------------------------- incidents
def test_incidents_need_pro(monkeypatch):
    set_license("pro")
    name = user("pro.admin", "admin")
    c = sso_client(name, monkeypatch)
    set_license("community")
    monkeypatch.setattr(editions, "has", lambda f: f == "sso")
    html = get(c, "/incidents", name).get_data(as_text=True)
    assert "One incident instead of fifteen alerts" in html and "PRO feature" in html
    assert "Need a person" not in html
    assert "incident" not in json.dumps(get(c, "/api/alerts?siem=tpro", name).get_json()["alerts"][0])


def test_incidents_group_the_seeded_alerts(monkeypatch):
    set_license("pro")
    name = user("pro.viewer", "viewer")
    c = sso_client(name, monkeypatch)
    html = get(c, "/incidents?siem=tpro", name).get_data(as_text=True)
    assert "Need a person (1)" in html and "20 alerts" in html and "on ws-it-03" in html
    assert "=HYPERLINK(&#34;https://evil&#34;" in html and "<b>x" not in html          # titles are escaped
    inc_id = __import__("re").search(r'href="/incidents/(inc-[0-9a-f]{12})"', html).group(1)
    detail = get(c, f"/incidents/{inc_id}", name).get_data(as_text=True)
    assert detail.count('class="inc-step ') == 20 and "helpdesk1" in detail and "Needs a person" in detail
    assert "/?q=tpro%3Ap0" in detail
    alerts = get(c, "/api/alerts?siem=tpro", name).get_json()["alerts"]
    assert all(a["incident"] == [inc_id, 20] for a in alerts)
    assert "Other customer rule" not in get(c, "/incidents?status=all", name).get_data(as_text=True)  # single alert


def test_incidents_respect_siem_access(monkeypatch):
    set_license("pro")
    admin = user("pro.admin", "admin")
    c = sso_client(admin, monkeypatch)
    html = get(c, "/incidents?siem=tpro", admin).get_data(as_text=True)
    inc_id = __import__("re").search(r'href="/incidents/(inc-[0-9a-f]{12})"', html).group(1)
    name = user("cust.viewer", "viewer", ["tother"])
    c2 = sso_client(name, monkeypatch)
    assert "ws-it-03" not in get(c2, "/incidents?status=all&range=30d", name).get_data(as_text=True)
    assert get(c2, f"/incidents/{inc_id}", name).status_code == 404
    assert get(c2, "/incidents/inc-000000000000", name).status_code == 404


# --------------------------------------------------------------------------- silent sources and digest
def _health_rows(rows):
    with auth.engine.begin() as c:
        c.execute(text("""CREATE TABLE IF NOT EXISTS source_health (siem TEXT PRIMARY KEY, checked_at TIMESTAMPTZ,
                          last_event_at TIMESTAMPTZ, status TEXT NOT NULL DEFAULT 'ok', detail TEXT,
                          failures INT NOT NULL DEFAULT 0, quiet_hosts JSONB NOT NULL DEFAULT '[]'::jsonb,
                          changed_at TIMESTAMPTZ)"""))
        c.execute(text("DELETE FROM source_health"))
        for siem, status, detail, hosts in rows:
            c.execute(text("INSERT INTO source_health (siem, status, detail, quiet_hosts) VALUES (:s, :st, :d, "
                           "CAST(:h AS jsonb))"), {"s": siem, "st": status, "d": detail, "h": json.dumps(hosts)})
    app_module._alarm_cache["at"] = 0


def test_silent_source_banner(monkeypatch):
    _health_rows([("tpro", "silent", "no events since 18/11 06:00 UTC", []),
                  ("tother", "ok", None, [{"host": "dc-01", "last": None}])])
    set_license("pro")
    admin = user("pro.admin", "admin")
    c = sso_client(admin, monkeypatch)
    html = get(c, "/", admin).get_data(as_text=True)
    assert "A data source went quiet." in html and "Pro Test has sent no events since 18/11 06:00 UTC" in html
    assert "dc-01" not in html                                     # watched hosts: MSP
    assert 'href="/admin/settings/monitoring"' in html
    set_license("msp")
    assert "Other: watched host dc-01 stopped sending events." in get(c, "/incidents", admin).get_data(as_text=True)
    cust = user("cust.viewer", "viewer", ["tother"])
    c2 = sso_client(cust, monkeypatch)
    html = get(c2, "/", cust).get_data(as_text=True)
    assert "Pro Test" not in html and "dc-01" in html and "/admin/settings/monitoring" not in html
    set_license("community")
    monkeypatch.setattr(editions, "has", lambda f: f == "sso")
    assert "A data source went quiet." not in get(c, "/", admin).get_data(as_text=True)
    _health_rows([])


def test_monitoring_settings_tab(monkeypatch):
    set_license("pro")
    admin = user("pro.admin", "admin")
    c = sso_client(admin, monkeypatch)
    html = get(c, "/admin/settings/monitoring", admin).get_data(as_text=True)
    assert 'data-test="health"' in html and 'data-test="digest"' in html
    assert "Every day at 08:00" in html and "Hosts that must never go quiet" in html
    r = post(c, "/admin/settings/test", admin)
    assert r.status_code == 400                                    # no kind given


# --------------------------------------------------------------------------- queue and deadlines
def form_post(c, path, name, data):
    html = get(c, "/", name).get_data(as_text=True)
    import re
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    return c.post(path, base_url=BASE, data={"csrf_token": csrf, **data},
                  headers={app_module.SSO_HEADER: name, "Origin": BASE})


def test_queue_needs_pro(monkeypatch):
    set_license("pro")
    name = user("pro.admin", "admin")
    c = sso_client(name, monkeypatch)
    set_license("community")
    monkeypatch.setattr(editions, "has", lambda f: f == "sso")
    assert "Nothing that needs a person falls through the cracks" in get(c, "/queue", name).get_data(as_text=True)
    assert form_post(c, "/queue/work", name, {"one": "tpro:p17"}).status_code == 403


def test_queue_take_assign_resolve(monkeypatch):
    set_license("pro")
    analyst = user("pro.analyst", "analyst")
    user("pro.admin", "admin")
    cust = user("cust.analyst", "analyst", ["tother"])
    c = sso_client(analyst, monkeypatch)
    html = get(c, "/queue?who=all", analyst).get_data(as_text=True)
    assert html.count('name="alert_id" value="tpro:') == 3                  # 2 true positives + 1 review
    assert "Overdue" in html
    assert get(c, "/queue?who=unassigned", analyst).get_data(as_text=True).count('name="alert_id" value="tpro:') == 3
    r = form_post(c, "/queue/work", analyst, {"one": "tpro:p17", "back": "/queue?who=mine"})
    assert r.status_code == 303 and "done=1" in r.headers["Location"]
    assert "Mine (1)" in get(c, "/queue?who=mine", analyst).get_data(as_text=True)
    r = form_post(c, "/queue/work", analyst, {"alert_id": ["tpro:p18", "tpro:p19"], "action": "assign",
                                              "assignee": cust})              # cust may not see tpro
    assert "error=" in r.headers["Location"]
    r = form_post(c, "/queue/work", analyst, {"alert_id": ["tpro:p18", "tpro:p19"], "action": "assign",
                                              "assignee": "pro.admin"})
    assert "done=2" in r.headers["Location"]
    r = form_post(c, "/queue/work", analyst, {"alert_id": "tpro:p17", "action": "resolve"})
    assert "error=" in r.headers["Location"]                                  # a note is required
    form_post(c, "/queue/work", analyst, {"alert_id": "tpro:p17", "action": "resolve", "note": "Host reimaged"})
    html = get(c, "/queue?who=all", analyst).get_data(as_text=True)
    assert 'value="tpro:p17"' not in html
    assert 'value="tpro:' not in get(c, "/queue?who=unassigned", analyst).get_data(as_text=True)
    assert "Host reimaged" in get(c, "/queue?who=all&handled=1", analyst).get_data(as_text=True)
    inc = __import__("re").search(r'href="/incidents/(inc-[0-9a-f]{12})"',
                                  get(c, "/incidents?siem=tpro", analyst).get_data(as_text=True)).group(1)
    page = get(c, f"/incidents/{inc}", analyst).get_data(as_text=True)
    assert "Who is on it" in page and "took it" in page and "resolved: Host reimaged" in page
    # someone who cannot see the SIEM cannot touch its alerts
    c2 = sso_client(cust, monkeypatch)
    r = form_post(c2, "/queue/work", cust, {"one": "tpro:p18", "one_action": "take"})
    assert "done" not in r.headers["Location"]
    viewer = user("pro.viewer", "viewer")
    c3 = sso_client(viewer, monkeypatch)
    assert form_post(c3, "/queue/work", viewer, {"one": "tpro:p18"}).status_code == 403
    assert 'name="one"' not in get(c3, "/queue?who=all", viewer).get_data(as_text=True)


# --------------------------------------------------------------------------- NIS2 drafts
def _tpro_incident(c, name):
    import re
    return re.search(r'href="/incidents/(inc-[0-9a-f]{12})"', get(c, "/incidents?siem=tpro&status=all&range=30d",
                                                                   name).get_data(as_text=True)).group(1)


def test_nis2_drafts(monkeypatch):
    import nis2
    import settings_admin
    set_license("pro")
    name = user("pro.analyst", "analyst")
    c = sso_client(name, monkeypatch)
    inc = _tpro_incident(c, name)
    html = get(c, f"/incidents/{inc}", name).get_data(as_text=True)
    assert f'href="/incidents/{inc}/nis2"' in html
    page = get(c, f"/incidents/{inc}/nis2", name).get_data(as_text=True)
    assert "NIS2 EARLY WARNING (DRAFT)" in page and "Yes, suspected" in page and "ws-it-03" in page
    assert "helpdesk1" in page and "[TO COMPLETE: legal name of the entity]" in page
    import work
    work.update(["tpro:p17"], "pro.analyst", "resolve", note="Host reimaged")
    monkeypatch.setattr(settings_admin, "publisher_value",
                        lambda n, d="": {"NIS2_ENTITY": "Acme Ltd"}.get(n, d))
    r = get(c, f"/incidents/{inc}/nis2?stage=final&download=1", name)
    body = r.get_data(as_text=True)
    assert r.headers["Content-Disposition"] == f'attachment; filename="nis2-final-{inc}.txt"'
    assert "Name: Acme Ltd" in body and "7. ROOT CAUSE AND LESSONS" in body and "5. INITIAL ASSESSMENT" in body
    assert "Done: Host reimaged" in body                                    # the resolved note from the queue test
    found = nis2.indicators([{"detail": {"summary": "upd.exe beacons to 203.0.113.45:443 and evil-cdn.top; "
                                                    "sha256 " + "a" * 64, "findings": []}}])
    assert found == {"IP addresses": ["203.0.113.45:443"], "Domains": ["evil-cdn.top"],
                     "File hashes": ["a" * 64], "Files": ["upd.exe"]}


def test_nis2_needs_pro_and_siem_access(monkeypatch):
    set_license("pro")
    admin = user("pro.admin", "admin")
    c = sso_client(admin, monkeypatch)
    inc = _tpro_incident(c, admin)
    cust = user("cust.viewer", "viewer", ["tother"])
    assert get(sso_client(cust, monkeypatch), f"/incidents/{inc}/nis2", cust).status_code == 404
    set_license("community")
    monkeypatch.setattr(editions, "has", lambda f: f == "sso")
    assert "The NIS2 report, drafted from the evidence" in get(c, f"/incidents/{inc}/nis2", admin).get_data(as_text=True)


# --------------------------------------------------------------------------- incident export
def test_incident_export_zip(monkeypatch):
    import zipfile
    set_license("pro")
    name = user("pro.viewer", "viewer")
    c = sso_client(name, monkeypatch)
    inc = _tpro_incident(c, name)
    assert f'/incidents/{inc}/export.zip' in get(c, f"/incidents/{inc}", name).get_data(as_text=True)
    r = get(c, f"/incidents/{inc}/export.zip", name)
    assert r.status_code == 200 and r.mimetype == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.data))
    names = set(z.namelist())
    assert {"report.md", "timeline.csv", "incident.json", "README.txt", "trails/tpro_p0.json"} <= names
    rows = list(csv.reader(io.StringIO(z.read("timeline.csv").decode())))
    assert rows[0][0] == "time" and len(rows) == 21
    assert any(r_[5].startswith("'=HYPERLINK") for r_ in rows[1:])            # formulas neutralised
    data = json.loads(z.read("incident.json"))
    assert data["count"] == 20 and data["hosts"] == ["ws-it-03"] and len(data["alerts"]) == 20
    assert "## Timeline" in z.read("report.md").decode()
    cust = user("cust.viewer", "viewer", ["tother"])
    assert get(sso_client(cust, monkeypatch), f"/incidents/{inc}/export.zip", cust).status_code == 404
