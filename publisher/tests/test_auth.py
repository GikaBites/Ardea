"""End-to-end tests of login, roles, sessions and user administration against a real Postgres.

Needs an EMPTY throwaway database whose name ends in '_test' (it creates the default admin):
    POSTGRES_HOST=... POSTGRES_DB=ardea_test POSTGRES_USER=... POSTGRES_PASSWORD=... pytest publisher/tests -q
The tables of db/init.sql must exist (psql -f db/init.sql). The tests run in order and share state.
"""
import logging
import os
import re
import sys
import time

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_captured = []


class _Capture(logging.Handler):
    def emit(self, record):
        _captured.append(record.getMessage())


logging.getLogger("ardea.auth").addHandler(_Capture())
import app as app_module  # noqa: E402  (creates the schema and the default admin)
import auth  # noqa: E402
from sqlalchemy import text  # noqa: E402

BASE = "https://localhost"
STATE = {}


def client():
    return app_module.app.test_client()


def post(c, path, data=None, csrf=None, origin=BASE, **kw):
    headers = {"Origin": origin} if origin else {}
    data = dict(data or {})
    if csrf:
        data["csrf_token"] = csrf
    return c.post(path, base_url=BASE, data=data, headers=headers, **kw)


def get(c, path, **kw):
    return c.get(path, base_url=BASE, **kw)


def csrf_of(c):
    html = get(c, "/account/password").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def login(c, username, password):
    return post(c, "/login", {"username": username, "password": password, "next": "/"})


# --------------------------------------------------------------------------- first start
def test_default_admin_created_with_logged_one_time_password():
    msg = next(m for m in _captured if "Temporary password" in m)
    STATE["admin_pw"] = re.search(r"Temporary password: (\S+)", msg).group(1)
    users = auth.list_users()
    assert [(u["username"], u["role"], u["must_change_password"]) for u in users] == [("admin", "admin", True)]
    auth.ensure_schema_and_admin()                   # a second start creates nothing
    assert len(auth.list_users()) == 1


def test_everything_requires_login():
    c = client()
    r = get(c, "/")
    assert r.status_code == 302 and r.headers["Location"].startswith("/login")
    assert get(c, "/api/alerts").status_code == 401
    assert get(c, "/stream").status_code == 401
    assert get(c, "/admin/users").status_code == 302
    assert get(c, "/healthz").status_code == 200
    assert get(c, "/static/css/style.css").status_code == 200


def test_wrong_password_is_rejected():
    c = client()
    r = login(c, "admin", "not-the-password")
    assert r.status_code == 401 and auth.COOKIE_NAME not in r.headers.get("Set-Cookie", "")


def test_login_cross_origin_is_rejected():
    c = client()
    r = post(c, "/login", {"username": "admin", "password": STATE["admin_pw"]}, origin="https://evil.example")
    assert r.status_code == 403


def test_browser_form_post_with_origin_null_is_accepted():
    """What Chromium sends for a form post: Origin: null plus Sec-Fetch-Site: same-origin."""
    c = client()
    browser = {"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}
    r = c.post("/login", base_url=BASE, data={"username": "nobody", "password": "x"}, headers=browser)
    assert r.status_code == 401                                   # reached the password check, not 403
    for forged in ({"Origin": "null", "Sec-Fetch-Site": "cross-site"}, {"Origin": "null"},
                   {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}):
        assert c.post("/login", base_url=BASE, data={"username": "nobody", "password": "x"},
                      headers=forged).status_code == 403
    # Behind a port forward / proxy that rewrites Host, Origin no longer matches Host; the browser's own
    # Sec-Fetch-Site (which other sites cannot set) still says same-origin, so the post is accepted.
    behind_nat = {"Origin": "https://ardea.example:8443", "Sec-Fetch-Site": "same-origin"}
    assert c.post("/login", base_url=BASE, data={"username": "nobody", "password": "x"},
                  headers=behind_nat).status_code == 401
    assert get(c, "/login").headers["Referrer-Policy"] == "same-origin"


def test_first_login_forces_password_change():
    c = client()
    r = login(c, "admin", STATE["admin_pw"])
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/password")
    cookie = r.headers["Set-Cookie"]
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
        assert flag in cookie
    assert cookie.startswith("__Host-")
    assert get(c, "/").headers["Location"].endswith("/account/password")
    r = get(c, "/api/alerts")
    assert r.status_code == 403 and r.get_json()["error"] == "password_change_required"
    assert get(c, "/admin/users").headers["Location"].endswith("/account/password")
    STATE["admin_client"] = c


def test_password_change_needs_csrf_and_policy():
    c = STATE["admin_client"]
    form = {"current": STATE["admin_pw"], "new": "Correct horse battery 1", "confirm": "Correct horse battery 1"}
    assert post(c, "/account/password", form).status_code == 403                       # no CSRF token
    csrf = csrf_of(c)
    assert post(c, "/account/password", form, csrf, origin="https://evil.example").status_code == 403
    weak = {"current": STATE["admin_pw"], "new": "short", "confirm": "short"}
    assert post(c, "/account/password", weak, csrf).status_code == 400
    has_name = {"current": STATE["admin_pw"], "new": "my-admin-password!", "confirm": "my-admin-password!"}
    assert post(c, "/account/password", has_name, csrf).status_code == 400
    wrong_current = dict(form, current="nope")
    assert post(c, "/account/password", wrong_current, csrf).status_code == 400


def test_password_change_succeeds_and_rotates_session():
    c = STATE["admin_client"]
    old_cookie = c.get_cookie(auth.COOKIE_NAME, domain="localhost").value
    csrf = csrf_of(c)
    form = {"current": STATE["admin_pw"], "new": "Correct horse battery 1", "confirm": "Correct horse battery 1"}
    r = post(c, "/account/password", form, csrf)
    assert r.status_code == 302 and r.headers["Location"] == "/"
    assert c.get_cookie(auth.COOKIE_NAME, domain="localhost").value != old_cookie
    assert auth.load_session(old_cookie) is None                                       # old token is dead
    r = get(c, "/")
    assert r.status_code == 200 and '"canFeedback": true' in r.get_data(as_text=True)
    assert get(c, "/api/alerts").status_code == 200
    one_time = STATE["admin_pw"]
    STATE["admin_pw"] = "Correct horse battery 1"
    STATE["admin_csrf"] = csrf_of(c)
    assert login(client(), "admin", one_time).status_code == 401          # the one-time password is gone


# --------------------------------------------------------------------------- user administration
def test_admin_creates_viewer_with_one_time_password():
    c = STATE["admin_client"]
    r = post(c, "/admin/users", {"username": "Ana.Viewer", "role": "viewer"}, STATE["admin_csrf"])
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "ana.viewer" in html
    STATE["viewer_pw"] = re.search(r'class="one-time-password">([^<]+)<', html).group(1)
    assert post(c, "/admin/users", {"username": "ana.viewer", "role": "viewer"},
                STATE["admin_csrf"]).status_code == 400                                # duplicate
    assert post(c, "/admin/users", {"username": "x", "role": "viewer"}, STATE["admin_csrf"]).status_code == 400
    assert post(c, "/admin/users", {"username": "bob", "role": "root"}, STATE["admin_csrf"]).status_code == 400


def test_viewer_must_change_password_then_is_read_only():
    c = client()
    r = login(c, "ana.viewer", STATE["viewer_pw"])
    assert r.headers["Location"].endswith("/account/password")
    csrf = csrf_of(c)
    r = post(c, "/account/password", {"current": STATE["viewer_pw"], "new": "Viewer pass phrase 22",
                                      "confirm": "Viewer pass phrase 22"}, csrf)
    assert r.status_code == 302
    page = get(c, "/").get_data(as_text=True)
    assert '"canFeedback": false' in page and "/admin/users" not in page
    assert get(c, "/admin/users").status_code == 403
    csrf = csrf_of(c)
    r = c.post("/api/alerts/x/feedback", base_url=BASE, json={"agrees": True},
               headers={"Origin": BASE, "X-CSRF-Token": csrf})
    assert r.status_code == 403
    assert post(c, "/admin/users", {"username": "sneaky", "role": "admin"}, csrf).status_code == 403
    STATE["viewer_client"] = c
    STATE["viewer_id"] = next(u["id"] for u in auth.list_users() if u["username"] == "ana.viewer")


def test_admin_feedback_allowed_with_csrf_header():
    c = STATE["admin_client"]
    with auth.engine.begin() as conn:
        conn.execute(text("INSERT INTO alerts (alert_id, timestamp) VALUES ('fb1', NOW()) ON CONFLICT DO NOTHING"))
    r = c.post("/api/alerts/fb1/feedback", base_url=BASE, json={"agrees": True},
               headers={"Origin": BASE, "X-CSRF-Token": STATE["admin_csrf"]})
    assert r.status_code == 200
    r = c.post("/api/alerts/fb1/feedback", base_url=BASE, json={"agrees": True}, headers={"Origin": BASE})
    assert r.status_code == 403


def test_analyst_can_give_feedback_but_not_manage_users():
    admin = STATE["admin_client"]
    r = post(admin, "/admin/users", {"username": "sam.analyst", "role": "analyst"}, STATE["admin_csrf"])
    otp = re.search(r'class="one-time-password">([^<]+)<', r.get_data(as_text=True)).group(1)
    c = client()
    assert login(c, "sam.analyst", otp).headers["Location"].endswith("/account/password")
    post(c, "/account/password", {"current": otp, "new": "Analyst pass phrase 7",
                                  "confirm": "Analyst pass phrase 7"}, csrf_of(c))
    page = get(c, "/").get_data(as_text=True)
    assert '"canFeedback": true' in page and "/admin/users" not in page and "ar-role--analyst" in page
    csrf = csrf_of(c)
    r = c.post("/api/alerts/fb1/feedback", base_url=BASE, json={"agrees": False, "correct_verdict": "True Positive"},
               headers={"Origin": BASE, "X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert get(c, "/admin/users").status_code == 403
    assert post(c, "/admin/users", {"username": "sneaky2", "role": "admin"}, csrf).status_code == 403
    analyst_id = next(u["id"] for u in auth.list_users() if u["username"] == "sam.analyst")
    assert post(c, f"/admin/users/{analyst_id}/role", {"role": "admin"}, csrf).status_code == 403
    # an admin can move users between all three roles
    for role in ("viewer", "admin", "analyst"):
        assert post(admin, f"/admin/users/{analyst_id}/role", {"role": role}, STATE["admin_csrf"]).status_code == 302
    # restarting with an analyst in the table keeps the widened role constraint valid
    auth.ensure_schema_and_admin()
    assert [u["role"] for u in auth.list_users() if u["username"] == "sam.analyst"] == ["analyst"]


def test_role_change_signs_the_user_out():
    c = STATE["admin_client"]
    r = post(c, f"/admin/users/{STATE['viewer_id']}/role", {"role": "admin"}, STATE["admin_csrf"])
    assert r.status_code == 302
    assert get(STATE["viewer_client"], "/api/alerts").status_code == 401
    post(c, f"/admin/users/{STATE['viewer_id']}/role", {"role": "viewer"}, STATE["admin_csrf"])


def test_admin_cannot_lock_themselves_out():
    c = STATE["admin_client"]
    admin_id = next(u["id"] for u in auth.list_users() if u["username"] == "admin")
    for path, data in ((f"/admin/users/{admin_id}/role", {"role": "viewer"}),
                       (f"/admin/users/{admin_id}/status", {"disabled": "true"}),
                       (f"/admin/users/{admin_id}/delete", {"confirm": "yes"})):
        assert post(c, path, data, STATE["admin_csrf"]).status_code == 400
    assert [u["role"] for u in auth.list_users() if u["username"] == "admin"] == ["admin"]


def test_last_admin_rule():
    with pytest.raises(auth.AuthError):
        auth.set_role(-1, "test", next(u["id"] for u in auth.list_users() if u["username"] == "admin"), "viewer", None)


def test_reset_password_and_disable():
    c = STATE["admin_client"]
    r = post(c, f"/admin/users/{STATE['viewer_id']}/reset", {}, STATE["admin_csrf"])
    new_pw = re.search(r'class="one-time-password">([^<]+)<', r.get_data(as_text=True)).group(1)
    assert login(client(), "ana.viewer", "Viewer pass phrase 22").status_code == 401   # old password gone
    v = client()
    assert login(v, "ana.viewer", new_pw).headers["Location"].endswith("/account/password")
    post(c, f"/admin/users/{STATE['viewer_id']}/status", {"disabled": "true"}, STATE["admin_csrf"])
    assert get(v, "/api/alerts").status_code == 401                                  # signed out
    assert login(client(), "ana.viewer", new_pw).status_code == 401                  # cannot log in
    post(c, f"/admin/users/{STATE['viewer_id']}/status", {"disabled": "false"}, STATE["admin_csrf"])
    assert login(client(), "ana.viewer", new_pw).status_code == 302
    STATE["viewer_pw"] = new_pw


def test_lockout_after_failed_logins():
    for _ in range(auth.MAX_FAILED_LOGINS):
        assert login(client(), "ana.viewer", "wrong password!!").status_code == 401
    assert login(client(), "ana.viewer", STATE["viewer_pw"]).status_code == 401       # locked
    assert any(u["locked"] for u in auth.list_users() if u["username"] == "ana.viewer")
    events = [e["event"] for e in auth.recent_events()]
    assert "account_locked" in events
    with auth.engine.begin() as conn:                                              # let the lock expire
        conn.execute(text("UPDATE users SET locked_until = NOW() - interval '1 second' WHERE username='ana.viewer'"))
    assert login(client(), "ana.viewer", STATE["viewer_pw"]).status_code == 302


def test_unknown_user_and_open_redirect():
    assert login(client(), "nobody", "whatever-password").status_code == 401
    c = client()
    r = post(c, "/login", {"username": "admin", "password": STATE["admin_pw"], "next": "//evil.example/x"})
    assert r.headers["Location"] == "/"
    r = post(client(), "/login", {"username": "admin", "password": STATE["admin_pw"], "next": "/admin/users"})
    assert r.headers["Location"] == "/admin/users"


def test_delete_needs_confirmation():
    c = STATE["admin_client"]
    assert post(c, f"/admin/users/{STATE['viewer_id']}/delete", {}, STATE["admin_csrf"]).status_code == 400
    assert post(c, f"/admin/users/{STATE['viewer_id']}/delete", {"confirm": "yes"},
                STATE["admin_csrf"]).status_code == 302
    assert "ana.viewer" not in [u["username"] for u in auth.list_users()]


def test_logout_revokes_session_and_stream_closes():
    c = client()
    login(c, "admin", STATE["admin_pw"])
    csrf = csrf_of(c)
    stream = get(c, "/stream", buffered=False)
    chunks = iter(stream.response)
    first = next(chunks).decode()
    assert first.startswith("event:")
    token = c.get_cookie(auth.COOKIE_NAME, domain="localhost").value
    auth.end_session(token)                                    # e.g. logged out in another tab
    t0 = time.time()
    second = next(chunks).decode()
    assert "event: logout" in second and time.time() - t0 < 10
    stream.close()
    c2 = client()
    login(c2, "admin", STATE["admin_pw"])
    r = post(c2, "/logout", {}, csrf_of(c2))
    assert r.status_code == 302 and get(c2, "/api/alerts").status_code == 401


def test_cli_reset_password(capsys):
    import manage
    assert manage.main(["reset-password", "admin"]) == 0
    pw = re.search(r"password for 'admin': (\S+)", capsys.readouterr().out).group(1)
    assert login(client(), "admin", pw).headers["Location"].endswith("/account/password")


# --------------------------------------------------------------------------- alert API
def test_alert_api_structure_stats_range_and_sort():
    import json as _json
    rows = [("a-old", "100 days", "Benign Positive", "Low", 90, False),
            ("a-tp", "1 hour", "True Positive", "High", 80, True),
            ("a-rev", "2 hours", "Needs Human Review", "Critical", 60, True)]
    with auth.engine.begin() as conn:
        for alert_id, age, verdict, severity, conf, esc in rows:
            result = {"verdict": verdict, "severity": severity, "confidence": conf, "should_escalate": esc,
                      "rule_name": "Rule <b>x</b>", "hostname": "ws01", "summary": "<img src=x onerror=alert(1)>",
                      "key_findings": [{"claim": "c", "stance": "suspicious", "evidence_ids": ["E1"]}],
                      "mitre_techniques": [{"technique_id": "T1202", "name": "Indirect"}],
                      "alert_url": "javascript:alert(1)", "investigation": {"guardrails_applied": ["g1"]}}
            conn.execute(text(f"INSERT INTO alerts (alert_id, timestamp) VALUES (:id, NOW() - interval '{age}')"),
                         {"id": alert_id})
            conn.execute(text("INSERT INTO triage_results (alert_id, response) VALUES (:id, :r)"),
                         {"id": alert_id, "r": _json.dumps(result)})
    app_module._cache["at"] = 0
    _, otp = auth.create_user("test", "api.admin", "admin", None)
    c = client()
    login(c, "api.admin", otp)
    post(c, "/account/password", {"current": otp, "new": "Api admin phrase 99", "confirm": "Api admin phrase 99"},
         csrf_of(c))
    data = get(c, "/api/alerts").get_json()
    a = next(x for x in data["alerts"] if x["alert_id"] == "a-tp")
    assert a["rule_name"] == "Rule <b>x</b>" and a["detail"]["summary"].startswith("<img")   # raw text, escaped by the browser
    assert a["post_url"] == "" and "post_body" not in a
    assert a["detail"]["findings"][0]["evidence"] == ["E1"] and a["detail"]["mitre"][0]["id"] == "T1202"
    assert data["stats"]["verdicts"]["True Positive"] == 1 and data["stats"]["escalate"] == 2
    # range filter
    ids = [x["alert_id"] for x in get(c, "/api/alerts?range=24h").get_json()["alerts"]]
    assert "a-old" not in ids and {"a-tp", "a-rev"} <= set(ids)
    # tiles count every verdict even when one verdict is selected
    stats = get(c, "/api/alerts?verdict=True+Positive").get_json()["stats"]
    assert stats["verdicts"]["Needs Human Review"] == 1 and stats["verdicts"]["True Positive"] == 1
    # sorting
    by_sev = [x["alert_id"] for x in get(c, "/api/alerts?sort=severity").get_json()["alerts"]]
    assert by_sev.index("a-rev") < by_sev.index("a-tp") < by_sev.index("a-old")
    by_conf = [x["alert_id"] for x in get(c, "/api/alerts?sort=confidence").get_json()["alerts"]]
    assert by_conf.index("a-old") < by_conf.index("a-tp") < by_conf.index("a-rev")
    # bogus values fall back to defaults
    assert get(c, "/api/alerts?range=999y&sort=evil").status_code == 200
    html = get(c, "/").get_data(as_text=True)
    assert "cdn.jsdelivr" not in html and "vendor/bootstrap.min.css" in html
    csp = get(c, "/").headers["Content-Security-Policy"]
    assert "cdn.jsdelivr" not in csp and "font-src 'self'" in csp
    assert get(c, "/static/fonts/OFL-barlow.txt").status_code == 200
    STATE["api_client"] = c


def test_siem_filter_and_per_siem_kibana_links():
    import json as _json
    c = STATE["api_client"]
    with auth.engine.begin() as conn:
        conn.execute(text("""INSERT INTO siems (id, name, kibana_url, position) VALUES
                             ('hq', 'Head office', 'https://kibana-hq.example', 0),
                             ('br', 'Branch', 'https://kibana-br.example:5601', 1)"""))
        for alert_id, siem, url in (("hq:1", "hq", "https://kibana-hq.example/app/1"),
                                    ("br:1", "br", "https://kibana-br.example:5601/app/1"),
                                    ("br:2", "br", "https://kibana-hq.example/app/2")):   # other SIEM's Kibana
            conn.execute(text("INSERT INTO alerts (alert_id, timestamp, siem) VALUES (:id, NOW(), :s)"),
                         {"id": alert_id, "s": siem})
            conn.execute(text("INSERT INTO triage_results (alert_id, response) VALUES (:id, :r)"),
                         {"id": alert_id, "r": _json.dumps({"verdict": "True Positive", "severity": "High",
                                                           "alert_url": url})})
    app_module._cache["at"] = 0
    every = {x["alert_id"]: x for x in get(c, "/api/alerts?limit=100").get_json()["alerts"]}
    assert {"hq:1", "br:1", "br:2", "a-tp"} <= set(every)
    assert every["a-tp"]["siem"] == "hq"                         # stored before multi-SIEM: first SIEM
    assert every["br:1"]["siem_name"] == "Branch" and every["br:1"]["post_url"].startswith("https://kibana-br")
    assert every["br:2"]["post_url"] == ""
    br = get(c, "/api/alerts?siem=br").get_json()
    assert {x["alert_id"] for x in br["alerts"]} == {"br:1", "br:2"} and br["stats"]["total"] == 2
    assert get(c, "/api/alerts?siem=nope").get_json()["total"] == 0
    html = get(c, "/?siem=br").get_data(as_text=True)
    assert '<option value="br" selected>Branch</option>' in html and '"multiSiem": true' in html


def _new_user(admin, name, role, siems):
    data = {"username": name, "role": role, "siem_picker": "1"}
    if siems is None:
        data["siem_all"] = "1"
    r = admin.post("/admin/users", base_url=BASE, headers={"Origin": BASE},
                   data={**data, "csrf_token": csrf_of(admin), "siem": siems or []})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    otp = re.search(r'class="one-time-password">([^<]+)<', r.get_data(as_text=True)).group(1)
    c = client()
    login(c, name, otp)
    post(c, "/account/password", {"current": otp, "new": "Long enough phrase 12345", "confirm": "Long enough phrase 12345"},
         csrf_of(c))
    return c


def test_users_see_only_their_siems():
    admin = STATE["api_client"]
    app_module._cache["at"] = 0
    page = get(admin, "/admin/users").get_data(as_text=True)
    assert 'name="siem" value="br"' in page and "<th>SIEMs</th>" in page

    br = _new_user(admin, "br.viewer", "viewer", ["br"])
    assert auth.list_users()[[u["username"] for u in auth.list_users()].index("br.viewer")]["siem_access"] == ["br"]
    data = get(br, "/api/alerts?limit=100").get_json()
    assert {x["alert_id"] for x in data["alerts"]} == {"br:1", "br:2"}
    assert data["stats"]["total"] == 2 and data["total"] == 2
    assert get(br, "/api/alerts?siem=hq").get_json()["total"] == 0          # asking for another SIEM gives nothing
    assert get(br, "/api/alerts?q=hq:1").get_json()["total"] == 0
    assert get(br, "/api/alerts/br:1/trail").status_code == 200
    for other in ("hq:1", "a-tp", "does-not-exist"):                          # a-tp: pre-multi-SIEM -> first SIEM
        assert get(br, f"/api/alerts/{other}/trail").status_code == 404
    html = get(br, "/").get_data(as_text=True)
    assert 'id="siem"' not in html and '"multiSiem": false' in html          # one SIEM: no selector, no badges

    # analysts can only give feedback on alerts they can see
    an = _new_user(admin, "two.analyst", "analyst", ["br", "hq"])
    csrf = csrf_of(an)
    fb = lambda aid: an.post(f"/api/alerts/{aid}/feedback", base_url=BASE, json={"agrees": True},
                             headers={"Origin": BASE, "X-CSRF-Token": csrf})
    assert fb("hq:1").status_code == 200 and fb("br:1").status_code == 200
    assert len(get(an, "/api/alerts?limit=100").get_json()["alerts"]) >= 4
    one = _new_user(admin, "hq.analyst", "analyst", ["hq"])
    csrf = csrf_of(one)
    assert one.post("/api/alerts/br:1/feedback", base_url=BASE, json={"agrees": True},
                    headers={"Origin": BASE, "X-CSRF-Token": csrf}).status_code == 404

    # unrestricted by default ("All SIEMs"), and admins always see everything
    everyone = _new_user(admin, "all.viewer", "viewer", None)
    assert get(everyone, "/api/alerts?limit=100").get_json()["total"] == get(admin, "/api/alerts?limit=100").get_json()["total"]

    # changing access signs the user out; an empty choice is refused
    uid = next(u["id"] for u in auth.list_users() if u["username"] == "br.viewer")
    r = post(admin, f"/admin/users/{uid}/siems", {"siem_picker": "1", "siem": ["hq"]}, csrf_of(admin))
    assert r.status_code == 302 and r.headers["Location"].endswith("done=siems")
    assert get(br, "/api/alerts").status_code == 401
    r = post(admin, f"/admin/users/{uid}/siems", {"siem_picker": "1"}, csrf_of(admin))
    assert r.status_code == 400 and "at least one SIEM" in r.get_data(as_text=True)
    r = post(admin, f"/admin/users/{uid}/siems", {"siem_picker": "1", "siem_all": "1", "siem": ["hq"]},
             csrf_of(admin))
    assert r.status_code == 302
    assert next(u for u in auth.list_users() if u["username"] == "br.viewer")["siem_access"] is None
    events = [e["event"] for e in auth.recent_events()]
    assert "siems_changed" in events
    # viewers cannot change access
    assert post(everyone, f"/admin/users/{uid}/siems", {"siem_all": "1"}, csrf_of(everyone)).status_code == 403
