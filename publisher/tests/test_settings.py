"""Settings page against a real Postgres: who may change what, sealed secrets, .env precedence, SIEMs, tests.
Same throwaway '_test' database as test_auth.py."""
import base64
import json
import os
import re
import sys

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app as app_module  # noqa: E402
import appsettings as A  # noqa: E402
import auth  # noqa: E402
import settings_admin  # noqa: E402
from db import get_connection  # noqa: E402
from sqlalchemy import text  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

BASE = "https://localhost"
PASSWORD = "Settings-test-pass-2026"
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 64


def _user(name, role):
    with auth.engine.begin() as c:
        c.execute(text("DELETE FROM users WHERE username = :u"), {"u": name})
        c.execute(text("""INSERT INTO users (username, password_hash, role, must_change_password, created_by)
                          VALUES (:u, :h, :r, FALSE, 'test')"""),
                  {"u": name, "h": generate_password_hash(PASSWORD), "r": role})


@pytest.fixture(scope="module")
def key(tmp_path_factory):
    k = A.load_or_create_key(tmp_path_factory.mktemp("keys") / "settings.key")
    with get_connection() as conn:
        with conn.transaction():
            A.ensure_schema(conn.execute)
        conn.execute("DELETE FROM settings_meta")
        A.publish_key(conn, k)
        for t in ("app_settings", "settings_env", "settings_audit", "settings_tests"):
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
    _user("set.admin", "admin")
    _user("set.analyst", "analyst")
    return k


def login(name):
    c = app_module.app.test_client()
    c.post("/login", base_url=BASE, data={"username": name, "password": PASSWORD, "next": "/"},
           headers={"Origin": BASE})
    html = c.get("/account/password", base_url=BASE).get_data(as_text=True)
    c.csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    return c


def post(c, path, data=None, **kw):
    return c.post(path, base_url=BASE, data={"csrf_token": c.csrf, **(data or {})}, headers={"Origin": BASE}, **kw)


def rows():
    with get_connection() as conn:
        return {r["name"]: r for r in conn.execute("SELECT * FROM app_settings").fetchall()}


def audit():
    with get_connection() as conn:
        return [(r["name"], r["action"]) for r in conn.execute("SELECT name, action FROM settings_audit ORDER BY id")]


def test_only_admins(key):
    c = login("set.analyst")
    assert c.get("/admin/settings/ai", base_url=BASE).status_code == 403
    assert post(c, "/admin/settings/ai", {"LLM_MODEL": "x"}).status_code == 403
    assert post(c, "/admin/settings/test", {"kind": "llm"}).status_code == 403


def test_plain_settings_save_validate_and_audit(key, monkeypatch):
    monkeypatch.delenv("LLM_MODEL", raising=False)
    c = login("set.admin")
    r = post(c, "/admin/settings/ai", {"LLM_URL": "http://10.0.0.5:11434", "LLM_MODEL": "qwen3:30b",
                                       "LLM_NUM_CTX": "32768", "LLM_THINK": "false"})
    assert r.status_code == 200 and "Saved" in r.get_data(as_text=True)
    got = rows()
    assert got["LLM_MODEL"]["value"] == "qwen3:30b" and got["LLM_MODEL"]["updated_by"] == "set.admin"
    assert ("LLM_MODEL", "changed") in audit()
    bad = post(c, "/admin/settings/ai", {"LLM_URL": "javascript:alert(1)", "LLM_NUM_CTX": "5"})
    assert bad.status_code == 400 and "must start with http" in bad.get_data(as_text=True)
    assert rows()["LLM_URL"]["value"] == "http://10.0.0.5:11434"          # nothing saved on an error
    post(c, "/admin/settings/ai", {"LLM_URL": "http://10.0.0.5:11434", "LLM_MODEL": ""})
    assert "LLM_MODEL" not in rows() and ("LLM_MODEL", "reset to default") in audit()


def test_env_values_are_read_only(key, monkeypatch):
    with get_connection() as conn:
        conn.execute("INSERT INTO settings_env (service, name, value) VALUES ('worker', 'LLM_MODEL', 'from-env')")
        conn.commit()
    c = login("set.admin")
    html = c.get("/admin/settings/ai", base_url=BASE).get_data(as_text=True)
    assert "from-env" in html and "Set in the <code>.env</code> file" in html
    post(c, "/admin/settings/ai", {"LLM_MODEL": "should-not-save", "LLM_URL": "http://10.0.0.5:11434"})
    assert "LLM_MODEL" not in rows()
    with get_connection() as conn:
        conn.execute("DELETE FROM settings_env")
        conn.commit()


def test_secrets_need_the_password_and_are_never_shown(key):
    c = login("set.admin")
    form = {"SMTP_HOST": "mail.example.com", "SMTP_PASSWORD": "very-secret-smtp-pw", "SMTP_TO": "soc@example.com"}
    r = post(c, "/admin/settings/notifications", {**form, "confirm_password": "wrong"})
    assert r.status_code == 400 and "password is not correct" in r.get_data(as_text=True)
    assert "SMTP_PASSWORD" not in rows() and "SMTP_HOST" not in rows()
    r = post(c, "/admin/settings/notifications", {**form, "confirm_password": PASSWORD})
    assert r.status_code == 200
    row = rows()["SMTP_PASSWORD"]
    assert row["secret"] and row["value"].startswith("v1:") and "very-secret" not in row["value"]
    assert row["hint"] == "p-pw"
    page = c.get("/admin/settings/notifications", base_url=BASE).get_data(as_text=True)
    assert "very-secret" not in page and "ends in p-pw" in page
    # only the worker's private key opens it, and only for this host
    assert A.unseal(key, "SMTP_PASSWORD", row["value"], "mail.example.com") == "very-secret-smtp-pw"
    assert ("SMTP_PASSWORD", "secret set") in audit()


def test_changing_the_host_clears_a_bound_secret(key):
    c = login("set.admin")
    r = post(c, "/admin/settings/notifications", {"SMTP_HOST": "evil.example.net", "SMTP_TO": "soc@example.com"})
    assert r.status_code == 200 and "Mail password was cleared" in r.get_data(as_text=True)
    assert "SMTP_PASSWORD" not in rows()


def test_clearing_a_secret(key):
    c = login("set.admin")
    post(c, "/admin/settings/websearch", {"BRAVE_API_KEY": "brave-key-1234567", "confirm_password": PASSWORD})
    assert "BRAVE_API_KEY" in rows()
    post(c, "/admin/settings/websearch", {"BRAVE_API_KEY__clear": "1", "confirm_password": PASSWORD})
    assert "BRAVE_API_KEY" not in rows() and ("BRAVE_API_KEY", "secret cleared") in audit()


def test_siems_add_change_url_and_remove(key):
    c = login("set.admin")
    form = {"id": "hq", "name": "Head office", "url": "https://es-hq.example:9200", "enabled": "true",
            "fetcher_api_key": "fetcher-key-123456", "worker_api_key": "worker-key-123456",
            "events_indices": "logs-*", "confirm_password": PASSWORD}
    r = post(c, "/admin/settings/siems/save", form)
    assert r.status_code == 200, r.get_data(as_text=True)
    got = rows()
    assert json.loads(got[A.SIEMS_KEY]["value"])[0]["id"] == "hq"
    assert A.unseal(key, "SIEM.hq.worker_api_key", got["SIEM.hq.worker_api_key"]["value"],
                    "https://es-hq.example:9200") == "worker-key-123456"
    dup = post(c, "/admin/settings/siems/save", {**form})
    assert dup.status_code == 400 and "already exists" in dup.get_data(as_text=True)
    bad = post(c, "/admin/settings/siems/save", {**form, "id": "Bad ID"})
    assert bad.status_code == 400
    r = post(c, "/admin/settings/siems/save", {"siem_id": "hq", "name": "Head office", "enabled": "true",
                                               "url": "https://attacker.example:9200", "confirm_password": PASSWORD})
    assert "cleared because the URL changed" in r.get_data(as_text=True)
    assert "SIEM.hq.worker_api_key" not in rows() and "SIEM.hq.fetcher_api_key" not in rows()
    r = post(c, "/admin/settings/siems/hq/delete", {"confirm_password": PASSWORD})
    assert r.status_code == 200 and A.SIEMS_KEY not in rows()


def test_siems_json_on_the_server_makes_the_list_read_only(key):
    with get_connection() as conn:
        conn.execute("INSERT INTO settings_env (service, name, value) VALUES ('fetcher', 'SIEMS_FILE', '/app/siems/siems.json')")
        conn.commit()
    c = login("set.admin")
    assert "read-only here" in c.get("/admin/settings/siems", base_url=BASE).get_data(as_text=True)
    r = post(c, "/admin/settings/siems/save", {"id": "x", "url": "https://es:9200", "confirm_password": PASSWORD})
    assert r.status_code == 400 and "siems.json" in r.get_data(as_text=True)
    with get_connection() as conn:
        conn.execute("DELETE FROM settings_env")
        conn.commit()


def test_tests_are_queued_for_the_worker(key):
    c = login("set.admin")
    assert post(c, "/admin/settings/test", {"kind": "rm -rf /"}).status_code == 400
    r = post(c, "/admin/settings/test", {"kind": "notify:slack"})
    test_id = r.get_json()["id"]
    assert c.get(f"/admin/settings/test/{test_id}", base_url=BASE).get_json()["status"] == "queued"


def test_logo_upload(key):
    c = login("set.admin")
    import io
    r = post(c, "/admin/settings/reports", {"BRAND_LOGO": (io.BytesIO(b"<svg onload=alert(1)>"), "x.svg"),
                                            "confirm_password": PASSWORD}, content_type="multipart/form-data")
    assert r.status_code == 400 and "PNG, JPEG or WebP" in r.get_data(as_text=True)
    r = post(c, "/admin/settings/reports", {"BRAND_LOGO": (io.BytesIO(PNG), "logo.png"),
                                            "confirm_password": PASSWORD}, content_type="multipart/form-data")
    assert r.status_code == 200
    assert rows()[A.BRAND_LOGO_KEY]["value"] == "data:image/png;base64," + base64.b64encode(PNG).decode()
    settings_admin.publisher_cache.clear()
    assert app_module._brand_logo() == (PNG, "image/png")


def test_a_65_kb_logo_fits_but_other_forms_stay_small(key):
    import io
    c = login("set.admin")
    big_png = PNG + b"\0" * (65 * 1024)
    r = post(c, "/admin/settings/reports", {"BRAND_LOGO": (io.BytesIO(big_png), "logo.png"),
                                            "confirm_password": PASSWORD}, content_type="multipart/form-data")
    assert r.status_code == 200, r.status_code
    too_big = PNG + b"\0" * (210 * 1024)
    r = post(c, "/admin/settings/reports", {"BRAND_LOGO": (io.BytesIO(too_big), "logo.png"),
                                            "confirm_password": PASSWORD}, content_type="multipart/form-data")
    assert r.status_code == 400 and "larger than 200 KB" in r.get_data(as_text=True)
    r = post(c, "/admin/settings/ai", {"LLM_MODEL": "x" * (20 * 1024)})
    assert r.status_code == 303 and "too_large=1" in r.headers["Location"]
    page = c.get(r.headers["Location"], base_url=BASE).get_data(as_text=True)
    assert "nothing was saved" in page and "LLM_MODEL" not in rows()


# --------------------------------------------------------------------------- playbook pack tab
PACK_DOC = {"payload": {"version": "2026.12", "name": "Ardea playbook pack", "by_rule_name": {}}, "signature": "c2ln"}


def _packs():
    with get_connection() as conn:
        return conn.execute("SELECT id, version, source, status, added_by FROM playbook_packs ORDER BY id").fetchall()


def test_playbook_pack_tab_and_install_button(key):
    c = login("set.admin")
    html = c.get("/admin/settings/playbooks", base_url=BASE).get_data(as_text=True)
    assert "No playbook pack installed" in html and 'data-test="pack:install"' in html
    r = post(c, "/admin/settings/test", {"kind": "pack:install"})
    assert r.status_code == 200 and r.get_json()["id"]
    analyst = login("set.analyst")
    assert analyst.get("/admin/settings/playbooks", base_url=BASE).status_code == 403
    assert post(analyst, "/admin/settings/playbooks/upload").status_code == 403


def test_pack_upload_is_stored_for_the_worker(key):
    import io
    with get_connection() as conn:
        conn.execute("DELETE FROM playbook_packs")
        conn.commit()
    c = login("set.admin")
    r = post(c, "/admin/settings/playbooks/upload", {"PACK": (io.BytesIO(b"not json"), "x.ardpack")},
             content_type="multipart/form-data")
    assert r.status_code == 400 and "not an Ardea playbook pack" in r.get_data(as_text=True)
    r = post(c, "/admin/settings/playbooks/upload", {"PACK": (io.BytesIO(b'{"payload": {}}'), "x.ardpack")},
             content_type="multipart/form-data")
    assert r.status_code == 400 and "not a signed" in r.get_data(as_text=True)
    big = json.dumps(dict(PACK_DOC, pad="x" * (1024 * 1024))).encode()      # 1 MB: allowed on this path only
    r = post(c, "/admin/settings/playbooks/upload", {"PACK": (io.BytesIO(big), "ardea-playbooks-2026.12.ardpack")},
             content_type="multipart/form-data")
    assert r.status_code == 200 and "Pack 2026.12 uploaded" in r.get_data(as_text=True)
    [p] = _packs()
    assert (p["version"], p["source"], p["status"], p["added_by"]) == ("2026.12", "upload", "pending", "set.admin")
    assert ("PLAYBOOK_PACK", "uploaded 2026.12") in audit()
    huge = b"x" * (3 * 1024 * 1024)
    r = post(c, "/admin/settings/playbooks/upload", {"PACK": (io.BytesIO(huge), "x.ardpack")},
             content_type="multipart/form-data")
    assert r.status_code == 303 and "too_large=1" in r.headers["Location"]


def test_installed_pack_details_and_remove(key):
    with get_connection() as conn:
        conn.execute("DELETE FROM playbook_packs")
        conn.execute("""INSERT INTO playbook_packs (version, content, source, status, summary, added_by, installed_at)
                        VALUES ('2026.11', '{}', 'download', 'installed', %s, 'automatic update', NOW()),
                               ('2026.12', '{}', 'upload', 'installed', %s, 'set.admin', NOW())""",
                     (json.dumps({"version": "2026.11", "counts": {"by_rule_id": 1, "by_rule_name": 1, "by_tactic": 0},
                                  "rule_names": ["Old Rule"], "tactics": []}),
                      json.dumps({"version": "2026.12", "name": "Ardea playbook pack", "issued": "2026-12-01T09:00:00Z",
                                  "counts": {"by_rule_id": 5, "by_rule_name": 2, "by_tactic": 1},
                                  "rule_names": ["Whoami Process Activity", "<b>Rule</b>"], "tactics": ["Execution"]})))
        conn.commit()
    c = login("set.admin")
    html = c.get("/admin/settings/playbooks", base_url=BASE).get_data(as_text=True)
    assert "Installed: Ardea playbook pack" in html and "2026.12" in html and "released 2026-12-01" in html
    assert "What pack 2026.12 covers" in html and "Whoami Process Activity" in html and "plus 5 matched by rule ID" in html
    assert "<b>Rule</b>" not in html and "&lt;b&gt;Rule&lt;/b&gt;" in html            # names are escaped
    newest = [p for p in _packs() if p["version"] == "2026.12"][0]
    r = post(c, f"/admin/settings/playbooks/{newest['id']}/delete")
    assert r.status_code == 303 and [p["version"] for p in _packs()] == ["2026.11"]
    assert ("PLAYBOOK_PACK", "removed 2026.12") in audit()
    html = c.get("/admin/settings/playbooks", base_url=BASE).get_data(as_text=True)
    assert "Installed: Ardea playbook pack" in html and "2026.11" in html


def test_changing_the_pack_server_needs_the_password(key):
    c = login("set.admin")
    r = post(c, "/admin/settings/playbooks", {"ARDEA_PACK_AUTO_UPDATE": "false"})
    assert r.status_code == 200 and rows()["ARDEA_PACK_AUTO_UPDATE"]["value"] == "false"
    r = post(c, "/admin/settings/playbooks", {"ARDEA_PACK_SERVER": "https://evil.example"})
    assert r.status_code == 400 and "password is not correct" in r.get_data(as_text=True)
    r = post(c, "/admin/settings/playbooks", {"ARDEA_PACK_SERVER": "https://packs.example.net",
                                              "confirm_password": PASSWORD})
    assert r.status_code == 200 and rows()["ARDEA_PACK_SERVER"]["value"] == "https://packs.example.net"


def _siem(c, sid, **extra):
    form = {"id": sid, "name": sid.upper(), "url": f"https://es-{sid}.example:9200", "enabled": "true",
            "events_indices": "logs-*", "confirm_password": PASSWORD, **extra}
    assert post(c, "/admin/settings/siems/save", form).status_code == 200


def _seed_alerts(sid, n=2):
    with get_connection() as conn:
        for i in range(n):
            aid = f"{sid}:x{i}"
            conn.execute("INSERT INTO alerts (alert_id, timestamp, status, siem) VALUES (%s, NOW(), 'done', %s)",
                         (aid, sid))
            conn.execute("INSERT INTO triage_results (alert_id, response, result, verdict) "
                         "VALUES (%s, '{}', '{}', 'Benign Positive')", (aid,))
            conn.execute("INSERT INTO feedback (alert_id, analyst, agrees) VALUES (%s, 'x', TRUE)", (aid,))
            conn.execute("INSERT INTO alert_work (alert_id, status) VALUES (%s, 'open')", (aid,))
            conn.execute("INSERT INTO alert_work_log (alert_id, actor, action) VALUES (%s, 'x', 'took it')", (aid,))
            conn.execute("INSERT INTO alert_questions (alert_id, question) VALUES (%s, 'why?')", (aid,))
        conn.execute("INSERT INTO siems (id, name, active) VALUES (%s, %s, FALSE) "
                     "ON CONFLICT (id) DO UPDATE SET active = FALSE", (sid, sid.upper()))
        conn.execute("INSERT INTO suppressions (siem, rule_name, process_executable, reason, expires_at) "
                     "VALUES (%s, 'r', 'x.exe', 'because', NOW() + interval '1 day')", (sid,))
        conn.execute("UPDATE users SET siem_access = ARRAY[%s, 'keep'] WHERE username = 'set.analyst'", (sid,))
        conn.commit()


def _count(sid):
    with get_connection() as conn:
        return (conn.execute("SELECT count(*) AS n FROM alerts WHERE siem = %s", (sid,)).fetchone()["n"],
                conn.execute("SELECT count(*) AS n FROM alert_questions WHERE alert_id LIKE %s",
                             (f"{sid}:%",)).fetchone()["n"],
                conn.execute("SELECT count(*) AS n FROM suppressions WHERE siem = %s", (sid,)).fetchone()["n"])


def test_delete_the_data_of_a_removed_siem(key):
    _seed_alerts("gone")
    c = login("set.admin")
    html = c.get("/admin/settings/siems", base_url=BASE).get_data(as_text=True)
    assert "no longer configured" in html and "Type gone to confirm" in html
    r = post(c, "/admin/settings/siems/gone/purge", {"confirm_id": "nope", "confirm_password": PASSWORD})
    assert r.status_code == 400 and _count("gone") == (2, 2, 1)
    r = post(c, "/admin/settings/siems/gone/purge", {"confirm_id": "gone", "confirm_password": "wrong"})
    assert r.status_code == 400 and _count("gone")[0] == 2
    r = post(c, "/admin/settings/siems/gone/purge", {"confirm_id": "gone", "confirm_password": PASSWORD})
    assert r.status_code == 200 and "2 alerts" in r.get_data(as_text=True)
    assert _count("gone") == (0, 0, 0)
    with get_connection() as conn:
        assert conn.execute("SELECT siem_access FROM users WHERE username = 'set.analyst'").fetchone()["siem_access"] == ["keep"]
        assert not conn.execute("SELECT 1 FROM siems WHERE id = 'gone'").fetchone()
    assert ("SIEM gone", "data deleted (2 alerts)") in audit()
    _siem(c, "live")
    _seed_alerts("live", 1)
    assert post(c, "/admin/settings/siems/live/purge", {"confirm_id": "live", "confirm_password": PASSWORD}).status_code == 400
    r = post(c, "/admin/settings/siems/live/delete", {"purge": "1", "confirm_id": "x", "confirm_password": PASSWORD})
    assert r.status_code == 400 and _count("live")[0] == 1
    r = post(c, "/admin/settings/siems/live/delete", {"purge": "1", "confirm_id": "live", "confirm_password": PASSWORD})
    assert r.status_code == 200 and "data deleted (1 alerts)" in r.get_data(as_text=True) and _count("live") == (0, 0, 0)
    with get_connection() as conn:
        conn.execute("UPDATE users SET siem_access = NULL WHERE username = 'set.analyst'")
        conn.commit()


def test_settings_templates_need_msp_and_apply_to_many_siems(key, monkeypatch):
    c = login("set.admin")
    _siem(c, "acme", context="Backups run as svc.backup")
    _siem(c, "beta")
    import editions
    monkeypatch.setattr(editions, "has", lambda f: f != "templates")
    assert "With Ardea MSP" in c.get("/admin/settings/siems", base_url=BASE).get_data(as_text=True)
    assert post(c, "/admin/settings/siems/templates/save", {"name": "x"}).status_code == 403
    monkeypatch.setattr(editions, "has", lambda f: True)
    t = {"name": "Windows customers", "events_indices": "logs-endpoint.*, logs-windows.*",
         "context": "RMM agent runs as SYSTEM\nBackups run as svc.backup", "context_mode": "add",
         "notify_smtp_to": "soc@msp.example", "default": "1"}
    assert post(c, "/admin/settings/siems/templates/save", {**t, "notify_smtp_to": "not-mail"}).status_code == 400
    assert post(c, "/admin/settings/siems/templates/save", t).status_code == 200
    assert post(c, "/admin/settings/siems/templates/save", t).status_code == 400          # same name twice
    r = c.post("/admin/settings/siems/templates/apply", base_url=BASE, headers={"Origin": BASE},
               data={"csrf_token": c.csrf, "name": "Windows customers", "siem": ["acme", "beta"]})
    assert r.status_code == 200 and "Applied to 2 SIEMs" in r.get_data(as_text=True)
    items = {s["id"]: s for s in json.loads(rows()[A.SIEMS_KEY]["value"])}
    assert items["acme"]["context"] == ["Backups run as svc.backup", "RMM agent runs as SYSTEM"]
    assert items["beta"]["events_indices"] == ["logs-endpoint.*", "logs-windows.*"]
    assert items["beta"]["notify"] == {"smtp_to": ["soc@msp.example"]} and items["acme"]["url"] == "https://es-acme.example:9200"
    html = c.get("/admin/settings/siems?edit=new", base_url=BASE).get_data(as_text=True)
    assert 'Started from the default template "Windows customers"' in html and "logs-endpoint.*" in html
    assert html.count("POST /_security/api_key") == 3 and "field_security" in html          # the key requests to copy
    assert 'data-licence="basic"' in html and 'data-licence="paid"' in html
    assert post(c, "/admin/settings/siems/templates/delete", {"name": "Windows customers"}).status_code == 200
    assert json.loads(rows()[A.SIEM_TEMPLATES_KEY]["value"]) == []
    for sid in ("acme", "beta"):
        post(c, f"/admin/settings/siems/{sid}/delete", {"confirm_password": PASSWORD})


def test_start_here_and_password_check_and_values_kept(key):
    c = login("set.admin")
    assert c.get("/admin/settings", base_url=BASE).headers["Location"].endswith("/admin/settings/overview")
    html = c.get("/admin/settings/overview", base_url=BASE).get_data(as_text=True)
    assert "Start here" in html and "SIEMs (Elastic)" in html and "Alerts to your team" in html
    r = c.post("/admin/settings/confirm-password", base_url=BASE, json={"password": "wrong"},
               headers={"Origin": BASE, "X-CSRF-Token": c.csrf})
    assert r.status_code == 403 and r.get_json() == {"ok": False}
    r = c.post("/admin/settings/confirm-password", base_url=BASE, json={"password": PASSWORD},
               headers={"Origin": BASE, "X-CSRF-Token": c.csrf})
    assert r.status_code == 200 and r.get_json() == {"ok": True}
    # a failed save keeps what was typed (here: a wrong password for a new mail password)
    r = post(c, "/admin/settings/notifications", {"SMTP_HOST": "mail.example.org", "SMTP_TO": "team@example.org",
                                                  "SMTP_PASSWORD": "new-secret-123", "NOTIFY_CHANNELS": "smtp",
                                                  "confirm_password": "wrong"})
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "Nothing was saved" in html
    assert 'value="mail.example.org"' in html and 'value="team@example.org"' in html and "new-secret-123" not in html
    assert rows().get("SMTP_HOST", {}).get("value") != "mail.example.org"
    analyst = login("set.analyst")
    assert analyst.post("/admin/settings/confirm-password", base_url=BASE, json={"password": PASSWORD},
                        headers={"Origin": BASE, "X-CSRF-Token": analyst.csrf}).status_code == 403


def test_health_page_and_backup_now(key):
    c = login("set.admin")
    html = c.get("/admin/settings/health", base_url=BASE).get_data(as_text=True)
    assert "System health" in html and "Services" in html and "No report yet" in html
    r = post(c, "/admin/settings/backups/run")
    assert r.status_code == 303 and "Backup+requested" in r.headers["Location"]
    with get_connection() as conn:
        assert conn.execute("SELECT status, requested_by FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone() == \
            {"status": "requested", "requested_by": "set.admin"}
    r = post(c, "/admin/settings/backups/run")
    assert "already" in r.headers["Location"]
    html = c.get("/admin/settings/backups", base_url=BASE).get_data(as_text=True)
    assert "A backup is on its way" in html and "restore.sh" in html and "Back up every night" in html
    assert "Backups" in c.get("/admin/settings/overview", base_url=BASE).get_data(as_text=True)
    assert login("set.analyst").get("/admin/settings/health", base_url=BASE).status_code == 403
