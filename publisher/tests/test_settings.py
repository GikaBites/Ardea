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
    assert "from-env" in html and "Set in <code>.env</code>" in html
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
    assert r.status_code == 200 and "SMTP password was cleared" in r.get_data(as_text=True)
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
