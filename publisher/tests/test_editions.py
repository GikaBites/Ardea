"""Editions in the web UI: SSO sign-in (Pro), branding (MSP), the licence panel, and that a missing or
expired licence never weakens security. Same throwaway '_test' database as test_auth.py."""
import os
import re
import sys

import pytest

if not os.environ.get("POSTGRES_DB", "").endswith("_test"):
    pytest.skip("set POSTGRES_DB to an empty database ending in _test", allow_module_level=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app as app_module  # noqa: E402
import auth  # noqa: E402
import editions  # noqa: E402
from sqlalchemy import text  # noqa: E402

BASE = "https://localhost"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def set_license(tier, valid_hours=24 * 30):
    with auth.engine.begin() as c:
        c.execute(text("INSERT INTO license_state (id, install_id) VALUES (1, 'test') ON CONFLICT (id) DO NOTHING"))
        c.execute(text("""UPDATE license_state SET tier = :t, source = :s,
                          valid_until = CASE WHEN CAST(:h AS INT) IS NULL THEN NULL ELSE NOW() + make_interval(hours => CAST(:h AS INT)) END
                          WHERE id = 1"""),
                  {"t": tier, "s": "none" if tier == "community" else "lemonsqueezy", "h": valid_hours})
    editions.reset_cache()


def user(name, role="analyst"):
    with auth.engine.begin() as c:
        exists = c.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": name}).first()
    if not exists:
        auth.create_user("test", name, role, None)
    return name


def get(c, path, sso=None, **kw):
    headers = {app_module.SSO_HEADER: sso} if sso else {}
    return c.get(path, base_url=BASE, headers=headers, **kw)


@pytest.fixture(autouse=True)
def _sso_on(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "SSO_ENABLED", True)
    monkeypatch.setattr(app_module, "BRAND_DIR", str(tmp_path))
    monkeypatch.setenv("ARDEA_BRAND_NAME", "Acme SOC")
    app_module._sso_warned["done"] = False
    yield
    set_license("community", None)


def test_community_ignores_sso_header():
    set_license("community", None)
    user("sso.analyst")
    r = get(app_module.app.test_client(), "/", sso="sso.analyst")
    assert r.status_code == 302 and r.headers["Location"].startswith("/login")


def test_expired_licence_is_community():
    set_license("pro", valid_hours=-1)
    assert editions.edition() == "community"
    r = get(app_module.app.test_client(), "/", sso=user("sso.analyst"))
    assert r.status_code == 302


def test_pro_sso_signs_in_existing_user_without_password_change():
    set_license("pro")
    c = app_module.app.test_client()
    r = get(c, "/", sso="SSO.Analyst")                       # case-insensitive, like the login form
    assert r.status_code == 200
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith(auth.COOKIE_NAME) and "HttpOnly" in cookie and "Secure" in cookie
    assert get(c, "/api/alerts", sso="sso.analyst").status_code == 200      # no forced password change
    with auth.engine.begin() as conn:
        events = [e for (e,) in conn.execute(text(
            "SELECT event FROM auth_events WHERE actor = 'sso.analyst' ORDER BY id DESC LIMIT 1"))]
    assert events == ["sso_login"]


def test_sso_unknown_invalid_and_disabled_users_are_refused():
    set_license("pro")
    c = app_module.app.test_client()
    r = get(c, "/", sso="nobody.here")
    assert r.status_code == 403 and "no active Ardea account" in r.get_data(as_text=True)
    assert auth.COOKIE_NAME not in r.headers.get("Set-Cookie", "")
    assert get(c, "/", sso="evil@example.com").status_code == 403           # not a valid username
    assert get(c, "/api/alerts", sso="nobody.here").get_json() == {"error": "sso_no_account"}
    name = user("sso.disabled")
    with auth.engine.begin() as conn:
        conn.execute(text("UPDATE users SET disabled = TRUE WHERE username = :u"), {"u": name})
    assert get(c, "/", sso=name).status_code == 403


def test_sso_switches_user_and_never_reuses_the_previous_session():
    set_license("pro")
    c = app_module.app.test_client()
    assert get(c, "/", sso=user("sso.analyst")).status_code == 200
    first = c.get_cookie(auth.COOKIE_NAME).value
    r = get(c, "/", sso=user("sso.viewer", "viewer"))
    assert r.status_code == 200
    assert auth.load_session(first) is None                   # the first user's session was ended
    assert auth.load_session(c.get_cookie(auth.COOKIE_NAME).value)["username"] == "sso.viewer"


def test_sso_session_still_needs_csrf_for_changes():
    set_license("pro")
    c = app_module.app.test_client()
    get(c, "/", sso=user("sso.analyst"))
    r = c.post("/logout", base_url=BASE, headers={"Origin": BASE, app_module.SSO_HEADER: "sso.analyst"})
    assert r.status_code == 403


def test_sso_off_by_default_even_with_licence(monkeypatch):
    set_license("msp")
    monkeypatch.setattr(app_module, "SSO_ENABLED", False)
    r = get(app_module.app.test_client(), "/", sso=user("sso.analyst"))
    assert r.status_code == 302


def test_branding_needs_msp(tmp_path):
    (tmp_path / "logo.png").write_bytes(PNG)
    set_license("pro")
    c = app_module.app.test_client()
    assert get(c, "/branding/logo").status_code == 404
    html = get(c, "/login").get_data(as_text=True)
    assert "<title>Sign in · Ardea</title>" in html and "Acme SOC" not in html

    set_license("msp")
    r = get(c, "/branding/logo")
    assert r.status_code == 200 and r.mimetype == "image/png"
    html = get(c, "/login").get_data(as_text=True)
    assert "<title>Sign in · Acme SOC</title>" in html and 'src="/branding/logo"' in html


def test_branding_rejects_svg_and_fake_images(tmp_path):
    set_license("msp")
    (tmp_path / "logo.png").write_bytes(b"<svg onload=alert(1)>")                # not really a PNG
    assert get(app_module.app.test_client(), "/branding/logo").status_code == 404
    (tmp_path / "logo.svg").write_bytes(b"<svg/>")
    assert get(app_module.app.test_client(), "/branding/logo").status_code == 404


def test_users_page_shows_edition():
    set_license("msp")
    c = app_module.app.test_client()
    get(c, "/", sso=user("sso.admin", "admin"))
    html = get(c, "/admin/users", sso="sso.admin").get_data(as_text=True)
    assert re.search(r"Edition: <span[^>]*>MSP</span>", html)
    assert "Several SIEMs: on" in html
    set_license("community", None)
    html = get(c, "/admin/users").get_data(as_text=True)           # existing session keeps working
    assert re.search(r"Edition: <span[^>]*>Community</span>", html) and "Several SIEMs: off" in html


def test_per_user_siem_restrictions_survive_a_lapsed_licence():
    """A lapsed licence must never widen what a user can see."""
    set_license("community", None)
    restricted = {"role": "analyst", "siem_access": ["hq"]}
    assert not auth.can_see_siem(restricted, "branch")
    assert auth.can_see_siem(restricted, "hq")
