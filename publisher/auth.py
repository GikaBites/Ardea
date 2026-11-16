"""Users, roles, sessions and passwords for the Ardea web UI.

  * roles: admin (everything, including user management), analyst (read + feedback on verdicts)
    and viewer (read-only)
  * SIEM access: analysts and viewers see alerts of all SIEMs (siem_access NULL) or only of the listed
    ones; admins always see every SIEM
  * passwords: scrypt hashes (werkzeug); new and reset accounts get a random one-time password and
    must change it at first login
  * sessions: random token in a Secure/HttpOnly/SameSite=Strict cookie, only its SHA-256 is stored;
    idle and absolute expiry; revoked on logout, password change, role change, disable and delete
  * brute force: an account is locked for LOCKOUT_MINUTES after MAX_FAILED_LOGINS wrong passwords
  * first start: if there are no users, an 'admin' account with a random password is created and the
    password is written once to the log
"""
import hashlib
import logging
import os
import re
import secrets

from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash

from db import engine

log = logging.getLogger("ardea.auth")

ROLES = ("admin", "analyst", "viewer")
FEEDBACK_ROLES = ("admin", "analyst")
COOKIE_NAME = "__Host-ardea_session"
SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "480"))
SESSION_MAX_HOURS = int(os.getenv("SESSION_MAX_HOURS", "24"))
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
MIN_PASSWORD_LENGTH = 11
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
SIEM_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")            # same rule as siems.json ids
_DUMMY_HASH = generate_password_hash("timing-equaliser-not-a-real-password")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                   BIGSERIAL PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE,
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    disabled             BOOLEAN NOT NULL DEFAULT FALSE,
    failed_logins        INT NOT NULL DEFAULT 0,
    locked_until         TIMESTAMPTZ,
    password_changed_at  TIMESTAMPTZ,
    last_login_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           TEXT
);
CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions (user_id);
CREATE TABLE IF NOT EXISTS auth_events (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor       TEXT,
    event       TEXT NOT NULL,
    target      TEXT,
    ip          TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS auth_events_time_idx ON auth_events (created_at);
ALTER TABLE users ADD COLUMN IF NOT EXISTS siem_access TEXT[];
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS sso BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'analyst', 'viewer'));
"""
_BOOTSTRAP_LOCK = 7270010


class AuthError(Exception):
    """A user-facing validation error (shown on the page)."""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def temporary_password() -> str:
    return secrets.token_urlsafe(12)            # 16 characters, ~96 bits


# --------------------------------------------------------------------------- setup
def ensure_schema_and_admin():
    """Create the auth tables and, if no user exists, the default admin. Safe with several workers."""
    with engine.begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _BOOTSTRAP_LOCK})
        for statement in filter(str.strip, SCHEMA.split(";")):
            c.execute(text(statement))
        if c.execute(text("SELECT count(*) FROM users")).scalar():
            return
        password = temporary_password()
        c.execute(text("""INSERT INTO users (username, password_hash, role, must_change_password, created_by)
                          VALUES ('admin', :h, 'admin', TRUE, 'first start')"""),
                  {"h": generate_password_hash(password)})
        c.execute(text("INSERT INTO auth_events (actor, event, target) VALUES ('system', 'admin_created', 'admin')"))
    banner = "=" * 64
    log.warning("\n%s\nArdea first start: created the user 'admin'.\nTemporary password: %s\n"
                "It must be changed at the first login. This message is shown only once.\n%s",
                banner, password, banner)


def audit(actor, event, target=None, ip=None, detail=None):
    with engine.begin() as c:
        c.execute(text("""INSERT INTO auth_events (actor, event, target, ip, detail)
                          VALUES (:a, :e, :t, :ip, :d)"""),
                  {"a": actor, "e": event, "t": target, "ip": ip, "d": (detail or "")[:500] or None})


# --------------------------------------------------------------------------- passwords
def check_new_password(username: str, new: str, confirm: str, current: str | None = None):
    if new != confirm:
        raise AuthError("The new passwords do not match.")
    if len(new) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"The password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(new) > 128:
        raise AuthError("The password must be at most 128 characters long.")
    if username.lower() in new.lower():
        raise AuthError("The password must not contain the username.")
    if current is not None and new == current:
        raise AuthError("The new password must be different from the current one.")


def normalise_siem_access(siems):
    """None = all SIEMs; otherwise a sorted, de-duplicated list of SIEM ids (at least one)."""
    if siems is None:
        return None
    ids = sorted({str(s).strip() for s in siems if str(s).strip()})
    if not ids:
        raise AuthError("Pick at least one SIEM, or All SIEMs.")
    if not all(SIEM_ID_RE.match(i) for i in ids):
        raise AuthError("Unknown SIEM.")
    return ids


def can_see_siem(user, siem_id) -> bool:
    """For a session row from load_session: admins and unrestricted users see every SIEM."""
    if not user:
        return False
    if user["role"] == "admin" or user.get("siem_access") is None:
        return True
    return siem_id in user["siem_access"]


def normalise_username(username: str) -> str:
    name = (username or "").strip().lower()
    if not USERNAME_RE.match(name):
        raise AuthError("Usernames are 3-32 characters: lowercase letters, digits, '.', '_' or '-'.")
    return name


# --------------------------------------------------------------------------- login / sessions
def authenticate(username: str, password: str, ip: str | None):
    """Return the user row on success, None otherwise. Wrong passwords count towards a lockout."""
    name = (username or "").strip().lower()
    with engine.begin() as c:
        user = c.execute(text("""SELECT *, (locked_until IS NOT NULL AND locked_until > NOW()) AS locked
                                 FROM users WHERE username = :u FOR UPDATE"""), {"u": name}).mappings().first()
        if user is None:
            check_password_hash(_DUMMY_HASH, password or "")       # same cost as a real check
            c.execute(text("INSERT INTO auth_events (actor, event, ip) VALUES (:a, 'login_failed', :ip)"),
                      {"a": name[:64] or None, "ip": ip})
            return None
        if user["disabled"] or user["locked"]:
            check_password_hash(_DUMMY_HASH, password or "")
            c.execute(text("INSERT INTO auth_events (actor, event, ip, detail) VALUES (:a, 'login_failed', :ip, :d)"),
                      {"a": name, "ip": ip, "d": "disabled" if user["disabled"] else "locked"})
            return None
        if not check_password_hash(user["password_hash"], password or ""):
            failed = user["failed_logins"] + 1
            lock = failed >= MAX_FAILED_LOGINS
            c.execute(text("""UPDATE users SET failed_logins = :f,
                                     locked_until = CASE WHEN :lock THEN NOW() + make_interval(mins => :m)
                                                         ELSE locked_until END
                              WHERE id = :id"""),
                      {"f": 0 if lock else failed, "lock": lock, "m": LOCKOUT_MINUTES, "id": user["id"]})
            c.execute(text("INSERT INTO auth_events (actor, event, ip, detail) VALUES (:a, :e, :ip, :d)"),
                      {"a": name, "e": "account_locked" if lock else "login_failed", "ip": ip,
                       "d": f"{LOCKOUT_MINUTES} min" if lock else "wrong password"})
            return None
        c.execute(text("""UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = NOW()
                          WHERE id = :id"""), {"id": user["id"]})
        c.execute(text("INSERT INTO auth_events (actor, event, ip) VALUES (:a, 'login', :ip)"),
                  {"a": name, "ip": ip})
        return dict(user)


def sso_login(username: str, ip: str | None):
    """Single sign-on: the reverse proxy has already authenticated this username. Only an existing,
    enabled, unlocked Ardea account is accepted (no automatic accounts: an admin decides who gets in
    and with which role). Returns the user row or None."""
    name = (username or "").strip().lower()
    with engine.begin() as c:
        user = c.execute(text("""SELECT *, (locked_until IS NOT NULL AND locked_until > NOW()) AS locked
                                 FROM users WHERE username = :u FOR UPDATE"""), {"u": name}).mappings().first()
        if user is None or user["disabled"] or user["locked"]:
            reason = "no such user" if user is None else ("disabled" if user["disabled"] else "locked")
            c.execute(text("INSERT INTO auth_events (actor, event, ip, detail) VALUES (:a, 'sso_login_failed', :ip, :d)"),
                      {"a": name[:64] or None, "ip": ip, "d": reason})
            return None
        c.execute(text("UPDATE users SET last_login_at = NOW() WHERE id = :id"), {"id": user["id"]})
        c.execute(text("INSERT INTO auth_events (actor, event, ip) VALUES (:a, 'sso_login', :ip)"),
                  {"a": name, "ip": ip})
        return dict(user)


def create_session(user_id: int, ip: str | None, user_agent: str | None, sso: bool = False) -> str:
    token = secrets.token_urlsafe(32)
    with engine.begin() as c:
        c.execute(text("DELETE FROM user_sessions WHERE expires_at < NOW() "
                       "OR last_seen_at < NOW() - make_interval(mins => :idle)"), {"idle": SESSION_IDLE_MINUTES})
        c.execute(text("""INSERT INTO user_sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent, sso)
                          VALUES (:h, :u, :csrf, NOW() + make_interval(hours => :max), :ip, :ua, :sso)"""),
                  {"h": _hash_token(token), "u": user_id, "csrf": secrets.token_urlsafe(32),
                   "max": SESSION_MAX_HOURS, "ip": ip, "ua": (user_agent or "")[:300], "sso": sso})
    return token


def load_session(token: str | None):
    """The session joined with its user, or None if missing, expired, idle too long or the user is disabled."""
    if not token or len(token) > 100:
        return None
    with engine.begin() as c:
        row = c.execute(text("""
            SELECT s.token_hash, s.csrf_token, s.sso, s.last_seen_at < NOW() - interval '1 minute' AS stale,
                   u.id AS user_id, u.username, u.role, u.must_change_password, u.siem_access
            FROM user_sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = :h AND s.expires_at > NOW() AND NOT u.disabled
              AND s.last_seen_at > NOW() - make_interval(mins => :idle)"""),
            {"h": _hash_token(token), "idle": SESSION_IDLE_MINUTES}).mappings().first()
        if row and row["stale"]:                     # refresh at most once a minute
            c.execute(text("UPDATE user_sessions SET last_seen_at = NOW() WHERE token_hash = :h"),
                      {"h": row["token_hash"]})
    return dict(row) if row else None


def session_still_valid(token_hash: str) -> bool:
    with engine.connect() as c:
        return bool(c.execute(text("""SELECT 1 FROM user_sessions s JOIN users u ON u.id = s.user_id
                                      WHERE s.token_hash = :h AND s.expires_at > NOW() AND NOT u.disabled"""),
                              {"h": token_hash}).first())


def end_session(token: str | None):
    if token:
        with engine.begin() as c:
            c.execute(text("DELETE FROM user_sessions WHERE token_hash = :h"), {"h": _hash_token(token)})


def _revoke_sessions(c, user_id, keep_hash=None):
    c.execute(text("DELETE FROM user_sessions WHERE user_id = :u AND token_hash IS DISTINCT FROM :k"),
              {"u": user_id, "k": keep_hash})


# --------------------------------------------------------------------------- self-service
def change_own_password(user_id: int, username: str, current: str, new: str, confirm: str,
                        ip: str | None, session_hash: str):
    with engine.begin() as c:
        row = c.execute(text("SELECT password_hash FROM users WHERE id = :id FOR UPDATE"),
                        {"id": user_id}).mappings().first()
        if not row or not check_password_hash(row["password_hash"], current or ""):
            raise AuthError("The current password is not correct.")
        check_new_password(username, new or "", confirm or "", current)
        c.execute(text("""UPDATE users SET password_hash = :h, must_change_password = FALSE,
                                 password_changed_at = NOW() WHERE id = :id"""),
                  {"h": generate_password_hash(new), "id": user_id})
        _revoke_sessions(c, user_id, keep_hash=session_hash)
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip) VALUES (:a, 'password_changed', :a, :ip)"),
                  {"a": username, "ip": ip})


def confirm_password(user_id: int, username: str, password: str, ip: str | None) -> bool:
    """Re-check the signed-in admin's password before a sensitive change. Wrong answers count towards the
    same lockout as failed logins."""
    with engine.begin() as c:
        row = c.execute(text("SELECT password_hash, failed_logins FROM users WHERE id = :id FOR UPDATE"),
                        {"id": user_id}).mappings().first()
        if row and check_password_hash(row["password_hash"], password or ""):
            c.execute(text("UPDATE users SET failed_logins = 0 WHERE id = :id"), {"id": user_id})
            return True
        if row:
            failed = row["failed_logins"] + 1
            lock = failed >= MAX_FAILED_LOGINS
            c.execute(text("""UPDATE users SET failed_logins = :f,
                                     locked_until = CASE WHEN :lock THEN NOW() + make_interval(mins => :m)
                                                         ELSE locked_until END WHERE id = :id"""),
                      {"f": 0 if lock else failed, "lock": lock, "m": LOCKOUT_MINUTES, "id": user_id})
            if lock:
                _revoke_sessions(c, user_id)
        c.execute(text("INSERT INTO auth_events (actor, event, ip, detail) VALUES (:a, 'reauth_failed', :ip, :d)"),
                  {"a": username, "ip": ip, "d": "settings"})
        return False


# --------------------------------------------------------------------------- administration
def list_users():
    with engine.connect() as c:
        return [dict(r) for r in c.execute(text("""
            SELECT id, username, role, must_change_password, disabled, last_login_at, created_at, created_by,
                   siem_access,
                   (locked_until IS NOT NULL AND locked_until > NOW()) AS locked
            FROM users ORDER BY username""")).mappings()]


def recent_events(limit=50):
    with engine.connect() as c:
        return [dict(r) for r in c.execute(text("""SELECT created_at, actor, event, target, ip, detail
                                                   FROM auth_events ORDER BY id DESC LIMIT :n"""),
                                           {"n": limit}).mappings()]


def _active_admins(c, excluding_id=None) -> int:
    return c.execute(text("""SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled
                             AND id IS DISTINCT FROM :x"""), {"x": excluding_id}).scalar()


def _get_user_for_update(c, user_id):
    user = c.execute(text("SELECT * FROM users WHERE id = :id FOR UPDATE"), {"id": user_id}).mappings().first()
    if not user:
        raise AuthError("That user no longer exists.")
    return user


def create_user(actor: str, username: str, role: str, ip: str | None, siems=None) -> tuple[str, str]:
    name = normalise_username(username)
    if role not in ROLES:
        raise AuthError("Unknown role.")
    siems = normalise_siem_access(siems)
    password = temporary_password()
    with engine.begin() as c:
        if c.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": name}).first():
            raise AuthError(f"The user '{name}' already exists.")
        c.execute(text("""INSERT INTO users (username, password_hash, role, must_change_password, created_by,
                                             siem_access)
                          VALUES (:u, :h, :r, TRUE, :by, :s)"""),
                  {"u": name, "h": generate_password_hash(password), "r": role, "by": actor, "s": siems})
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip, detail) VALUES (:a, 'user_created', :t, :ip, :d)"),
                  {"a": actor, "t": name, "ip": ip, "d": f"{role}, SIEMs: {_siems_text(siems)}"})
    return name, password


def set_role(actor_id: int, actor: str, user_id: int, role: str, ip: str | None):
    if role not in ROLES:
        raise AuthError("Unknown role.")
    with engine.begin() as c:
        user = _get_user_for_update(c, user_id)
        if user["id"] == actor_id:
            raise AuthError("You cannot change your own role.")
        if user["role"] == "admin" and role != "admin" and not user["disabled"] and _active_admins(c, user["id"]) == 0:
            raise AuthError("At least one active admin is required.")
        c.execute(text("UPDATE users SET role = :r WHERE id = :id"), {"r": role, "id": user_id})
        _revoke_sessions(c, user_id)
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip, detail) VALUES (:a, 'role_changed', :t, :ip, :d)"),
                  {"a": actor, "t": user["username"], "ip": ip, "d": f"{user['role']} -> {role}"})


def _siems_text(siems) -> str:
    return "all" if siems is None else ", ".join(siems)


def set_siem_access(actor: str, user_id: int, siems, ip: str | None):
    """Change which SIEMs a user sees. Their sessions are signed out, so an open live view cannot keep
    streaming alerts they may no longer see."""
    siems = normalise_siem_access(siems)
    with engine.begin() as c:
        user = _get_user_for_update(c, user_id)
        if (user["siem_access"] is None and siems is None) or user["siem_access"] == siems:
            return
        c.execute(text("UPDATE users SET siem_access = :s WHERE id = :id"), {"s": siems, "id": user_id})
        _revoke_sessions(c, user_id)
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip, detail) VALUES (:a, 'siems_changed', :t, :ip, :d)"),
                  {"a": actor, "t": user["username"], "ip": ip,
                   "d": f"{_siems_text(user['siem_access'])} -> {_siems_text(siems)}"})


def reset_password(actor: str, user_id: int, ip: str | None) -> tuple[str, str]:
    password = temporary_password()
    with engine.begin() as c:
        user = _get_user_for_update(c, user_id)
        c.execute(text("""UPDATE users SET password_hash = :h, must_change_password = TRUE, failed_logins = 0,
                                 locked_until = NULL WHERE id = :id"""),
                  {"h": generate_password_hash(password), "id": user_id})
        _revoke_sessions(c, user_id)
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip) VALUES (:a, 'password_reset', :t, :ip)"),
                  {"a": actor, "t": user["username"], "ip": ip})
    return user["username"], password


def set_disabled(actor_id: int, actor: str, user_id: int, disabled: bool, ip: str | None):
    with engine.begin() as c:
        user = _get_user_for_update(c, user_id)
        if user["id"] == actor_id:
            raise AuthError("You cannot disable your own account.")
        if disabled and user["role"] == "admin" and _active_admins(c, user["id"]) == 0:
            raise AuthError("At least one active admin is required.")
        c.execute(text("UPDATE users SET disabled = :d, failed_logins = 0, locked_until = NULL WHERE id = :id"),
                  {"d": disabled, "id": user_id})
        if disabled:
            _revoke_sessions(c, user_id)
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip) VALUES (:a, :e, :t, :ip)"),
                  {"a": actor, "e": "user_disabled" if disabled else "user_enabled", "t": user["username"], "ip": ip})


def delete_user(actor_id: int, actor: str, user_id: int, ip: str | None):
    with engine.begin() as c:
        user = _get_user_for_update(c, user_id)
        if user["id"] == actor_id:
            raise AuthError("You cannot delete your own account.")
        if user["role"] == "admin" and not user["disabled"] and _active_admins(c, user["id"]) == 0:
            raise AuthError("At least one active admin is required.")
        c.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        c.execute(text("INSERT INTO auth_events (actor, event, target, ip) VALUES (:a, 'user_deleted', :t, :ip)"),
                  {"a": actor, "t": user["username"], "ip": ip})
