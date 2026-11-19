"""The Settings page: admins change what used to need .env, siems.json or a restart.

The publisher writes settings but never reads a secret back: secrets are sealed with the worker's public key
(appsettings.seal) and only the worker and fetcher can open them. Every change is audited (who, what, when;
never the value), and changing a secret, the licence or a SIEM asks for the admin's password again.
"""
import base64
import json
import re
import time
from contextlib import contextmanager

from flask import Blueprint, abort, g, jsonify, redirect, render_template, request, url_for

import appsettings as A
import auth
import editions
import siems as siem_config
from db import get_connection

bp = Blueprint("settings", __name__)
GROUP_NAMES = dict(A.GROUPS)
EMAIL_RE = re.compile(r"^[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
URL_RE = re.compile(r"^https?://[^\s<>\"']{1,490}$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
LOGO_TYPES = {b"\x89PNG\r\n\x1a\n": "image/png", b"\xff\xd8\xff": "image/jpeg", b"RIFF": "image/webp"}
MAX_LOGO = 200 * 1024
_schema = {"ok": False}


class SettingsError(Exception):
    pass


def _main():
    import app as main          # late import: app registers this blueprint at the end of its module
    return main


@contextmanager
def _conn():
    conn = get_connection()
    try:
        if not _schema["ok"]:
            with conn.transaction():
                A.ensure_schema(conn.execute)
            _schema["ok"] = True
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _admin():
    if not g.user or g.user["role"] != "admin":
        abort(403)


# --------------------------------------------------------------------------- reading
def _snapshot(conn) -> dict:
    rows = {r["name"]: r for r in conn.execute(
        "SELECT name, value, secret, hint, kid, updated_by, updated_at FROM app_settings").fetchall()}
    env = {}
    for r in conn.execute("SELECT service, name, value FROM settings_env").fetchall():
        env.setdefault(r["name"], {"services": [], "value": r["value"]})["services"].append(r["service"])
    for f in A.FIELDS:                                      # the publisher's own .env
        if "publisher" in f.services and A.from_env(f.name):
            env.setdefault(f.name, {"services": [], "value": None if f.secret else A.from_env(f.name)})
            env[f.name]["services"].append("publisher")
    meta = conn.execute("SELECT public_key, kid FROM settings_meta WHERE id = 1").fetchone()
    status = {r["service"]: r for r in conn.execute(
        "SELECT service, problems, updated_at FROM settings_status").fetchall()}
    problems = {}
    for r in status.values():
        problems.update(r["problems"] or {})
    return {"rows": rows, "env": env, "meta": meta, "status": status, "problems": problems}


def _field_state(f, snap) -> dict:
    row = snap["rows"].get(f.name)
    env = snap["env"].get(f.name)
    st = {"f": f, "env": bool(env), "env_value": env["value"] if env else None,
          "env_services": env["services"] if env else [], "problem": snap["problems"].get(f.name),
          "needs": editions.FEATURES.get(f.feature) if f.feature and not editions.has(f.feature) else None}
    if f.secret:
        st.update(set=bool(row), hint=row["hint"] if row else None)
    else:
        st.update(value=row["value"] if row else "")
    if f.kind == "multi":
        current = st.get("value") or (env["value"] if env and env["value"] else f.default)
        st["selected"] = {x.strip() for x in str(current or "").split(",") if x.strip()}
    return st


def _siems_state(snap) -> dict:
    try:
        items = json.loads(snap["rows"][A.SIEMS_KEY]["value"]) if A.SIEMS_KEY in snap["rows"] else []
    except ValueError:
        items = []
    out = []
    for s in items:
        sid = s.get("id", "")
        sec = {}
        for k in A.SIEM_SECRETS + tuple("notify." + n for n in A.SIEM_NOTIFY_SECRETS):
            row = snap["rows"].get(A.siem_secret_name(sid, k))
            sec[k] = {"set": bool(row), "hint": row["hint"] if row else None,
                      "problem": snap["problems"].get(A.siem_secret_name(sid, k))}
        out.append({**s, "secrets": sec})
    return {"items": out, "file": snap["env"].get("SIEMS_FILE"), "env_url": snap["env"].get("ELASTIC_URL")}


# --------------------------------------------------------------------------- validation
def _clean_text(v: str, limit: int = 300) -> str:
    v = (v or "").strip()
    if CTRL_RE.search(v):
        raise SettingsError("contains control characters")
    if len(v) > limit:
        raise SettingsError(f"is longer than {limit} characters")
    return v


def validate(f, form) -> str:
    """The value to store for one field ('' = back to the default). Raises SettingsError."""
    if f.kind == "bool":
        return "true" if form.get(f.name) == "true" else "false"
    if f.kind == "multi":
        allowed = {o[0] for o in f.options}
        chosen = [v for v in form.getlist(f.name) if v in allowed]
        return ",".join(chosen)
    raw = form.get(f.name, "")
    if f.kind == "lines":
        v = (raw or "").replace("\r\n", "\n").strip()
        if len(v) > 20000:
            raise SettingsError("is too long")
        if CTRL_RE.search(v.replace("\t", " ")):
            raise SettingsError("contains control characters")
        if f.name == "ARDEA_LICENSE_OFFLINE" and v:
            try:
                doc = json.loads(v)
                assert isinstance(doc, dict) and "payload" in doc and "signature" in doc
            except Exception:
                raise SettingsError("is not an Ardea offline licence file") from None
        return v
    v = _clean_text(raw)
    if not v:
        return ""
    if f.kind == "url" and not URL_RE.match(v):
        raise SettingsError("must start with http:// or https://")
    if f.kind == "int":
        try:
            n = int(v)
        except ValueError:
            raise SettingsError("must be a whole number") from None
        if (f.min is not None and n < f.min) or (f.max is not None and n > f.max):
            raise SettingsError(f"must be between {f.min} and {f.max}")
        return str(n)
    if f.kind == "choice":
        if v not in {o[0] for o in f.options}:
            raise SettingsError("is not one of the choices")
        return v
    if f.kind == "email":
        if not EMAIL_RE.match(v):
            raise SettingsError("is not an e-mail address")
        return v
    if f.kind == "emails":
        items = [x.strip() for x in v.split(",") if x.strip()]
        bad = [x for x in items if not EMAIL_RE.match(x)]
        if bad:
            raise SettingsError(f"has an address that is not valid: {bad[0][:60]}")
        return ", ".join(items)
    if f.kind == "list":
        return ", ".join(x.strip() for x in v.split(",") if x.strip())
    return v


# --------------------------------------------------------------------------- writing
def _public_key(snap):
    if not snap["meta"]:
        raise SettingsError("The worker has not created its encryption key yet. Start the worker once, then try again.")
    return snap["meta"]["public_key"], snap["meta"]["kid"]


def _hint(secret: str) -> str:
    return secret[-4:] if len(secret) >= 12 else ""


def _put(conn, name, value, actor, *, secret=False, hint=None, kid=None):
    conn.execute("""INSERT INTO app_settings (name, value, secret, hint, kid, updated_by, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value, secret = EXCLUDED.secret,
                        hint = EXCLUDED.hint, kid = EXCLUDED.kid, updated_by = EXCLUDED.updated_by, updated_at = NOW()""",
                 (name, value, secret, hint, kid, actor))


def _delete(conn, name) -> bool:
    return conn.execute("DELETE FROM app_settings WHERE name = %s", (name,)).rowcount > 0


def _audit(conn, actor, ip, name, action):
    conn.execute("INSERT INTO settings_audit (actor, ip, name, action) VALUES (%s, %s, %s, %s)",
                 (actor, ip, name, action))


def _check_password(form):
    if g.user.get("sso"):
        return                                  # signed in through the identity provider, which checked them
    if not auth.confirm_password(g.user["user_id"], g.user["username"], form.get("confirm_password", ""),
                                 _main()._client_ip()):
        raise SettingsError("Your password is not correct. Nothing was saved.")


def _secret_input(form, name) -> str:
    v = (form.get(name) or "").strip()
    if CTRL_RE.search(v) or len(v) > 4000:
        raise SettingsError("contains characters that are not allowed")
    return v


def save_group(group: str, form, files=None) -> list[str]:
    """Save one group of the Settings page. Returns notes for the admin. Raises SettingsError."""
    actor, ip = g.user["username"], _main()._client_ip()
    fields = [f for f in A.FIELDS if f.group == group]
    notes = []
    with _conn() as conn:
        snap = _snapshot(conn)
        new_plain, errors = {}, []
        for f in fields:
            if f.secret or f.name in snap["env"]:
                continue
            try:
                new_plain[f.name] = validate(f, form)
            except SettingsError as exc:
                errors.append(f"{f.label} {exc}.")
        secrets = {}
        for f in fields:
            if not f.secret or f.name in snap["env"]:
                continue
            try:
                v = _secret_input(form, f.name)
            except SettingsError as exc:
                errors.append(f"{f.label} {exc}.")
                continue
            if form.get(f.name + "__clear") == "1":
                secrets[f.name] = None
            elif v:
                secrets[f.name] = v
        logo = None
        if group == "reports" and files is not None:
            logo = _logo_from(files, form, errors)
        if errors:
            raise SettingsError(" ".join(errors))
        server_changed = ("ARDEA_PACK_SERVER" in new_plain and new_plain["ARDEA_PACK_SERVER"]
                          != (snap["rows"].get("ARDEA_PACK_SERVER") or {}).get("value", ""))
        sensitive = bool(secrets) or group == "licence" or logo is not None or server_changed
        if sensitive:
            _check_password(form)

        def current(name):
            if name in new_plain:
                return new_plain[name]
            if name in snap["env"]:
                return snap["env"][name]["value"] or ""
            row = snap["rows"].get(name)
            return row["value"] if row else ""

        for name, value in new_plain.items():
            old = snap["rows"].get(name)
            old_value = old["value"] if old else ""
            if value == old_value:
                continue
            if value == "":
                _delete(conn, name)
                _audit(conn, actor, ip, name, "reset to default")
            else:
                _put(conn, name, value, actor)
                _audit(conn, actor, ip, name, "changed")
        # a secret bound to a host that changed no longer opens: drop it and say so
        for f in fields:
            if not f.secret or not f.bind or f.name in secrets or f.name not in snap["rows"]:
                continue
            default = A.BY_NAME[f.bind].default
            old_bound = (snap["rows"][f.bind]["value"] if f.bind in snap["rows"] else "") or default
            if f.bind in new_plain and (new_plain[f.bind] or default) != old_bound:
                _delete(conn, f.name)
                _audit(conn, actor, ip, f.name, "secret cleared (its host changed)")
                notes.append(f"{f.label} was cleared because {A.BY_NAME[f.bind].label} changed. Enter it again.")
        if secrets:
            pub, kid = _public_key(snap)
            for name, value in secrets.items():
                f = A.BY_NAME[name]
                if value is None:
                    if _delete(conn, name):
                        _audit(conn, actor, ip, name, "secret cleared")
                    continue
                bound = (current(f.bind) or A.BY_NAME[f.bind].default) if f.bind else ""
                _put(conn, name, A.seal(pub, name, value, bound), actor, secret=True, hint=_hint(value), kid=kid)
                _audit(conn, actor, ip, name, "secret set")
        if logo is not None:
            if logo == "":
                if _delete(conn, A.BRAND_LOGO_KEY):
                    _audit(conn, actor, ip, A.BRAND_LOGO_KEY, "logo removed")
            else:
                _put(conn, A.BRAND_LOGO_KEY, logo, actor)
                _audit(conn, actor, ip, A.BRAND_LOGO_KEY, "logo uploaded")
    publisher_cache.clear()
    return notes


def _logo_from(files, form, errors):
    if form.get("BRAND_LOGO__clear") == "1":
        return ""
    up = files.get("BRAND_LOGO")
    if not up or not up.filename:
        return None
    data = up.read(MAX_LOGO + 1)
    if len(data) > MAX_LOGO:
        errors.append("The logo is larger than 200 KB.")
        return None
    mime = next((m for sig, m in LOGO_TYPES.items() if data.startswith(sig)), None)
    if mime is None or (mime == "image/webp" and data[8:12] != b"WEBP"):
        errors.append("The logo must be a PNG, JPEG or WebP image.")
        return None
    return f"data:{mime};base64," + base64.b64encode(data).decode()


# --------------------------------------------------------------------------- SIEMs
def _siem_list(snap) -> list[dict]:
    try:
        return json.loads(snap["rows"][A.SIEMS_KEY]["value"]) if A.SIEMS_KEY in snap["rows"] else []
    except ValueError:
        return []


def save_siem(form, siem_id: str | None) -> list[str]:
    """Add (siem_id None) or change one SIEM. Raises SettingsError."""
    actor, ip = g.user["username"], _main()._client_ip()
    notes = []
    with _conn() as conn:
        snap = _snapshot(conn)
        if snap["env"].get("SIEMS_FILE"):
            raise SettingsError("The SIEMs come from siems/siems.json on the server. Edit that file, or remove it "
                                "to manage SIEMs here.")
        items = _siem_list(snap)
        existing = next((s for s in items if s.get("id") == siem_id), None) if siem_id else None
        if siem_id and existing is None:
            raise SettingsError("That SIEM does not exist any more.")
        sid = siem_id or _clean_text(form.get("id", "")).lower()
        if not A.SIEM_ID_RE.match(sid):
            raise SettingsError("The ID must be 1-32 characters: a-z, 0-9, '_' or '-'. It cannot be changed later.")
        if not siem_id and any(s.get("id") == sid for s in items):
            raise SettingsError(f"A SIEM with the ID '{sid}' already exists.")
        try:
            item = {
                "id": sid,
                "name": _clean_text(form.get("name", ""), 60) or sid,
                "url": _clean_text(form.get("url", ""), 300).rstrip("/"),
                "kibana_url": _clean_text(form.get("kibana_url", ""), 300).rstrip("/"),
                "alerts_index": _clean_text(form.get("alerts_index", ""), 200) or siem_config.DEFAULT_ALERTS_INDEX,
                "events_indices": [x.strip() for x in _clean_text(form.get("events_indices", ""), 500).split(",")
                                   if x.strip()] or ["logs-*"],
                "enabled": form.get("enabled") == "true",
            }
        except SettingsError as exc:
            raise SettingsError(f"A field {exc}.") from None
        pem = (form.get("ca_pem") or "").replace("\r\n", "\n").strip()
        if pem and ("-----BEGIN CERTIFICATE-----" not in pem or len(pem) > 20000 or CTRL_RE.search(pem)):
            raise SettingsError("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
        if pem:
            item["ca_pem"] = pem + "\n"
        elif existing and existing.get("ca_pem") and form.get("ca_pem__clear") != "1":
            item["ca_pem"] = existing["ca_pem"]
        if item["kibana_url"] and not URL_RE.match(item["kibana_url"]):
            raise SettingsError("The Kibana URL must start with https://.")
        context = [x.strip()[:300] for x in (form.get("context") or "").splitlines() if x.strip()][:20]
        report_to = [x.strip() for x in (form.get("report_to") or "").split(",") if x.strip()]
        smtp_to = [x.strip() for x in (form.get("notify_smtp_to") or "").split(",") if x.strip()]
        if context:
            item["context"] = context
        if report_to:
            item["report_to"] = report_to
        if smtp_to:
            item["notify"] = {"smtp_to": smtp_to}
        try:                                           # the same checks the worker and fetcher run
            siem_config.parse({"siems": [item]})
        except siem_config.SiemConfigError as exc:
            raise SettingsError(str(exc).replace("siems.json ", "").replace("siems.json", "SIEM")) from None

        secrets = {}
        for k in A.SIEM_SECRETS + tuple("notify." + n for n in A.SIEM_NOTIFY_SECRETS):
            field = k.replace(".", "_")
            if form.get(field + "__clear") == "1":
                secrets[k] = None
                continue
            v = _secret_input(form, field)
            if v:
                if k.startswith("notify.") and k != "notify.webhook_secret" and not URL_RE.match(v):
                    raise SettingsError("Webhook addresses must start with https://.")
                secrets[k] = v
        if not siem_id and not secrets.get("fetcher_api_key"):
            notes.append("No fetcher API key yet: alerts are collected once you add it.")
        _check_password(form)

        url_changed = bool(existing) and existing.get("url", "").rstrip("/") != item["url"]
        if url_changed:
            for k in A.SIEM_SECRETS + tuple("notify." + n for n in A.SIEM_NOTIFY_SECRETS):
                if k not in secrets and _delete(conn, A.siem_secret_name(sid, k)):
                    _audit(conn, actor, ip, A.siem_secret_name(sid, k), "secret cleared (SIEM URL changed)")
                    if k in A.SIEM_SECRETS:
                        notes.append(f"The {k.replace('_', ' ')} was cleared because the URL changed. Enter it again.")
        if secrets:
            pub, kid = _public_key(snap)
            for k, v in secrets.items():
                name = A.siem_secret_name(sid, k)
                if v is None:
                    if _delete(conn, name):
                        _audit(conn, actor, ip, name, "secret cleared")
                    continue
                _put(conn, name, A.seal(pub, name, v, item["url"]), actor, secret=True, hint=_hint(v), kid=kid)
                _audit(conn, actor, ip, name, "secret set")
        if existing:
            items = [item if s.get("id") == sid else s for s in items]
        else:
            items.append(item)
        _put(conn, A.SIEMS_KEY, json.dumps(items), actor)
        _audit(conn, actor, ip, f"SIEM {sid}", "changed" if existing else "added")
    return notes


def delete_siem(form, siem_id: str):
    actor, ip = g.user["username"], _main()._client_ip()
    with _conn() as conn:
        snap = _snapshot(conn)
        if snap["env"].get("SIEMS_FILE"):
            raise SettingsError("The SIEMs come from siems/siems.json on the server.")
        items = _siem_list(snap)
        if not any(s.get("id") == siem_id for s in items):
            raise SettingsError("That SIEM does not exist any more.")
        purge = form.get("purge") == "1"
        if purge and (form.get("confirm_id") or "").strip() != siem_id:
            raise SettingsError(f"Type the SIEM ID ({siem_id}) to delete its data too. Nothing was removed.")
        _check_password(form)
        items = [s for s in items if s.get("id") != siem_id]
        if items:
            _put(conn, A.SIEMS_KEY, json.dumps(items), actor)
        else:
            _delete(conn, A.SIEMS_KEY)
        for k in A.SIEM_SECRETS + tuple("notify." + n for n in A.SIEM_NOTIFY_SECRETS):
            _delete(conn, A.siem_secret_name(siem_id, k))
        _audit(conn, actor, ip, f"SIEM {siem_id}", "removed")
        if not purge:
            return None
        conn.execute("UPDATE siems SET active = FALSE WHERE id = %s", (siem_id,))
        n = purge_siem_data(conn, siem_id)
        _audit(conn, actor, ip, f"SIEM {siem_id}", f"data deleted ({n} alerts)")
    auth.audit(actor, "siem_data_deleted", siem_id, ip, f"{n} alerts")
    return n


# --------------------------------------------------------------------------- deleting a SIEM's data
PURGE_ALERT_TABLES = ("alert_work_log", "alert_work", "alert_questions", "notifications", "feedback",
                      "investigation_steps", "triage_results", "outbound_requests")


def configured_siem_ids(conn, snap=None) -> set[str]:
    snap = snap or _snapshot(conn)
    ids = {s.get("id") for s in _siem_list(snap)}
    ids |= {r["id"] for r in conn.execute("SELECT id FROM siems WHERE active").fetchall()}
    return ids


def leftover_siems(conn, snap=None) -> list[dict]:
    """SIEMs that are no longer configured but still have alerts in the database."""
    configured = configured_siem_ids(conn, snap)
    rows = conn.execute("""SELECT a.siem, count(*) AS alerts, max(a.timestamp) AS last, max(s.name) AS name
                           FROM alerts a LEFT JOIN siems s ON s.id = a.siem
                           WHERE a.siem IS NOT NULL GROUP BY a.siem ORDER BY a.siem""").fetchall()
    return [r for r in rows if r["siem"] not in configured]


def purge_siem_data(conn, siem_id: str) -> int:
    """Delete everything stored for one SIEM: alerts and all that hangs off them, its health, fetch position,
    suppressions and name. Users restricted to it keep their other SIEMs (and see nothing if it was the only one).
    Returns the number of alerts deleted."""
    ids = "SELECT alert_id FROM alerts WHERE siem = %(s)s"
    p = {"s": siem_id}
    for t in PURGE_ALERT_TABLES:
        conn.execute(f"DELETE FROM {t} WHERE alert_id IN ({ids})", p)
    conn.execute(f"DELETE FROM alert_occurrences WHERE parent_alert_id IN ({ids})", p)
    n = conn.execute("DELETE FROM alerts WHERE siem = %(s)s", p).rowcount
    for t, col in (("source_health", "siem"), ("fetcher_siem_state", "siem"), ("suppressions", "siem"),
                   ("siems", "id")):
        if conn.execute("SELECT to_regclass(%s) AS t", (f"public.{t}",)).fetchone()["t"]:
            conn.execute(f"DELETE FROM {t} WHERE {col} = %(s)s", p)
    conn.execute("DELETE FROM app_settings WHERE name LIKE %s", (f"SIEM.{siem_id}.%",))
    conn.execute("UPDATE users SET siem_access = array_remove(siem_access, %(s)s) WHERE %(s)s = ANY(siem_access)", p)
    return n


def delete_siem_data(form, siem_id: str) -> int:
    """The 'Delete its data' button for a SIEM that is no longer configured."""
    actor, ip = g.user["username"], _main()._client_ip()
    if (form.get("confirm_id") or "").strip() != siem_id:
        raise SettingsError(f"Type the SIEM ID ({siem_id}) to confirm. Nothing was deleted.")
    _check_password(form)
    with _conn() as conn:
        if siem_id in configured_siem_ids(conn):
            raise SettingsError("That SIEM is still configured. Remove it first.")
        n = purge_siem_data(conn, siem_id)
        _audit(conn, actor, ip, f"SIEM {siem_id}", f"data deleted ({n} alerts)")
    auth.audit(actor, "siem_data_deleted", siem_id, ip, f"{n} alerts")
    return n


# --------------------------------------------------------------------------- settings templates (MSP)
TEMPLATE_FIELDS = ("alerts_index", "events_indices", "context", "report_to", "notify_smtp_to")
MAX_TEMPLATES = 30


def _templates(snap) -> list[dict]:
    try:
        v = json.loads(snap["rows"][A.SIEM_TEMPLATES_KEY]["value"]) if A.SIEM_TEMPLATES_KEY in snap["rows"] else []
        return v if isinstance(v, list) else []
    except ValueError:
        return []


def _template_from(form) -> dict:
    t = {"name": _clean_text(form.get("name", ""), 60)}
    if not t["name"]:
        raise SettingsError("Give the template a name.")
    t["alerts_index"] = _clean_text(form.get("alerts_index", ""), 200)
    t["events_indices"] = [x.strip() for x in _clean_text(form.get("events_indices", ""), 500).split(",") if x.strip()]
    t["context"] = [x.strip()[:300] for x in (form.get("context") or "").splitlines() if x.strip()][:20]
    if any(CTRL_RE.search(x) for x in t["context"]):
        raise SettingsError("The facts contain characters that are not allowed.")
    t["context_mode"] = "replace" if form.get("context_mode") == "replace" else "add"
    t["report_to"] = [x.strip() for x in (form.get("report_to") or "").split(",") if x.strip()][:20]
    t["notify_smtp_to"] = [x.strip() for x in (form.get("notify_smtp_to") or "").split(",") if x.strip()][:20]
    for x in t["report_to"] + t["notify_smtp_to"]:
        if not EMAIL_RE.match(x):
            raise SettingsError(f"'{x[:80]}' is not an e-mail address.")
    t["default"] = form.get("default") == "1"
    return t


def save_template(form, old_name: str | None):
    actor, ip = g.user["username"], _main()._client_ip()
    t = _template_from(form)
    with _conn() as conn:
        items = _templates(_snapshot(conn))
        if old_name and not any(x.get("name") == old_name for x in items):
            raise SettingsError("That template does not exist any more.")
        if t["name"] != old_name and any(x.get("name") == t["name"] for x in items):
            raise SettingsError(f"A template called '{t['name']}' already exists.")
        if not old_name and len(items) >= MAX_TEMPLATES:
            raise SettingsError(f"At most {MAX_TEMPLATES} templates.")
        if t["default"]:
            for x in items:
                x["default"] = False
        items = [t if x.get("name") == old_name else x for x in items] if old_name else items + [t]
        _put(conn, A.SIEM_TEMPLATES_KEY, json.dumps(items), actor)
        _audit(conn, actor, ip, f"template {t['name']}", "changed" if old_name else "added")


def delete_template(name: str):
    actor, ip = g.user["username"], _main()._client_ip()
    with _conn() as conn:
        items = _templates(_snapshot(conn))
        rest = [x for x in items if x.get("name") != name]
        if len(rest) == len(items):
            return
        _put(conn, A.SIEM_TEMPLATES_KEY, json.dumps(rest), actor)
        _audit(conn, actor, ip, f"template {name}", "removed")


def apply_template_to(item: dict, t: dict) -> dict:
    """A SIEM entry with the template's non-empty values applied. Facts are added (or replace, if the template
    says so); every other value set in the template replaces the SIEM's own."""
    out = dict(item)
    if t.get("alerts_index"):
        out["alerts_index"] = t["alerts_index"]
    if t.get("events_indices"):
        out["events_indices"] = list(t["events_indices"])
    if t.get("context"):
        base = [] if t.get("context_mode") == "replace" else list(item.get("context") or [])
        out["context"] = list(dict.fromkeys(base + list(t["context"])))[:20]
    if t.get("report_to"):
        out["report_to"] = list(t["report_to"])
    if t.get("notify_smtp_to"):
        out["notify"] = {**(item.get("notify") or {}), "smtp_to": list(t["notify_smtp_to"])}
    return out


def apply_template(form, name: str) -> list[str]:
    """Apply a template to the ticked SIEMs. Returns their ids."""
    actor, ip = g.user["username"], _main()._client_ip()
    chosen = set(form.getlist("siem")) if hasattr(form, "getlist") else set(form.get("siem") or [])
    with _conn() as conn:
        snap = _snapshot(conn)
        if snap["env"].get("SIEMS_FILE"):
            raise SettingsError("The SIEMs come from siems/siems.json on the server.")
        t = next((x for x in _templates(snap) if x.get("name") == name), None)
        if t is None:
            raise SettingsError("That template does not exist any more.")
        items = _siem_list(snap)
        done = []
        new = []
        for s in items:
            if s.get("id") in chosen:
                s = apply_template_to(s, t)
                done.append(s["id"])
            new.append(s)
        if not done:
            raise SettingsError("Tick at least one SIEM.")
        try:
            siem_config.parse({"siems": [{**s, "enabled": True} for s in new if s.get("id") in done]})
        except siem_config.SiemConfigError as exc:
            raise SettingsError(str(exc).replace("siems.json ", "")) from None
        _put(conn, A.SIEMS_KEY, json.dumps(new), actor)
        _audit(conn, actor, ip, f"template {name}", f"applied to {', '.join(done)}"[:300])
    return done


def move_siem(siem_id: str, up: bool):
    """Change the order (the first SIEM is the one the Community and Pro editions collect from)."""
    actor, ip = g.user["username"], _main()._client_ip()
    with _conn() as conn:
        items = _siem_list(_snapshot(conn))
        i = next((n for n, s in enumerate(items) if s.get("id") == siem_id), None)
        j = None if i is None else (i - 1 if up else i + 1)
        if i is None or j < 0 or j >= len(items):
            return
        items[i], items[j] = items[j], items[i]
        _put(conn, A.SIEMS_KEY, json.dumps(items), actor)
        _audit(conn, actor, ip, f"SIEM {siem_id}", "moved")


# --------------------------------------------------------------------------- what the publisher itself uses
class _Cache(dict):
    at = 0.0


publisher_cache = _Cache()


def publisher_value(name: str, default: str = "") -> str:
    """A non-secret setting for the publisher itself: .env first, then the Settings page (cached 30 s)."""
    v = A.from_env(name)
    if v:
        return v
    if time.monotonic() - publisher_cache.at > 30 or not publisher_cache:
        try:
            with _conn() as conn:
                rows = conn.execute("SELECT name, value FROM app_settings WHERE NOT secret AND name = ANY(%s)",
                                    ([f.name for f in A.FIELDS if "publisher" in f.services] + [A.BRAND_LOGO_KEY],)
                                    ).fetchall()
            publisher_cache.clear()
            publisher_cache.update({r["name"]: r["value"] for r in rows})
            publisher_cache["__loaded__"] = "1"
        except Exception:
            pass
        publisher_cache.at = time.monotonic()
    return publisher_cache.get(name) or default


# --------------------------------------------------------------------------- pages
TEST_KINDS = re.compile(r"^(llm|licence|pack:install|digest|health|siem:[a-z0-9][a-z0-9_-]{0,31}|notify:(smtp|ntfy|slack|teams|webhook|jira|thehive))$")
MAX_PACK = 2 * 1024 * 1024


# --------------------------------------------------------------------------- playbook pack
def _version_key(version):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", str(version or "")))


def _packs_state(conn) -> dict:
    """The Playbook pack tab: installed packs (newest first), uploads waiting for the worker, the last check."""
    rows = conn.execute("""SELECT id, version, source, status, detail, summary, added_by, added_at, installed_at
                           FROM playbook_packs ORDER BY id DESC LIMIT 30""").fetchall()
    installed = sorted((r for r in rows if r["status"] == "installed"),
                       key=lambda r: (_version_key(r["version"]), r["id"]), reverse=True)
    state = conn.execute("SELECT last_check_at, last_ok, last_detail FROM playbook_pack_state WHERE id = 1").fetchone()
    return {"current": installed[0] if installed else None, "installed": installed,
            "others": [r for r in rows if r["status"] != "installed"][:5], "state": state}


def upload_pack(files) -> str:
    """Store an uploaded .ardpack as 'pending'; the worker checks the signature and installs it."""
    f = files.get("PACK") if files else None
    if f is None or not f.filename:
        raise SettingsError("Choose a .ardpack file first.")
    data = f.read(MAX_PACK + 1)
    if len(data) > MAX_PACK:
        raise SettingsError("That file is larger than 2 MB, so it is not an Ardea playbook pack.")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SettingsError("That file is not an Ardea playbook pack (.ardpack).") from None
    payload = doc.get("payload") if isinstance(doc, dict) else None
    if not isinstance(payload, dict) or not isinstance(doc.get("signature"), str):
        raise SettingsError("That file is not a signed Ardea playbook pack.")
    version = payload.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.\-]{1,40}", version):
        raise SettingsError("That pack has no valid version.")
    with _conn() as conn:
        waiting = conn.execute("SELECT count(*) AS n FROM playbook_packs WHERE status = 'pending'").fetchone()
        if waiting["n"] >= 3:
            raise SettingsError("Three uploads are already waiting for the worker. Is the worker running?")
        conn.execute("""INSERT INTO playbook_packs (version, content, source, status, added_by)
                        VALUES (%s, %s, 'upload', 'pending', %s)""",
                     (version, json.dumps(doc, ensure_ascii=False), g.user["username"]))
        _audit(conn, g.user["username"], _main()._client_ip(), "PLAYBOOK_PACK", f"uploaded {version}")
    return version


def remove_pack(pack_id: int) -> str | None:
    with _conn() as conn:
        row = conn.execute("DELETE FROM playbook_packs WHERE id = %s RETURNING version", (pack_id,)).fetchone()
        if row:
            _audit(conn, g.user["username"], _main()._client_ip(), "PLAYBOOK_PACK", f"removed {row['version'] or '?'}")
    return row["version"] if row else None


def _edit_values(siems_state, edit, form) -> dict:
    """The SIEM form's values as text: from the form just sent (after an error), else from the saved SIEM."""
    s = next((x for x in siems_state["items"] if x.get("id") == edit), None) if siems_state else None
    if form:
        keys = ("id", "name", "url", "kibana_url", "alerts_index", "events_indices", "context", "report_to",
                "notify_smtp_to")
        out = {k: form.get(k, "") for k in keys}
        out["enabled"] = form.get("enabled") == "true"
    elif s:
        out = {"id": s.get("id", ""), "name": s.get("name", ""), "url": s.get("url", ""),
               "kibana_url": s.get("kibana_url", ""), "alerts_index": s.get("alerts_index", ""),
               "events_indices": ", ".join(s.get("events_indices") or []),
               "context": "\n".join(s.get("context") or []), "report_to": ", ".join(s.get("report_to") or []),
               "notify_smtp_to": ", ".join((s.get("notify") or {}).get("smtp_to") or []),
               "enabled": s.get("enabled", True)}
    else:
        out = {"enabled": True}
    out["saved"] = s
    return out


def _render(group, status=200, error=None, notes=None, edit=None, form=None, template=None):
    template = template or (request.args.get("template") if group == "siems" else None)
    with _conn() as conn:
        snap = _snapshot(conn)
        leftovers = leftover_siems(conn, snap) if group == "siems" else []
        audit = conn.execute("""SELECT at, actor, name, action FROM settings_audit
                                ORDER BY id DESC LIMIT 40""").fetchall() if group == "audit" else []
        packs = _packs_state(conn) if group == "playbooks" else None
    fields = [_field_state(f, snap) for f in A.FIELDS if f.group == group]
    siems = _siems_state(snap) if group == "siems" else None
    ev = _edit_values(siems, edit, None if template else form) if edit else None
    templates = _templates(snap) if group == "siems" else []
    if ev is not None and edit == "new" and not form:            # a new SIEM starts from the default template
        t = next((x for x in templates if x.get("default")), None)
        if t and editions.has("templates"):
            ev.update(alerts_index=t.get("alerts_index", ""), events_indices=", ".join(t.get("events_indices") or []),
                      context="\n".join(t.get("context") or []), report_to=", ".join(t.get("report_to") or []),
                      notify_smtp_to=", ".join(t.get("notify_smtp_to") or []), from_template=t["name"])
    tv = None
    if template:
        saved = next((x for x in templates if x.get("name") == template), None)
        if form is not None:
            tv = {k: form.get(k, "") for k in ("name", "alerts_index", "events_indices", "context", "report_to",
                                               "notify_smtp_to", "context_mode", "default")}
            tv["default"] = form.get("default") == "1"
        elif saved:
            tv = {"name": saved["name"], "alerts_index": saved.get("alerts_index", ""),
                  "events_indices": ", ".join(saved.get("events_indices") or []),
                  "context": "\n".join(saved.get("context") or []), "report_to": ", ".join(saved.get("report_to") or []),
                  "notify_smtp_to": ", ".join(saved.get("notify_smtp_to") or []),
                  "context_mode": saved.get("context_mode", "add"), "default": saved.get("default", False)}
        else:
            tv = {"context_mode": "add"}
        tv["old_name"] = saved["name"] if saved else None
    logo = snap["rows"].get(A.BRAND_LOGO_KEY)
    return render_template(
        "settings.html", group=group, groups=A.GROUPS + [("audit", "Change log")], fields=fields,
        siems=siems, edit=edit, ev=ev, packs=packs, templates=templates, template=template, tv=tv,
        leftovers=leftovers, can_templates=editions.has("templates"), pack_feature=editions.has("playbook_pack"),
        has_key=bool(snap["meta"]), error=error, notes=notes or [], audit=audit,
        workers=snap["status"], logo=bool(logo), needs_password=not g.user.get("sso"),
        msp=editions.has("multi_siem"), edition=editions.edition(), license=_main()._license_view()), status


@bp.app_errorhandler(413)
def too_large(_exc):
    """A friendly answer instead of the bare 413 page, on the Settings page."""
    group = "playbooks" if request.path == "/admin/settings/playbooks/upload" else request.path.rsplit("/", 1)[-1]
    if request.path.startswith("/admin/settings/") and group in GROUP_NAMES:
        return redirect(url_for("settings.settings_page", group=group, too_large=1), code=303)
    if request.path in ("/queue/work", "/incidents/work"):
        back = "/queue" if request.path == "/queue/work" else "/incidents"
        return redirect(f"{back}?error=Too+many+alerts+ticked+at+once.+Tick+fewer+and+apply+again.", code=303)
    return "Request too large.", 413


@bp.get("/admin/settings")
def settings_home():
    _admin()
    return redirect(url_for("settings.settings_page", group="licence"))


@bp.get("/admin/settings/<group>")
def settings_page(group):
    _admin()
    if group not in GROUP_NAMES and group != "audit":
        abort(404)
    edit = request.args.get("edit")
    error = ("That was too large, so nothing was saved. A logo can be up to 200 KB, a playbook pack 2 MB; other "
             "settings forms are limited to 16 KB.") if request.args.get("too_large") else None
    return _render(group, edit=edit, error=error, notes=[n for n in [request.args.get("note", "")[:300]] if n])


@bp.post("/admin/settings/<group>")
def settings_save(group):
    _admin()
    if group not in GROUP_NAMES or group == "siems":
        abort(404)
    try:
        notes = save_group(group, request.form, request.files)
    except SettingsError as exc:
        return _render(group, 400, error=str(exc))
    return _render(group, notes=["Saved. The worker applies changes within about 30 seconds."] + notes)


@bp.post("/admin/settings/siems/save")
def siem_save():
    _admin()
    siem_id = request.form.get("siem_id") or None
    try:
        notes = save_siem(request.form, siem_id)
    except SettingsError as exc:
        return _render("siems", 400, error=str(exc), edit=siem_id or "new", form=request.form)
    return _render("siems", notes=["SIEM saved. Collection starts or changes within about a minute."] + notes)


@bp.post("/admin/settings/siems/<siem_id>/delete")
def siem_delete(siem_id):
    _admin()
    try:
        n = delete_siem(request.form, siem_id)
    except SettingsError as exc:
        return _render("siems", 400, error=str(exc), edit=siem_id)
    if n is None:
        return _render("siems", notes=[f"SIEM {siem_id} removed. Its alerts stay in Ardea."])
    return _render("siems", notes=[f"SIEM {siem_id} removed and its data deleted ({n} alerts)."])


@bp.post("/admin/settings/siems/<siem_id>/purge")
def siem_purge(siem_id):
    _admin()
    try:
        n = delete_siem_data(request.form, siem_id)
    except SettingsError as exc:
        return _render("siems", 400, error=str(exc))
    return _render("siems", notes=[f"Deleted everything stored for {siem_id} ({n} alerts)."])


def _templates_allowed():
    _admin()
    if not editions.has("templates"):
        abort(403)


@bp.post("/admin/settings/siems/templates/save")
def template_save():
    _templates_allowed()
    old = request.form.get("old_name") or None
    try:
        save_template(request.form, old)
    except SettingsError as exc:
        return _render("siems", 400, error=str(exc), template=old or "new", form=request.form)
    return _render("siems", notes=["Template saved. Apply it to SIEMs below; nothing changes until you do."])


@bp.post("/admin/settings/siems/templates/delete")
def template_delete():
    _templates_allowed()
    delete_template(request.form.get("name", ""))
    return _render("siems", notes=["Template removed. SIEMs it was applied to keep their values."])


@bp.post("/admin/settings/siems/templates/apply")
def template_apply():
    _templates_allowed()
    try:
        done = apply_template(request.form, request.form.get("name", ""))
    except SettingsError as exc:
        return _render("siems", 400, error=str(exc))
    return _render("siems", notes=[f"Applied to {len(done)} SIEM{'s' if len(done) != 1 else ''}: {', '.join(done)}. "
                                   "The worker and fetcher pick it up within about a minute."])


@bp.post("/admin/settings/siems/<siem_id>/move")
def siem_move(siem_id):
    _admin()
    move_siem(siem_id, request.form.get("dir") == "up")
    return redirect(url_for("settings.settings_page", group="siems"))


@bp.post("/admin/settings/playbooks/upload")
def pack_upload():
    _admin()
    try:
        version = upload_pack(request.files)
    except SettingsError as exc:
        return _render("playbooks", 400, error=str(exc))
    return _render("playbooks", notes=[f"Pack {version} uploaded. The worker checks its signature and installs it "
                                       "within a minute: reload this page to see the result."])


@bp.post("/admin/settings/playbooks/<int:pack_id>/delete")
def pack_delete(pack_id):
    _admin()
    version = remove_pack(pack_id)
    note = f"Pack {version} removed." if version else "That pack was already removed."
    return redirect(url_for("settings.settings_page", group="playbooks", note=note), code=303)


@bp.post("/admin/settings/test")
def test_start():
    _admin()
    kind = request.form.get("kind") or (request.get_json(silent=True) or {}).get("kind")
    if not kind or not TEST_KINDS.match(kind):
        return jsonify(error="unknown test"), 400
    with _conn() as conn:
        recent = conn.execute("""SELECT count(*) AS n FROM settings_tests WHERE requested_by = %s
                                 AND requested_at > NOW() - interval '1 minute'""", (g.user["username"],)).fetchone()
        if recent["n"] >= 10:
            return jsonify(error="too many tests: wait a minute"), 429
        row = conn.execute("INSERT INTO settings_tests (kind, requested_by) VALUES (%s, %s) RETURNING id",
                           (kind, g.user["username"])).fetchone()
    return jsonify(id=row["id"])


@bp.get("/admin/settings/test/<int:test_id>")
def test_status(test_id):
    _admin()
    with _conn() as conn:
        row = conn.execute("SELECT status, detail, requested_at FROM settings_tests WHERE id = %s",
                           (test_id,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(status=row["status"], detail=row["detail"] or "")
