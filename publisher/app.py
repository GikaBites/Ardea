import base64
import json
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
import time
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Response,
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    stream_with_context,
    url_for,
)
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

import appsettings
import auth
import demo
import editions
import incidents
import settings_admin
from db import (AlertRepository, add_feedback, alert_siem, ensure_schema, get_feedback,  # type: ignore
                get_connection, get_session, get_trail, list_siems)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ardea.publisher")

app = Flask(__name__)
# Requests are small (forms, feedback): 16 KB. The exceptions are the two uploads on the Settings page.
MAX_REQUEST_BYTES = 16 * 1024
MAX_UPLOAD_BYTES = 320 * 1024                     # a 200 KB logo, base64-free multipart, plus the form
MAX_PACK_UPLOAD_BYTES = 2 * 1024 * 1024 + 16 * 1024   # a signed playbook pack (up to 2 MB) plus the form
MAX_BULK_BYTES = 256 * 1024                       # bulk actions: up to 2000 ticked alerts
UPLOAD_PATHS = {"/admin/settings/reports": MAX_UPLOAD_BYTES,
                "/admin/settings/playbooks/upload": MAX_PACK_UPLOAD_BYTES,
                "/queue/work": MAX_BULK_BYTES, "/incidents/work": MAX_BULK_BYTES}
app.config["MAX_CONTENT_LENGTH"] = max(UPLOAD_PATHS.values())


@app.before_request
def limit_request_size():
    """16 KB for everything but the two uploads, which have their own limits (UPLOAD_PATHS)."""
    if request.method in ("GET", "HEAD"):
        return None
    limit = UPLOAD_PATHS.get(request.path, MAX_REQUEST_BYTES)
    request.max_content_length = limit            # also caps chunked uploads without a Content-Length
    if request.content_length is not None and request.content_length > limit:
        abort(413)
    return None
# Requests arrive through the Caddy reverse proxy, which terminates HTTPS.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
KIBANA_HOST = urlparse(os.environ.get("KIBANA_BASE_URL", "")).hostname     # single-SIEM installs (no siems table rows)


def _bootstrap():
    for attempt in range(30):
        try:
            demo.seed(auth.engine)                        # ARDEA_DEMO only: sample data, user demo
            auth.ensure_schema_and_admin()
            ensure_schema()                               # multi-SIEM columns (if the fetcher has not added them yet)
            with get_connection() as conn:                # Settings page, assignments and pack tables
                with conn.transaction():
                    appsettings.ensure_schema(conn.execute)
            return
        except Exception as exc:                      # database still starting
            log.warning("auth setup failed (%s), retrying", type(exc).__name__)
            time.sleep(2)
    raise SystemExit("could not set up the users table")


_bootstrap()

# --------------------------------------------------------------------------- authentication
PASSWORD_CHANGE_PATHS = {"/account/password", "/logout"}


def current_user():
    return g.user["username"] if g.get("user") else None


def _client_ip():
    return request.remote_addr


def _is_api():
    return request.path.startswith(("/api/", "/stream"))


# Public URLs the UI is reached at, e.g. behind a firewall port forward that changes the port:
# ALLOWED_ORIGINS=https://ardea.example.com:8443,https://192.168.1.10
ALLOWED_ORIGINS = {o.strip().rstrip("/").lower() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()}


def _origin_ok(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}".lower() in ALLOWED_ORIGINS or p.netloc.lower() == request.host.lower()


def _same_origin():
    """True if the request was made by an Ardea page.

    Sec-Fetch-Site is set by the browser itself (other sites cannot set it) and is not affected by
    proxies or port forwards that rewrite Host, so it is checked first. Origin/Referer are the
    fallback for browsers that do not send it."""
    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site:
        return fetch_site == "same-origin"
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        return _origin_ok(origin)
    referer = request.headers.get("Referer")
    return bool(referer) and _origin_ok(referer)


def _safe_next(target):
    """Only redirect to a local path after login (no //host or backslash tricks)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


# --------------------------------------------------------------------------- single sign-on (Pro / MSP)
# Caddy authenticates the user with your identity provider (forward_auth) and passes the username in this
# header. Caddy always removes the header from browser requests first (caddy/Caddyfile), and the UI is
# only reachable through Caddy, so a browser can never set it itself.
SSO_ENABLED = os.getenv("ARDEA_SSO", "").strip().lower() in ("1", "true", "yes")
SSO_HEADER = "X-Ardea-User"
_sso_warned = {"done": False}


def _sso_username():
    """None: SSO is not in use for this request. "": a header that is not a valid username."""
    if not SSO_ENABLED:
        return None
    raw = request.headers.get(SSO_HEADER)
    if not raw:
        return None
    if not editions.has("sso"):
        if not _sso_warned["done"]:
            _sso_warned["done"] = True
            log.warning("ARDEA_SSO is on, but single sign-on needs Ardea Pro or MSP (edition: %s). "
                        "Users sign in with their Ardea password.", editions.edition())
        return None
    name = raw.strip().lower()
    return name if auth.USERNAME_RE.match(name) else ""


def _sso_refused(name):
    msg = (f"Your single sign-on account '{name[:64]}' has no active Ardea account. Ask an Ardea admin "
           "to create a user with exactly this username." if name else
           "Your single sign-on username is not a valid Ardea username.")
    if _is_api():
        return jsonify(error="sso_no_account"), 403
    return render_template("login.html", next="/", username="", error=msg, sso_refused=True), 403


# --------------------------------------------------------------------------- branding (MSP)
BRAND_DIR = os.getenv("ARDEA_BRANDING_DIR", "/app/branding")
_LOGO_TYPES = {b"\x89PNG\r\n\x1a\n": "image/png", b"\xff\xd8\xff": "image/jpeg", b"RIFF": "image/webp"}


def _brand_name() -> str:
    """.env first, then the Settings page."""
    return settings_admin.publisher_value("ARDEA_BRAND_NAME").strip()[:40]


def _brand_logo():
    """(source, mime): a file in branding/, else the logo uploaded on the Settings page (bytes)."""
    found = _brand_logo_file()
    if found:
        return found
    uri = settings_admin.publisher_value(appsettings.BRAND_LOGO_KEY)
    m = re.match(r"^data:(image/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$", uri or "")
    if m:
        return base64.b64decode(m.group(2)), m.group(1)
    return None


def _brand_logo_file():
    """(path, mimetype) of branding/logo.png|jpg|webp, checked by content (no SVG: it can carry script)."""
    for name in ("logo.png", "logo.jpg", "logo.jpeg", "logo.webp"):
        path = os.path.join(BRAND_DIR, name)
        try:
            if os.path.getsize(path) > 512 * 1024:
                continue
            with open(path, "rb") as f:
                head = f.read(12)
        except OSError:
            continue
        for magic, mime in _LOGO_TYPES.items():
            if head.startswith(magic) and (mime != "image/webp" or head[8:12] == b"WEBP"):
                return path, mime
    return None


def current_brand():
    if not editions.has("branding"):
        return None
    name, logo = _brand_name(), _brand_logo()
    if not (name or logo):
        return None
    return {"name": name or "Ardea", "logo": bool(logo)}


_alarm_cache = {"at": 0.0, "rows": []}


def _source_alarm_rows():
    """SIEMs that went quiet, unreachable ones, and quiet watched hosts (written by the worker)."""
    if time.monotonic() - _alarm_cache["at"] < 30:
        return _alarm_cache["rows"]
    rows = []
    try:
        with get_connection() as conn:
            if conn.execute("SELECT to_regclass('public.source_health') AS t").fetchone()["t"]:
                rows = conn.execute("""SELECT h.siem, h.status, h.detail, h.quiet_hosts, s.name FROM source_health h
                                       LEFT JOIN siems s ON s.id = h.siem
                                       WHERE h.status <> 'ok' OR h.quiet_hosts <> '[]'::jsonb
                                       ORDER BY h.siem""").fetchall()
    except Exception:
        log.exception("could not read source_health")
    _alarm_cache.update(at=time.monotonic(), rows=rows)
    return rows


def source_alarms(user):
    """Banner lines for this user: only SIEMs they may see. Pro (source_health)."""
    if not user or not editions.has("source_health"):
        return []
    out = []
    for r in _source_alarm_rows():
        if not auth.can_see_siem(user, r["siem"]):
            continue
        name = r["name"] or r["siem"]
        if r["status"] == "silent":
            out.append(f"{name} has sent {r['detail'] or 'no events'}. Alerts cannot fire without events.")
        elif r["status"] == "unreachable":
            out.append(f"{name} {r['detail'] or 'cannot be reached'}. Its alerts are not being collected.")
        hosts = [h["host"] for h in (r["quiet_hosts"] or [])]
        if hosts and editions.has("host_watch"):
            more = f" and {len(hosts) - 5} more" if len(hosts) > 5 else ""
            out.append(f"{name}: watched host{'s' if len(hosts) > 1 else ''} {', '.join(hosts[:5])}{more} "
                       f"stopped sending events.")
    return out


@app.context_processor
def inject_brand():
    brand = current_brand()
    return {"brand": brand, "product_name": brand["name"] if brand else "Ardea", "demo_mode": demo.ENABLED,
            "source_alarms": source_alarms(getattr(g, "user", None)),
            "queue_on": _queue_on()}


def _queue_on() -> bool:
    """The Queue nav link: Community also sees it (the page explains Pro), unless an admin switched it off."""
    import work
    if not getattr(g, "user", None):
        return False
    return not editions.has("assignments") or work.enabled()


@app.get("/branding/logo")
def brand_logo():
    found = _brand_logo() if editions.has("branding") else None
    if not found:
        abort(404)
    if isinstance(found[0], bytes):
        return Response(found[0], mimetype=found[1], headers={"Cache-Control": "max-age=300"})
    return send_file(found[0], mimetype=found[1], max_age=3600)


def _set_session_cookie(resp, token):
    resp.set_cookie(auth.COOKIE_NAME, token, max_age=auth.SESSION_MAX_HOURS * 3600, path="/",
                    secure=True, httponly=True, samesite="Strict")
    return resp


@app.before_request
def require_login():
    g.user = None
    if request.path in ("/healthz", "/branding/logo") or request.path.startswith("/static/"):
        return None
    if request.method not in ("GET", "HEAD") and not _same_origin():
        log.warning("cross-origin %s %s refused: Origin=%r Sec-Fetch-Site=%r Host=%r",
                    request.method, request.path, request.headers.get("Origin"),
                    request.headers.get("Sec-Fetch-Site"), request.host)
        abort(403)
    token = request.cookies.get(auth.COOKIE_NAME)
    session = auth.load_session(token)
    g.user, g.token = session, token
    sso = _sso_username()
    if sso is not None and (session is None or session["username"] != sso):
        if token:
            auth.end_session(token)                     # another user on this browser: never mix sessions
        g.user = g.token = None
        user = auth.sso_login(sso, _client_ip()) if sso else None
        if user is None:
            return _sso_refused(sso)
        token = auth.create_session(user["id"], _client_ip(), request.user_agent.string, sso=True)
        session = auth.load_session(token)
        g.user, g.token, g.new_session_token = session, token, token
    if request.path == "/login":
        return None
    if session is None:
        if _is_api():
            return jsonify(error="login_required"), 401
        target = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=target))
    if request.method not in ("GET", "HEAD"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if not secrets.compare_digest(sent, session["csrf_token"]):
            abort(403)
    # SSO users never use their Ardea password, so a pending password change does not block them
    if session["must_change_password"] and not session.get("sso") and request.path not in PASSWORD_CHANGE_PATHS:
        if _is_api():
            return jsonify(error="password_change_required"), 403
        return redirect(url_for("change_password"))
    return None


def can_give_feedback():
    return bool(g.user) and g.user["role"] in auth.FEEDBACK_ROLES


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user or g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if g.user:
            return redirect("/")
        return render_template("login.html", error=None, next=_safe_next(request.args.get("next")), username="")
    username = request.form.get("username", "")
    target = _safe_next(request.form.get("next"))
    user = auth.authenticate(username, request.form.get("password", ""), _client_ip())
    if not user:
        return render_template("login.html", next=target, username=username[:64],
                               error="Wrong username or password, or the account is locked or disabled."), 401
    if g.token:
        auth.end_session(g.token)
    token = auth.create_session(user["id"], _client_ip(), request.user_agent.string)
    resp = redirect(url_for("change_password") if user["must_change_password"] else target)
    return _set_session_cookie(resp, token)


@app.post("/logout")
def logout():
    auth.end_session(g.token)
    auth.audit(current_user(), "logout", ip=_client_ip())
    resp = redirect(url_for("login"))
    resp.delete_cookie(auth.COOKIE_NAME, path="/", secure=True, httponly=True, samesite="Strict")
    return resp


@app.route("/account/password", methods=["GET", "POST"])
def change_password():
    forced = g.user["must_change_password"]
    if request.method == "GET":
        return render_template("password.html", forced=forced, error=None, min_length=auth.MIN_PASSWORD_LENGTH)
    try:
        auth.change_own_password(g.user["user_id"], g.user["username"], request.form.get("current", ""),
                                 request.form.get("new", ""), request.form.get("confirm", ""),
                                 _client_ip(), g.user["token_hash"])
    except auth.AuthError as exc:
        return render_template("password.html", forced=forced, error=str(exc),
                               min_length=auth.MIN_PASSWORD_LENGTH), 400
    auth.end_session(g.token)                          # new session token after a password change
    token = auth.create_session(g.user["user_id"], _client_ip(), request.user_agent.string)
    return _set_session_cookie(redirect("/"), token)


# --------------------------------------------------------------------------- user administration
USER_MESSAGES = {"siems": "SIEM access updated; the user was signed out.", "role": "Role updated.", "disabled": "Account disabled.", "enabled": "Account enabled.",
                 "deleted": "User deleted."}


def _users_page(status=200, error=None, secret=None, message=None):
    return render_template("users.html", feature_labels=editions.LABELS, users=auth.list_users(), events=auth.recent_events(),
                           roles=auth.ROLES, error=error, secret=secret, siems=load_siems(),
                           license=_license_view(),
                           message=message or USER_MESSAGES.get(request.args.get("done", ""))), status


def _license_view():
    st = dict(editions.state(max_age=0))
    st["features"] = [(f, editions.has(f)) for f in editions.FEATURES]
    st["sso_configured"] = SSO_ENABLED
    return st


@app.get("/admin/users")
@admin_required
def users_page():
    return _users_page()


@app.post("/admin/users")
@admin_required
def users_create():
    try:
        name, password = auth.create_user(current_user(), request.form.get("username", ""),
                                          request.form.get("role", ""), _client_ip(), _form_siems())
    except auth.AuthError as exc:
        return _users_page(400, error=str(exc))
    return _users_page(secret={"username": name, "password": password, "action": "created"})


def _form_siems():
    """SIEM picker on the Users page: 'All SIEMs' (None), or the ticked SIEM ids. Without the picker
    (only one SIEM, so it is not shown) a new user sees all SIEMs."""
    if request.form.get("siem_all") == "1" or not request.form.get("siem_picker"):
        return None
    return request.form.getlist("siem")


@app.post("/admin/users/<int:user_id>/siems")
@admin_required
def users_siems(user_id):
    try:
        auth.set_siem_access(current_user(), user_id, _form_siems(), _client_ip())
    except auth.AuthError as exc:
        return _users_page(400, error=str(exc))
    return redirect(url_for("users_page", done="siems"))


@app.post("/admin/users/<int:user_id>/role")
@admin_required
def users_role(user_id):
    try:
        auth.set_role(g.user["user_id"], current_user(), user_id, request.form.get("role", ""), _client_ip())
    except auth.AuthError as exc:
        return _users_page(400, error=str(exc))
    return redirect(url_for("users_page", done="role"))


@app.post("/admin/users/<int:user_id>/reset")
@admin_required
def users_reset(user_id):
    try:
        name, password = auth.reset_password(current_user(), user_id, _client_ip())
    except auth.AuthError as exc:
        return _users_page(400, error=str(exc))
    return _users_page(secret={"username": name, "password": password, "action": "reset"})


@app.post("/admin/users/<int:user_id>/status")
@admin_required
def users_status(user_id):
    disable = request.form.get("disabled") == "true"
    try:
        auth.set_disabled(g.user["user_id"], current_user(), user_id, disable, _client_ip())
    except auth.AuthError as exc:
        return _users_page(400, error=str(exc))
    return redirect(url_for("users_page", done="disabled" if disable else "enabled"))


@app.post("/admin/users/<int:user_id>/delete")
@admin_required
def users_delete(user_id):
    if request.form.get("confirm") != "yes":
        return _users_page(400, error="Tick the confirmation box to delete a user.")
    try:
        auth.delete_user(g.user["user_id"], current_user(), user_id, _client_ip())
    except auth.AuthError as exc:
        return _users_page(400, error=str(exc))
    return redirect(url_for("users_page", done="deleted"))


@app.after_request
def sso_cookie(resp):
    if g.get("new_session_token"):
        _set_session_cookie(resp, g.new_session_token)
    return resp


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; font-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # same-origin: our own forms carry a real Origin; nothing is sent to other sites (e.g. Kibana links)
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["X-Frame-Options"] = "DENY"
    if not request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def safe_url(url, kibana_host=None):
    """Only http(s) links to the Kibana host of the alert's own SIEM. Blocks javascript:/data: URLs
    from alert content."""
    kibana_host = kibana_host or KIBANA_HOST
    try:
        p = urlparse(url or "")
    except ValueError:
        return ""
    if p.scheme not in ("https", "http"):
        return ""
    if kibana_host and p.hostname != kibana_host:
        return ""
    return url


@app.get("/healthz")
def healthz():
    try:
        with get_session() as s:
            s.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception:
        return {"status": "db_unavailable"}, 503
PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
STREAM_POLL_SECONDS = 5
FILTER_KEYS = ("verdict", "severity")
SIEM_ID_MAX = 32


def _list_values(args, key):
    values = []
    for raw in args.getlist(key):
        for part in str(raw).split(","):
            value = part.strip()
            if value:
                values.append(value)
    return values


def parse_response(response):
    if isinstance(response, dict):
        return response
    try:
        value = json.loads(response)
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


@app.template_filter("localtime")
def localtime_filter(value, fmt="%d/%m/%Y %H:%M"):
    return value.astimezone().strftime(fmt) if value else ""


def format_timestamp(value):
    if value is None:
        return ""
    value = value.astimezone()  # Convert to local timezone
    return f"{value.day:02d}/{value.month:02d}/{value.year} {value.hour:02d}:{value.minute:02d}:{value.second:02d}"


_cache = {"at": 0.0, "alerts": [], "siems": [], "incidents": None}
_cache_lock = threading.Lock()
CACHE_SECONDS = 5


def load_alerts():
    """Shared 5-second cache, so SSE clients don't each re-read and re-parse the whole table."""
    with _cache_lock:
        if time.monotonic() - _cache["at"] < CACHE_SECONDS:
            return _cache["alerts"]
        _cache["siems"] = _load_siems()
        _cache["alerts"] = _load_alerts_uncached(_cache["siems"])
        _cache["incidents"] = None
        _cache["at"] = time.monotonic()
        return _cache["alerts"]


def load_incidents():
    """(all incidents, alert_id -> (incident id, size)) for the current alert cache (Pro: Incidents)."""
    alerts = load_alerts()
    with _cache_lock:
        if _cache["incidents"] is None or _cache["incidents"][0] is not alerts:
            built = incidents.build(alerts)
            _cache["incidents"] = (alerts, built, incidents.alert_index(built))
        return _cache["incidents"][1], _cache["incidents"][2]


def load_siems():
    """SIEMs known to the fetcher, refreshed together with the alert cache."""
    load_alerts()
    return _cache["siems"]


def _load_siems():
    try:
        rows = list_siems()
    except Exception:                                  # table not there yet: single-SIEM view
        log.exception("could not read the SIEM list")
        return []
    return [{"id": r["id"], "name": r["name"], "active": r["active"],
             "kibana_host": urlparse(r["kibana_url"] or "").hostname} for r in rows]


VERDICT_ORDER = ("True Positive", "Needs Human Review", "Benign Positive", "False Positive")
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}


def _text_list(items, limit=10):
    return [str(i)[:400] for i in (items or [])[:limit] if str(i).strip()]


def _detail(result):
    """The parts of a verdict the alert view shows. Rendered in the browser with textContent only."""
    inv = result.get("investigation") or {}
    return {
        "summary": str(result.get("summary") or "")[:800],
        "findings": [{"claim": str(f.get("claim", ""))[:400], "stance": f.get("stance", "neutral"),
                      "evidence": [str(e) for e in (f.get("evidence_ids") or [])][:6]}
                     for f in (result.get("key_findings") or [])[:10] if isinstance(f, dict)],
        "malicious": str(result.get("malicious_hypothesis") or "")[:500],
        "benign": str(result.get("benign_hypothesis") or "")[:500],
        "gaps": _text_list(result.get("information_gaps"), 6),
        "actions": [{"action": str(a.get("action", ""))[:300], "priority": a.get("priority", "")}
                    for a in (result.get("recommended_actions") or [])[:6] if isinstance(a, dict)],
        "mitre": [{"id": str(m.get("technique_id", ""))[:12], "name": str(m.get("name", ""))[:120]}
                  for m in (result.get("mitre_techniques") or [])[:5] if isinstance(m, dict)],
        "guardrails": _text_list(inv.get("guardrails_applied"), 8),
        "injection": bool(result.get("prompt_injection_suspected")),
        "tool_calls": inv.get("tool_calls"),
        "duration_ms": inv.get("duration_ms"),
        "model": str(inv.get("model") or "")[:80],
        # how the verdict was reached when it was not a full investigation
        "how": {"suppressed": "suppressed", "flood_reused": "burst"}.get(inv.get("stop_reason")),
        "suppression_id": inv.get("suppression_id"),
        "reused_from": [str(x)[:200] for x in (inv.get("reused_from") or [])[:5]],
    }


def _load_alerts_uncached(siems=()):
    with get_session() as session:
        rows = AlertRepository.list_alert_rows(session)

    by_id = {s["id"]: s for s in siems}
    first = siems[0]["id"] if siems else ""
    alerts = []
    for row in rows:
        result = parse_response(row.response)
        siem_id = row.siem or first                    # alerts from before multi-SIEM support
        siem = by_id.get(siem_id) or {}
        verdict = str(result.get("verdict", "Unknown"))
        severity = str(result.get("severity", "Unknown"))
        try:
            confidence_score = int(result.get("confidence"))
        except (TypeError, ValueError):
            confidence_score = None
        alerts.append({
            "alert_id": row.alert_id,
            "rule_name": str(result.get("rule_name") or "Unknown rule"),
            "hostname": str(result.get("hostname") or "unknown host"),
            "post_url": safe_url(result.get("alert_url"), siem.get("kibana_host")),
            "siem": siem_id,
            "siem_name": siem.get("name") or siem_id,
            "user": str(row.user_name or "")[:200],
            "occurrences": result.get("occurrences") or 1,
            "steps": (result.get("investigation") or {}).get("steps"),
            "timestamp": format_timestamp(row.timestamp),
            "timestamp_iso": row.timestamp.isoformat() if row.timestamp else "",
            "timestamp_raw": row.timestamp,
            "verdict": verdict,
            "severity": severity,
            "confidence_score": confidence_score,
            "should_escalate": result.get("should_escalate", False) in (True, "true", "True", 1),
            "detail": _detail(result),
            "search_text": (json.dumps(result, default=str) + " " + str(siem.get("name") or "")).casefold(),
        })
    return alerts


RANGES = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}
SORTS = ("newest", "severity", "confidence")


def get_filters(args):
    includes = {key: _list_values(args, key) for key in FILTER_KEYS}
    excludes = {key: _list_values(args, f"exclude_{key}") for key in FILTER_KEYS}
    return {
        "q": args.get("q", ""),
        "siem": args.get("siem", "")[:SIEM_ID_MAX],          # one SIEM id, or "" for all
        "escalate": args.get("escalate", ""),
        "min_confidence": args.get("min_confidence", ""),
        "max_confidence": args.get("max_confidence", ""),
        "logic_mode": args.get("logic_mode", "and"),
        "range": args.get("range", "") if args.get("range", "") in RANGES else "",
        "sort": args.get("sort", "newest") if args.get("sort", "newest") in SORTS else "newest",
        "includes": includes,
        "excludes": excludes,
    }


def _filter_by_search(alerts, query):
    if not query:
        return alerts
    query = query.casefold()
    return [
        alert
        for alert in alerts
        if query in (alert["alert_id"] + " " + alert["search_text"]).casefold()
    ]


def _filter_by_confidence(alerts, min_confidence, max_confidence):
    if min_confidence:
        try:
            threshold = int(min_confidence)
        except ValueError:
            threshold = None
        if threshold is not None:
            alerts = [
                alert
                for alert in alerts
                if alert["confidence_score"] is not None
                and alert["confidence_score"] >= threshold
            ]

    if max_confidence:
        try:
            threshold = int(max_confidence)
        except ValueError:
            threshold = None
        if threshold is not None:
            alerts = [
                alert
                for alert in alerts
                if alert["confidence_score"] is not None
                and alert["confidence_score"] <= threshold
            ]

    return alerts


def apply_filters(alerts, filters, skip=()):
    filtered = alerts
    if filters.get("siem"):
        filtered = [alert for alert in filtered if alert["siem"] == filters["siem"]]
    if filters.get("range"):
        since = datetime.now(timezone.utc) - timedelta(hours=RANGES[filters["range"]])
        filtered = [alert for alert in filtered if alert["timestamp_raw"] and alert["timestamp_raw"] >= since]
    for name in FILTER_KEYS:
        if name in skip:
            continue
        includes = set(filters["includes"].get(name, []))
        excludes = set(filters["excludes"].get(name, []))

        if includes:
            filtered = [alert for alert in filtered if alert[name] in includes]
        if excludes:
            filtered = [alert for alert in filtered if alert[name] not in excludes]

    if filters["escalate"]:
        expected = filters["escalate"] == "true"
        filtered = [alert for alert in filtered if alert["should_escalate"] is expected]

    has_confidence_filter = bool(filters["min_confidence"] or filters["max_confidence"])

    if filters.get("logic_mode") == "or" and has_confidence_filter and filters["q"]:
        search_filtered = _filter_by_search(filtered, filters["q"])
        confidence_filtered = _filter_by_confidence(
            filtered, filters["min_confidence"], filters["max_confidence"]
        )
        combined_ids = {alert["alert_id"] for alert in search_filtered} | {
            alert["alert_id"] for alert in confidence_filtered
        }
        filtered = [alert for alert in filtered if alert["alert_id"] in combined_ids]
    else:
        filtered = _filter_by_search(filtered, filters["q"])
        filtered = _filter_by_confidence(
            filtered, filters["min_confidence"], filters["max_confidence"]
        )

    if filters.get("sort") == "severity":
        filtered = sorted(filtered, key=lambda a: SEVERITY_RANK.get(a["severity"], 9))       # stable: newest first within
    elif filters.get("sort") == "confidence":
        filtered = sorted(filtered, key=lambda a: -(a["confidence_score"] or -1))
    return filtered


def verdict_stats(alerts, filters):
    """Counts per verdict among alerts matching every filter except the verdict filter, so each tile
    shows what clicking it would give."""
    base = apply_filters(alerts, filters, skip=("verdict",))
    counts = {v: 0 for v in VERDICT_ORDER}
    for alert in base:
        counts[alert["verdict"]] = counts.get(alert["verdict"], 0) + 1
    return {"total": len(base), "verdicts": counts,
            "escalate": sum(1 for a in base if a["should_escalate"])}


def serialize_alert(alert, incident_of=None):
    out = {key: alert[key] for key in (
        "alert_id", "rule_name", "hostname", "post_url", "timestamp", "timestamp_iso", "verdict", "severity",
        "siem", "siem_name",
        "confidence_score", "should_escalate", "occurrences", "steps", "detail")}
    if incident_of:
        out["incident"] = incident_of.get(alert["alert_id"])          # [id, number of alerts] or None
    return out


def _incident_of():
    return load_incidents()[1] if editions.has("incidents") else None


def _distinct_values(alerts, key, exclude_unknown=True):
    values = {str(alert[key]) for alert in alerts if str(alert[key]).strip()}
    if exclude_unknown:
        values.discard("Unknown")
    return tuple(sorted(values))


def _ordered(values, order):
    return tuple([v for v in order if v in values] + sorted(v for v in values if v not in order))


def get_filter_options(alerts):
    return (
        ("verdict", "Verdict", _ordered(_distinct_values(alerts, "verdict"), VERDICT_ORDER)),
        ("severity", "Severity", _ordered(_distinct_values(alerts, "severity", exclude_unknown=False),
                                          SEVERITY_ORDER)),
    )


def get_escalate_options(alerts):
    return {
        "true": any(alert["should_escalate"] for alert in alerts),
        "false": any(not alert["should_escalate"] for alert in alerts),
    }


def visible_alerts(alerts, user=None):
    """Only alerts of the SIEMs this user may see (admins and unrestricted users: all)."""
    user = user or g.user
    if user["role"] == "admin" or user.get("siem_access") is None:
        return alerts
    allowed = set(user["siem_access"])
    return [alert for alert in alerts if alert["siem"] in allowed]


def require_alert_access(alert_id):
    """404 (not 403: don't confirm the alert exists) for alerts of a SIEM the user may not see."""
    found, siem_id = alert_siem(alert_id)
    if not found:
        abort(404)
    if siem_id is None:                                # stored before multi-SIEM support: first SIEM
        siems = load_siems()
        siem_id = siems[0]["id"] if siems else ""
    if not auth.can_see_siem(g.user, siem_id):
        abort(404)


@app.get("/")
def index():
    filters = get_filters(request.args)
    loaded_alerts = visible_alerts(load_alerts())
    with_alerts = {a["siem"] for a in loaded_alerts}
    # removed SIEMs stay selectable while their alerts are still listed
    siems = [{"id": s["id"], "name": s["name"]} for s in load_siems()
             if (s["active"] or s["id"] in with_alerts) and auth.can_see_siem(g.user, s["id"])]

    return render_template(
        "index.html",
        filters=filters,
        siems=siems,
        filter_options=get_filter_options(loaded_alerts),
        escalate_options=get_escalate_options(loaded_alerts),
        page_size=PAGE_SIZE,
        can_feedback=can_give_feedback(),
        can_retriage=can_give_feedback() and editions.has("retriage"),
        can_ask=can_give_feedback() and editions.has("ask"),
        can_csv=editions.has("csv_export"),
    )


@app.get("/api/status")
def api_status():
    """The status bar: worker, fetcher and queue (status.py)."""
    import status
    user = g.user
    return jsonify(status.snapshot(user, lambda s: auth.can_see_siem(user, s)))


@app.get("/api/alerts")
def get_alerts_page():
    filters = get_filters(request.args)
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        offset = 0
    try:
        limit = int(request.args.get("limit", PAGE_SIZE))
    except ValueError:
        limit = PAGE_SIZE
    limit = max(1, min(limit, MAX_PAGE_SIZE))

    mine = visible_alerts(load_alerts())
    all_alerts = apply_filters(mine, filters)
    page = all_alerts[offset : offset + limit]
    next_offset = offset + len(page)
    incident_of = _incident_of()

    return jsonify(
        {
            "alerts": [serialize_alert(alert, incident_of) for alert in page],
            "total": len(all_alerts),
            "next_offset": next_offset,
            "has_more": next_offset < len(all_alerts),
            "stats": verdict_stats(mine, filters),
        }
    )


@app.get("/stream")
def stream_alerts():
    filters = get_filters(request.args)
    filters["sort"] = "newest"          # new alerts are detected from the top of the newest-first list
    last_seen_id = request.args.get("since_id", "")
    seeded = bool(last_seen_id)
    session_hash = g.user["token_hash"]
    user = dict(g.user)          # the stream outlives the request; access changes end the session (below)

    def event_stream():
        nonlocal last_seen_id, seeded
        while True:
            if not auth.session_still_valid(session_hash):      # logged out, disabled or expired
                yield "event: logout\ndata: {}\n\n"
                return
            alerts = apply_filters(visible_alerts(load_alerts(), user), filters)
            new_alerts = []
            found_last_seen = False

            if not seeded:
                if alerts:
                    new_alerts = alerts[:PAGE_SIZE]
                    seeded = True
            elif last_seen_id:
                for alert in alerts:
                    if alert["alert_id"] == last_seen_id:
                        found_last_seen = True
                        break
                    new_alerts.append(alert)

            should_emit = bool(new_alerts) and (
                (not last_seen_id and seeded) or found_last_seen
            )

            if should_emit:
                if len(new_alerts) > PAGE_SIZE:
                    new_alerts = new_alerts[:PAGE_SIZE]
                last_seen_id = new_alerts[0]["alert_id"]
                incident_of = _incident_of()
                payload = json.dumps({"alerts": [serialize_alert(alert, incident_of) for alert in new_alerts],
                                      "stats": verdict_stats(visible_alerts(load_alerts(), user), filters)})
                yield f"event: alerts\ndata: {payload}\n\n"
            else:
                yield "event: ping\ndata: {}\n\n"

            time.sleep(STREAM_POLL_SECONDS)

    return (
        stream_with_context(event_stream()),
        {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/alerts/<alert_id>/trail")
def alert_trail(alert_id):
    """Ordered audit trail: every LLM turn, tool call (args, status, evidence id, result), guardrail."""
    require_alert_access(alert_id)
    return jsonify({"alert_id": alert_id, "steps": get_trail(alert_id), "feedback": get_feedback(alert_id)})


VALID_VERDICTS = {"True Positive", "Benign Positive", "False Positive", "Needs Human Review"}


@app.post("/api/alerts/<alert_id>/feedback")
def alert_feedback(alert_id):
    if not can_give_feedback():
        abort(403)
    body = request.get_json(silent=True) or {}
    agrees = body.get("agrees")
    correct = body.get("correct_verdict")
    if not isinstance(agrees, bool) or (correct is not None and correct not in VALID_VERDICTS):
        abort(400)
    require_alert_access(alert_id)
    add_feedback(alert_id, current_user(), agrees, correct, str(body.get("comment") or "")[:2000])
    return {"ok": True}


from pro import bp as pro_blueprint  # noqa: E402  (Insights, CSV export, re-triage, MSP usage)
from settings_admin import bp as settings_blueprint  # noqa: E402  (Settings page)

app.register_blueprint(pro_blueprint)
app.register_blueprint(settings_blueprint)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        threaded=True,
    )
