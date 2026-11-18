"""Verdict notifications (Pro / MSP), delivered from a DB outbox.

Channels: smtp (e-mail), ntfy (push), slack, teams, webhook (JSON, optionally HMAC-signed), jira (issue),
thehive (alert). MSP: per-SIEM routing from siems/siems.json "notify" (channel name "<kind>@<siem id>").
Destinations and secrets are looked up when a message is SENT, never stored in the outbox.

Flow:
  worker.process -> build_notifications(final)            -> rows written in the SAME transaction
                                                             as the verdict (db.store_result)
  worker loop    -> deliver_pending(conn) -> smtp / ntfy  -> retried with backoff, never lost

Security notes:
  * Alert fields are attacker-influenced. Everything is sent as PLAIN TEXT (no HTML e-mail), control
    characters are stripped, one-line fields cannot contain newlines (no header injection), and links
    are only the Ardea UI and http(s) links to your Kibana host.
  * Notifications leave the worker. With a cloud mail provider (e.g. Microsoft 365) or ntfy.sh, the
    hostnames / usernames in the message go there too. NOTIFY_DETAIL=minimal sends only verdict,
    severity, rule name and links.
"""
import hashlib
import hmac
import json
import logging
import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import make_msgid
from urllib.parse import urlparse

import requests

import config
import db
import elastic
import licensing

log = logging.getLogger("notifier")

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")   # incl. bidi overrides


class NotifyError(Exception):
    pass


# --------------------------------------------------------------------------- policy + payload
def should_notify(final: dict) -> bool:
    if final.get("verdict") not in config.NOTIFY_VERDICTS:
        return False
    try:
        return SEVERITY_ORDER.index(final.get("severity")) >= SEVERITY_ORDER.index(config.NOTIFY_MIN_SEVERITY)
    except ValueError:
        return True                     # unknown severity: notify rather than drop


def _line(value, n=200) -> str:
    """Single-line, control-free, bounded."""
    return _CTRL.sub("", re.sub(r"[\r\n\t]+", " ", str(value or ""))).strip()[:n]


def _text(value, n=600) -> str:
    return _CTRL.sub("", str(value or "")).strip()[:n]


def _kibana_host(siem_id) -> str | None:
    """Kibana of the SIEM the alert came from (links to any other host are dropped)."""
    siem = elastic.configured().get(siem_id) if siem_id else None
    return urlparse(siem.kibana_url if siem else config.env("KIBANA_BASE_URL", "")).hostname


def _safe_kibana(url, siem_id=None) -> str | None:
    kibana_host = _kibana_host(siem_id)
    try:
        p = urlparse(url or "")
    except ValueError:
        return None
    if p.scheme in ("http", "https") and kibana_host and p.hostname == kibana_host:
        return url
    return None


def build_payload(final: dict, user: str | None = None) -> dict:
    """Channel-independent content. Stored in the outbox, so what was sent is auditable."""
    alert_id = _line(final.get("alert_id"), 100)
    ui = f"{config.ARDEA_PUBLIC_URL}/?q={alert_id}" if config.ARDEA_PUBLIC_URL else None
    p = {
        "alert_id": alert_id,
        "verdict": _line(final.get("verdict"), 40),
        "severity": _line(final.get("severity"), 20),
        "confidence": final.get("confidence"),
        "rule_name": _line(final.get("rule_name"), 150),
        "ardea_url": ui,
        "kibana_url": _safe_kibana(final.get("alert_url"), final.get("siem")),
        "siem": _line(final.get("siem_name") or final.get("siem"), 60) or None,
        "detail": config.NOTIFY_DETAIL,
    }
    if config.NOTIFY_DETAIL != "minimal":
        findings = sorted(final.get("key_findings") or [], key=lambda f: f.get("stance") != "suspicious")
        p.update({
            "hostname": _line(final.get("hostname"), 120),
            "user": _line(user, 120) if user else None,
            "summary": _text(final.get("summary"), 600),
            "findings": [f"[{_line(f.get('stance'), 12)}] {_line(f.get('claim'), 300)}" for f in findings[:5]],
            "actions": [f"[{_line(a.get('priority'), 12)}] {_line(a.get('action'), 300)}"
                        for a in (final.get("recommended_actions") or [])[:5]],
            "mitre": [f"{_line(m.get('technique_id'), 12)} {_line(m.get('name'), 80)}"
                      for m in (final.get("mitre_techniques") or [])[:5]],
            "injection_suspected": bool(final.get("prompt_injection_suspected")),
        })
    return p


def build_notifications(final: dict, user: str | None = None) -> list[tuple[str, dict]]:
    channels = [ch for ch in config.NOTIFY_CHANNELS if ch in SENDERS]
    siem = elastic.configured().get(final.get("siem")) if final.get("siem") else None
    routed = _siem_channels(siem)
    if not (channels or routed) or not should_notify(final):
        return []
    if not licensing.has("notifications"):
        _warn_unlicensed()
        return []
    if not licensing.has("integrations"):
        channels = [ch for ch in channels if ch in ("smtp", "ntfy")]
    if routed and not licensing.has("customer_routing"):
        routed = []
    payload = build_payload(final, user)
    return [(ch, payload) for ch in channels + routed]


def _siem_channels(siem) -> list[str]:
    """MSP: per-SIEM destinations from siems.json, e.g. 'smtp@acme', 'slack@acme'."""
    if siem is None or not siem.notify:
        return []
    kinds = {"smtp_to": "smtp", "slack_webhook_url": "slack", "teams_webhook_url": "teams", "webhook_url": "webhook"}
    return [f"{kind}@{siem.id}" for key, kind in kinds.items() if siem.notify.get(key)]


def _brand() -> str:
    """The product name in messages: your own brand with Ardea MSP branding, else Ardea."""
    name = config.env("ARDEA_BRAND_NAME").strip()[:40] if licensing.has("branding") else ""
    return re.sub(r"[\r\n\[\]<>]", "", name) or "Ardea"


def _subject(p: dict) -> str:
    where = f" on {p['hostname']}" if p.get("hostname") else ""
    siem = f"[{p['siem']}] " if p.get("siem") else ""
    return _line(f"[{_brand()}] {siem}{p['verdict']} ({p['severity']}): {p['rule_name']}{where}", 200)


def _body(p: dict) -> str:
    out = [f"Verdict:    {p['verdict']}", f"Severity:   {p['severity']}",
           f"Confidence: {p['confidence']}", f"Rule:       {p['rule_name']}"]
    if p.get("siem"):
        out.append(f"SIEM:       {p['siem']}")
    if p.get("hostname"):
        out.append(f"Host:       {p['hostname']}")
    if p.get("user"):
        out.append(f"User:       {p['user']}")
    out.append(f"Alert id:   {p['alert_id']}")
    if p.get("injection_suspected"):
        out += ["", "WARNING: the alert contains text that tried to manipulate the triage model."]
    if p.get("summary"):
        out += ["", "Summary:", p["summary"]]
    for title, key in (("Key findings", "findings"), ("Recommended actions", "actions"), ("MITRE", "mitre")):
        if p.get(key):
            out += ["", f"{title}:"] + [f"  - {x}" for x in p[key]]
    out.append("")
    if p.get("ardea_url"):
        out.append(f"{_brand()}: {p['ardea_url']}")
    if p.get("kibana_url"):
        out.append(f"Kibana:   {p['kibana_url']}")
    out += ["", "Automated verdict by a local LLM. Verify before acting. Alert text quoted above is "
                "untrusted data from the monitored system."]
    return "\n".join(out)


# --------------------------------------------------------------------------- senders
def send_smtp(p: dict, target: dict | None = None, subject: str | None = None, body: str | None = None):
    host = config.env("SMTP_HOST")
    to = list((target or {}).get("smtp_to") or
              [a.strip() for a in config.env("SMTP_TO", "").split(",") if a.strip()])
    sender = config.env("SMTP_FROM")
    if not (host and to and sender):
        raise NotifyError("SMTP_HOST, SMTP_FROM and SMTP_TO must be set")
    port = int(config.env("SMTP_PORT", "587"))
    security = config.env("SMTP_SECURITY", "starttls").lower()       # starttls | ssl | none
    msg = EmailMessage()
    msg["Subject"] = subject or _subject(p)
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1])
    if p.get("severity") in ("Critical", "High"):
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"
    msg.set_content(body or _body(p))                                # text/plain only
    tls = ssl.create_default_context(cafile=config.env("SMTP_CA_CERT") or None)
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20, context=tls)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=tls)
            if config.env("SMTP_USER"):
                server.login(config.env("SMTP_USER"), config.env("SMTP_PASSWORD", ""))
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotifyError(f"SMTP: {type(exc).__name__}: {str(exc)[:200]}") from None


def send_ntfy(p: dict, target: dict | None = None):
    base = config.env("NTFY_URL", "https://ntfy.sh").rstrip("/")
    topic = config.env("NTFY_TOPIC")
    if not topic:
        raise NotifyError("NTFY_TOPIC must be set")
    prio = {"Critical": 5, "High": 5, "Medium": 4}.get(p.get("severity"), 3)
    body = {"topic": topic, "title": _subject(p), "message": _body(p)[:3500], "priority": prio,
            "tags": ["rotating_light"] if prio == 5 else ["warning"]}
    if p.get("ardea_url"):
        body["click"] = p["ardea_url"]
    headers = {"Authorization": f"Bearer {config.env("NTFY_TOKEN")}"} if config.env("NTFY_TOKEN") else {}
    _post("ntfy", base, json=body, headers=headers, proxy=config.env("NTFY_PROXY"))


def _post(name, url, *, proxy=None, ok_statuses=(), **kw):
    proxy = proxy if proxy is not None else config.env("NOTIFY_PROXY")
    try:
        r = requests.post(url, timeout=15, proxies={"https": proxy, "http": proxy} if proxy else None, **kw)
        if r.status_code in ok_statuses:
            return r
        r.raise_for_status()
        return r
    except requests.RequestException as exc:
        # never echo the URL: webhook URLs are secrets
        code = getattr(getattr(exc, "response", None), "status_code", None)
        raise NotifyError(f"{name}: {type(exc).__name__}{f' HTTP {code}' if code else ''}") from None


FENCE = "`" * 3


def _unfenced(text) -> str:
    return str(text or "").replace(FENCE, "'" * 3)


def _slack_escape(text) -> str:
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_neutral(text) -> str:
    """Untrusted text inside a Markdown card (Teams): break link and image syntax."""
    return str(text or "").replace("](", "] (").replace("![", "! [")


def _links(p) -> list[tuple[str, str]]:
    return [(label, url) for label, url in ((f"Open in {_brand()}", p.get("ardea_url")),
                                            ("Open in Kibana", p.get("kibana_url"))) if url]


def send_slack(p: dict, target: dict | None = None):
    url = (target or {}).get("slack_webhook_url") or config.env("SLACK_WEBHOOK_URL")
    if not url:
        raise NotifyError("SLACK_WEBHOOK_URL must be set")
    text = FENCE + _slack_escape(_unfenced(_body(p)))[:2800] + FENCE
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": _subject(p)[:150]}},
              {"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    links = _links(p)
    if links:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": label}, "url": u} for label, u in links]})
    _post("slack", url, json={"text": _subject(p), "blocks": blocks})


def send_teams(p: dict, target: dict | None = None):
    url = (target or {}).get("teams_webhook_url") or config.env("TEAMS_WEBHOOK_URL")
    if not url:
        raise NotifyError("TEAMS_WEBHOOK_URL must be set")
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4",
            "body": [{"type": "TextBlock", "text": _md_neutral(_subject(p)), "weight": "Bolder", "size": "Medium",
                      "wrap": True},
                     {"type": "TextBlock", "text": _md_neutral(_body(p))[:3500], "wrap": True,
                      "fontType": "Monospace"}],
            "actions": [{"type": "Action.OpenUrl", "title": label, "url": u} for label, u in _links(p)]}
    _post("teams", url, json={"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})


def send_webhook(p: dict, target: dict | None = None):
    target = target or {}
    url = target.get("webhook_url") or config.env("WEBHOOK_URL")
    if not url:
        raise NotifyError("WEBHOOK_URL must be set")
    body = json.dumps({"event": "ardea.verdict", "payload": p}, ensure_ascii=False, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Ardea"}
    secret = target.get("webhook_secret") or config.env("WEBHOOK_SECRET")
    if secret:
        headers["X-Ardea-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    _post("webhook", url, data=body, headers=headers)


def _adf(text: str) -> dict:
    """Jira's document format: plain paragraphs (no markup is interpreted)."""
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]} if line else {"type": "paragraph"}
        for line in text.splitlines()[:120]]}


def send_jira(p: dict, target: dict | None = None):
    base = config.env("JIRA_URL").rstrip("/")
    user, token, project = config.env("JIRA_USER"), config.env("JIRA_API_TOKEN"), config.env("JIRA_PROJECT")
    if not (base and user and token and project):
        raise NotifyError("JIRA_URL, JIRA_USER, JIRA_API_TOKEN and JIRA_PROJECT must be set")
    label = re.sub(r"[^a-z0-9]+", "-", str(p.get("verdict", "")).lower()).strip("-")
    fields = {"project": {"key": project}, "issuetype": {"name": config.env("JIRA_ISSUE_TYPE", "Task")},
              "summary": _subject(p)[:250], "description": _adf(_body(p)), "labels": ["ardea", label]}
    _post("jira", f"{base}/rest/api/3/issue", json={"fields": fields}, auth=(user, token))


THEHIVE_SEVERITY = {"Informational": 1, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def send_thehive(p: dict, target: dict | None = None):
    base, key = config.env("THEHIVE_URL").rstrip("/"), config.env("THEHIVE_API_KEY")
    if not (base and key):
        raise NotifyError("THEHIVE_URL and THEHIVE_API_KEY must be set")
    alert = {"type": "ardea", "source": "Ardea", "sourceRef": str(p.get("alert_id"))[:120],
             "title": _subject(p)[:250], "severity": THEHIVE_SEVERITY.get(p.get("severity"), 2),
             "description": FENCE + "\n" + _unfenced(_body(p)) + "\n" + FENCE,
             "tags": ["ardea", str(p.get("verdict", ""))]}
    # 409 = this alert was already sent (same sourceRef): nothing to do
    _post("thehive", f"{base}/api/v1/alert", json=alert, headers={"Authorization": f"Bearer {key}"},
          ok_statuses=(409,))


SENDERS = {"smtp": send_smtp, "ntfy": send_ntfy, "slack": send_slack, "teams": send_teams,
           "webhook": send_webhook, "jira": send_jira, "thehive": send_thehive}


# --------------------------------------------------------------------------- system messages
MESSAGE_CHANNELS = ("smtp", "ntfy", "slack", "teams", "webhook")      # Jira / TheHive take verdicts only


def send_message(kind: str, title: str, body: str, link: str | None = None, urgent: bool = False,
                 channels=None) -> list[tuple[str, str | None]]:
    """A message that is not about one alert (silent-source alarm, daily digest) to the configured
    channels. Returns [(channel, error or None)]. Never raises."""
    title = _line(f"[{_brand()}] {title}", 200)
    body = str(body)[:6000] + (f"\n\n{_brand()}: {link}" if link else "")
    results = []
    for channel in channels if channels is not None else config.NOTIFY_CHANNELS:
        if channel not in MESSAGE_CHANNELS:
            continue
        try:
            _MESSAGE_SENDERS[channel](kind, title, body, link, urgent)
            results.append((channel, None))
        except NotifyError as exc:
            results.append((channel, str(exc)))
        except Exception as exc:                       # a broken channel must not stop the others
            results.append((channel, type(exc).__name__))
    return results


def _msg_smtp(kind, title, body, link, urgent):
    send_smtp({"severity": "High" if urgent else "Low"}, None, title, body)


def _msg_ntfy(kind, title, body, link, urgent):
    base = config.env("NTFY_URL", "https://ntfy.sh").rstrip("/")
    topic = config.env("NTFY_TOPIC")
    if not topic:
        raise NotifyError("NTFY_TOPIC must be set")
    msg = {"topic": topic, "title": title, "message": body[:3500], "priority": 4 if urgent else 3,
           "tags": ["warning"] if urgent else ["clipboard"]}
    if link:
        msg["click"] = link
    headers = {"Authorization": f"Bearer {config.env('NTFY_TOKEN')}"} if config.env("NTFY_TOKEN") else {}
    _post("ntfy", base, json=msg, headers=headers, proxy=config.env("NTFY_PROXY"))


def _msg_slack(kind, title, body, link, urgent):
    url = config.env("SLACK_WEBHOOK_URL")
    if not url:
        raise NotifyError("SLACK_WEBHOOK_URL must be set")
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
              {"type": "section", "text": {"type": "mrkdwn",
                                           "text": FENCE + _slack_escape(_unfenced(body))[:2800] + FENCE}}]
    if link:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": f"Open {_brand()}"}, "url": link}]})
    _post("slack", url, json={"text": title, "blocks": blocks})


def _msg_teams(kind, title, body, link, urgent):
    url = config.env("TEAMS_WEBHOOK_URL")
    if not url:
        raise NotifyError("TEAMS_WEBHOOK_URL must be set")
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4",
            "body": [{"type": "TextBlock", "text": _md_neutral(title), "weight": "Bolder", "size": "Medium",
                      "wrap": True},
                     {"type": "TextBlock", "text": _md_neutral(body)[:3500], "wrap": True, "fontType": "Monospace"}],
            "actions": [{"type": "Action.OpenUrl", "title": f"Open {_brand()}", "url": link}] if link else []}
    _post("teams", url, json={"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})


def _msg_webhook(kind, title, body, link, urgent):
    url = config.env("WEBHOOK_URL")
    if not url:
        raise NotifyError("WEBHOOK_URL must be set")
    data = json.dumps({"event": f"ardea.{kind}", "payload": {"title": title, "text": body, "link": link,
                                                             "urgent": urgent}}, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Ardea"}
    if config.env("WEBHOOK_SECRET"):
        headers["X-Ardea-Signature"] = "sha256=" + hmac.new(config.env("WEBHOOK_SECRET").encode(), data,
                                                            hashlib.sha256).hexdigest()
    _post("webhook", url, data=data, headers=headers)


_MESSAGE_SENDERS = {"smtp": _msg_smtp, "ntfy": _msg_ntfy, "slack": _msg_slack, "teams": _msg_teams,
                    "webhook": _msg_webhook}


def resolve(channel: str):
    """(sender, target) for an outbox channel: 'slack' (settings from .env) or 'slack@acme' (siems.json)."""
    kind, _, siem_id = channel.partition("@")
    sender = SENDERS.get(kind)
    if sender is None:
        raise NotifyError(f"unknown channel {channel}")
    if not siem_id:
        return sender, None
    siem = elastic.configured().get(siem_id)
    if siem is None or not siem.notify:
        raise NotifyError(f"SIEM '{siem_id}' has no notify settings in siems.json any more")
    return sender, siem.notify


_warned = {"at": 0.0}


def _warn_unlicensed():
    if time.monotonic() - _warned["at"] > 3600 or not _warned["at"]:
        _warned["at"] = time.monotonic()
        log.warning("NOTIFY_CHANNELS is set, but notifications need Ardea Pro or MSP (edition: %s). "
                    "Verdicts are still triaged and shown in the UI.", licensing.tier())


# --------------------------------------------------------------------------- delivery
def deliver_pending(conn):
    """Send whatever is due. Called from the worker loop; never raises."""
    try:
        rows = db.pending_notifications(conn)
    except Exception:
        log.exception("cannot read notification outbox")
        return
    for r in rows:
        try:
            sender, target = resolve(r["channel"])
            sender(r["payload"], target)
            db.mark_notification(conn, r["id"], True)
            log.info("notification %s sent via %s for alert %s", r["id"], r["channel"], r["alert_id"])
        except Exception as exc:
            state = db.mark_notification(conn, r["id"], False, str(exc), r["attempts"])
            log.error("notification %s via %s failed (%s): %s", r["id"], r["channel"], state, exc)


def check_ready(conn):
    """Fail loudly at startup if notifications are configured but the outbox table is missing:
    otherwise every True Positive would fail to store."""
    if not config.NOTIFY_CHANNELS and not any(x.notify for x in elastic.configured().values()):
        return
    unknown = set(config.NOTIFY_CHANNELS) - set(SENDERS)
    if unknown:
        raise SystemExit(f"NOTIFY_CHANNELS has unknown channel(s): {sorted(unknown)}")
    if conn.execute("SELECT to_regclass('public.notifications') AS t").fetchone()["t"] is None:
        raise SystemExit("notifications are configured but table 'notifications' is missing: "
                         "create it from db/init.sql")


if __name__ == "__main__":      # `docker compose exec worker python notifier.py` -> sends a test message
    import sys
    logging.basicConfig(level="INFO")
    with db.get_connection() as _c:
        licensing.sync(_c, max_age=0)
    if not licensing.has("notifications"):
        raise SystemExit(f"notifications need Ardea Pro or MSP (this installation runs {licensing.tier()})")
    test = build_payload({"alert_id": "test", "verdict": "True Positive", "severity": "High", "confidence": 99,
                          "rule_name": "Ardea notification test", "hostname": "test-host",
                          "summary": "This is a test notification from Ardea.",
                          "key_findings": [{"claim": "Test finding", "stance": "suspicious"}]})
    targets = sys.argv[1:] or (config.NOTIFY_CHANNELS + [ch for x in elastic.configured().values()
                                                          for ch in _siem_channels(x)])
    for ch in targets:
        sender, target = resolve(ch)
        sender(test, target)
        print(f"sent test via {ch}")
