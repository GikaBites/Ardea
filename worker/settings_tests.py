"""The test buttons on the Settings page. The publisher queues a test; the worker runs it here, because only
the worker can open the secrets. Results say what worked and why not, never a secret or a full URL."""
import logging
import re

import requests

import appsettings
import config
import siems as siem_config

log = logging.getLogger("settings")
KINDS = re.compile(r"^(llm|licence|siem:[a-z0-9][a-z0-9_-]{0,31}|notify:[a-z]+)$")


def _scrub(text: str) -> str:
    """Remove every known secret from a message before it is stored."""
    text = str(text)[:400]
    for name, value in appsettings.OVERLAY.items():
        is_secret = name.startswith("SIEM.") or (appsettings.BY_NAME.get(name) and appsettings.BY_NAME[name].secret)
        if is_secret and value and len(value) >= 4:
            text = text.replace(value, "•••")
    for name in ("ARDEA_LICENSE_KEY", "SMTP_PASSWORD", "NTFY_TOKEN", "SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL",
                 "WEBHOOK_SECRET", "JIRA_API_TOKEN", "THEHIVE_API_KEY", "BRAVE_API_KEY", "GOOGLE_API_KEY"):
        v = appsettings.from_env(name)
        if v and len(v) >= 4:
            text = text.replace(v, "•••")
    return re.sub(r"https?://\S+", "<url>", text)


def _llm() -> tuple[bool, str]:
    from ollama import Client
    try:
        names = sorted(m.model for m in Client(host=config.LLM_URL, timeout=10).list().models)
    except Exception as exc:
        return False, f"Ollama is not reachable ({type(exc).__name__})."
    if config.MODEL in names or f"{config.MODEL}:latest" in names:
        return True, f"Ollama answered. Model {config.MODEL} is installed ({len(names)} models in total)."
    return False, f"Ollama answered, but {config.MODEL} is not installed. Installed: {', '.join(names[:12]) or 'none'}."


def _siem(siem_id: str) -> tuple[bool, str]:
    try:
        siems = {s.id: s for s in siem_config.load(ui_data=appsettings.siems_data())}
    except siem_config.SiemConfigError as exc:
        return False, f"The SIEM settings are not valid: {exc}"
    siem = siems.get(siem_id)
    if siem is None:
        return False, "This SIEM is not saved yet, or it is switched off."
    parts, ok = [], True
    for label, key, index in (("Fetcher key", siem.fetcher_api_key, siem.alerts_index),
                              ("Worker key", siem.worker_api_key, siem.events_indices[0])):
        if not key:
            parts.append(f"{label}: not set.")
            ok = False
            continue
        try:
            r = requests.post(f"{siem.url}/{index}*/_search?ignore_unavailable=true&allow_no_indices=true",
                              json={"size": 0, "track_total_hits": False}, timeout=10, verify=siem.verify,
                              headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"})
        except requests.exceptions.SSLError:
            parts.append(f"{label}: TLS certificate not trusted. Add the cluster's CA certificate.")
            ok = False
            continue
        except requests.RequestException as exc:
            parts.append(f"{label}: cluster not reachable ({type(exc).__name__}).")
            ok = False
            continue
        if r.status_code == 200:
            parts.append(f"{label}: OK.")
        elif r.status_code in (401, 403):
            parts.append(f"{label}: refused (HTTP {r.status_code}). Check the key and its role (elastic/roles.json).")
            ok = False
        else:
            parts.append(f"{label}: HTTP {r.status_code}.")
            ok = False
    return ok, " ".join(parts)


def _notify(channel: str) -> tuple[bool, str]:
    import licensing
    import notifier
    if not licensing.has("notifications"):
        return False, f"Notifications need Ardea Pro or MSP (this installation runs {licensing.tier().title()})."
    if channel not in notifier.SENDERS:
        return False, "Unknown channel."
    test = notifier.build_payload({"alert_id": "test", "verdict": "True Positive", "severity": "High",
                                   "confidence": 99, "rule_name": "Ardea notification test", "hostname": "test-host",
                                   "summary": "This is a test notification from the Ardea Settings page.",
                                   "key_findings": [{"claim": "Test finding", "stance": "suspicious"}]})
    try:
        sender, target = notifier.resolve(channel)
        sender(test, target)
    except Exception as exc:
        return False, f"Sending failed: {exc}"
    return True, "Test message sent. Check that it arrived."


def _licence(conn) -> tuple[bool, str]:
    import licensing
    row = licensing.refresh(conn, force=True)
    tier = licensing.effective_tier(row).upper()
    if row.get("last_error"):
        return tier != "COMMUNITY", f"Edition {tier}. {row['last_error']}"
    return True, f"Edition {tier}" + (f", {row['product']}" if row.get("product") else "") + "."


def run_pending(conn, limit: int = 3):
    """Run queued tests. Called from the worker loop; never raises."""
    for _ in range(limit):
        try:
            row = conn.execute("""UPDATE settings_tests SET status = 'running'
                                  WHERE id = (SELECT id FROM settings_tests WHERE status = 'queued'
                                              ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
                                  RETURNING id, kind""").fetchone()
        except Exception:
            log.exception("cannot read settings tests")
            return
        if not row:
            return
        kind = row["kind"]
        try:
            if not KINDS.match(kind):
                ok, detail = False, "Unknown test."
            elif kind == "llm":
                ok, detail = _llm()
            elif kind == "licence":
                ok, detail = _licence(conn)
            elif kind.startswith("siem:"):
                ok, detail = _siem(kind[5:])
            else:
                ok, detail = _notify(kind[7:])
        except Exception as exc:
            ok, detail = False, f"The test failed: {type(exc).__name__}"
            log.exception("settings test %s failed", kind)
        conn.execute("UPDATE settings_tests SET status = %s, detail = %s, finished_at = NOW() WHERE id = %s",
                     ("ok" if ok else "failed", _scrub(detail), row["id"]))
    conn.execute("DELETE FROM settings_tests WHERE requested_at < NOW() - interval '1 day'")
