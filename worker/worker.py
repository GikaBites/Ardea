"""Ardea worker: leases alerts from the queue, investigates them, stores verdict + audit trail.

  * an alert is marked done only in the same transaction that stores its result
  * a failed alert is retried with backoff, then published as 'Needs Human Review', never dropped
  * if Ollama is unreachable, alerts stay queued instead of using up their retries
  * True Positive notifications are queued with the result and delivered from the outbox
"""
import logging
import os
import pathlib
import signal
import time

from ollama import Client

import config
import db
import elastic
import licensing
import notifier
import playbooks
import reports
from agent import Investigation, LLMUnavailable
from alert_context import build_context
from verdict_schema import fallback_verdict

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("worker")
# httpx logs every request at INFO; the Ollama readiness probe runs every poll (~17k lines/day).
logging.getLogger("httpx").setLevel(os.getenv("HTTPX_LOG_LEVEL", "WARNING"))
HEARTBEAT = pathlib.Path("/tmp/heartbeat")
_running = True


def _stop(*_):
    global _running
    _running = False
    log.info("shutdown requested; finishing current alert")


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


def _siem_fields(siem_id) -> dict:
    siem = elastic.configured().get(siem_id)
    return {"siem": siem_id, "siem_name": siem.name if siem else siem_id}


def enrich_result(final: dict, ctx: dict, row: dict) -> dict:
    final.update({
        "alert_id": row["alert_id"], "hostname": ctx["hostname"], "rule_name": ctx["rule"]["name"],
        "rule_id": ctx["rule"]["rule_id"], "alert_url": ctx["kibana_url"], "occurrences": row["count"],
        "incident_key": row.get("incident_key"), "rule_mitre": ctx["rule"]["mitre"],
        **_siem_fields(row["siem"]),
    })
    return final


def process(conn, llm, row: dict):
    """Investigate one alert, entirely inside the SIEM it came from."""
    row["siem"] = row.get("siem") or elastic.default_id()           # alerts from before multi-SIEM support
    if row["siem"] not in elastic.configured():
        # removed from siems.json: say so instead of retrying against nothing
        final = fallback_verdict(f"SIEM '{row['siem']}' is no longer configured in siems.json")
        db.store_result(conn, row["alert_id"], {**final, "alert_id": row["alert_id"], "rule_name": row["rule_name"],
                                                "hostname": row["host_name"], **_siem_fields(row["siem"])},
                        {"model": None, "prompt_version": config.PROMPT_VERSION})
        return
    with elastic.use(row["siem"]):
        _process(conn, llm, row)


def _process(conn, llm, row: dict):
    alert_id = row["alert_id"]
    raw = elastic.fetch_alert(row.get("elastic_id") or alert_id)
    if raw is None:
        # alert deleted / index rolled over: publish that fact instead of crashing
        final = fallback_verdict("alert document no longer found in Elastic")
        db.store_result(conn, alert_id, {**final, "alert_id": alert_id, "rule_name": row["rule_name"],
                                         "hostname": row["host_name"], **_siem_fields(row["siem"])},
                        {"model": None, "prompt_version": config.PROMPT_VERSION})
        return
    ctx = build_context(raw, occurrences=row["count"] or 1)
    ctx["siem"] = row["siem"]
    pb = playbooks.resolve(ctx)
    try:
        history = db.similar_feedback(conn, row, config.FEEDBACK_EXAMPLES)
    except Exception:                               # history is a bonus; never block triage on it
        log.exception("could not load analyst history")
        history = []
    final, meta = Investigation(conn, llm, alert_id, ctx, pb, history=history).run()
    final = enrich_result(final, ctx, row)
    db.store_result(conn, alert_id, final, meta, notifier.build_notifications(final, row.get("user_name")))
    log.info("alert %s -> %s (conf %s, %s tool calls, %s ms)", alert_id, final["verdict"],
             final["confidence"], meta["tool_calls"], meta["duration_ms"])


def llm_ready(llm) -> bool:
    """Cheap check (GET /api/tags) and the model is installed. Checked BEFORE leasing an alert, so an
    Ollama outage leaves alerts queued instead of burning their retry attempts into 'failed'."""
    try:
        names = {m.model for m in llm.list().models}
    except Exception as exc:
        log.warning("LLM not reachable at %s (%s); waiting", config.LLM_URL, type(exc).__name__)
        return False
    if config.MODEL not in names and f"{config.MODEL}:latest" not in names:
        log.error("model %s is not installed on %s (have: %s)", config.MODEL, config.LLM_URL, sorted(names))
        return False
    return True


def run_worker():
    log.info("worker %s running, model=%s ctx=%s notify=%s web_search=%s%s siems=%s", db.WORKER_ID, config.MODEL,
             config.NUM_CTX, config.NOTIFY_CHANNELS or "off", config.WEB_SEARCH_PROVIDER,
             " (dry-run)" if config.WEB_SEARCH_DRY_RUN else "", ",".join(elastic.configured()) or "NONE")
    if not elastic.configured():
        raise SystemExit("no SIEM configured: create siems/siems.json (see siems/siems.example.json) "
                         "or set ELASTIC_URL")
    missing = [s.id for s in elastic.configured().values() if not s.worker_api_key]
    if missing:
        raise SystemExit(f"worker_api_key missing for SIEM(s): {', '.join(missing)}")
    llm = Client(host=config.LLM_URL, timeout=config.LLM_TIMEOUT)
    probe = Client(host=config.LLM_URL, timeout=10)
    conn = None
    checked = False
    last_maintenance = 0.0
    while _running:
        try:
            if conn is None or conn.closed:
                conn = db.get_connection()
            if not checked:
                db.ensure_schema(conn)
                licensing.ensure_schema(conn)
                reports.ensure_schema(conn)
                notifier.check_ready(conn)
                state = licensing.refresh(conn)
                log.info("edition %s%s", licensing.tier().upper(),
                         f" (licence: {state['last_error']})" if state and state["last_error"] else "")
                checked = True
            if time.monotonic() - last_maintenance > 300:
                db.reap_stale_leases(conn)
                db.cache_purge(conn)
                licensing.refresh(conn)          # only contacts the licence server when a check is due
                reports.run_due(conn)            # scheduled report e-mails (Pro), once per period
                last_maintenance = time.monotonic()
            HEARTBEAT.touch()
            licensing.sync(conn)
            notifier.deliver_pending(conn)

            if not llm_ready(probe):
                time.sleep(config.LLM_UNAVAILABLE_BACKOFF)
                continue
            row = db.claim_next_alert(conn)
            if row is None:
                time.sleep(config.POLL_SECONDS)
                continue
            try:
                process(conn, llm, row)
            except LLMUnavailable as exc:
                log.warning("alert %s: LLM went away mid-investigation (%s); re-queued", row["alert_id"], exc)
                db.release_alert(conn, row["alert_id"], f"LLM unavailable: {exc}", config.LLM_UNAVAILABLE_BACKOFF)
            except Exception as exc:
                log.exception("alert %s failed (attempt %s)", row["alert_id"], row["attempts"])
                state = db.mark_retry(conn, row["alert_id"], row["attempts"], f"{type(exc).__name__}: {exc}")
                if state == "failed":
                    # make the failure visible to analysts
                    final = fallback_verdict(f"{type(exc).__name__} after {row['attempts']} attempts")
                    db.store_result(conn, row["alert_id"], {**final, "alert_id": row["alert_id"],
                                                            "rule_name": row["rule_name"],
                                                            "hostname": row["host_name"],
                                                            **_siem_fields(row.get("siem"))},
                                    {"model": config.MODEL, "prompt_version": config.PROMPT_VERSION})
                    # store_result clears last_error and marks done: restore both so the cause is kept
                    conn.execute("UPDATE alerts SET status='failed', last_error=%s WHERE alert_id=%s",
                                 (f"{type(exc).__name__}: {exc}"[:2000], row["alert_id"]))
        except Exception:
            log.exception("worker loop error; reconnecting in 10s")
            try:
                conn and conn.close()
            except Exception:
                pass
            conn = None
            time.sleep(10)
    log.info("worker stopped")


if __name__ == "__main__":
    run_worker()
