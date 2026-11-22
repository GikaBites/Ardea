"""Ardea worker: leases alerts from the queue, investigates them, stores verdict + audit trail.

  * an alert is marked done only in the same transaction that stores its result
  * a failed alert is retried with backoff, then published as 'Needs Human Review', never dropped
  * if Ollama is unreachable, alerts stay queued instead of using up their retries
  * True Positive notifications are queued with the result and delivered from the outbox
"""
import faulthandler
import importlib
import logging
import os
import pathlib
import signal
import sys
import threading
import time

from ollama import Client

import appsettings
import ask
import config
import db
import digest
import elastic
import flood
import health
import licensing
import notifier
import packs
import playbooks
import reports
import settings_tests
import sla
import suppress
import sysinfo
import siems as siem_config
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


# --------------------------------------------------------------------------- hang protection
class Overrun(BaseException):
    """Raised by SIGALRM when one alert or question runs far past its time limit. A BaseException, so that no
    'except Exception' inside the investigation swallows it."""


def _alarm(_signum, frame):
    import traceback
    raise Overrun("".join(traceback.format_stack(frame, limit=15)))


signal.signal(signal.SIGALRM, _alarm)
faulthandler.enable()                                  # a crash prints every thread's stack to the log
faulthandler.register(signal.SIGUSR1, all_threads=True)   # docker kill -s USR1 <worker>: print where it is
_beat = {"at": time.monotonic(), "what": "starting"}


def _alive(what: str):
    _beat["at"], _beat["what"] = time.monotonic(), what


def watchdog_limit() -> int:
    """Seconds without a sign of life before the worker gives up and exits (Docker then restarts it)."""
    return max(1800, config.MAX_WALL_SECONDS + config.LLM_TIMEOUT + 600)


def _watchdog():
    while True:
        time.sleep(30)
        if time.monotonic() - _beat["at"] > watchdog_limit():
            log.critical("worker has not made progress for %s minutes (%s): printing where it hangs and exiting "
                         "so that Docker restarts it", watchdog_limit() // 60, _beat["what"])
            faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
            sys.stderr.flush()
            os._exit(70)


def _hard_limit(seconds: int):
    signal.alarm(max(1, int(seconds)))


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
    s = suppress.find(conn, row)
    if s is not None:
        why_not = suppress.blocked(ctx)
        if why_not is None:
            final = enrich_result(suppress.verdict(s), ctx, row)
            db.store_result(conn, alert_id, final, {"model": None, "prompt_version": config.PROMPT_VERSION,
                                                    "steps": 0, "tool_calls": 0, "duration_ms": 0})
            suppress.record_hit(conn, s)
            log.info("alert %s -> %s by suppression #%s", alert_id, final["verdict"], s["id"])
            return
        log.info("alert %s matches suppression #%s but is investigated: %s", alert_id, s["id"], why_not)
    burst = flood.find(conn, row) if flood.blocked(ctx) is None else None
    if burst is not None:
        final = enrich_result(flood.verdict(burst), ctx, row)
        db.store_result(conn, alert_id, final, {"model": None, "prompt_version": config.PROMPT_VERSION,
                                                "steps": 0, "tool_calls": 0, "duration_ms": 0},
                        notifier.build_notifications(final, row.get("user_name")))
        log.info("alert %s -> %s reused from %s investigated alerts of the same burst", alert_id, final["verdict"],
                 len(burst["samples"]))
        return
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


def _settings_env() -> dict:
    """Extra facts for the Settings page: where the SIEM list comes from."""
    out = {}
    if siem_config.file_path().is_file():
        out["SIEMS_FILE"] = str(siem_config.file_path())
    if appsettings.from_env("ELASTIC_URL"):
        out["ELASTIC_URL"] = appsettings.from_env("ELASTIC_URL")
    return out


def _describe():
    log.info("worker %s: model=%s ctx=%s notify=%s web_search=%s%s siems=%s", db.WORKER_ID, config.MODEL,
             config.NUM_CTX, config.NOTIFY_CHANNELS or "off", config.WEB_SEARCH_PROVIDER,
             " (dry-run)" if config.WEB_SEARCH_DRY_RUN else "", ",".join(elastic.configured()) or "NONE")
    if not elastic.configured():
        log.warning("no SIEM configured yet: add one on the Settings page (or siems/siems.json, or ELASTIC_URL)")
    missing = [s.id for s in elastic.configured().values() if not s.worker_api_key]
    if missing:
        log.error("worker API key missing for SIEM(s): %s", ", ".join(missing))


def apply_settings(conn) -> bool:
    """Reload config and the SIEM list from the Settings page. Returns True if anything changed."""
    importlib.reload(config)
    try:
        elastic.reload()
    except siem_config.SiemConfigError as exc:
        log.error("SIEM configuration: %s", exc)
    for name, why in appsettings.PROBLEMS.items():
        log.warning("setting %s ignored: %s", name, why)
    return True


def _reconnect(conn):
    """After an Overrun the connection may be mid-query: start a fresh one."""
    try:
        conn and conn.close()
    except Exception:
        pass
    return db.get_connection()


def _give_up_or_retry(conn, row, error: str):
    state = db.mark_retry(conn, row["alert_id"], row["attempts"], error)
    if state == "failed":
        # make the failure visible to analysts
        final = fallback_verdict(f"{error.split(':')[0]} after {row['attempts']} attempts")
        db.store_result(conn, row["alert_id"], {**final, "alert_id": row["alert_id"],
                                                "rule_name": row["rule_name"],
                                                "hostname": row["host_name"],
                                                **_siem_fields(row.get("siem"))},
                        {"model": config.MODEL, "prompt_version": config.PROMPT_VERSION})
        # store_result clears last_error and marks done: restore both so the cause is kept
        conn.execute("UPDATE alerts SET status='failed', last_error=%s WHERE alert_id=%s",
                     (error[:2000], row["alert_id"]))


_tasks_seen = {"at": -1e9, "alive": False}


def tasks_worker_alive(conn) -> bool:
    """Is the worker-tasks service running? Then settings tests and questions are left to it (checked every 30 s)."""
    if time.monotonic() - _tasks_seen["at"] < 30:
        return _tasks_seen["alive"]
    try:
        row = conn.execute("""SELECT 1 FROM service_activity WHERE service = 'worker-tasks'
                              AND updated_at > NOW() - interval '2 minutes'""").fetchone()
        _tasks_seen["alive"] = row is not None
    except Exception:
        _tasks_seen["alive"] = False
    _tasks_seen["at"] = time.monotonic()
    return _tasks_seen["alive"]


def run_tasks():
    """The worker-tasks service: settings tests and analysts' questions only, never alerts or scheduled jobs."""
    settings = appsettings.Runtime("worker-tasks", extra_env=_settings_env)
    llm = probe = None
    conn = None
    threading.Thread(target=_watchdog, name="watchdog", daemon=True).start()
    log.info("worker-tasks: settings tests and questions only")
    while _running:
        _alive("tasks loop")
        try:
            if conn is None or conn.closed:
                conn = db.get_connection()
            if settings.tick(conn, now=settings_tests.queued(conn)) or llm is None:
                apply_settings(conn)
                llm = Client(host=config.LLM_URL, timeout=config.LLM_TIMEOUT)
                probe = Client(host=config.LLM_URL, timeout=10)
            licensing.sync(conn)
            HEARTBEAT.touch()
            settings_tests.run_pending(conn)
            busy = False
            if licensing.has("ask") and llm_ready(probe):
                _hard_limit(ask.MAX_SECONDS + 300)
                try:
                    busy = ask.run_pending(conn, llm)
                except Overrun as where:
                    log.error("a question ran past %s s and was stopped. It was here:\n%s", ask.MAX_SECONDS + 300, where)
                    ask.fail_running(conn, "Answering took too long and was stopped.")
                    conn = _reconnect(conn)
                finally:
                    signal.alarm(0)
            if not busy:
                appsettings.activity(conn, config.SERVICE, "idle", "Waiting for settings tests and questions")
                time.sleep(2)
        except Exception:
            log.exception("tasks loop error; reconnecting in 10s")
            try:
                conn and conn.close()
            except Exception:
                pass
            conn = None
            time.sleep(10)
    log.info("worker-tasks stopped")


def run_worker():
    settings = appsettings.Runtime("worker", extra_env=_settings_env)
    llm = probe = None
    conn = None
    described = False
    checked = False
    last_maintenance = 0.0
    threading.Thread(target=_watchdog, name="watchdog", daemon=True).start()
    while _running:
        _alive("main loop")
        try:
            if conn is None or conn.closed:
                conn = db.get_connection()
            tasks_elsewhere = tasks_worker_alive(conn)
            test_waiting = not tasks_elsewhere and settings_tests.queued(conn)
            if settings.tick(conn, now=test_waiting) or llm is None:
                apply_settings(conn)
                llm = Client(host=config.LLM_URL, timeout=config.LLM_TIMEOUT)
                probe = Client(host=config.LLM_URL, timeout=10)
                if described:
                    log.info("settings changed on the Settings page: applied")
                    licensing.refresh(conn)
                _describe()
                described = True
            if not tasks_elsewhere:
                settings_tests.run_pending(conn)
            packs.tick(conn)                     # playbook pack: uploads, daily update (Pro / MSP)
            if not checked:
                db.ensure_schema(conn)
                licensing.ensure_schema(conn)
                reports.ensure_schema(conn)
                health.ensure_schema(conn)
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
                health.run_due(conn)             # silent-source alarm (Pro), every 15 minutes
                digest.run_due(conn)             # daily handover digest (Pro), at DIGEST_TIME
                sla.run_due(conn)                # overdue alerts (Pro: assignments)
                sysinfo.run_due(conn)            # Health page snapshot; disk, backup and queue warnings
                ask.requeue_stuck(conn)          # questions left 'running' by a stopped worker
                last_maintenance = time.monotonic()
            HEARTBEAT.touch()
            licensing.sync(conn)
            notifier.deliver_pending(conn)

            if not elastic.configured():
                appsettings.activity(conn, "worker", "waiting", "No SIEM is configured yet")
                time.sleep(config.POLL_SECONDS)
                continue
            if not llm_ready(probe):
                appsettings.activity(conn, "worker", "blocked", f"The AI model ({config.MODEL}) is not reachable; "
                                     "alerts wait in the queue")
                time.sleep(config.LLM_UNAVAILABLE_BACKOFF)
                continue
            if licensing.has("ask") and not tasks_elsewhere:
                _alive("answering a question")
                _hard_limit(ask.MAX_SECONDS + 300)
                try:
                    if ask.run_pending(conn, llm):
                        continue                 # analysts' follow-up questions go before the next alert
                except Overrun as where:
                    log.error("a question ran past %s s and was stopped. It was here:\n%s", ask.MAX_SECONDS + 300, where)
                    ask.fail_running(conn, "Answering took too long and was stopped.")
                    conn = _reconnect(conn)
                    continue
                finally:
                    signal.alarm(0)
            row = db.claim_next_alert(conn)
            if row is None:
                appsettings.activity(conn, "worker", "idle", "Waiting for new alerts")
                time.sleep(config.POLL_SECONDS)
                continue
            appsettings.activity(conn, "worker", "investigating",
                                 f"{row['rule_name'] or 'Alert'} on {row['host_name'] or 'an unknown host'}",
                                 alert_id=row["alert_id"], siem=row.get("siem"), max_steps=config.MAX_STEPS,
                                 info={"attempt": row["attempts"],
                                       "max_seconds": config.MAX_WALL_SECONDS})
            limit = config.MAX_WALL_SECONDS + config.LLM_TIMEOUT + 300
            _alive(f"alert {row['alert_id']}")
            _hard_limit(limit)
            try:
                process(conn, llm, row)
            except Overrun as where:
                log.error("alert %s ran past %s minutes and was stopped (attempt %s). It was here:\n%s",
                          row["alert_id"], limit // 60, row["attempts"], where)
                conn = _reconnect(conn)
                _give_up_or_retry(conn, row, f"Overrun: the investigation ran past {limit // 60} minutes and was stopped")
            except LLMUnavailable as exc:
                log.warning("alert %s: LLM went away mid-investigation (%s); re-queued", row["alert_id"], exc)
                db.release_alert(conn, row["alert_id"], f"LLM unavailable: {exc}", config.LLM_UNAVAILABLE_BACKOFF)
            except Exception as exc:
                log.exception("alert %s failed (attempt %s)", row["alert_id"], row["attempts"])
                _give_up_or_retry(conn, row, f"{type(exc).__name__}: {exc}")
            finally:
                signal.alarm(0)
        except Overrun as where:                 # an alarm that fired outside the guarded calls
            log.error("worker step stopped by the time limit. It was here:\n%s", where)
            conn = _reconnect(conn)
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
    run_tasks() if config.WORKER_ROLE == "tasks" else run_worker()
