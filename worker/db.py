"""Postgres access for the worker: queue leasing, results, audit trail, cache, rate limits."""
import hashlib
import json
import os
import socket
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

import config

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


def get_connection():
    return psycopg.connect(
        host=os.environ["POSTGRES_HOST"],
        port=int(os.environ.get("POSTGRES_PORT", 5432)),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        row_factory=dict_row,
        connect_timeout=10,                 # a database that does not answer is an error, never a hang
        keepalives=1, keepalives_idle=60, keepalives_interval=10, keepalives_count=5,   # dead peer: ~2 min
        autocommit=True,
    )


# --------------------------------------------------------------------------- schema
# Same statements as the fetcher's (it also fills the siems table): whichever starts first adds them.
MULTI_SIEM_SCHEMA = """
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS siem TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS elastic_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS process_name TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS process_executable TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parent_executable TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 50;
CREATE INDEX IF NOT EXISTS alerts_siem_idx ON alerts (siem, elastic_id);
CREATE TABLE IF NOT EXISTS siems (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kibana_url TEXT, position INT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
"""


def ensure_schema(conn):
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(7270020)")
        for statement in filter(str.strip, MULTI_SIEM_SCHEMA.split(";")):
            conn.execute(statement)


# --------------------------------------------------------------------------- queue
def reap_stale_leases(conn):
    """Alerts stuck in 'processing' (worker crashed / OOM) go back to the queue."""
    conn.execute(
        """UPDATE alerts SET status = 'retry', locked_by = NULL, next_attempt_at = NOW()
           WHERE status = 'processing' AND locked_at < NOW() - make_interval(mins => %s)""",
        (config.LEASE_MINUTES,))


def claim_next_alert(conn):
    """Atomically lease the most urgent runnable alert. Safe with several worker replicas.
    Most urgent = the rule's risk (priority, set by the fetcher), plus 1 point for every 5 minutes it has waited
    (at most 40), so a low alert is never starved; equal ones oldest first."""
    return conn.execute(
        """UPDATE alerts SET status = 'processing', locked_by = %s, locked_at = NOW(),
                             attempts = attempts + 1
           WHERE alert_id = (
               SELECT alert_id FROM alerts
               WHERE status IN ('new', 'retry')
                 AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
               ORDER BY COALESCE(priority, 50)
                        + LEAST(EXTRACT(EPOCH FROM NOW() - COALESCE(inserted_at, NOW())) / 300, 40) DESC,
                        timestamp ASC
               LIMIT 1
               FOR UPDATE SKIP LOCKED)
           RETURNING alert_id, attempts, count, rule_id, rule_name, host_name, user_name, alert_hash,
                     incident_key, siem, elastic_id, process_executable, parent_executable""",
        (WORKER_ID,)).fetchone()


def release_alert(conn, alert_id, reason, delay_seconds):
    """Give the lease back WITHOUT using up an attempt (the LLM was down — not the alert's fault)."""
    conn.execute("""UPDATE alerts SET status='retry', attempts=GREATEST(attempts - 1, 0), locked_by=NULL,
                           last_error=%s, next_attempt_at=NOW() + make_interval(secs => %s)
                    WHERE alert_id=%s""", (reason[:2000], delay_seconds, alert_id))


def mark_retry(conn, alert_id, attempts, error):
    if attempts >= config.MAX_ATTEMPTS:
        conn.execute("UPDATE alerts SET status='failed', last_error=%s, locked_by=NULL "
                     "WHERE alert_id=%s", (error[:2000], alert_id))
        return "failed"
    backoff = timedelta(minutes=2 ** attempts)       # 2, 4, 8 ... minutes
    conn.execute("UPDATE alerts SET status='retry', last_error=%s, locked_by=NULL, next_attempt_at=%s "
                 "WHERE alert_id=%s",
                 (error[:2000], datetime.now(timezone.utc) + backoff, alert_id))
    return "retry"


def store_result(conn, alert_id, result: dict, meta: dict, notifications: list[tuple[str, dict]] = ()):
    """Result row + queue status + notification outbox in ONE transaction, so a crash can't leave
    half a state (e.g. a True Positive stored but never notified)."""
    with conn.transaction():
        conn.execute(
            """INSERT INTO triage_results (alert_id, response, result, verdict, severity, confidence,
                                           should_escalate, model, prompt_version, steps, tool_calls,
                                           duration_ms, updated_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
               ON CONFLICT (alert_id) DO UPDATE SET
                   response=EXCLUDED.response, result=EXCLUDED.result, verdict=EXCLUDED.verdict,
                   severity=EXCLUDED.severity, confidence=EXCLUDED.confidence,
                   should_escalate=EXCLUDED.should_escalate, model=EXCLUDED.model,
                   prompt_version=EXCLUDED.prompt_version, steps=EXCLUDED.steps,
                   tool_calls=EXCLUDED.tool_calls, duration_ms=EXCLUDED.duration_ms, updated_at=NOW()""",
            (alert_id, json.dumps(result, default=str), Jsonb(result), result.get("verdict"),
             result.get("severity"), result.get("confidence"), result.get("should_escalate"),
             meta.get("model"), meta.get("prompt_version"), meta.get("steps"),
             meta.get("tool_calls"), meta.get("duration_ms")))
        conn.execute("UPDATE alerts SET status='done', locked_by=NULL, last_error=NULL "
                     "WHERE alert_id=%s", (alert_id,))
        for channel, payload in notifications:
            conn.execute("""INSERT INTO notifications (alert_id, channel, payload) VALUES (%s, %s, %s)
                            ON CONFLICT (alert_id, channel) DO NOTHING""", (alert_id, channel, Jsonb(payload)))


# --------------------------------------------------------------------------- analyst feedback
def similar_feedback(conn, row: dict, limit: int) -> list[dict]:
    """Latest analyst verdicts on earlier alerts of the same rule, best matches first:
    same dedup pattern (rule+host+user+exe+parent+cmdline) > same host > same rule.
    Pattern and host only match within the same SIEM (the same host name elsewhere is another machine);
    'same rule' feedback is shared across SIEMs (prebuilt rules have the same rule_id everywhere)."""
    if limit <= 0 or not row.get("rule_id"):
        return []
    rows = conn.execute(
        """WITH latest AS (
               SELECT DISTINCT ON (alert_id) alert_id, agrees, correct_verdict, comment, created_at
               FROM feedback WHERE created_at > NOW() - make_interval(days => %(days)s)
               ORDER BY alert_id, created_at DESC)
           SELECT l.comment, l.created_at, t.verdict AS model_verdict, t.result->>'summary' AS summary,
                  CASE WHEN l.agrees THEN t.verdict ELSE l.correct_verdict END AS analyst_verdict,
                  CASE WHEN a.alert_hash = %(hash)s AND a.siem IS NOT DISTINCT FROM %(siem)s
                            THEN 'same pattern'                                   -- NULL hash -> not a match
                       WHEN a.host_name = %(host)s AND a.siem IS NOT DISTINCT FROM %(siem)s THEN 'same host'
                       ELSE 'same rule' END AS match
           FROM latest l JOIN alerts a USING (alert_id) JOIN triage_results t USING (alert_id)
           WHERE a.rule_id = %(rule)s AND a.alert_id <> %(id)s
             AND (CASE WHEN l.agrees THEN t.verdict ELSE l.correct_verdict END)
                 IN ('True Positive', 'Benign Positive', 'False Positive')
           ORDER BY COALESCE(a.alert_hash = %(hash)s AND a.siem IS NOT DISTINCT FROM %(siem)s, FALSE) DESC,
                    COALESCE(a.host_name = %(host)s AND a.siem IS NOT DISTINCT FROM %(siem)s, FALSE) DESC,
                    l.created_at DESC
           LIMIT %(n)s""",
        {"days": config.FEEDBACK_LOOKBACK_DAYS, "hash": row.get("alert_hash"), "host": row.get("host_name"),
         "rule": row["rule_id"], "id": row["alert_id"], "n": limit, "siem": row.get("siem")}).fetchall()
    for r in rows:
        r["date"] = r.pop("created_at").date().isoformat()
    return rows


# --------------------------------------------------------------------------- notifications
def pending_notifications(conn, limit=20):
    return conn.execute(
        """SELECT id, alert_id, channel, attempts, payload FROM notifications
           WHERE status = 'pending' AND next_attempt_at <= NOW() ORDER BY id LIMIT %s""", (limit,)).fetchall()


def mark_notification(conn, nid, ok: bool, error: str | None = None, attempts: int = 0):
    if ok:
        conn.execute("UPDATE notifications SET status='sent', sent_at=NOW(), attempts=attempts+1, last_error=NULL "
                     "WHERE id=%s", (nid,))
        return "sent"
    failed = attempts + 1 >= config.NOTIFY_MAX_ATTEMPTS
    backoff = min(3600, 30 * 2 ** attempts)          # 30 s, 1, 2, 4 ... min, capped at 1 h
    conn.execute("""UPDATE notifications SET attempts=attempts+1, last_error=%s, status=%s,
                           next_attempt_at=NOW() + make_interval(secs => %s) WHERE id=%s""",
                 ((error or "")[:1000], "failed" if failed else "pending", backoff, nid))
    return "failed" if failed else "pending"


# --------------------------------------------------------------------------- audit
def log_step(conn, alert_id, run_id, step, kind, *, tool_name=None, arguments=None, status="ok",
             evidence_id=None, result=None, llm_content=None, error=None, duration_ms=None):
    conn.execute(
        """INSERT INTO investigation_steps (alert_id, run_id, step, kind, tool_name, arguments, status,
                                            evidence_id, result, llm_content, error, duration_ms)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (alert_id, run_id, step, kind, tool_name,
         Jsonb(arguments) if arguments is not None else None, status, evidence_id,
         Jsonb(result) if result is not None else None,
         llm_content[:8000] if llm_content else None, error, duration_ms))


def log_outbound(conn, alert_id, provider, query, status):
    conn.execute("INSERT INTO outbound_requests (alert_id, provider, query, status) VALUES (%s,%s,%s,%s)",
                 (alert_id, provider, query, status))


def outbound_counts(conn):
    row = conn.execute(
        """SELECT count(*) FILTER (WHERE created_at > NOW() - interval '1 hour') AS hour,
                  count(*) FILTER (WHERE created_at > NOW() - interval '1 day')  AS day
           FROM outbound_requests WHERE status = 'sent'""").fetchone()
    return row["hour"], row["day"]


# --------------------------------------------------------------------------- cache
def cache_key(tool_name: str, args: dict) -> str:
    canon = json.dumps({"t": tool_name, "a": args}, sort_keys=True, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def cache_get(conn, key):
    row = conn.execute("SELECT result FROM tool_cache WHERE cache_key=%s AND expires_at > NOW()",
                       (key,)).fetchone()
    return row["result"] if row else None


def cache_put(conn, key, tool_name, result, ttl_seconds):
    conn.execute(
        """INSERT INTO tool_cache (cache_key, tool_name, result, expires_at)
           VALUES (%s,%s,%s, NOW() + make_interval(secs => %s))
           ON CONFLICT (cache_key) DO UPDATE SET result=EXCLUDED.result, created_at=NOW(),
                                                expires_at=EXCLUDED.expires_at""",
        (key, tool_name, Jsonb(result), ttl_seconds))


def cache_purge(conn):
    conn.execute("DELETE FROM tool_cache WHERE expires_at < NOW()")
