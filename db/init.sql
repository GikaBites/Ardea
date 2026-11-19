-- Ardea database schema. Runs automatically when the Postgres volume is created.

BEGIN;

-- ---------------------------------------------------------------------------
-- alerts: the work queue. Filled by the fetcher, leased and completed by the worker.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,                  -- '<siem id>:<Elastic _id>' (older rows: the bare _id)
    timestamp       TIMESTAMPTZ NOT NULL,
    first_seen      TIMESTAMPTZ,
    alert_hash      TEXT,                              -- dedup key (rule, host, user, process, command line)
    count           INT         NOT NULL DEFAULT 1,    -- 1 + number of duplicates folded into this alert
    status          TEXT        NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new','processing','retry','done','failed','suppressed')),
    attempts        INT         NOT NULL DEFAULT 0,
    locked_by       TEXT,
    locked_at       TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    rule_id         TEXT,
    rule_name       TEXT,
    host_name       TEXT,
    user_name       TEXT,
    incident_key    TEXT,                              -- same host within the same time bucket
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    siem            TEXT,                              -- id from siems/siems.json
    elastic_id      TEXT,                              -- the alert's _id in that SIEM
    process_name       TEXT,                           -- for the rule-tuning advisor (Pro)
    process_executable TEXT,
    parent_executable  TEXT,
    priority        INT         NOT NULL DEFAULT 50     -- rule risk (+20 high-impact tactic): the worker takes the highest first
);
CREATE INDEX IF NOT EXISTS alerts_queue_idx    ON alerts (status, next_attempt_at, timestamp);
CREATE INDEX IF NOT EXISTS alerts_hash_idx     ON alerts (alert_hash, timestamp DESC);
CREATE INDEX IF NOT EXISTS alerts_incident_idx ON alerts (incident_key);
CREATE INDEX IF NOT EXISTS alerts_siem_idx     ON alerts (siem, elastic_id);

-- Duplicate alerts folded into an alert that is queued or already triaged.
CREATE TABLE IF NOT EXISTS alert_occurrences (
    alert_id        TEXT PRIMARY KEY,                  -- the duplicate's own Elastic _id
    parent_alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
    timestamp       TIMESTAMPTZ NOT NULL
);

-- Fetcher position before multi-SIEM support (read once to seed fetcher_siem_state).
CREATE TABLE IF NOT EXISTS fetcher_state (
    id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    watermark   TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SIEMs from siems/siems.json, written by the fetcher (names and Kibana links for the UI; no secrets).
CREATE TABLE IF NOT EXISTS siems (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kibana_url  TEXT,
    position    INT  NOT NULL DEFAULT 0,               -- order in siems.json
    active      BOOLEAN NOT NULL DEFAULT TRUE,         -- FALSE = removed from siems.json
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fetcher position in each SIEM's alerts index.
CREATE TABLE IF NOT EXISTS fetcher_siem_state (
    siem        TEXT PRIMARY KEY,
    watermark   TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- triage_results: one verdict per alert.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS triage_results (
    alert_id        TEXT PRIMARY KEY REFERENCES alerts(alert_id),
    response        TEXT,                              -- verdict JSON as text (read by the UI)
    result          JSONB,                             -- same verdict as JSONB (for SQL queries)
    verdict         TEXT,
    severity        TEXT,
    confidence      INT,
    should_escalate BOOLEAN,
    model           TEXT,
    prompt_version  TEXT,
    steps           INT,
    tool_calls      INT,
    duration_ms     INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS triage_verdict_idx ON triage_results (verdict, severity);

-- ---------------------------------------------------------------------------
-- Audit trail: every LLM turn, tool call, review and guardrail, in order.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_steps (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        TEXT NOT NULL REFERENCES alerts(alert_id),
    run_id          TEXT NOT NULL,                     -- one per attempt
    step            INT  NOT NULL,
    kind            TEXT NOT NULL,                     -- enrichment | llm | tool | final | review | guardrail
    tool_name       TEXT,
    arguments       JSONB,
    status          TEXT NOT NULL,                     -- ok | error | blocked | cached | duplicate
    evidence_id     TEXT,                              -- E1, E2 ... (what the model must cite)
    result          JSONB,
    llm_content     TEXT,
    error           TEXT,
    duration_ms     INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS steps_alert_idx ON investigation_steps (alert_id, run_id, step);

-- Cache for SIEM and web search results.
CREATE TABLE IF NOT EXISTS tool_cache (
    cache_key   TEXT PRIMARY KEY,                      -- sha256(tool + canonical arguments)
    tool_name   TEXT NOT NULL,
    result      JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS tool_cache_exp_idx ON tool_cache (expires_at);

-- Every web search query (sent, dry_run, failed, rate_limited). Also the source for rate limits.
CREATE TABLE IF NOT EXISTS outbound_requests (
    id          BIGSERIAL PRIMARY KEY,
    alert_id    TEXT,
    provider    TEXT NOT NULL,
    query       TEXT NOT NULL,                         -- the sanitised query
    status      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS outbound_time_idx ON outbound_requests (created_at);

-- Analyst feedback from the UI. Shown to the model for similar alerts and used to build eval cases.
CREATE TABLE IF NOT EXISTS feedback (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        TEXT NOT NULL REFERENCES alerts(alert_id),
    analyst         TEXT NOT NULL,
    agrees          BOOLEAN NOT NULL,
    correct_verdict TEXT,
    comment         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS feedback_alert_idx ON feedback (alert_id);

-- Notification outbox. Rows are written in the same transaction as the verdict and delivered by the
-- worker with retries, so an SMTP / ntfy outage delays a notification but never loses it.
CREATE TABLE IF NOT EXISTS notifications (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        TEXT NOT NULL REFERENCES alerts(alert_id),
    channel         TEXT NOT NULL,                     -- smtp | ntfy
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | sent | failed
    attempts        INT  NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error      TEXT,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at         TIMESTAMPTZ,
    UNIQUE (alert_id, channel)                         -- re-triage never notifies twice
);
CREATE INDEX IF NOT EXISTS notifications_pending_idx ON notifications (status, next_attempt_at);

-- Edition and licence check result. Written by the worker only; the fetcher and the UI read it.
CREATE TABLE IF NOT EXISTS license_state (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    install_id      TEXT NOT NULL,
    tier            TEXT NOT NULL DEFAULT 'community',
    source          TEXT NOT NULL DEFAULT 'none',
    status          TEXT,
    customer        TEXT,
    product         TEXT,
    key_hash        TEXT,
    instance_id     TEXT,
    expires_at      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    last_ok_at      TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    last_error      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scheduled report e-mails already sent (one row per period and recipient group).
CREATE TABLE IF NOT EXISTS report_runs (
    run_key     TEXT PRIMARY KEY,                      -- e.g. 'monthly:2026-11:hq'
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status      TEXT NOT NULL DEFAULT 'sent',
    detail      TEXT
);

-- Optional least-privilege role for the publisher (read everything, write only feedback):
-- CREATE ROLE ardea_publisher LOGIN PASSWORD 'change-me';
-- GRANT SELECT ON alerts, triage_results, investigation_steps, alert_occurrences, siems, license_state TO ardea_publisher;
-- GRANT SELECT, INSERT ON feedback TO ardea_publisher;
-- GRANT UPDATE (status, attempts, next_attempt_at, last_error, locked_by) ON alerts TO ardea_publisher;  -- re-triage (Pro)
-- GRANT USAGE ON SEQUENCE feedback_id_seq TO ardea_publisher;
-- Pro (queue and deadlines, silent sources): GRANT SELECT, INSERT, UPDATE ON alert_work TO ardea_publisher;
-- GRANT SELECT, INSERT ON alert_work_log TO ardea_publisher; GRANT USAGE ON SEQUENCE alert_work_log_id_seq TO ardea_publisher;
-- GRANT SELECT ON source_health TO ardea_publisher;

COMMIT;
