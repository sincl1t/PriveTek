CREATE TABLE privetek_search_queue (
    job_id TEXT PRIMARY KEY REFERENCES privetek_jobs(id) ON DELETE CASCADE,
    recipient_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    finished_at TIMESTAMPTZ,
    lease_until TIMESTAMPTZ,
    lease_token TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    sending BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX privetek_search_pending ON privetek_search_queue (created_at, job_id) WHERE finished_at IS NULL;
CREATE INDEX privetek_search_recent ON privetek_search_queue (created_at);
CREATE INDEX privetek_search_fingerprint ON privetek_search_queue (fingerprint);
CREATE TABLE privetek_source_limits (
    source TEXT PRIMARY KEY,
    next_at TIMESTAMPTZ NOT NULL
);
