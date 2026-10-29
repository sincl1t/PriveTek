-- Opt-in pilot only: no existing user is enrolled.
CREATE TABLE IF NOT EXISTS privetek_monitor_pilot (
    id INTEGER PRIMARY KEY CHECK (id=1),
    ends_at TIMESTAMPTZ NOT NULL,
    day DATE NOT NULL DEFAULT CURRENT_DATE,
    scans INTEGER NOT NULL DEFAULT 0,
    mails INTEGER NOT NULL DEFAULT 0
);
INSERT INTO privetek_monitor_pilot (id,ends_at) VALUES (1,CURRENT_TIMESTAMP+INTERVAL '28 days') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS privetek_monitors (
    user_id TEXT PRIMARY KEY REFERENCES privetek_users(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('active','paused')),
    config BYTEA NOT NULL,
    baseline BYTEA,
    version INTEGER NOT NULL DEFAULT 1,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMPTZ,
    last_status TEXT,
    lease TEXT,
    lease_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS privetek_monitors_due ON privetek_monitors(next_run_at) WHERE state='active';
CREATE TABLE IF NOT EXISTS privetek_monitor_runs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES privetek_monitors(user_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    changes BYTEA,
    new_count INTEGER NOT NULL DEFAULT 0,
    mail_state TEXT NOT NULL DEFAULT 'none',
    mail_started_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS privetek_monitor_runs_owner ON privetek_monitor_runs(user_id,started_at DESC);
CREATE INDEX IF NOT EXISTS privetek_monitor_runs_pending ON privetek_monitor_runs(mail_state) WHERE mail_state='pending';
