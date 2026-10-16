-- Additive migration; existing anonymous jobs are not assigned retroactively.
CREATE TABLE IF NOT EXISTS privetek_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_key TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS privetek_account_codes (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_key TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('register', 'reset')),
    code_hash TEXT NOT NULL,
    pending_password_hash TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS privetek_account_codes_email_idx
    ON privetek_account_codes(email_key, purpose);
CREATE TABLE IF NOT EXISTS privetek_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES privetek_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS privetek_sessions_user_idx ON privetek_sessions(user_id);
CREATE TABLE IF NOT EXISTS privetek_account_limits (
    key TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requests INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS privetek_job_owners (
    job_id TEXT PRIMARY KEY REFERENCES privetek_jobs(id) ON DELETE CASCADE,
    email_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS privetek_job_owners_email_idx ON privetek_job_owners(email_key, job_id);
CREATE TABLE IF NOT EXISTS privetek_account_reports (
    job_id TEXT PRIMARY KEY REFERENCES privetek_jobs(id) ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS privetek_account_reports_expiry_idx ON privetek_account_reports(expires_at);
CREATE INDEX IF NOT EXISTS privetek_account_codes_expiry_idx ON privetek_account_codes(expires_at);
CREATE INDEX IF NOT EXISTS privetek_sessions_expiry_idx ON privetek_sessions(expires_at);
