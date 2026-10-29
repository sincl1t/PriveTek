-- Optional per-user MFA. Existing accounts keep their current login until enrolled.
ALTER TABLE privetek_users ADD COLUMN IF NOT EXISTS mfa_secret BYTEA;
ALTER TABLE privetek_users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE privetek_users ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT NOT NULL DEFAULT -1;
ALTER TABLE privetek_users ADD COLUMN IF NOT EXISTS mfa_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS privetek_mfa_setup (
    user_id TEXT PRIMARY KEY REFERENCES privetek_users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL,
    secret BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS privetek_mfa_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES privetek_users(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS privetek_mfa_challenges_user_idx ON privetek_mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS privetek_mfa_challenges_expiry_idx ON privetek_mfa_challenges(expires_at);
CREATE TABLE IF NOT EXISTS privetek_mfa_recovery (
    user_id TEXT NOT NULL REFERENCES privetek_users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
