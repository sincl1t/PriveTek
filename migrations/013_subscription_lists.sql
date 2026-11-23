CREATE TABLE IF NOT EXISTS privetek_subscription_lists (
    user_id TEXT PRIMARY KEY REFERENCES privetek_users(id) ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
