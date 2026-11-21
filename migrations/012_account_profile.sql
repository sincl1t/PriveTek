-- Optional profile settings; authentication identifiers remain unchanged.
CREATE TABLE privetek_account_profiles (
    user_id TEXT PRIMARY KEY REFERENCES privetek_users(id) ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
