CREATE TABLE privetek_profile_search (
    user_id TEXT PRIMARY KEY REFERENCES privetek_users(id) ON DELETE CASCADE,
    free_used BOOLEAN NOT NULL DEFAULT FALSE,
    access_until TIMESTAMPTZ,
    lease_token TEXT,
    lease_until TIMESTAMPTZ,
    ciphertext BYTEA,
    result_until TIMESTAMPTZ
);
