CREATE TABLE privetek_account_phones (
    user_id TEXT PRIMARY KEY REFERENCES privetek_users(id) ON DELETE CASCADE,
    phone_key TEXT NOT NULL UNIQUE,
    ciphertext BYTEA NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE privetek_phone_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES privetek_users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('bind','login')),
    phone_key TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    code_hash TEXT NOT NULL,
    accepted BOOLEAN NOT NULL DEFAULT FALSE,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE privetek_sms_budget (
    day DATE PRIMARY KEY,
    used INTEGER NOT NULL DEFAULT 0
);
