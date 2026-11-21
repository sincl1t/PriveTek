-- A challenge for email MFA stores only a keyed digest of the one-time code.
ALTER TABLE privetek_mfa_challenges ADD COLUMN IF NOT EXISTS email_code_hash TEXT;
