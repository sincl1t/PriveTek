-- Private review snapshot follows the PDF's existing ownership, expiry and deletion.
ALTER TABLE privetek_account_reports ADD COLUMN IF NOT EXISTS identity_ciphertext BYTEA;
ALTER TABLE privetek_account_reports ADD COLUMN IF NOT EXISTS identity_revision INTEGER NOT NULL DEFAULT 0;
