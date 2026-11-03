-- Verified customer account email-change challenges.
-- Apply before deploying the matching application revision.
CREATE TABLE IF NOT EXISTS account_email_change_challenges (
    id VARCHAR(64) PRIMARY KEY,
    old_email VARCHAR(255) NOT NULL,
    new_email VARCHAR(255) NOT NULL,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_old_email
    ON account_email_change_challenges (old_email);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_new_email
    ON account_email_change_challenges (new_email);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_license_id
    ON account_email_change_challenges (license_id);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_old_created
    ON account_email_change_challenges (old_email, created_at);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_new_created
    ON account_email_change_challenges (new_email, created_at);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_expires_at
    ON account_email_change_challenges (expires_at);
