-- Passwordless customer account login challenges and revocable sessions.
-- Safe to apply repeatedly.
CREATE TABLE IF NOT EXISTS account_login_challenges (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_email ON account_login_challenges(email);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_email_created
    ON account_login_challenges(email, created_at);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_expires_at
    ON account_login_challenges(expires_at);

CREATE TABLE IF NOT EXISTS account_sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS ix_account_sessions_license_id ON account_sessions(license_id);
CREATE INDEX IF NOT EXISTS ix_account_sessions_license_created
    ON account_sessions(license_id, created_at);
CREATE INDEX IF NOT EXISTS ix_account_sessions_expires_at ON account_sessions(expires_at);
