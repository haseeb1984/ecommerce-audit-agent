-- Customer-managed device sessions. Public IDs are opaque and distinct from bearer token digests.
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS public_id VARCHAR(64);
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS user_agent VARCHAR(500);
UPDATE account_sessions SET public_id = md5(token_hash || COALESCE(created_at::text, '')) WHERE public_id IS NULL;
ALTER TABLE account_sessions ALTER COLUMN public_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_account_sessions_public_id ON account_sessions (public_id);
