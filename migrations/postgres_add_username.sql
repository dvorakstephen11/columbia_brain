ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username) WHERE username IS NOT NULL;

ALTER TABLE email_verification_tokens DROP CONSTRAINT IF EXISTS email_verification_tokens_token_hash_key;

DROP INDEX IF EXISTS ix_evt_valid;
CREATE INDEX ix_evt_valid ON email_verification_tokens (user_id, token_hash, used);
