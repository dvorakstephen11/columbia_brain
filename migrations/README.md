# Database Migration Notes

The login refactor introduces a `username` column on `users` and relaxes the uniqueness requirement on `email_verification_tokens.token_hash` so that 6-digit verification codes can be reissued safely. Apply the statements below in your environment before deploying the new backend.

## SQLite (development)

```
.read migrations/sqlite_add_username.sql
.read migrations/sqlite_rebuild_email_verification_tokens.sql
```

The helper scripts add the `username` column, build a partial unique index, and rebuild the `email_verification_tokens` table without the legacy unique constraint.

## PostgreSQL (production)

```
ALTER TABLE users ADD COLUMN username TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username) WHERE username IS NOT NULL;
ALTER TABLE email_verification_tokens DROP CONSTRAINT IF EXISTS email_verification_tokens_token_hash_key;
DROP INDEX IF EXISTS ix_evt_valid;
CREATE INDEX ix_evt_valid ON email_verification_tokens (user_id, token_hash, used);
```

Run these statements inside a regular migration transaction before rolling out the new services. Existing tokens remain valid.
