ALTER TABLE users ADD COLUMN username TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username) WHERE username IS NOT NULL;
