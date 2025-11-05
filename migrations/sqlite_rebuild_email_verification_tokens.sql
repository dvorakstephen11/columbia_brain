BEGIN TRANSACTION;

CREATE TABLE email_verification_tokens_new (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO email_verification_tokens_new (id, user_id, token_hash, expires_at, used)
SELECT id, user_id, token_hash, expires_at, used FROM email_verification_tokens;

DROP TABLE email_verification_tokens;
ALTER TABLE email_verification_tokens_new RENAME TO email_verification_tokens;

CREATE INDEX ix_evt_valid ON email_verification_tokens (user_id, token_hash, used);

COMMIT;
