import os

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import declarative_base, sessionmaker

def normalize_db_url(url: str) -> str:
    # Render/Heroku occasionally provide postgres://; normalize to postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    # If no explicit driver is present, add +psycopg for psycopg v3
    # postgresql:// -> postgresql+psycopg://
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)

    return url

DB_URL = normalize_db_url(os.getenv("DATABASE_URL", "sqlite:///./dev.db"))

engine = create_engine(
    DB_URL,
    pool_pre_ping=True,
    pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "5")),
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()


def ensure_schema_upgrades() -> None:
    """Apply minimal in-app migrations so legacy databases get critical columns/indexes."""
    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())

        if "users" in tables:
            columns = {col["name"] for col in inspector.get_columns("users")}
            indexes = {idx["name"] for idx in inspector.get_indexes("users")}
            if "username" not in columns:
                if connection.dialect.name == "sqlite":
                    connection.exec_driver_sql("ALTER TABLE users ADD COLUMN username TEXT")
                elif connection.dialect.name.startswith("postgres"):
                    connection.exec_driver_sql("ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT")
            if "ix_users_username" not in indexes:
                connection.exec_driver_sql(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username "
                    "ON users (username) WHERE username IS NOT NULL"
                )

        if "email_verification_tokens" in tables:
            indexes = {idx["name"] for idx in inspector.get_indexes("email_verification_tokens")}
            if connection.dialect.name.startswith("postgres"):
                connection.exec_driver_sql(
                    "ALTER TABLE email_verification_tokens "
                    "DROP CONSTRAINT IF EXISTS email_verification_tokens_token_hash_key"
                )
            if "ix_evt_valid" not in indexes:
                connection.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_evt_valid "
                    "ON email_verification_tokens (user_id, token_hash, used)"
                )
