import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


def normalize_db_url(url: str) -> str:
    return url.replace("postgres://", "postgresql://", 1) if url.startswith("postgres://") else url


def _pool_int(name: str, default: int) -> int:
    value = os.getenv(name)
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


DB_URL = normalize_db_url(os.getenv("DATABASE_URL", "sqlite:///./dev.db"))

engine = create_engine(
    DB_URL,
    pool_pre_ping=True,
    pool_size=_pool_int("DB_POOL_SIZE", 5),
    max_overflow=_pool_int("DB_MAX_OVERFLOW", 5),
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()
