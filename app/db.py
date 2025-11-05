import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

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
