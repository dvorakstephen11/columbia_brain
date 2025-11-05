import os
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEST_DB_PATH = ROOT / "test_auth.db"
os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB_PATH}")
os.environ.setdefault("DEV_MODE", "1")
os.environ.setdefault("COOKIE_SECURE", "0")

from app.db import Base, engine, SessionLocal  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Ensure no stray sessions survive between tests
    try:
        SessionLocal().close()
    except Exception:
        pass
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
