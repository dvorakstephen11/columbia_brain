Here's what I'm seeing when I try to register a new account:
- Reload page
- Click Create account
- Type in email and password
- Click Register
- Get a "Check your email window" on the /verify route (see screenshot), with a "Verification code" form that already contains a verification code, along with a button that says "Verify"
- Click Verify
- Navigates to /username-setup with a Username field and a "Save username" button
- Enter username and click Save username
- New view: a "You're almost there" window that says  "Finish registration by verifying your email first so we know it's really you." and an "Enter verification code" button.
- Click "Enter verification code"
- Navigates to /verify with a window that says "Need an account? Start by registering with your email and password so we know where to send your verification code."


I'll reproduce my codebase below. Please look through it, identify everything wrong with my login/registration implementation, and suggest a plan for refactoring it. It should preserve the "mocking" of the verification code sent by email, but everything else should be enterprise-grade authentication.


Code:
```
.dockerignore
.gitattributes
.github/
  workflows/
    ci.yml
    render-deployment.yml
.gitignore
app/
  auth.py
  config.py
  db.py
  email.py
  main.py
  models.py
  security.py
  __init__.py
dev.db
Dockerfile
frontend/
  dist/
    assets/
      index-B6gKFgHG.css
      index-oDZKR0nZ.js
    index.html
  index.html
  package.json
  postcss.config.cjs
  src/
    App.jsx
    components/
      AccountMenu.jsx
      CalendarGrid.jsx
      DayCell.jsx
      EventChip.jsx
      EventPanel.jsx
    context/
      AuthContext.jsx
    data/
      mockEvents.js
    hooks/
      useAuth.js
    layouts/
      AppLayout.jsx
    main.jsx
    pages/
      CalendarPage.jsx
      LoginPage.jsx
      RegisterPage.jsx
      UsernameSetupPage.jsx
      VerifyPage.jsx
    styles.css
    utils/
      a11y.js
      api.js
      dates.js
  vite.config.js
migrations/
  postgres_add_username.sql
  sqlite_add_username.sql
  sqlite_rebuild_email_verification_tokens.sql
templates/
  index.html


-------


File: .dockerignore
.git
.github
__pycache__/
*.pyc
*.pyo

# Node
frontend/node_modules
frontend/dist

# Local env
.env
.DS_Store


File: .gitattributes
* text=auto eol=lf

# Ensure critical files are LF
*.sh text eol=lf
Dockerfile text eol=lf
*.py text eol=lf
*.js text eol=lf
*.jsx text eol=lf
*.ts text eol=lf
*.tsx text eol=lf
*.css text eol=lf
*.html text eol=lf
*.json text eol=lf
*.yml text eol=lf
*.yaml text eol=lf
*.cjs text eol=lf


File: .github\workflows\ci.yml
name: CI

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  tests:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run tests
        run: pytest

File: .github\workflows\render-deployment.yml
name: Build Image & Deploy (Render)

on:
  push:
    branches: [ main ]

jobs:
  docker:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write 
    env:
      IMAGE_SHA: ghcr.io/${{ github.repository }}:main-${{ github.sha }}
      IMAGE_LATEST: ghcr.io/${{ github.repository }}:latest

    steps:
      - uses: actions/checkout@v4

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: ${{ env.IMAGE_SHA }},${{ env.IMAGE_LATEST }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Trigger Render Deploy
        env:
          RENDER_DEPLOY_HOOK: ${{ secrets.RENDER_DEPLOY_HOOK }}
        run: curl -fsSL -X POST "$RENDER_DEPLOY_HOOK"


File: .gitignore
# Python
# Python cache directories
__pycache__/
**/__pycache__/
*.py[cod]
*.sqlite3

# Node
frontend/node_modules/
frontend/dist/

# Misc
.DS_Store
.env


File: Dockerfile
# syntax=docker/dockerfile:1

# -------- Frontend build (Vite) --------
    FROM node:20-alpine AS frontend
    WORKDIR /app/frontend
    
    # Install deps (works whether or not you have a package-lock.json)
    COPY frontend/package.json frontend/package-lock.json* ./
    RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
    
    # Copy sources and build
    COPY frontend/ .
    RUN npm run build
    
    # -------- Backend runtime (FastAPI) --------
    FROM python:3.12-slim AS backend
    ENV PYTHONDONTWRITEBYTECODE=1 \
        PYTHONUNBUFFERED=1
    
    WORKDIR /app
    
    # (Optional) system deps if you build native wheels; keep lean if you use psycopg2-binary.
    RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
     && rm -rf /var/lib/apt/lists/*
    
    # Python deps
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    
    # App code and templates
    COPY app/ app/
    COPY templates/ templates/
    
    # Bring in the built frontend
    COPY --from=frontend /app/frontend/dist ./frontend/dist
    
    # Render sets $PORT. Shell-form CMD expands it and falls back to 8000 locally.
    CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
    

File: app\__init__.py


File: app\auth.py
import datetime as dt
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .config import COOKIE_SECURE, DEV_MODE, PUBLIC_BASE_URL, SESSION_MAX_AGE
from .db import SessionLocal
from .email import send_email
from .models import EmailVerificationToken, OutboundEmail, User
from .security import (
    create_registration_token,
    create_session_jwt,
    decode_registration_token,
    decode_session_jwt,
    hash_password,
    make_csrf_token,
    make_numeric_code,
    safe_eq,
    sha256_hex,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

REG_STAGE_AWAITING_VERIFICATION = "awaiting_verification"
REG_STAGE_AWAITING_USERNAME = "awaiting_username"
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def set_session_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(
        key="session",
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


def clear_session_cookie(resp: Response) -> None:
    resp.delete_cookie("session", path="/")


def set_csrf_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(
        key="csrf_token",
        value=token,
        max_age=60 * 60 * 2,
        httponly=False,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


def require_csrf(request: Request) -> None:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        cookie = request.cookies.get("csrf_token")
        header = request.headers.get("X-CSRF-Token")
        if not cookie or not header or not safe_eq(cookie, header):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed")


def get_session_user(request: Request, db: Session) -> Optional[User]:
    session_token = request.cookies.get("session")
    if not session_token:
        return None
    user_id = decode_session_jwt(session_token)
    if not user_id:
        return None
    return db.get(User, user_id)


def ensure_session_user(request: Request, db: Session) -> User:
    user = get_session_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user


def normalize_username(raw: str) -> str:
    value = raw.strip()
    if not (3 <= len(value) <= 30):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username must be 3-30 characters")
    if not USERNAME_PATTERN.fullmatch(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username can contain letters, numbers, and underscores only",
        )
    return value.lower()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyCodeRequest(BaseModel):
    code: str
    email: Optional[EmailStr] = None
    registration_token: Optional[str] = None


class UsernameRequest(BaseModel):
    username: str
    registration_token: Optional[str] = None


class MeResponse(BaseModel):
    id: int
    email: EmailStr
    is_email_verified: bool
    username: Optional[str]


@router.get("/csrf")
def csrf(response: Response):
    token = make_csrf_token()
    set_csrf_cookie(response, token)
    return {"csrf": "ok"}


@router.post("/register")
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    require_csrf(request)

    email_norm = req.email.strip().lower()
    existing = db.query(User).filter(User.email == email_norm).one_or_none()
    if existing:
        if existing.is_email_verified:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account already exists")
        existing.password_hash = hash_password(req.password)
        tokens = (
            db.query(EmailVerificationToken)
            .filter(EmailVerificationToken.user_id == existing.id, EmailVerificationToken.used.is_(False))
            .all()
        )
        for token in tokens:
            token.used = True
        user = existing
    else:
        user = User(email=email_norm, password_hash=hash_password(req.password))
        db.add(user)
        db.flush()

    raw_code, token_hash = make_numeric_code()
    token_row = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=dt.datetime.utcnow() + dt.timedelta(hours=24),
    )
    db.add(token_row)
    db.commit()

    if PUBLIC_BASE_URL:
        verify_url = f"{PUBLIC_BASE_URL}/auth/verify?token={raw_code}"
    else:
        verify_url = f"/auth/verify?token={raw_code}"

    subject = "Verify your email"
    html = (
        "<p>Welcome! Use this verification code to activate your account:</p>"
        f"<p><strong style='font-size:20px; letter-spacing:4px;'>{raw_code}</strong></p>"
        "<p>If the app asks for it, enter the code exactly as shown above.</p>"
        "<p>You can also click the link below:</p>"
        f"<p><a href='{verify_url}'>Verify Email</a></p>"
    )
    send_email(db, to=email_norm, subject=subject, html=html)

    payload = {
        "pending_verification": True,
        "registration_token": create_registration_token(user.id, REG_STAGE_AWAITING_VERIFICATION),
    }
    if DEV_MODE:
        payload["mock_verification_code"] = raw_code
    return payload


@router.get("/verify")
def verify(token: str, db: Session = Depends(get_db)):
    token_hash = sha256_hex(token)
    token_row = (
        db.query(EmailVerificationToken)
        .filter(EmailVerificationToken.token_hash == token_hash)
        .one_or_none()
    )
    now = dt.datetime.utcnow()
    if not token_row or token_row.used or token_row.expires_at < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    user = db.get(User, token_row.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    user.is_email_verified = True
    token_row.used = True
    db.commit()

    return HTMLResponse("<p>Email verified. You can close this tab and return to the app.</p>")


@router.post("/verify-code")
def verify_code(req: VerifyCodeRequest, db: Session = Depends(get_db)):
    code_value = req.code.strip()
    if not code_value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code required")
    if not code_value.isdigit() or len(code_value) != 6:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Code must be a 6-digit number")

    user: Optional[User] = None
    if req.registration_token:
        user_id = decode_registration_token(req.registration_token, expected_stage=REG_STAGE_AWAITING_VERIFICATION)
        if not user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid registration token")
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account not found")
    elif req.email:
        email_norm = req.email.strip().lower()
        user = db.query(User).filter(User.email == email_norm).one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account not found")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration token or email is required",
        )

    token_hash = sha256_hex(code_value)
    now = dt.datetime.utcnow()
    query = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.token_hash == token_hash,
            EmailVerificationToken.used.is_(False),
            EmailVerificationToken.expires_at >= now,
        )
        .order_by(EmailVerificationToken.id.desc())
    )
    query = query.filter(EmailVerificationToken.user_id == user.id)

    token_row = query.first()
    if not token_row:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired code")

    user.is_email_verified = True
    token_row.used = True
    db.commit()

    response_payload = {
        "verified": True,
        "username_required": user.username is None,
    }
    if user.username is None:
        response_payload["registration_token"] = create_registration_token(user.id, REG_STAGE_AWAITING_USERNAME)
    return response_payload


@router.post("/username")
def set_username(req: UsernameRequest, request: Request, db: Session = Depends(get_db)):
    username = normalize_username(req.username)

    used_registration_token = bool(req.registration_token)
    if used_registration_token:
        user_id = decode_registration_token(req.registration_token, expected_stage=REG_STAGE_AWAITING_USERNAME)
        if not user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid registration token")
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account not found")
    else:
        require_csrf(request)
        user = ensure_session_user(request, db)

    if not user.is_email_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified")

    existing = db.query(User).filter(User.username == username).one_or_none()
    if existing and existing.id != user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already in use")

    user.username = username
    db.commit()

    payload = {"username": user.username, "completed": True}
    if used_registration_token:
        payload["next"] = "login"
    return payload


@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    require_csrf(request)

    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).one_or_none()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")
    if not user.is_email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    if not user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Username required")

    token = create_session_jwt(user.id)
    set_session_cookie(response, token)
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, response: Response):
    require_csrf(request)
    clear_session_cookie(response)
    return {"ok": True}


@router.get("/me", response_model=MeResponse)
def me(request: Request, db: Session = Depends(get_db)):
    user = ensure_session_user(request, db)
    return MeResponse(
        id=user.id,
        email=user.email,
        is_email_verified=user.is_email_verified,
        username=user.username,
    )


if DEV_MODE:

    @router.get("/dev/emails")
    def list_emails(db: Session = Depends(get_db)):
        rows = (
            db.query(OutboundEmail)
            .order_by(OutboundEmail.id.desc())
            .limit(50)
            .all()
        )
        return [
            {"id": row.id, "to": row.to_email, "subject": row.subject, "created_at": row.created_at.isoformat()}
            for row in rows
        ]

    @router.get("/dev/emails/{email_id}")
    def get_email(email_id: int, db: Session = Depends(get_db)):
        row = db.get(OutboundEmail, email_id)
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return {
            "id": row.id,
            "to": row.to_email,
            "subject": row.subject,
            "html": row.html,
            "created_at": row.created_at.isoformat(),
        }


File: app\config.py
import os


def env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip() in ("1", "true", "TRUE", "yes", "on")


DEV_MODE = env_bool("DEV_MODE", True)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", str(60 * 60 * 24 * 7)))
# Default to secure cookies only when not in dev mode so local HTTP works out of the box.
COOKIE_SECURE = env_bool("COOKIE_SECURE", not DEV_MODE)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")

EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "mock")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@example.com")


File: app\db.py
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


File: app\email.py
import os

import httpx
from sqlalchemy.orm import Session

from .config import EMAIL_BACKEND, FROM_EMAIL
from .models import OutboundEmail

RESEND_API_KEY = os.getenv("RESEND_API_KEY")


def send_email(db: Session, *, to: str, subject: str, html: str) -> None:
    if EMAIL_BACKEND == "resend" and RESEND_API_KEY:
        headers = {"Authorization": f"Bearer {RESEND_API_KEY}"}
        data = {"from": FROM_EMAIL, "to": [to], "subject": subject, "html": html}
        with httpx.Client(timeout=10) as client:
            response = client.post("https://api.resend.com/emails", json=data, headers=headers)
            response.raise_for_status()
        return

    record = OutboundEmail(to_email=to, subject=subject, html=html)
    db.add(record)
    db.commit()
    print(f"[MOCK EMAIL] To: {to} | Subject: {subject}\n{html}\n")


File: app\main.py
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .auth import router as auth_router
from .db import Base, ensure_schema_upgrades, engine

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent.parent

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)
ensure_schema_upgrades()

dist_dir = BASE_DIR / "frontend" / "dist"
assets_dir = dist_dir / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


def resolve_index_path() -> Path:
    if dist_dir.exists():
        candidate = dist_dir / "index.html"
        if candidate.exists():
            return candidate
    return BASE_DIR / "templates" / "index.html"


def _split_hosts(raw_hosts: str) -> list[str]:
    return [host.strip() for host in raw_hosts.split(",") if host.strip()]


allowed_hosts_default = "testserver,localhost,127.0.0.1,0.0.0.0,*.onrender.com"
allowed_hosts = _split_hosts(os.environ.get("ALLOWED_HOSTS", allowed_hosts_default))
if allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def secure_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "connect-src 'self'"
    )
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    index_path = resolve_index_path()
    content = index_path.read_text(encoding="utf-8")
    return HTMLResponse(content)


@app.get("/time", response_class=PlainTextResponse)
def time():
    import datetime as dt

    return dt.datetime.utcnow().isoformat()


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return "ok"


app.include_router(auth_router)


File: app\models.py
import datetime as dt

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(320), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow, nullable=False)


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash = Column(String(128), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)


Index("ix_evt_valid", EmailVerificationToken.user_id, EmailVerificationToken.token_hash, EmailVerificationToken.used)


class OutboundEmail(Base):
    __tablename__ = "outbound_emails"

    id = Column(Integer, primary_key=True)
    to_email = Column(String(320), index=True, nullable=False)
    subject = Column(String(255), nullable=False)
    html = Column(Text, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)


File: app\security.py
import datetime as dt
import hashlib
import hmac
import secrets
from typing import Optional, Tuple

import bcrypt
from jose import JWTError, jwt

from .config import SECRET_KEY, SESSION_MAX_AGE

JWT_ALG = "HS256"


def hash_password(password: str) -> str:
    # bcrypt returns ASCII-encoded hash; decode for storage
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (TypeError, ValueError):
        return False


def create_session_jwt(user_id: int) -> str:
    now = dt.datetime.utcnow()
    exp = now + dt.timedelta(seconds=SESSION_MAX_AGE)
    payload = {"sub": str(user_id), "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)


def decode_session_jwt(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return int(payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        return None


def make_numeric_code() -> Tuple[str, str]:
    value = f"{secrets.randbelow(1_000_000):06d}"
    return value, sha256_hex(value)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def make_csrf_token() -> str:
    return secrets.token_urlsafe(32)


REGISTRATION_TOKEN_TTL_SECONDS = 60 * 60 * 24


def create_registration_token(user_id: int, stage: str, ttl_seconds: int = REGISTRATION_TOKEN_TTL_SECONDS) -> str:
    now = dt.datetime.utcnow()
    exp = now + dt.timedelta(seconds=ttl_seconds)
    payload = {
        "sub": str(user_id),
        "stage": stage,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)


def decode_registration_token(token: str, expected_stage: Optional[str] = None) -> Optional[int]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
    except JWTError:
        return None

    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        return None

    stage = payload.get("stage")
    if expected_stage and stage != expected_stage:
        return None
    return user_id


File: dev.db
File: frontend\dist\assets\index-B6gKFgHG.css
:root{color-scheme:light;--bg-gradient-start: #f6f7fb;--bg-gradient-end: #ffffff;--card-bg: #ffffff;--card-radius: 18px;--chip-radius: 10px;--shadow-soft: 0 20px 45px -28px rgba(15, 23, 42, .45);--text-primary: #1f2937;--text-secondary: #4b5563;--accent: #2563eb;--accent-soft: rgba(37, 99, 235, .12);--muted: #e5e7eb;--today-bg: #2563eb;--today-ring: rgba(37, 99, 235, .16);--backdrop: rgba(15, 23, 42, .28);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}*,*:before,*:after{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,var(--bg-gradient-start),var(--bg-gradient-end));color:var(--text-primary)}button{font-family:inherit}a{color:inherit}#root{min-height:100vh}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}:focus-visible{outline:3px solid var(--accent);outline-offset:2px}@media (prefers-reduced-motion: reduce){*{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}.app-shell{display:flex;flex-direction:column;min-height:100vh;padding:48px 32px 64px}.app-header{margin:0 auto 36px;max-width:1180px;width:100%;display:flex;justify-content:space-between;align-items:flex-start;gap:24px}.app-header h1{margin:6px 0 0;font-size:clamp(32px,4vw,40px);font-weight:600}.app-header__eyebrow{margin:0;font-size:15px;font-weight:500;color:var(--accent);text-transform:uppercase;letter-spacing:.08em}.app-header__subtitle{margin:0;max-width:420px;font-size:16px;color:var(--text-secondary);line-height:1.5}.account-menu{position:relative;display:flex;align-items:center;justify-content:flex-end;min-width:52px}.account-menu__placeholder{width:44px;height:44px;border-radius:999px;background:var(--muted);opacity:.35}.account-menu__button{border:none;background:var(--card-bg);border-radius:999px;width:48px;height:48px;display:grid;place-items:center;cursor:pointer;box-shadow:0 12px 30px -18px #0f172a66;transition:transform .12s ease,box-shadow .12s ease}.account-menu__button:hover,.account-menu__button:focus-visible{transform:translateY(-1px);box-shadow:0 16px 38px -18px #0f172a80}.account-menu__avatar{display:grid;place-items:center;width:36px;height:36px;border-radius:999px;background:var(--accent);color:#fff;font-weight:600;font-size:16px}.account-menu__avatar--inline{width:40px;height:40px;font-size:18px}.account-menu__dropdown{position:absolute;top:58px;right:0;width:-moz-max-content;width:max-content;min-width:240px;background:var(--card-bg);border-radius:18px;box-shadow:var(--shadow-soft);padding:18px;display:flex;flex-direction:column;gap:12px;z-index:50}.account-menu__summary{display:flex;align-items:center;gap:12px}.account-menu__summary-name{margin:0;font-size:16px;font-weight:600}.account-menu__summary-email{margin:4px 0 0;font-size:14px;color:var(--text-secondary)}.account-menu__item{border:none;background:#2563eb14;color:var(--accent);font-weight:600;padding:10px 14px;border-radius:12px;cursor:pointer;text-align:left;transition:background .12s ease,transform .12s ease}.account-menu__item:hover,.account-menu__item:focus-visible{background:#2563eb29;transform:translateY(-1px)}.account-menu__item--primary{background:var(--accent);color:#fff}.account-menu__item--primary:hover,.account-menu__item--primary:focus-visible{background:#1d4ed8}.account-menu__pending{display:flex;flex-direction:column;gap:6px}.account-menu__pending p{margin:0;font-size:14px}.account-menu__pending-email{color:var(--text-secondary)}.app-main{display:flex;justify-content:center;align-items:flex-start;padding:0 16px}.calendar-card{background:var(--card-bg);box-shadow:var(--shadow-soft);border-radius:var(--card-radius);padding:28px;max-width:1180px;width:100%;display:flex;flex-direction:column;gap:16px}.calendar-card__header{display:flex;justify-content:space-between;align-items:center;width:100%}.calendar-card__title{margin:0;font-size:clamp(26px,3vw,32px);font-weight:600}.calendar-card__subtitle{margin:6px 0 0;font-size:14px;color:var(--text-secondary)}.weekday-row{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));font-size:14px;font-weight:600;color:var(--text-secondary);letter-spacing:.05em;text-transform:uppercase}.weekday{padding:0 12px 8px}.calendar-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px}.day-cell{background:linear-gradient(180deg,#f9fafbb3,#fff);border-radius:14px;padding:12px;min-height:120px;display:flex;flex-direction:column;gap:10px;border:1px solid rgba(226,232,240,.7);position:relative;transition:border .15s ease-in-out,box-shadow .15s ease-in-out}.day-cell--muted{opacity:.55}.day-cell--today{border-color:var(--today-bg);box-shadow:0 0 0 2px var(--today-ring)}.day-cell__header{display:flex;justify-content:space-between;align-items:center;font-size:14px}.day-cell__number{font-weight:600}.day-cell__count{font-size:12px;background:#0f172a14;color:var(--text-secondary);border-radius:999px;padding:2px 6px}.day-cell__events{display:flex;flex-direction:column;gap:8px}.event-chip{border:none;border-radius:var(--chip-radius);padding:8px 10px;text-align:left;cursor:pointer;transition:transform .15s ease-in-out,box-shadow .15s ease-in-out;box-shadow:0 10px 22px -18px #0f172abf}.event-chip:hover,.event-chip:focus-visible{transform:translateY(-1px);box-shadow:0 14px 30px -20px #0f172acc}.event-chip__title{display:block;font-size:14px;font-weight:600;margin-bottom:2px}.event-chip__time{display:block;font-size:13px;opacity:.9}.event-panel__portal{position:fixed;top:0;right:0;bottom:0;left:0;display:flex;justify-content:flex-end;align-items:stretch;z-index:1000}.event-panel__backdrop{flex:1;background:var(--backdrop);-webkit-backdrop-filter:blur(2px);backdrop-filter:blur(2px);animation:fadeIn .22s ease}.event-panel{width:min(420px,90vw);background:#fff;padding:32px;box-shadow:-18px 0 30px -24px #0f172a59;display:flex;flex-direction:column;gap:24px;overflow-y:auto;animation:slideIn .28s ease-out}.event-panel__header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.event-panel__header h2{margin:0;font-size:24px}.event-panel__close{background:none;border:none;font-size:32px;line-height:1;cursor:pointer;color:var(--text-secondary);padding:0;border-radius:8px;transition:background .15s ease}.event-panel__close:hover,.event-panel__close:focus-visible{background:#94a3b829}.event-panel__meta{display:flex;flex-wrap:wrap;gap:12px;align-items:center;font-size:15px;color:var(--text-secondary)}.event-panel__badge{border-radius:999px;padding:6px 12px;font-weight:600;font-size:13px}.event-panel__time{font-weight:500}.event-panel__description{margin:0;font-size:16px;line-height:1.6;color:var(--text-primary)}.event-panel__details{margin:0;display:grid;gap:16px;font-size:15px}.event-panel__details div{display:grid;gap:4px}.event-panel__details dt{font-weight:600;color:var(--text-secondary)}.event-panel__details dd{margin:0}.event-panel__footnote{margin:0;font-size:13px;color:var(--text-secondary)}.auth-card{background:var(--card-bg);box-shadow:var(--shadow-soft);border-radius:var(--card-radius);padding:32px;max-width:420px;width:100%;display:flex;flex-direction:column;gap:20px}.auth-card__title{margin:0;font-size:clamp(26px,3vw,32px);font-weight:600}.auth-card__intro{margin:0;color:var(--text-secondary);line-height:1.5}.auth-card__footer{margin:0;font-size:14px;color:var(--text-secondary)}.auth-card__footer--stack{display:flex;flex-direction:column;gap:6px}.auth-card__mock-code{margin:0;font-size:14px;background:#1f2937;color:#fff;border-radius:12px;padding:10px 14px;align-self:flex-start}.auth-card__mock-code span{font-weight:600;letter-spacing:.24em}.auth-form{display:flex;flex-direction:column;gap:16px}.auth-form__field{display:flex;flex-direction:column;gap:6px;font-size:14px;color:var(--text-secondary)}.auth-form__field input{border:1px solid rgba(148,163,184,.5);border-radius:10px;padding:12px 14px;font-size:16px;transition:border .12s ease,box-shadow .12s ease}.auth-form__field input:focus-visible{border-color:var(--accent);box-shadow:0 0 0 3px #2563eb2e;outline:none}.auth-form__message{margin:0;font-size:14px;padding:10px 12px;border-radius:10px}.auth-form__message--error{background:#ef44441f;color:#b91c1c}.auth-form__message--success{background:#10b9811f;color:#047857}.auth-form__submit{border:none;background:var(--accent);color:#fff;border-radius:12px;padding:12px 16px;font-size:16px;font-weight:600;cursor:pointer;transition:transform .12s ease,box-shadow .12s ease}.auth-form__submit:hover,.auth-form__submit:focus-visible{transform:translateY(-1px);box-shadow:0 16px 44px -22px #2563eb99}.auth-form__submit:disabled{opacity:.7;cursor:wait;transform:none;box-shadow:none}.auth-form__submit--link{display:inline-flex;align-items:center;justify-content:center;gap:6px;background:#2563eb14;color:var(--accent);text-decoration:none;font-weight:600;padding:11px 16px;border-radius:12px;transition:background .12s ease}.auth-form__submit--link:hover,.auth-form__submit--link:focus-visible{background:#2563eb29}.auth-link{color:var(--accent);font-weight:600;text-decoration:none}.auth-link:hover,.auth-link:focus-visible{text-decoration:underline}@keyframes slideIn{0%{transform:translate(40px);opacity:0}to{transform:translate(0);opacity:1}}@keyframes fadeIn{0%{opacity:0}to{opacity:1}}@media (max-width: 960px){.app-shell{padding:32px 20px 48px}.app-header{flex-direction:column;align-items:flex-start}.app-main{padding:0}}@media (max-width: 680px){.calendar-card{padding:20px}.calendar-grid{gap:6px}.day-cell{padding:10px}}


File: frontend\dist\assets\index-oDZKR0nZ.js
function tf(e,t){for(var n=0;n<t.length;n++){const r=t[n];if(typeof r!="string"&&!Array.isArray(r)){for(const l in r)if(l!=="default"&&!(l in e)){const o=Object.getOwnPropertyDescriptor(r,l);o&&Object.defineProperty(e,l,o.get?o:{enumerable:!0,get:()=>r[l]})}}}return Object.freeze(Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}))}(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const l of document.querySelectorAll('link[rel="modulepreload"]'))r(l);new MutationObserver(l=>{for(const o of l)if(o.type==="childList")for(const i of o.addedNodes)i.tagName==="LINK"&&i.rel==="modulepreload"&&r(i)}).observe(document,{childList:!0,subtree:!0});function n(l){const o={};return l.integrity&&(o.integrity=l.integrity),l.referrerPolicy&&(o.referrerPolicy=l.referrerPolicy),l.crossOrigin==="use-credentials"?o.credentials="include":l.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function r(l){if(l.ep)return;l.ep=!0;const o=n(l);fetch(l.href,o)}})();function nf(e){return e&&e.__esModule&&Object.prototype.hasOwnProperty.call(e,"default")?e.default:e}var Ta={exports:{}},yl={},La={exports:{}},z={};/**
 * @license React
 * react.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var sr=Symbol.for("react.element"),rf=Symbol.for("react.portal"),lf=Symbol.for("react.fragment"),of=Symbol.for("react.strict_mode"),uf=Symbol.for("react.profiler"),af=Symbol.for("react.provider"),sf=Symbol.for("react.context"),cf=Symbol.for("react.forward_ref"),ff=Symbol.for("react.suspense"),df=Symbol.for("react.memo"),pf=Symbol.for("react.lazy"),fu=Symbol.iterator;function hf(e){return e===null||typeof e!="object"?null:(e=fu&&e[fu]||e["@@iterator"],typeof e=="function"?e:null)}var Ra={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},za=Object.assign,Oa={};function mn(e,t,n){this.props=e,this.context=t,this.refs=Oa,this.updater=n||Ra}mn.prototype.isReactComponent={};mn.prototype.setState=function(e,t){if(typeof e!="object"&&typeof e!="function"&&e!=null)throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,e,t,"setState")};mn.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")};function Ma(){}Ma.prototype=mn.prototype;function ci(e,t,n){this.props=e,this.context=t,this.refs=Oa,this.updater=n||Ra}var fi=ci.prototype=new Ma;fi.constructor=ci;za(fi,mn.prototype);fi.isPureReactComponent=!0;var du=Array.isArray,Da=Object.prototype.hasOwnProperty,di={current:null},Fa={key:!0,ref:!0,__self:!0,__source:!0};function Ia(e,t,n){var r,l={},o=null,i=null;if(t!=null)for(r in t.ref!==void 0&&(i=t.ref),t.key!==void 0&&(o=""+t.key),t)Da.call(t,r)&&!Fa.hasOwnProperty(r)&&(l[r]=t[r]);var u=arguments.length-2;if(u===1)l.children=n;else if(1<u){for(var a=Array(u),s=0;s<u;s++)a[s]=arguments[s+2];l.children=a}if(e&&e.defaultProps)for(r in u=e.defaultProps,u)l[r]===void 0&&(l[r]=u[r]);return{$$typeof:sr,type:e,key:o,ref:i,props:l,_owner:di.current}}function mf(e,t){return{$$typeof:sr,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}function pi(e){return typeof e=="object"&&e!==null&&e.$$typeof===sr}function vf(e){var t={"=":"=0",":":"=2"};return"$"+e.replace(/[=:]/g,function(n){return t[n]})}var pu=/\/+/g;function Ul(e,t){return typeof e=="object"&&e!==null&&e.key!=null?vf(""+e.key):t.toString(36)}function Dr(e,t,n,r,l){var o=typeof e;(o==="undefined"||o==="boolean")&&(e=null);var i=!1;if(e===null)i=!0;else switch(o){case"string":case"number":i=!0;break;case"object":switch(e.$$typeof){case sr:case rf:i=!0}}if(i)return i=e,l=l(i),e=r===""?"."+Ul(i,0):r,du(l)?(n="",e!=null&&(n=e.replace(pu,"$&/")+"/"),Dr(l,t,n,"",function(s){return s})):l!=null&&(pi(l)&&(l=mf(l,n+(!l.key||i&&i.key===l.key?"":(""+l.key).replace(pu,"$&/")+"/")+e)),t.push(l)),1;if(i=0,r=r===""?".":r+":",du(e))for(var u=0;u<e.length;u++){o=e[u];var a=r+Ul(o,u);i+=Dr(o,t,n,a,l)}else if(a=hf(e),typeof a=="function")for(e=a.call(e),u=0;!(o=e.next()).done;)o=o.value,a=r+Ul(o,u++),i+=Dr(o,t,n,a,l);else if(o==="object")throw t=String(e),Error("Objects are not valid as a React child (found: "+(t==="[object Object]"?"object with keys {"+Object.keys(e).join(", ")+"}":t)+"). If you meant to render a collection of children, use an array instead.");return i}function gr(e,t,n){if(e==null)return e;var r=[],l=0;return Dr(e,r,"","",function(o){return t.call(n,o,l++)}),r}function gf(e){if(e._status===-1){var t=e._result;t=t(),t.then(function(n){(e._status===0||e._status===-1)&&(e._status=1,e._result=n)},function(n){(e._status===0||e._status===-1)&&(e._status=2,e._result=n)}),e._status===-1&&(e._status=0,e._result=t)}if(e._status===1)return e._result.default;throw e._result}var se={current:null},Fr={transition:null},yf={ReactCurrentDispatcher:se,ReactCurrentBatchConfig:Fr,ReactCurrentOwner:di};function Ua(){throw Error("act(...) is not supported in production builds of React.")}z.Children={map:gr,forEach:function(e,t,n){gr(e,function(){t.apply(this,arguments)},n)},count:function(e){var t=0;return gr(e,function(){t++}),t},toArray:function(e){return gr(e,function(t){return t})||[]},only:function(e){if(!pi(e))throw Error("React.Children.only expected to receive a single React element child.");return e}};z.Component=mn;z.Fragment=lf;z.Profiler=uf;z.PureComponent=ci;z.StrictMode=of;z.Suspense=ff;z.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=yf;z.act=Ua;z.cloneElement=function(e,t,n){if(e==null)throw Error("React.cloneElement(...): The argument must be a React element, but you passed "+e+".");var r=za({},e.props),l=e.key,o=e.ref,i=e._owner;if(t!=null){if(t.ref!==void 0&&(o=t.ref,i=di.current),t.key!==void 0&&(l=""+t.key),e.type&&e.type.defaultProps)var u=e.type.defaultProps;for(a in t)Da.call(t,a)&&!Fa.hasOwnProperty(a)&&(r[a]=t[a]===void 0&&u!==void 0?u[a]:t[a])}var a=arguments.length-2;if(a===1)r.children=n;else if(1<a){u=Array(a);for(var s=0;s<a;s++)u[s]=arguments[s+2];r.children=u}return{$$typeof:sr,type:e.type,key:l,ref:o,props:r,_owner:i}};z.createContext=function(e){return e={$$typeof:sf,_currentValue:e,_currentValue2:e,_threadCount:0,Provider:null,Consumer:null,_defaultValue:null,_globalName:null},e.Provider={$$typeof:af,_context:e},e.Consumer=e};z.createElement=Ia;z.createFactory=function(e){var t=Ia.bind(null,e);return t.type=e,t};z.createRef=function(){return{current:null}};z.forwardRef=function(e){return{$$typeof:cf,render:e}};z.isValidElement=pi;z.lazy=function(e){return{$$typeof:pf,_payload:{_status:-1,_result:e},_init:gf}};z.memo=function(e,t){return{$$typeof:df,type:e,compare:t===void 0?null:t}};z.startTransition=function(e){var t=Fr.transition;Fr.transition={};try{e()}finally{Fr.transition=t}};z.unstable_act=Ua;z.useCallback=function(e,t){return se.current.useCallback(e,t)};z.useContext=function(e){return se.current.useContext(e)};z.useDebugValue=function(){};z.useDeferredValue=function(e){return se.current.useDeferredValue(e)};z.useEffect=function(e,t){return se.current.useEffect(e,t)};z.useId=function(){return se.current.useId()};z.useImperativeHandle=function(e,t,n){return se.current.useImperativeHandle(e,t,n)};z.useInsertionEffect=function(e,t){return se.current.useInsertionEffect(e,t)};z.useLayoutEffect=function(e,t){return se.current.useLayoutEffect(e,t)};z.useMemo=function(e,t){return se.current.useMemo(e,t)};z.useReducer=function(e,t,n){return se.current.useReducer(e,t,n)};z.useRef=function(e){return se.current.useRef(e)};z.useState=function(e){return se.current.useState(e)};z.useSyncExternalStore=function(e,t,n){return se.current.useSyncExternalStore(e,t,n)};z.useTransition=function(){return se.current.useTransition()};z.version="18.3.1";La.exports=z;var y=La.exports;const hi=nf(y),wf=tf({__proto__:null,default:hi},[y]);/**
 * @license React
 * react-jsx-runtime.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var Sf=y,kf=Symbol.for("react.element"),xf=Symbol.for("react.fragment"),_f=Object.prototype.hasOwnProperty,Ef=Sf.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,Cf={key:!0,ref:!0,__self:!0,__source:!0};function Aa(e,t,n){var r,l={},o=null,i=null;n!==void 0&&(o=""+n),t.key!==void 0&&(o=""+t.key),t.ref!==void 0&&(i=t.ref);for(r in t)_f.call(t,r)&&!Cf.hasOwnProperty(r)&&(l[r]=t[r]);if(e&&e.defaultProps)for(r in t=e.defaultProps,t)l[r]===void 0&&(l[r]=t[r]);return{$$typeof:kf,type:e,key:o,ref:i,props:l,_owner:Ef.current}}yl.Fragment=xf;yl.jsx=Aa;yl.jsxs=Aa;Ta.exports=yl;var v=Ta.exports,fo={},$a={exports:{}},Se={},Ba={exports:{}},Va={};/**
 * @license React
 * scheduler.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */(function(e){function t(N,L){var R=N.length;N.push(L);e:for(;0<R;){var Q=R-1>>>1,Z=N[Q];if(0<l(Z,L))N[Q]=L,N[R]=Z,R=Q;else break e}}function n(N){return N.length===0?null:N[0]}function r(N){if(N.length===0)return null;var L=N[0],R=N.pop();if(R!==L){N[0]=R;e:for(var Q=0,Z=N.length,mr=Z>>>1;Q<mr;){var _t=2*(Q+1)-1,Il=N[_t],Et=_t+1,vr=N[Et];if(0>l(Il,R))Et<Z&&0>l(vr,Il)?(N[Q]=vr,N[Et]=R,Q=Et):(N[Q]=Il,N[_t]=R,Q=_t);else if(Et<Z&&0>l(vr,R))N[Q]=vr,N[Et]=R,Q=Et;else break e}}return L}function l(N,L){var R=N.sortIndex-L.sortIndex;return R!==0?R:N.id-L.id}if(typeof performance=="object"&&typeof performance.now=="function"){var o=performance;e.unstable_now=function(){return o.now()}}else{var i=Date,u=i.now();e.unstable_now=function(){return i.now()-u}}var a=[],s=[],h=1,d=null,m=3,w=!1,S=!1,g=!1,x=typeof setTimeout=="function"?setTimeout:null,f=typeof clearTimeout=="function"?clearTimeout:null,c=typeof setImmediate<"u"?setImmediate:null;typeof navigator<"u"&&navigator.scheduling!==void 0&&navigator.scheduling.isInputPending!==void 0&&navigator.scheduling.isInputPending.bind(navigator.scheduling);function p(N){for(var L=n(s);L!==null;){if(L.callback===null)r(s);else if(L.startTime<=N)r(s),L.sortIndex=L.expirationTime,t(a,L);else break;L=n(s)}}function k(N){if(g=!1,p(N),!S)if(n(a)!==null)S=!0,Dl(E);else{var L=n(s);L!==null&&Fl(k,L.startTime-N)}}function E(N,L){S=!1,g&&(g=!1,f(T),T=-1),w=!0;var R=m;try{for(p(L),d=n(a);d!==null&&(!(d.expirationTime>L)||N&&!je());){var Q=d.callback;if(typeof Q=="function"){d.callback=null,m=d.priorityLevel;var Z=Q(d.expirationTime<=L);L=e.unstable_now(),typeof Z=="function"?d.callback=Z:d===n(a)&&r(a),p(L)}else r(a);d=n(a)}if(d!==null)var mr=!0;else{var _t=n(s);_t!==null&&Fl(k,_t.startTime-L),mr=!1}return mr}finally{d=null,m=R,w=!1}}var P=!1,j=null,T=-1,H=5,O=-1;function je(){return!(e.unstable_now()-O<H)}function kn(){if(j!==null){var N=e.unstable_now();O=N;var L=!0;try{L=j(!0,N)}finally{L?xn():(P=!1,j=null)}}else P=!1}var xn;if(typeof c=="function")xn=function(){c(kn)};else if(typeof MessageChannel<"u"){var cu=new MessageChannel,ef=cu.port2;cu.port1.onmessage=kn,xn=function(){ef.postMessage(null)}}else xn=function(){x(kn,0)};function Dl(N){j=N,P||(P=!0,xn())}function Fl(N,L){T=x(function(){N(e.unstable_now())},L)}e.unstable_IdlePriority=5,e.unstable_ImmediatePriority=1,e.unstable_LowPriority=4,e.unstable_NormalPriority=3,e.unstable_Profiling=null,e.unstable_UserBlockingPriority=2,e.unstable_cancelCallback=function(N){N.callback=null},e.unstable_continueExecution=function(){S||w||(S=!0,Dl(E))},e.unstable_forceFrameRate=function(N){0>N||125<N?console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported"):H=0<N?Math.floor(1e3/N):5},e.unstable_getCurrentPriorityLevel=function(){return m},e.unstable_getFirstCallbackNode=function(){return n(a)},e.unstable_next=function(N){switch(m){case 1:case 2:case 3:var L=3;break;default:L=m}var R=m;m=L;try{return N()}finally{m=R}},e.unstable_pauseExecution=function(){},e.unstable_requestPaint=function(){},e.unstable_runWithPriority=function(N,L){switch(N){case 1:case 2:case 3:case 4:case 5:break;default:N=3}var R=m;m=N;try{return L()}finally{m=R}},e.unstable_scheduleCallback=function(N,L,R){var Q=e.unstable_now();switch(typeof R=="object"&&R!==null?(R=R.delay,R=typeof R=="number"&&0<R?Q+R:Q):R=Q,N){case 1:var Z=-1;break;case 2:Z=250;break;case 5:Z=1073741823;break;case 4:Z=1e4;break;default:Z=5e3}return Z=R+Z,N={id:h++,callback:L,priorityLevel:N,startTime:R,expirationTime:Z,sortIndex:-1},R>Q?(N.sortIndex=R,t(s,N),n(a)===null&&N===n(s)&&(g?(f(T),T=-1):g=!0,Fl(k,R-Q))):(N.sortIndex=Z,t(a,N),S||w||(S=!0,Dl(E))),N},e.unstable_shouldYield=je,e.unstable_wrapCallback=function(N){var L=m;return function(){var R=m;m=L;try{return N.apply(this,arguments)}finally{m=R}}}})(Va);Ba.exports=Va;var Nf=Ba.exports;/**
 * @license React
 * react-dom.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var Pf=y,we=Nf;function _(e){for(var t="https://reactjs.org/docs/error-decoder.html?invariant="+e,n=1;n<arguments.length;n++)t+="&args[]="+encodeURIComponent(arguments[n]);return"Minified React error #"+e+"; visit "+t+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}var Wa=new Set,Hn={};function At(e,t){an(e,t),an(e+"Capture",t)}function an(e,t){for(Hn[e]=t,e=0;e<t.length;e++)Wa.add(t[e])}var Ye=!(typeof window>"u"||typeof window.document>"u"||typeof window.document.createElement>"u"),po=Object.prototype.hasOwnProperty,jf=/^[:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD][:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\-.0-9\u00B7\u0300-\u036F\u203F-\u2040]*$/,hu={},mu={};function Tf(e){return po.call(mu,e)?!0:po.call(hu,e)?!1:jf.test(e)?mu[e]=!0:(hu[e]=!0,!1)}function Lf(e,t,n,r){if(n!==null&&n.type===0)return!1;switch(typeof t){case"function":case"symbol":return!0;case"boolean":return r?!1:n!==null?!n.acceptsBooleans:(e=e.toLowerCase().slice(0,5),e!=="data-"&&e!=="aria-");default:return!1}}function Rf(e,t,n,r){if(t===null||typeof t>"u"||Lf(e,t,n,r))return!0;if(r)return!1;if(n!==null)switch(n.type){case 3:return!t;case 4:return t===!1;case 5:return isNaN(t);case 6:return isNaN(t)||1>t}return!1}function ce(e,t,n,r,l,o,i){this.acceptsBooleans=t===2||t===3||t===4,this.attributeName=r,this.attributeNamespace=l,this.mustUseProperty=n,this.propertyName=e,this.type=t,this.sanitizeURL=o,this.removeEmptyString=i}var ne={};"children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML suppressContentEditableWarning suppressHydrationWarning style".split(" ").forEach(function(e){ne[e]=new ce(e,0,!1,e,null,!1,!1)});[["acceptCharset","accept-charset"],["className","class"],["htmlFor","for"],["httpEquiv","http-equiv"]].forEach(function(e){var t=e[0];ne[t]=new ce(t,1,!1,e[1],null,!1,!1)});["contentEditable","draggable","spellCheck","value"].forEach(function(e){ne[e]=new ce(e,2,!1,e.toLowerCase(),null,!1,!1)});["autoReverse","externalResourcesRequired","focusable","preserveAlpha"].forEach(function(e){ne[e]=new ce(e,2,!1,e,null,!1,!1)});"allowFullScreen async autoFocus autoPlay controls default defer disabled disablePictureInPicture disableRemotePlayback formNoValidate hidden loop noModule noValidate open playsInline readOnly required reversed scoped seamless itemScope".split(" ").forEach(function(e){ne[e]=new ce(e,3,!1,e.toLowerCase(),null,!1,!1)});["checked","multiple","muted","selected"].forEach(function(e){ne[e]=new ce(e,3,!0,e,null,!1,!1)});["capture","download"].forEach(function(e){ne[e]=new ce(e,4,!1,e,null,!1,!1)});["cols","rows","size","span"].forEach(function(e){ne[e]=new ce(e,6,!1,e,null,!1,!1)});["rowSpan","start"].forEach(function(e){ne[e]=new ce(e,5,!1,e.toLowerCase(),null,!1,!1)});var mi=/[\-:]([a-z])/g;function vi(e){return e[1].toUpperCase()}"accent-height alignment-baseline arabic-form baseline-shift cap-height clip-path clip-rule color-interpolation color-interpolation-filters color-profile color-rendering dominant-baseline enable-background fill-opacity fill-rule flood-color flood-opacity font-family font-size font-size-adjust font-stretch font-style font-variant font-weight glyph-name glyph-orientation-horizontal glyph-orientation-vertical horiz-adv-x horiz-origin-x image-rendering letter-spacing lighting-color marker-end marker-mid marker-start overline-position overline-thickness paint-order panose-1 pointer-events rendering-intent shape-rendering stop-color stop-opacity strikethrough-position strikethrough-thickness stroke-dasharray stroke-dashoffset stroke-linecap stroke-linejoin stroke-miterlimit stroke-opacity stroke-width text-anchor text-decoration text-rendering underline-position underline-thickness unicode-bidi unicode-range units-per-em v-alphabetic v-hanging v-ideographic v-mathematical vector-effect vert-adv-y vert-origin-x vert-origin-y word-spacing writing-mode xmlns:xlink x-height".split(" ").forEach(function(e){var t=e.replace(mi,vi);ne[t]=new ce(t,1,!1,e,null,!1,!1)});"xlink:actuate xlink:arcrole xlink:role xlink:show xlink:title xlink:type".split(" ").forEach(function(e){var t=e.replace(mi,vi);ne[t]=new ce(t,1,!1,e,"http://www.w3.org/1999/xlink",!1,!1)});["xml:base","xml:lang","xml:space"].forEach(function(e){var t=e.replace(mi,vi);ne[t]=new ce(t,1,!1,e,"http://www.w3.org/XML/1998/namespace",!1,!1)});["tabIndex","crossOrigin"].forEach(function(e){ne[e]=new ce(e,1,!1,e.toLowerCase(),null,!1,!1)});ne.xlinkHref=new ce("xlinkHref",1,!1,"xlink:href","http://www.w3.org/1999/xlink",!0,!1);["src","href","action","formAction"].forEach(function(e){ne[e]=new ce(e,1,!1,e.toLowerCase(),null,!0,!0)});function gi(e,t,n,r){var l=ne.hasOwnProperty(t)?ne[t]:null;(l!==null?l.type!==0:r||!(2<t.length)||t[0]!=="o"&&t[0]!=="O"||t[1]!=="n"&&t[1]!=="N")&&(Rf(t,n,l,r)&&(n=null),r||l===null?Tf(t)&&(n===null?e.removeAttribute(t):e.setAttribute(t,""+n)):l.mustUseProperty?e[l.propertyName]=n===null?l.type===3?!1:"":n:(t=l.attributeName,r=l.attributeNamespace,n===null?e.removeAttribute(t):(l=l.type,n=l===3||l===4&&n===!0?"":""+n,r?e.setAttributeNS(r,t,n):e.setAttribute(t,n))))}var Ze=Pf.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED,yr=Symbol.for("react.element"),Wt=Symbol.for("react.portal"),Ht=Symbol.for("react.fragment"),yi=Symbol.for("react.strict_mode"),ho=Symbol.for("react.profiler"),Ha=Symbol.for("react.provider"),Qa=Symbol.for("react.context"),wi=Symbol.for("react.forward_ref"),mo=Symbol.for("react.suspense"),vo=Symbol.for("react.suspense_list"),Si=Symbol.for("react.memo"),tt=Symbol.for("react.lazy"),Ka=Symbol.for("react.offscreen"),vu=Symbol.iterator;function _n(e){return e===null||typeof e!="object"?null:(e=vu&&e[vu]||e["@@iterator"],typeof e=="function"?e:null)}var V=Object.assign,Al;function Rn(e){if(Al===void 0)try{throw Error()}catch(n){var t=n.stack.trim().match(/\n( *(at )?)/);Al=t&&t[1]||""}return`
`+Al+e}var $l=!1;function Bl(e,t){if(!e||$l)return"";$l=!0;var n=Error.prepareStackTrace;Error.prepareStackTrace=void 0;try{if(t)if(t=function(){throw Error()},Object.defineProperty(t.prototype,"props",{set:function(){throw Error()}}),typeof Reflect=="object"&&Reflect.construct){try{Reflect.construct(t,[])}catch(s){var r=s}Reflect.construct(e,[],t)}else{try{t.call()}catch(s){r=s}e.call(t.prototype)}else{try{throw Error()}catch(s){r=s}e()}}catch(s){if(s&&r&&typeof s.stack=="string"){for(var l=s.stack.split(`
`),o=r.stack.split(`
`),i=l.length-1,u=o.length-1;1<=i&&0<=u&&l[i]!==o[u];)u--;for(;1<=i&&0<=u;i--,u--)if(l[i]!==o[u]){if(i!==1||u!==1)do if(i--,u--,0>u||l[i]!==o[u]){var a=`
`+l[i].replace(" at new "," at ");return e.displayName&&a.includes("<anonymous>")&&(a=a.replace("<anonymous>",e.displayName)),a}while(1<=i&&0<=u);break}}}finally{$l=!1,Error.prepareStackTrace=n}return(e=e?e.displayName||e.name:"")?Rn(e):""}function zf(e){switch(e.tag){case 5:return Rn(e.type);case 16:return Rn("Lazy");case 13:return Rn("Suspense");case 19:return Rn("SuspenseList");case 0:case 2:case 15:return e=Bl(e.type,!1),e;case 11:return e=Bl(e.type.render,!1),e;case 1:return e=Bl(e.type,!0),e;default:return""}}function go(e){if(e==null)return null;if(typeof e=="function")return e.displayName||e.name||null;if(typeof e=="string")return e;switch(e){case Ht:return"Fragment";case Wt:return"Portal";case ho:return"Profiler";case yi:return"StrictMode";case mo:return"Suspense";case vo:return"SuspenseList"}if(typeof e=="object")switch(e.$$typeof){case Qa:return(e.displayName||"Context")+".Consumer";case Ha:return(e._context.displayName||"Context")+".Provider";case wi:var t=e.render;return e=e.displayName,e||(e=t.displayName||t.name||"",e=e!==""?"ForwardRef("+e+")":"ForwardRef"),e;case Si:return t=e.displayName||null,t!==null?t:go(e.type)||"Memo";case tt:t=e._payload,e=e._init;try{return go(e(t))}catch{}}return null}function Of(e){var t=e.type;switch(e.tag){case 24:return"Cache";case 9:return(t.displayName||"Context")+".Consumer";case 10:return(t._context.displayName||"Context")+".Provider";case 18:return"DehydratedFragment";case 11:return e=t.render,e=e.displayName||e.name||"",t.displayName||(e!==""?"ForwardRef("+e+")":"ForwardRef");case 7:return"Fragment";case 5:return t;case 4:return"Portal";case 3:return"Root";case 6:return"Text";case 16:return go(t);case 8:return t===yi?"StrictMode":"Mode";case 22:return"Offscreen";case 12:return"Profiler";case 21:return"Scope";case 13:return"Suspense";case 19:return"SuspenseList";case 25:return"TracingMarker";case 1:case 0:case 17:case 2:case 14:case 15:if(typeof t=="function")return t.displayName||t.name||null;if(typeof t=="string")return t}return null}function gt(e){switch(typeof e){case"boolean":case"number":case"string":case"undefined":return e;case"object":return e;default:return""}}function Ya(e){var t=e.type;return(e=e.nodeName)&&e.toLowerCase()==="input"&&(t==="checkbox"||t==="radio")}function Mf(e){var t=Ya(e)?"checked":"value",n=Object.getOwnPropertyDescriptor(e.constructor.prototype,t),r=""+e[t];if(!e.hasOwnProperty(t)&&typeof n<"u"&&typeof n.get=="function"&&typeof n.set=="function"){var l=n.get,o=n.set;return Object.defineProperty(e,t,{configurable:!0,get:function(){return l.call(this)},set:function(i){r=""+i,o.call(this,i)}}),Object.defineProperty(e,t,{enumerable:n.enumerable}),{getValue:function(){return r},setValue:function(i){r=""+i},stopTracking:function(){e._valueTracker=null,delete e[t]}}}}function wr(e){e._valueTracker||(e._valueTracker=Mf(e))}function Ga(e){if(!e)return!1;var t=e._valueTracker;if(!t)return!0;var n=t.getValue(),r="";return e&&(r=Ya(e)?e.checked?"true":"false":e.value),e=r,e!==n?(t.setValue(e),!0):!1}function Yr(e){if(e=e||(typeof document<"u"?document:void 0),typeof e>"u")return null;try{return e.activeElement||e.body}catch{return e.body}}function yo(e,t){var n=t.checked;return V({},t,{defaultChecked:void 0,defaultValue:void 0,value:void 0,checked:n??e._wrapperState.initialChecked})}function gu(e,t){var n=t.defaultValue==null?"":t.defaultValue,r=t.checked!=null?t.checked:t.defaultChecked;n=gt(t.value!=null?t.value:n),e._wrapperState={initialChecked:r,initialValue:n,controlled:t.type==="checkbox"||t.type==="radio"?t.checked!=null:t.value!=null}}function Xa(e,t){t=t.checked,t!=null&&gi(e,"checked",t,!1)}function wo(e,t){Xa(e,t);var n=gt(t.value),r=t.type;if(n!=null)r==="number"?(n===0&&e.value===""||e.value!=n)&&(e.value=""+n):e.value!==""+n&&(e.value=""+n);else if(r==="submit"||r==="reset"){e.removeAttribute("value");return}t.hasOwnProperty("value")?So(e,t.type,n):t.hasOwnProperty("defaultValue")&&So(e,t.type,gt(t.defaultValue)),t.checked==null&&t.defaultChecked!=null&&(e.defaultChecked=!!t.defaultChecked)}function yu(e,t,n){if(t.hasOwnProperty("value")||t.hasOwnProperty("defaultValue")){var r=t.type;if(!(r!=="submit"&&r!=="reset"||t.value!==void 0&&t.value!==null))return;t=""+e._wrapperState.initialValue,n||t===e.value||(e.value=t),e.defaultValue=t}n=e.name,n!==""&&(e.name=""),e.defaultChecked=!!e._wrapperState.initialChecked,n!==""&&(e.name=n)}function So(e,t,n){(t!=="number"||Yr(e.ownerDocument)!==e)&&(n==null?e.defaultValue=""+e._wrapperState.initialValue:e.defaultValue!==""+n&&(e.defaultValue=""+n))}var zn=Array.isArray;function tn(e,t,n,r){if(e=e.options,t){t={};for(var l=0;l<n.length;l++)t["$"+n[l]]=!0;for(n=0;n<e.length;n++)l=t.hasOwnProperty("$"+e[n].value),e[n].selected!==l&&(e[n].selected=l),l&&r&&(e[n].defaultSelected=!0)}else{for(n=""+gt(n),t=null,l=0;l<e.length;l++){if(e[l].value===n){e[l].selected=!0,r&&(e[l].defaultSelected=!0);return}t!==null||e[l].disabled||(t=e[l])}t!==null&&(t.selected=!0)}}function ko(e,t){if(t.dangerouslySetInnerHTML!=null)throw Error(_(91));return V({},t,{value:void 0,defaultValue:void 0,children:""+e._wrapperState.initialValue})}function wu(e,t){var n=t.value;if(n==null){if(n=t.children,t=t.defaultValue,n!=null){if(t!=null)throw Error(_(92));if(zn(n)){if(1<n.length)throw Error(_(93));n=n[0]}t=n}t==null&&(t=""),n=t}e._wrapperState={initialValue:gt(n)}}function Ja(e,t){var n=gt(t.value),r=gt(t.defaultValue);n!=null&&(n=""+n,n!==e.value&&(e.value=n),t.defaultValue==null&&e.defaultValue!==n&&(e.defaultValue=n)),r!=null&&(e.defaultValue=""+r)}function Su(e){var t=e.textContent;t===e._wrapperState.initialValue&&t!==""&&t!==null&&(e.value=t)}function Za(e){switch(e){case"svg":return"http://www.w3.org/2000/svg";case"math":return"http://www.w3.org/1998/Math/MathML";default:return"http://www.w3.org/1999/xhtml"}}function xo(e,t){return e==null||e==="http://www.w3.org/1999/xhtml"?Za(t):e==="http://www.w3.org/2000/svg"&&t==="foreignObject"?"http://www.w3.org/1999/xhtml":e}var Sr,qa=function(e){return typeof MSApp<"u"&&MSApp.execUnsafeLocalFunction?function(t,n,r,l){MSApp.execUnsafeLocalFunction(function(){return e(t,n,r,l)})}:e}(function(e,t){if(e.namespaceURI!=="http://www.w3.org/2000/svg"||"innerHTML"in e)e.innerHTML=t;else{for(Sr=Sr||document.createElement("div"),Sr.innerHTML="<svg>"+t.valueOf().toString()+"</svg>",t=Sr.firstChild;e.firstChild;)e.removeChild(e.firstChild);for(;t.firstChild;)e.appendChild(t.firstChild)}});function Qn(e,t){if(t){var n=e.firstChild;if(n&&n===e.lastChild&&n.nodeType===3){n.nodeValue=t;return}}e.textContent=t}var Dn={animationIterationCount:!0,aspectRatio:!0,borderImageOutset:!0,borderImageSlice:!0,borderImageWidth:!0,boxFlex:!0,boxFlexGroup:!0,boxOrdinalGroup:!0,columnCount:!0,columns:!0,flex:!0,flexGrow:!0,flexPositive:!0,flexShrink:!0,flexNegative:!0,flexOrder:!0,gridArea:!0,gridRow:!0,gridRowEnd:!0,gridRowSpan:!0,gridRowStart:!0,gridColumn:!0,gridColumnEnd:!0,gridColumnSpan:!0,gridColumnStart:!0,fontWeight:!0,lineClamp:!0,lineHeight:!0,opacity:!0,order:!0,orphans:!0,tabSize:!0,widows:!0,zIndex:!0,zoom:!0,fillOpacity:!0,floodOpacity:!0,stopOpacity:!0,strokeDasharray:!0,strokeDashoffset:!0,strokeMiterlimit:!0,strokeOpacity:!0,strokeWidth:!0},Df=["Webkit","ms","Moz","O"];Object.keys(Dn).forEach(function(e){Df.forEach(function(t){t=t+e.charAt(0).toUpperCase()+e.substring(1),Dn[t]=Dn[e]})});function ba(e,t,n){return t==null||typeof t=="boolean"||t===""?"":n||typeof t!="number"||t===0||Dn.hasOwnProperty(e)&&Dn[e]?(""+t).trim():t+"px"}function es(e,t){e=e.style;for(var n in t)if(t.hasOwnProperty(n)){var r=n.indexOf("--")===0,l=ba(n,t[n],r);n==="float"&&(n="cssFloat"),r?e.setProperty(n,l):e[n]=l}}var Ff=V({menuitem:!0},{area:!0,base:!0,br:!0,col:!0,embed:!0,hr:!0,img:!0,input:!0,keygen:!0,link:!0,meta:!0,param:!0,source:!0,track:!0,wbr:!0});function _o(e,t){if(t){if(Ff[e]&&(t.children!=null||t.dangerouslySetInnerHTML!=null))throw Error(_(137,e));if(t.dangerouslySetInnerHTML!=null){if(t.children!=null)throw Error(_(60));if(typeof t.dangerouslySetInnerHTML!="object"||!("__html"in t.dangerouslySetInnerHTML))throw Error(_(61))}if(t.style!=null&&typeof t.style!="object")throw Error(_(62))}}function Eo(e,t){if(e.indexOf("-")===-1)return typeof t.is=="string";switch(e){case"annotation-xml":case"color-profile":case"font-face":case"font-face-src":case"font-face-uri":case"font-face-format":case"font-face-name":case"missing-glyph":return!1;default:return!0}}var Co=null;function ki(e){return e=e.target||e.srcElement||window,e.correspondingUseElement&&(e=e.correspondingUseElement),e.nodeType===3?e.parentNode:e}var No=null,nn=null,rn=null;function ku(e){if(e=dr(e)){if(typeof No!="function")throw Error(_(280));var t=e.stateNode;t&&(t=_l(t),No(e.stateNode,e.type,t))}}function ts(e){nn?rn?rn.push(e):rn=[e]:nn=e}function ns(){if(nn){var e=nn,t=rn;if(rn=nn=null,ku(e),t)for(e=0;e<t.length;e++)ku(t[e])}}function rs(e,t){return e(t)}function ls(){}var Vl=!1;function os(e,t,n){if(Vl)return e(t,n);Vl=!0;try{return rs(e,t,n)}finally{Vl=!1,(nn!==null||rn!==null)&&(ls(),ns())}}function Kn(e,t){var n=e.stateNode;if(n===null)return null;var r=_l(n);if(r===null)return null;n=r[t];e:switch(t){case"onClick":case"onClickCapture":case"onDoubleClick":case"onDoubleClickCapture":case"onMouseDown":case"onMouseDownCapture":case"onMouseMove":case"onMouseMoveCapture":case"onMouseUp":case"onMouseUpCapture":case"onMouseEnter":(r=!r.disabled)||(e=e.type,r=!(e==="button"||e==="input"||e==="select"||e==="textarea")),e=!r;break e;default:e=!1}if(e)return null;if(n&&typeof n!="function")throw Error(_(231,t,typeof n));return n}var Po=!1;if(Ye)try{var En={};Object.defineProperty(En,"passive",{get:function(){Po=!0}}),window.addEventListener("test",En,En),window.removeEventListener("test",En,En)}catch{Po=!1}function If(e,t,n,r,l,o,i,u,a){var s=Array.prototype.slice.call(arguments,3);try{t.apply(n,s)}catch(h){this.onError(h)}}var Fn=!1,Gr=null,Xr=!1,jo=null,Uf={onError:function(e){Fn=!0,Gr=e}};function Af(e,t,n,r,l,o,i,u,a){Fn=!1,Gr=null,If.apply(Uf,arguments)}function $f(e,t,n,r,l,o,i,u,a){if(Af.apply(this,arguments),Fn){if(Fn){var s=Gr;Fn=!1,Gr=null}else throw Error(_(198));Xr||(Xr=!0,jo=s)}}function $t(e){var t=e,n=e;if(e.alternate)for(;t.return;)t=t.return;else{e=t;do t=e,t.flags&4098&&(n=t.return),e=t.return;while(e)}return t.tag===3?n:null}function is(e){if(e.tag===13){var t=e.memoizedState;if(t===null&&(e=e.alternate,e!==null&&(t=e.memoizedState)),t!==null)return t.dehydrated}return null}function xu(e){if($t(e)!==e)throw Error(_(188))}function Bf(e){var t=e.alternate;if(!t){if(t=$t(e),t===null)throw Error(_(188));return t!==e?null:e}for(var n=e,r=t;;){var l=n.return;if(l===null)break;var o=l.alternate;if(o===null){if(r=l.return,r!==null){n=r;continue}break}if(l.child===o.child){for(o=l.child;o;){if(o===n)return xu(l),e;if(o===r)return xu(l),t;o=o.sibling}throw Error(_(188))}if(n.return!==r.return)n=l,r=o;else{for(var i=!1,u=l.child;u;){if(u===n){i=!0,n=l,r=o;break}if(u===r){i=!0,r=l,n=o;break}u=u.sibling}if(!i){for(u=o.child;u;){if(u===n){i=!0,n=o,r=l;break}if(u===r){i=!0,r=o,n=l;break}u=u.sibling}if(!i)throw Error(_(189))}}if(n.alternate!==r)throw Error(_(190))}if(n.tag!==3)throw Error(_(188));return n.stateNode.current===n?e:t}function us(e){return e=Bf(e),e!==null?as(e):null}function as(e){if(e.tag===5||e.tag===6)return e;for(e=e.child;e!==null;){var t=as(e);if(t!==null)return t;e=e.sibling}return null}var ss=we.unstable_scheduleCallback,_u=we.unstable_cancelCallback,Vf=we.unstable_shouldYield,Wf=we.unstable_requestPaint,K=we.unstable_now,Hf=we.unstable_getCurrentPriorityLevel,xi=we.unstable_ImmediatePriority,cs=we.unstable_UserBlockingPriority,Jr=we.unstable_NormalPriority,Qf=we.unstable_LowPriority,fs=we.unstable_IdlePriority,wl=null,Ae=null;function Kf(e){if(Ae&&typeof Ae.onCommitFiberRoot=="function")try{Ae.onCommitFiberRoot(wl,e,void 0,(e.current.flags&128)===128)}catch{}}var Oe=Math.clz32?Math.clz32:Xf,Yf=Math.log,Gf=Math.LN2;function Xf(e){return e>>>=0,e===0?32:31-(Yf(e)/Gf|0)|0}var kr=64,xr=4194304;function On(e){switch(e&-e){case 1:return 1;case 2:return 2;case 4:return 4;case 8:return 8;case 16:return 16;case 32:return 32;case 64:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:return e&4194240;case 4194304:case 8388608:case 16777216:case 33554432:case 67108864:return e&130023424;case 134217728:return 134217728;case 268435456:return 268435456;case 536870912:return 536870912;case 1073741824:return 1073741824;default:return e}}function Zr(e,t){var n=e.pendingLanes;if(n===0)return 0;var r=0,l=e.suspendedLanes,o=e.pingedLanes,i=n&268435455;if(i!==0){var u=i&~l;u!==0?r=On(u):(o&=i,o!==0&&(r=On(o)))}else i=n&~l,i!==0?r=On(i):o!==0&&(r=On(o));if(r===0)return 0;if(t!==0&&t!==r&&!(t&l)&&(l=r&-r,o=t&-t,l>=o||l===16&&(o&4194240)!==0))return t;if(r&4&&(r|=n&16),t=e.entangledLanes,t!==0)for(e=e.entanglements,t&=r;0<t;)n=31-Oe(t),l=1<<n,r|=e[n],t&=~l;return r}function Jf(e,t){switch(e){case 1:case 2:case 4:return t+250;case 8:case 16:case 32:case 64:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:return t+5e3;case 4194304:case 8388608:case 16777216:case 33554432:case 67108864:return-1;case 134217728:case 268435456:case 536870912:case 1073741824:return-1;default:return-1}}function Zf(e,t){for(var n=e.suspendedLanes,r=e.pingedLanes,l=e.expirationTimes,o=e.pendingLanes;0<o;){var i=31-Oe(o),u=1<<i,a=l[i];a===-1?(!(u&n)||u&r)&&(l[i]=Jf(u,t)):a<=t&&(e.expiredLanes|=u),o&=~u}}function To(e){return e=e.pendingLanes&-1073741825,e!==0?e:e&1073741824?1073741824:0}function ds(){var e=kr;return kr<<=1,!(kr&4194240)&&(kr=64),e}function Wl(e){for(var t=[],n=0;31>n;n++)t.push(e);return t}function cr(e,t,n){e.pendingLanes|=t,t!==536870912&&(e.suspendedLanes=0,e.pingedLanes=0),e=e.eventTimes,t=31-Oe(t),e[t]=n}function qf(e,t){var n=e.pendingLanes&~t;e.pendingLanes=t,e.suspendedLanes=0,e.pingedLanes=0,e.expiredLanes&=t,e.mutableReadLanes&=t,e.entangledLanes&=t,t=e.entanglements;var r=e.eventTimes;for(e=e.expirationTimes;0<n;){var l=31-Oe(n),o=1<<l;t[l]=0,r[l]=-1,e[l]=-1,n&=~o}}function _i(e,t){var n=e.entangledLanes|=t;for(e=e.entanglements;n;){var r=31-Oe(n),l=1<<r;l&t|e[r]&t&&(e[r]|=t),n&=~l}}var D=0;function ps(e){return e&=-e,1<e?4<e?e&268435455?16:536870912:4:1}var hs,Ei,ms,vs,gs,Lo=!1,_r=[],at=null,st=null,ct=null,Yn=new Map,Gn=new Map,rt=[],bf="mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset submit".split(" ");function Eu(e,t){switch(e){case"focusin":case"focusout":at=null;break;case"dragenter":case"dragleave":st=null;break;case"mouseover":case"mouseout":ct=null;break;case"pointerover":case"pointerout":Yn.delete(t.pointerId);break;case"gotpointercapture":case"lostpointercapture":Gn.delete(t.pointerId)}}function Cn(e,t,n,r,l,o){return e===null||e.nativeEvent!==o?(e={blockedOn:t,domEventName:n,eventSystemFlags:r,nativeEvent:o,targetContainers:[l]},t!==null&&(t=dr(t),t!==null&&Ei(t)),e):(e.eventSystemFlags|=r,t=e.targetContainers,l!==null&&t.indexOf(l)===-1&&t.push(l),e)}function ed(e,t,n,r,l){switch(t){case"focusin":return at=Cn(at,e,t,n,r,l),!0;case"dragenter":return st=Cn(st,e,t,n,r,l),!0;case"mouseover":return ct=Cn(ct,e,t,n,r,l),!0;case"pointerover":var o=l.pointerId;return Yn.set(o,Cn(Yn.get(o)||null,e,t,n,r,l)),!0;case"gotpointercapture":return o=l.pointerId,Gn.set(o,Cn(Gn.get(o)||null,e,t,n,r,l)),!0}return!1}function ys(e){var t=Tt(e.target);if(t!==null){var n=$t(t);if(n!==null){if(t=n.tag,t===13){if(t=is(n),t!==null){e.blockedOn=t,gs(e.priority,function(){ms(n)});return}}else if(t===3&&n.stateNode.current.memoizedState.isDehydrated){e.blockedOn=n.tag===3?n.stateNode.containerInfo:null;return}}}e.blockedOn=null}function Ir(e){if(e.blockedOn!==null)return!1;for(var t=e.targetContainers;0<t.length;){var n=Ro(e.domEventName,e.eventSystemFlags,t[0],e.nativeEvent);if(n===null){n=e.nativeEvent;var r=new n.constructor(n.type,n);Co=r,n.target.dispatchEvent(r),Co=null}else return t=dr(n),t!==null&&Ei(t),e.blockedOn=n,!1;t.shift()}return!0}function Cu(e,t,n){Ir(e)&&n.delete(t)}function td(){Lo=!1,at!==null&&Ir(at)&&(at=null),st!==null&&Ir(st)&&(st=null),ct!==null&&Ir(ct)&&(ct=null),Yn.forEach(Cu),Gn.forEach(Cu)}function Nn(e,t){e.blockedOn===t&&(e.blockedOn=null,Lo||(Lo=!0,we.unstable_scheduleCallback(we.unstable_NormalPriority,td)))}function Xn(e){function t(l){return Nn(l,e)}if(0<_r.length){Nn(_r[0],e);for(var n=1;n<_r.length;n++){var r=_r[n];r.blockedOn===e&&(r.blockedOn=null)}}for(at!==null&&Nn(at,e),st!==null&&Nn(st,e),ct!==null&&Nn(ct,e),Yn.forEach(t),Gn.forEach(t),n=0;n<rt.length;n++)r=rt[n],r.blockedOn===e&&(r.blockedOn=null);for(;0<rt.length&&(n=rt[0],n.blockedOn===null);)ys(n),n.blockedOn===null&&rt.shift()}var ln=Ze.ReactCurrentBatchConfig,qr=!0;function nd(e,t,n,r){var l=D,o=ln.transition;ln.transition=null;try{D=1,Ci(e,t,n,r)}finally{D=l,ln.transition=o}}function rd(e,t,n,r){var l=D,o=ln.transition;ln.transition=null;try{D=4,Ci(e,t,n,r)}finally{D=l,ln.transition=o}}function Ci(e,t,n,r){if(qr){var l=Ro(e,t,n,r);if(l===null)bl(e,t,r,br,n),Eu(e,r);else if(ed(l,e,t,n,r))r.stopPropagation();else if(Eu(e,r),t&4&&-1<bf.indexOf(e)){for(;l!==null;){var o=dr(l);if(o!==null&&hs(o),o=Ro(e,t,n,r),o===null&&bl(e,t,r,br,n),o===l)break;l=o}l!==null&&r.stopPropagation()}else bl(e,t,r,null,n)}}var br=null;function Ro(e,t,n,r){if(br=null,e=ki(r),e=Tt(e),e!==null)if(t=$t(e),t===null)e=null;else if(n=t.tag,n===13){if(e=is(t),e!==null)return e;e=null}else if(n===3){if(t.stateNode.current.memoizedState.isDehydrated)return t.tag===3?t.stateNode.containerInfo:null;e=null}else t!==e&&(e=null);return br=e,null}function ws(e){switch(e){case"cancel":case"click":case"close":case"contextmenu":case"copy":case"cut":case"auxclick":case"dblclick":case"dragend":case"dragstart":case"drop":case"focusin":case"focusout":case"input":case"invalid":case"keydown":case"keypress":case"keyup":case"mousedown":case"mouseup":case"paste":case"pause":case"play":case"pointercancel":case"pointerdown":case"pointerup":case"ratechange":case"reset":case"resize":case"seeked":case"submit":case"touchcancel":case"touchend":case"touchstart":case"volumechange":case"change":case"selectionchange":case"textInput":case"compositionstart":case"compositionend":case"compositionupdate":case"beforeblur":case"afterblur":case"beforeinput":case"blur":case"fullscreenchange":case"focus":case"hashchange":case"popstate":case"select":case"selectstart":return 1;case"drag":case"dragenter":case"dragexit":case"dragleave":case"dragover":case"mousemove":case"mouseout":case"mouseover":case"pointermove":case"pointerout":case"pointerover":case"scroll":case"toggle":case"touchmove":case"wheel":case"mouseenter":case"mouseleave":case"pointerenter":case"pointerleave":return 4;case"message":switch(Hf()){case xi:return 1;case cs:return 4;case Jr:case Qf:return 16;case fs:return 536870912;default:return 16}default:return 16}}var ot=null,Ni=null,Ur=null;function Ss(){if(Ur)return Ur;var e,t=Ni,n=t.length,r,l="value"in ot?ot.value:ot.textContent,o=l.length;for(e=0;e<n&&t[e]===l[e];e++);var i=n-e;for(r=1;r<=i&&t[n-r]===l[o-r];r++);return Ur=l.slice(e,1<r?1-r:void 0)}function Ar(e){var t=e.keyCode;return"charCode"in e?(e=e.charCode,e===0&&t===13&&(e=13)):e=t,e===10&&(e=13),32<=e||e===13?e:0}function Er(){return!0}function Nu(){return!1}function ke(e){function t(n,r,l,o,i){this._reactName=n,this._targetInst=l,this.type=r,this.nativeEvent=o,this.target=i,this.currentTarget=null;for(var u in e)e.hasOwnProperty(u)&&(n=e[u],this[u]=n?n(o):o[u]);return this.isDefaultPrevented=(o.defaultPrevented!=null?o.defaultPrevented:o.returnValue===!1)?Er:Nu,this.isPropagationStopped=Nu,this}return V(t.prototype,{preventDefault:function(){this.defaultPrevented=!0;var n=this.nativeEvent;n&&(n.preventDefault?n.preventDefault():typeof n.returnValue!="unknown"&&(n.returnValue=!1),this.isDefaultPrevented=Er)},stopPropagation:function(){var n=this.nativeEvent;n&&(n.stopPropagation?n.stopPropagation():typeof n.cancelBubble!="unknown"&&(n.cancelBubble=!0),this.isPropagationStopped=Er)},persist:function(){},isPersistent:Er}),t}var vn={eventPhase:0,bubbles:0,cancelable:0,timeStamp:function(e){return e.timeStamp||Date.now()},defaultPrevented:0,isTrusted:0},Pi=ke(vn),fr=V({},vn,{view:0,detail:0}),ld=ke(fr),Hl,Ql,Pn,Sl=V({},fr,{screenX:0,screenY:0,clientX:0,clientY:0,pageX:0,pageY:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,getModifierState:ji,button:0,buttons:0,relatedTarget:function(e){return e.relatedTarget===void 0?e.fromElement===e.srcElement?e.toElement:e.fromElement:e.relatedTarget},movementX:function(e){return"movementX"in e?e.movementX:(e!==Pn&&(Pn&&e.type==="mousemove"?(Hl=e.screenX-Pn.screenX,Ql=e.screenY-Pn.screenY):Ql=Hl=0,Pn=e),Hl)},movementY:function(e){return"movementY"in e?e.movementY:Ql}}),Pu=ke(Sl),od=V({},Sl,{dataTransfer:0}),id=ke(od),ud=V({},fr,{relatedTarget:0}),Kl=ke(ud),ad=V({},vn,{animationName:0,elapsedTime:0,pseudoElement:0}),sd=ke(ad),cd=V({},vn,{clipboardData:function(e){return"clipboardData"in e?e.clipboardData:window.clipboardData}}),fd=ke(cd),dd=V({},vn,{data:0}),ju=ke(dd),pd={Esc:"Escape",Spacebar:" ",Left:"ArrowLeft",Up:"ArrowUp",Right:"ArrowRight",Down:"ArrowDown",Del:"Delete",Win:"OS",Menu:"ContextMenu",Apps:"ContextMenu",Scroll:"ScrollLock",MozPrintableKey:"Unidentified"},hd={8:"Backspace",9:"Tab",12:"Clear",13:"Enter",16:"Shift",17:"Control",18:"Alt",19:"Pause",20:"CapsLock",27:"Escape",32:" ",33:"PageUp",34:"PageDown",35:"End",36:"Home",37:"ArrowLeft",38:"ArrowUp",39:"ArrowRight",40:"ArrowDown",45:"Insert",46:"Delete",112:"F1",113:"F2",114:"F3",115:"F4",116:"F5",117:"F6",118:"F7",119:"F8",120:"F9",121:"F10",122:"F11",123:"F12",144:"NumLock",145:"ScrollLock",224:"Meta"},md={Alt:"altKey",Control:"ctrlKey",Meta:"metaKey",Shift:"shiftKey"};function vd(e){var t=this.nativeEvent;return t.getModifierState?t.getModifierState(e):(e=md[e])?!!t[e]:!1}function ji(){return vd}var gd=V({},fr,{key:function(e){if(e.key){var t=pd[e.key]||e.key;if(t!=="Unidentified")return t}return e.type==="keypress"?(e=Ar(e),e===13?"Enter":String.fromCharCode(e)):e.type==="keydown"||e.type==="keyup"?hd[e.keyCode]||"Unidentified":""},code:0,location:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,repeat:0,locale:0,getModifierState:ji,charCode:function(e){return e.type==="keypress"?Ar(e):0},keyCode:function(e){return e.type==="keydown"||e.type==="keyup"?e.keyCode:0},which:function(e){return e.type==="keypress"?Ar(e):e.type==="keydown"||e.type==="keyup"?e.keyCode:0}}),yd=ke(gd),wd=V({},Sl,{pointerId:0,width:0,height:0,pressure:0,tangentialPressure:0,tiltX:0,tiltY:0,twist:0,pointerType:0,isPrimary:0}),Tu=ke(wd),Sd=V({},fr,{touches:0,targetTouches:0,changedTouches:0,altKey:0,metaKey:0,ctrlKey:0,shiftKey:0,getModifierState:ji}),kd=ke(Sd),xd=V({},vn,{propertyName:0,elapsedTime:0,pseudoElement:0}),_d=ke(xd),Ed=V({},Sl,{deltaX:function(e){return"deltaX"in e?e.deltaX:"wheelDeltaX"in e?-e.wheelDeltaX:0},deltaY:function(e){return"deltaY"in e?e.deltaY:"wheelDeltaY"in e?-e.wheelDeltaY:"wheelDelta"in e?-e.wheelDelta:0},deltaZ:0,deltaMode:0}),Cd=ke(Ed),Nd=[9,13,27,32],Ti=Ye&&"CompositionEvent"in window,In=null;Ye&&"documentMode"in document&&(In=document.documentMode);var Pd=Ye&&"TextEvent"in window&&!In,ks=Ye&&(!Ti||In&&8<In&&11>=In),Lu=" ",Ru=!1;function xs(e,t){switch(e){case"keyup":return Nd.indexOf(t.keyCode)!==-1;case"keydown":return t.keyCode!==229;case"keypress":case"mousedown":case"focusout":return!0;default:return!1}}function _s(e){return e=e.detail,typeof e=="object"&&"data"in e?e.data:null}var Qt=!1;function jd(e,t){switch(e){case"compositionend":return _s(t);case"keypress":return t.which!==32?null:(Ru=!0,Lu);case"textInput":return e=t.data,e===Lu&&Ru?null:e;default:return null}}function Td(e,t){if(Qt)return e==="compositionend"||!Ti&&xs(e,t)?(e=Ss(),Ur=Ni=ot=null,Qt=!1,e):null;switch(e){case"paste":return null;case"keypress":if(!(t.ctrlKey||t.altKey||t.metaKey)||t.ctrlKey&&t.altKey){if(t.char&&1<t.char.length)return t.char;if(t.which)return String.fromCharCode(t.which)}return null;case"compositionend":return ks&&t.locale!=="ko"?null:t.data;default:return null}}var Ld={color:!0,date:!0,datetime:!0,"datetime-local":!0,email:!0,month:!0,number:!0,password:!0,range:!0,search:!0,tel:!0,text:!0,time:!0,url:!0,week:!0};function zu(e){var t=e&&e.nodeName&&e.nodeName.toLowerCase();return t==="input"?!!Ld[e.type]:t==="textarea"}function Es(e,t,n,r){ts(r),t=el(t,"onChange"),0<t.length&&(n=new Pi("onChange","change",null,n,r),e.push({event:n,listeners:t}))}var Un=null,Jn=null;function Rd(e){Ds(e,0)}function kl(e){var t=Gt(e);if(Ga(t))return e}function zd(e,t){if(e==="change")return t}var Cs=!1;if(Ye){var Yl;if(Ye){var Gl="oninput"in document;if(!Gl){var Ou=document.createElement("div");Ou.setAttribute("oninput","return;"),Gl=typeof Ou.oninput=="function"}Yl=Gl}else Yl=!1;Cs=Yl&&(!document.documentMode||9<document.documentMode)}function Mu(){Un&&(Un.detachEvent("onpropertychange",Ns),Jn=Un=null)}function Ns(e){if(e.propertyName==="value"&&kl(Jn)){var t=[];Es(t,Jn,e,ki(e)),os(Rd,t)}}function Od(e,t,n){e==="focusin"?(Mu(),Un=t,Jn=n,Un.attachEvent("onpropertychange",Ns)):e==="focusout"&&Mu()}function Md(e){if(e==="selectionchange"||e==="keyup"||e==="keydown")return kl(Jn)}function Dd(e,t){if(e==="click")return kl(t)}function Fd(e,t){if(e==="input"||e==="change")return kl(t)}function Id(e,t){return e===t&&(e!==0||1/e===1/t)||e!==e&&t!==t}var De=typeof Object.is=="function"?Object.is:Id;function Zn(e,t){if(De(e,t))return!0;if(typeof e!="object"||e===null||typeof t!="object"||t===null)return!1;var n=Object.keys(e),r=Object.keys(t);if(n.length!==r.length)return!1;for(r=0;r<n.length;r++){var l=n[r];if(!po.call(t,l)||!De(e[l],t[l]))return!1}return!0}function Du(e){for(;e&&e.firstChild;)e=e.firstChild;return e}function Fu(e,t){var n=Du(e);e=0;for(var r;n;){if(n.nodeType===3){if(r=e+n.textContent.length,e<=t&&r>=t)return{node:n,offset:t-e};e=r}e:{for(;n;){if(n.nextSibling){n=n.nextSibling;break e}n=n.parentNode}n=void 0}n=Du(n)}}function Ps(e,t){return e&&t?e===t?!0:e&&e.nodeType===3?!1:t&&t.nodeType===3?Ps(e,t.parentNode):"contains"in e?e.contains(t):e.compareDocumentPosition?!!(e.compareDocumentPosition(t)&16):!1:!1}function js(){for(var e=window,t=Yr();t instanceof e.HTMLIFrameElement;){try{var n=typeof t.contentWindow.location.href=="string"}catch{n=!1}if(n)e=t.contentWindow;else break;t=Yr(e.document)}return t}function Li(e){var t=e&&e.nodeName&&e.nodeName.toLowerCase();return t&&(t==="input"&&(e.type==="text"||e.type==="search"||e.type==="tel"||e.type==="url"||e.type==="password")||t==="textarea"||e.contentEditable==="true")}function Ud(e){var t=js(),n=e.focusedElem,r=e.selectionRange;if(t!==n&&n&&n.ownerDocument&&Ps(n.ownerDocument.documentElement,n)){if(r!==null&&Li(n)){if(t=r.start,e=r.end,e===void 0&&(e=t),"selectionStart"in n)n.selectionStart=t,n.selectionEnd=Math.min(e,n.value.length);else if(e=(t=n.ownerDocument||document)&&t.defaultView||window,e.getSelection){e=e.getSelection();var l=n.textContent.length,o=Math.min(r.start,l);r=r.end===void 0?o:Math.min(r.end,l),!e.extend&&o>r&&(l=r,r=o,o=l),l=Fu(n,o);var i=Fu(n,r);l&&i&&(e.rangeCount!==1||e.anchorNode!==l.node||e.anchorOffset!==l.offset||e.focusNode!==i.node||e.focusOffset!==i.offset)&&(t=t.createRange(),t.setStart(l.node,l.offset),e.removeAllRanges(),o>r?(e.addRange(t),e.extend(i.node,i.offset)):(t.setEnd(i.node,i.offset),e.addRange(t)))}}for(t=[],e=n;e=e.parentNode;)e.nodeType===1&&t.push({element:e,left:e.scrollLeft,top:e.scrollTop});for(typeof n.focus=="function"&&n.focus(),n=0;n<t.length;n++)e=t[n],e.element.scrollLeft=e.left,e.element.scrollTop=e.top}}var Ad=Ye&&"documentMode"in document&&11>=document.documentMode,Kt=null,zo=null,An=null,Oo=!1;function Iu(e,t,n){var r=n.window===n?n.document:n.nodeType===9?n:n.ownerDocument;Oo||Kt==null||Kt!==Yr(r)||(r=Kt,"selectionStart"in r&&Li(r)?r={start:r.selectionStart,end:r.selectionEnd}:(r=(r.ownerDocument&&r.ownerDocument.defaultView||window).getSelection(),r={anchorNode:r.anchorNode,anchorOffset:r.anchorOffset,focusNode:r.focusNode,focusOffset:r.focusOffset}),An&&Zn(An,r)||(An=r,r=el(zo,"onSelect"),0<r.length&&(t=new Pi("onSelect","select",null,t,n),e.push({event:t,listeners:r}),t.target=Kt)))}function Cr(e,t){var n={};return n[e.toLowerCase()]=t.toLowerCase(),n["Webkit"+e]="webkit"+t,n["Moz"+e]="moz"+t,n}var Yt={animationend:Cr("Animation","AnimationEnd"),animationiteration:Cr("Animation","AnimationIteration"),animationstart:Cr("Animation","AnimationStart"),transitionend:Cr("Transition","TransitionEnd")},Xl={},Ts={};Ye&&(Ts=document.createElement("div").style,"AnimationEvent"in window||(delete Yt.animationend.animation,delete Yt.animationiteration.animation,delete Yt.animationstart.animation),"TransitionEvent"in window||delete Yt.transitionend.transition);function xl(e){if(Xl[e])return Xl[e];if(!Yt[e])return e;var t=Yt[e],n;for(n in t)if(t.hasOwnProperty(n)&&n in Ts)return Xl[e]=t[n];return e}var Ls=xl("animationend"),Rs=xl("animationiteration"),zs=xl("animationstart"),Os=xl("transitionend"),Ms=new Map,Uu="abort auxClick cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");function wt(e,t){Ms.set(e,t),At(t,[e])}for(var Jl=0;Jl<Uu.length;Jl++){var Zl=Uu[Jl],$d=Zl.toLowerCase(),Bd=Zl[0].toUpperCase()+Zl.slice(1);wt($d,"on"+Bd)}wt(Ls,"onAnimationEnd");wt(Rs,"onAnimationIteration");wt(zs,"onAnimationStart");wt("dblclick","onDoubleClick");wt("focusin","onFocus");wt("focusout","onBlur");wt(Os,"onTransitionEnd");an("onMouseEnter",["mouseout","mouseover"]);an("onMouseLeave",["mouseout","mouseover"]);an("onPointerEnter",["pointerout","pointerover"]);an("onPointerLeave",["pointerout","pointerover"]);At("onChange","change click focusin focusout input keydown keyup selectionchange".split(" "));At("onSelect","focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" "));At("onBeforeInput",["compositionend","keypress","textInput","paste"]);At("onCompositionEnd","compositionend focusout keydown keypress keyup mousedown".split(" "));At("onCompositionStart","compositionstart focusout keydown keypress keyup mousedown".split(" "));At("onCompositionUpdate","compositionupdate focusout keydown keypress keyup mousedown".split(" "));var Mn="abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" "),Vd=new Set("cancel close invalid load scroll toggle".split(" ").concat(Mn));function Au(e,t,n){var r=e.type||"unknown-event";e.currentTarget=n,$f(r,t,void 0,e),e.currentTarget=null}function Ds(e,t){t=(t&4)!==0;for(var n=0;n<e.length;n++){var r=e[n],l=r.event;r=r.listeners;e:{var o=void 0;if(t)for(var i=r.length-1;0<=i;i--){var u=r[i],a=u.instance,s=u.currentTarget;if(u=u.listener,a!==o&&l.isPropagationStopped())break e;Au(l,u,s),o=a}else for(i=0;i<r.length;i++){if(u=r[i],a=u.instance,s=u.currentTarget,u=u.listener,a!==o&&l.isPropagationStopped())break e;Au(l,u,s),o=a}}}if(Xr)throw e=jo,Xr=!1,jo=null,e}function I(e,t){var n=t[Uo];n===void 0&&(n=t[Uo]=new Set);var r=e+"__bubble";n.has(r)||(Fs(t,e,2,!1),n.add(r))}function ql(e,t,n){var r=0;t&&(r|=4),Fs(n,e,r,t)}var Nr="_reactListening"+Math.random().toString(36).slice(2);function qn(e){if(!e[Nr]){e[Nr]=!0,Wa.forEach(function(n){n!=="selectionchange"&&(Vd.has(n)||ql(n,!1,e),ql(n,!0,e))});var t=e.nodeType===9?e:e.ownerDocument;t===null||t[Nr]||(t[Nr]=!0,ql("selectionchange",!1,t))}}function Fs(e,t,n,r){switch(ws(t)){case 1:var l=nd;break;case 4:l=rd;break;default:l=Ci}n=l.bind(null,t,n,e),l=void 0,!Po||t!=="touchstart"&&t!=="touchmove"&&t!=="wheel"||(l=!0),r?l!==void 0?e.addEventListener(t,n,{capture:!0,passive:l}):e.addEventListener(t,n,!0):l!==void 0?e.addEventListener(t,n,{passive:l}):e.addEventListener(t,n,!1)}function bl(e,t,n,r,l){var o=r;if(!(t&1)&&!(t&2)&&r!==null)e:for(;;){if(r===null)return;var i=r.tag;if(i===3||i===4){var u=r.stateNode.containerInfo;if(u===l||u.nodeType===8&&u.parentNode===l)break;if(i===4)for(i=r.return;i!==null;){var a=i.tag;if((a===3||a===4)&&(a=i.stateNode.containerInfo,a===l||a.nodeType===8&&a.parentNode===l))return;i=i.return}for(;u!==null;){if(i=Tt(u),i===null)return;if(a=i.tag,a===5||a===6){r=o=i;continue e}u=u.parentNode}}r=r.return}os(function(){var s=o,h=ki(n),d=[];e:{var m=Ms.get(e);if(m!==void 0){var w=Pi,S=e;switch(e){case"keypress":if(Ar(n)===0)break e;case"keydown":case"keyup":w=yd;break;case"focusin":S="focus",w=Kl;break;case"focusout":S="blur",w=Kl;break;case"beforeblur":case"afterblur":w=Kl;break;case"click":if(n.button===2)break e;case"auxclick":case"dblclick":case"mousedown":case"mousemove":case"mouseup":case"mouseout":case"mouseover":case"contextmenu":w=Pu;break;case"drag":case"dragend":case"dragenter":case"dragexit":case"dragleave":case"dragover":case"dragstart":case"drop":w=id;break;case"touchcancel":case"touchend":case"touchmove":case"touchstart":w=kd;break;case Ls:case Rs:case zs:w=sd;break;case Os:w=_d;break;case"scroll":w=ld;break;case"wheel":w=Cd;break;case"copy":case"cut":case"paste":w=fd;break;case"gotpointercapture":case"lostpointercapture":case"pointercancel":case"pointerdown":case"pointermove":case"pointerout":case"pointerover":case"pointerup":w=Tu}var g=(t&4)!==0,x=!g&&e==="scroll",f=g?m!==null?m+"Capture":null:m;g=[];for(var c=s,p;c!==null;){p=c;var k=p.stateNode;if(p.tag===5&&k!==null&&(p=k,f!==null&&(k=Kn(c,f),k!=null&&g.push(bn(c,k,p)))),x)break;c=c.return}0<g.length&&(m=new w(m,S,null,n,h),d.push({event:m,listeners:g}))}}if(!(t&7)){e:{if(m=e==="mouseover"||e==="pointerover",w=e==="mouseout"||e==="pointerout",m&&n!==Co&&(S=n.relatedTarget||n.fromElement)&&(Tt(S)||S[Ge]))break e;if((w||m)&&(m=h.window===h?h:(m=h.ownerDocument)?m.defaultView||m.parentWindow:window,w?(S=n.relatedTarget||n.toElement,w=s,S=S?Tt(S):null,S!==null&&(x=$t(S),S!==x||S.tag!==5&&S.tag!==6)&&(S=null)):(w=null,S=s),w!==S)){if(g=Pu,k="onMouseLeave",f="onMouseEnter",c="mouse",(e==="pointerout"||e==="pointerover")&&(g=Tu,k="onPointerLeave",f="onPointerEnter",c="pointer"),x=w==null?m:Gt(w),p=S==null?m:Gt(S),m=new g(k,c+"leave",w,n,h),m.target=x,m.relatedTarget=p,k=null,Tt(h)===s&&(g=new g(f,c+"enter",S,n,h),g.target=p,g.relatedTarget=x,k=g),x=k,w&&S)t:{for(g=w,f=S,c=0,p=g;p;p=Vt(p))c++;for(p=0,k=f;k;k=Vt(k))p++;for(;0<c-p;)g=Vt(g),c--;for(;0<p-c;)f=Vt(f),p--;for(;c--;){if(g===f||f!==null&&g===f.alternate)break t;g=Vt(g),f=Vt(f)}g=null}else g=null;w!==null&&$u(d,m,w,g,!1),S!==null&&x!==null&&$u(d,x,S,g,!0)}}e:{if(m=s?Gt(s):window,w=m.nodeName&&m.nodeName.toLowerCase(),w==="select"||w==="input"&&m.type==="file")var E=zd;else if(zu(m))if(Cs)E=Fd;else{E=Md;var P=Od}else(w=m.nodeName)&&w.toLowerCase()==="input"&&(m.type==="checkbox"||m.type==="radio")&&(E=Dd);if(E&&(E=E(e,s))){Es(d,E,n,h);break e}P&&P(e,m,s),e==="focusout"&&(P=m._wrapperState)&&P.controlled&&m.type==="number"&&So(m,"number",m.value)}switch(P=s?Gt(s):window,e){case"focusin":(zu(P)||P.contentEditable==="true")&&(Kt=P,zo=s,An=null);break;case"focusout":An=zo=Kt=null;break;case"mousedown":Oo=!0;break;case"contextmenu":case"mouseup":case"dragend":Oo=!1,Iu(d,n,h);break;case"selectionchange":if(Ad)break;case"keydown":case"keyup":Iu(d,n,h)}var j;if(Ti)e:{switch(e){case"compositionstart":var T="onCompositionStart";break e;case"compositionend":T="onCompositionEnd";break e;case"compositionupdate":T="onCompositionUpdate";break e}T=void 0}else Qt?xs(e,n)&&(T="onCompositionEnd"):e==="keydown"&&n.keyCode===229&&(T="onCompositionStart");T&&(ks&&n.locale!=="ko"&&(Qt||T!=="onCompositionStart"?T==="onCompositionEnd"&&Qt&&(j=Ss()):(ot=h,Ni="value"in ot?ot.value:ot.textContent,Qt=!0)),P=el(s,T),0<P.length&&(T=new ju(T,e,null,n,h),d.push({event:T,listeners:P}),j?T.data=j:(j=_s(n),j!==null&&(T.data=j)))),(j=Pd?jd(e,n):Td(e,n))&&(s=el(s,"onBeforeInput"),0<s.length&&(h=new ju("onBeforeInput","beforeinput",null,n,h),d.push({event:h,listeners:s}),h.data=j))}Ds(d,t)})}function bn(e,t,n){return{instance:e,listener:t,currentTarget:n}}function el(e,t){for(var n=t+"Capture",r=[];e!==null;){var l=e,o=l.stateNode;l.tag===5&&o!==null&&(l=o,o=Kn(e,n),o!=null&&r.unshift(bn(e,o,l)),o=Kn(e,t),o!=null&&r.push(bn(e,o,l))),e=e.return}return r}function Vt(e){if(e===null)return null;do e=e.return;while(e&&e.tag!==5);return e||null}function $u(e,t,n,r,l){for(var o=t._reactName,i=[];n!==null&&n!==r;){var u=n,a=u.alternate,s=u.stateNode;if(a!==null&&a===r)break;u.tag===5&&s!==null&&(u=s,l?(a=Kn(n,o),a!=null&&i.unshift(bn(n,a,u))):l||(a=Kn(n,o),a!=null&&i.push(bn(n,a,u)))),n=n.return}i.length!==0&&e.push({event:t,listeners:i})}var Wd=/\r\n?/g,Hd=/\u0000|\uFFFD/g;function Bu(e){return(typeof e=="string"?e:""+e).replace(Wd,`
`).replace(Hd,"")}function Pr(e,t,n){if(t=Bu(t),Bu(e)!==t&&n)throw Error(_(425))}function tl(){}var Mo=null,Do=null;function Fo(e,t){return e==="textarea"||e==="noscript"||typeof t.children=="string"||typeof t.children=="number"||typeof t.dangerouslySetInnerHTML=="object"&&t.dangerouslySetInnerHTML!==null&&t.dangerouslySetInnerHTML.__html!=null}var Io=typeof setTimeout=="function"?setTimeout:void 0,Qd=typeof clearTimeout=="function"?clearTimeout:void 0,Vu=typeof Promise=="function"?Promise:void 0,Kd=typeof queueMicrotask=="function"?queueMicrotask:typeof Vu<"u"?function(e){return Vu.resolve(null).then(e).catch(Yd)}:Io;function Yd(e){setTimeout(function(){throw e})}function eo(e,t){var n=t,r=0;do{var l=n.nextSibling;if(e.removeChild(n),l&&l.nodeType===8)if(n=l.data,n==="/$"){if(r===0){e.removeChild(l),Xn(t);return}r--}else n!=="$"&&n!=="$?"&&n!=="$!"||r++;n=l}while(n);Xn(t)}function ft(e){for(;e!=null;e=e.nextSibling){var t=e.nodeType;if(t===1||t===3)break;if(t===8){if(t=e.data,t==="$"||t==="$!"||t==="$?")break;if(t==="/$")return null}}return e}function Wu(e){e=e.previousSibling;for(var t=0;e;){if(e.nodeType===8){var n=e.data;if(n==="$"||n==="$!"||n==="$?"){if(t===0)return e;t--}else n==="/$"&&t++}e=e.previousSibling}return null}var gn=Math.random().toString(36).slice(2),Ue="__reactFiber$"+gn,er="__reactProps$"+gn,Ge="__reactContainer$"+gn,Uo="__reactEvents$"+gn,Gd="__reactListeners$"+gn,Xd="__reactHandles$"+gn;function Tt(e){var t=e[Ue];if(t)return t;for(var n=e.parentNode;n;){if(t=n[Ge]||n[Ue]){if(n=t.alternate,t.child!==null||n!==null&&n.child!==null)for(e=Wu(e);e!==null;){if(n=e[Ue])return n;e=Wu(e)}return t}e=n,n=e.parentNode}return null}function dr(e){return e=e[Ue]||e[Ge],!e||e.tag!==5&&e.tag!==6&&e.tag!==13&&e.tag!==3?null:e}function Gt(e){if(e.tag===5||e.tag===6)return e.stateNode;throw Error(_(33))}function _l(e){return e[er]||null}var Ao=[],Xt=-1;function St(e){return{current:e}}function U(e){0>Xt||(e.current=Ao[Xt],Ao[Xt]=null,Xt--)}function F(e,t){Xt++,Ao[Xt]=e.current,e.current=t}var yt={},ie=St(yt),pe=St(!1),Mt=yt;function sn(e,t){var n=e.type.contextTypes;if(!n)return yt;var r=e.stateNode;if(r&&r.__reactInternalMemoizedUnmaskedChildContext===t)return r.__reactInternalMemoizedMaskedChildContext;var l={},o;for(o in n)l[o]=t[o];return r&&(e=e.stateNode,e.__reactInternalMemoizedUnmaskedChildContext=t,e.__reactInternalMemoizedMaskedChildContext=l),l}function he(e){return e=e.childContextTypes,e!=null}function nl(){U(pe),U(ie)}function Hu(e,t,n){if(ie.current!==yt)throw Error(_(168));F(ie,t),F(pe,n)}function Is(e,t,n){var r=e.stateNode;if(t=t.childContextTypes,typeof r.getChildContext!="function")return n;r=r.getChildContext();for(var l in r)if(!(l in t))throw Error(_(108,Of(e)||"Unknown",l));return V({},n,r)}function rl(e){return e=(e=e.stateNode)&&e.__reactInternalMemoizedMergedChildContext||yt,Mt=ie.current,F(ie,e),F(pe,pe.current),!0}function Qu(e,t,n){var r=e.stateNode;if(!r)throw Error(_(169));n?(e=Is(e,t,Mt),r.__reactInternalMemoizedMergedChildContext=e,U(pe),U(ie),F(ie,e)):U(pe),F(pe,n)}var Ve=null,El=!1,to=!1;function Us(e){Ve===null?Ve=[e]:Ve.push(e)}function Jd(e){El=!0,Us(e)}function kt(){if(!to&&Ve!==null){to=!0;var e=0,t=D;try{var n=Ve;for(D=1;e<n.length;e++){var r=n[e];do r=r(!0);while(r!==null)}Ve=null,El=!1}catch(l){throw Ve!==null&&(Ve=Ve.slice(e+1)),ss(xi,kt),l}finally{D=t,to=!1}}return null}var Jt=[],Zt=0,ll=null,ol=0,xe=[],_e=0,Dt=null,We=1,He="";function Nt(e,t){Jt[Zt++]=ol,Jt[Zt++]=ll,ll=e,ol=t}function As(e,t,n){xe[_e++]=We,xe[_e++]=He,xe[_e++]=Dt,Dt=e;var r=We;e=He;var l=32-Oe(r)-1;r&=~(1<<l),n+=1;var o=32-Oe(t)+l;if(30<o){var i=l-l%5;o=(r&(1<<i)-1).toString(32),r>>=i,l-=i,We=1<<32-Oe(t)+l|n<<l|r,He=o+e}else We=1<<o|n<<l|r,He=e}function Ri(e){e.return!==null&&(Nt(e,1),As(e,1,0))}function zi(e){for(;e===ll;)ll=Jt[--Zt],Jt[Zt]=null,ol=Jt[--Zt],Jt[Zt]=null;for(;e===Dt;)Dt=xe[--_e],xe[_e]=null,He=xe[--_e],xe[_e]=null,We=xe[--_e],xe[_e]=null}var ye=null,ge=null,A=!1,ze=null;function $s(e,t){var n=Ee(5,null,null,0);n.elementType="DELETED",n.stateNode=t,n.return=e,t=e.deletions,t===null?(e.deletions=[n],e.flags|=16):t.push(n)}function Ku(e,t){switch(e.tag){case 5:var n=e.type;return t=t.nodeType!==1||n.toLowerCase()!==t.nodeName.toLowerCase()?null:t,t!==null?(e.stateNode=t,ye=e,ge=ft(t.firstChild),!0):!1;case 6:return t=e.pendingProps===""||t.nodeType!==3?null:t,t!==null?(e.stateNode=t,ye=e,ge=null,!0):!1;case 13:return t=t.nodeType!==8?null:t,t!==null?(n=Dt!==null?{id:We,overflow:He}:null,e.memoizedState={dehydrated:t,treeContext:n,retryLane:1073741824},n=Ee(18,null,null,0),n.stateNode=t,n.return=e,e.child=n,ye=e,ge=null,!0):!1;default:return!1}}function $o(e){return(e.mode&1)!==0&&(e.flags&128)===0}function Bo(e){if(A){var t=ge;if(t){var n=t;if(!Ku(e,t)){if($o(e))throw Error(_(418));t=ft(n.nextSibling);var r=ye;t&&Ku(e,t)?$s(r,n):(e.flags=e.flags&-4097|2,A=!1,ye=e)}}else{if($o(e))throw Error(_(418));e.flags=e.flags&-4097|2,A=!1,ye=e}}}function Yu(e){for(e=e.return;e!==null&&e.tag!==5&&e.tag!==3&&e.tag!==13;)e=e.return;ye=e}function jr(e){if(e!==ye)return!1;if(!A)return Yu(e),A=!0,!1;var t;if((t=e.tag!==3)&&!(t=e.tag!==5)&&(t=e.type,t=t!=="head"&&t!=="body"&&!Fo(e.type,e.memoizedProps)),t&&(t=ge)){if($o(e))throw Bs(),Error(_(418));for(;t;)$s(e,t),t=ft(t.nextSibling)}if(Yu(e),e.tag===13){if(e=e.memoizedState,e=e!==null?e.dehydrated:null,!e)throw Error(_(317));e:{for(e=e.nextSibling,t=0;e;){if(e.nodeType===8){var n=e.data;if(n==="/$"){if(t===0){ge=ft(e.nextSibling);break e}t--}else n!=="$"&&n!=="$!"&&n!=="$?"||t++}e=e.nextSibling}ge=null}}else ge=ye?ft(e.stateNode.nextSibling):null;return!0}function Bs(){for(var e=ge;e;)e=ft(e.nextSibling)}function cn(){ge=ye=null,A=!1}function Oi(e){ze===null?ze=[e]:ze.push(e)}var Zd=Ze.ReactCurrentBatchConfig;function jn(e,t,n){if(e=n.ref,e!==null&&typeof e!="function"&&typeof e!="object"){if(n._owner){if(n=n._owner,n){if(n.tag!==1)throw Error(_(309));var r=n.stateNode}if(!r)throw Error(_(147,e));var l=r,o=""+e;return t!==null&&t.ref!==null&&typeof t.ref=="function"&&t.ref._stringRef===o?t.ref:(t=function(i){var u=l.refs;i===null?delete u[o]:u[o]=i},t._stringRef=o,t)}if(typeof e!="string")throw Error(_(284));if(!n._owner)throw Error(_(290,e))}return e}function Tr(e,t){throw e=Object.prototype.toString.call(t),Error(_(31,e==="[object Object]"?"object with keys {"+Object.keys(t).join(", ")+"}":e))}function Gu(e){var t=e._init;return t(e._payload)}function Vs(e){function t(f,c){if(e){var p=f.deletions;p===null?(f.deletions=[c],f.flags|=16):p.push(c)}}function n(f,c){if(!e)return null;for(;c!==null;)t(f,c),c=c.sibling;return null}function r(f,c){for(f=new Map;c!==null;)c.key!==null?f.set(c.key,c):f.set(c.index,c),c=c.sibling;return f}function l(f,c){return f=mt(f,c),f.index=0,f.sibling=null,f}function o(f,c,p){return f.index=p,e?(p=f.alternate,p!==null?(p=p.index,p<c?(f.flags|=2,c):p):(f.flags|=2,c)):(f.flags|=1048576,c)}function i(f){return e&&f.alternate===null&&(f.flags|=2),f}function u(f,c,p,k){return c===null||c.tag!==6?(c=ao(p,f.mode,k),c.return=f,c):(c=l(c,p),c.return=f,c)}function a(f,c,p,k){var E=p.type;return E===Ht?h(f,c,p.props.children,k,p.key):c!==null&&(c.elementType===E||typeof E=="object"&&E!==null&&E.$$typeof===tt&&Gu(E)===c.type)?(k=l(c,p.props),k.ref=jn(f,c,p),k.return=f,k):(k=Kr(p.type,p.key,p.props,null,f.mode,k),k.ref=jn(f,c,p),k.return=f,k)}function s(f,c,p,k){return c===null||c.tag!==4||c.stateNode.containerInfo!==p.containerInfo||c.stateNode.implementation!==p.implementation?(c=so(p,f.mode,k),c.return=f,c):(c=l(c,p.children||[]),c.return=f,c)}function h(f,c,p,k,E){return c===null||c.tag!==7?(c=Ot(p,f.mode,k,E),c.return=f,c):(c=l(c,p),c.return=f,c)}function d(f,c,p){if(typeof c=="string"&&c!==""||typeof c=="number")return c=ao(""+c,f.mode,p),c.return=f,c;if(typeof c=="object"&&c!==null){switch(c.$$typeof){case yr:return p=Kr(c.type,c.key,c.props,null,f.mode,p),p.ref=jn(f,null,c),p.return=f,p;case Wt:return c=so(c,f.mode,p),c.return=f,c;case tt:var k=c._init;return d(f,k(c._payload),p)}if(zn(c)||_n(c))return c=Ot(c,f.mode,p,null),c.return=f,c;Tr(f,c)}return null}function m(f,c,p,k){var E=c!==null?c.key:null;if(typeof p=="string"&&p!==""||typeof p=="number")return E!==null?null:u(f,c,""+p,k);if(typeof p=="object"&&p!==null){switch(p.$$typeof){case yr:return p.key===E?a(f,c,p,k):null;case Wt:return p.key===E?s(f,c,p,k):null;case tt:return E=p._init,m(f,c,E(p._payload),k)}if(zn(p)||_n(p))return E!==null?null:h(f,c,p,k,null);Tr(f,p)}return null}function w(f,c,p,k,E){if(typeof k=="string"&&k!==""||typeof k=="number")return f=f.get(p)||null,u(c,f,""+k,E);if(typeof k=="object"&&k!==null){switch(k.$$typeof){case yr:return f=f.get(k.key===null?p:k.key)||null,a(c,f,k,E);case Wt:return f=f.get(k.key===null?p:k.key)||null,s(c,f,k,E);case tt:var P=k._init;return w(f,c,p,P(k._payload),E)}if(zn(k)||_n(k))return f=f.get(p)||null,h(c,f,k,E,null);Tr(c,k)}return null}function S(f,c,p,k){for(var E=null,P=null,j=c,T=c=0,H=null;j!==null&&T<p.length;T++){j.index>T?(H=j,j=null):H=j.sibling;var O=m(f,j,p[T],k);if(O===null){j===null&&(j=H);break}e&&j&&O.alternate===null&&t(f,j),c=o(O,c,T),P===null?E=O:P.sibling=O,P=O,j=H}if(T===p.length)return n(f,j),A&&Nt(f,T),E;if(j===null){for(;T<p.length;T++)j=d(f,p[T],k),j!==null&&(c=o(j,c,T),P===null?E=j:P.sibling=j,P=j);return A&&Nt(f,T),E}for(j=r(f,j);T<p.length;T++)H=w(j,f,T,p[T],k),H!==null&&(e&&H.alternate!==null&&j.delete(H.key===null?T:H.key),c=o(H,c,T),P===null?E=H:P.sibling=H,P=H);return e&&j.forEach(function(je){return t(f,je)}),A&&Nt(f,T),E}function g(f,c,p,k){var E=_n(p);if(typeof E!="function")throw Error(_(150));if(p=E.call(p),p==null)throw Error(_(151));for(var P=E=null,j=c,T=c=0,H=null,O=p.next();j!==null&&!O.done;T++,O=p.next()){j.index>T?(H=j,j=null):H=j.sibling;var je=m(f,j,O.value,k);if(je===null){j===null&&(j=H);break}e&&j&&je.alternate===null&&t(f,j),c=o(je,c,T),P===null?E=je:P.sibling=je,P=je,j=H}if(O.done)return n(f,j),A&&Nt(f,T),E;if(j===null){for(;!O.done;T++,O=p.next())O=d(f,O.value,k),O!==null&&(c=o(O,c,T),P===null?E=O:P.sibling=O,P=O);return A&&Nt(f,T),E}for(j=r(f,j);!O.done;T++,O=p.next())O=w(j,f,T,O.value,k),O!==null&&(e&&O.alternate!==null&&j.delete(O.key===null?T:O.key),c=o(O,c,T),P===null?E=O:P.sibling=O,P=O);return e&&j.forEach(function(kn){return t(f,kn)}),A&&Nt(f,T),E}function x(f,c,p,k){if(typeof p=="object"&&p!==null&&p.type===Ht&&p.key===null&&(p=p.props.children),typeof p=="object"&&p!==null){switch(p.$$typeof){case yr:e:{for(var E=p.key,P=c;P!==null;){if(P.key===E){if(E=p.type,E===Ht){if(P.tag===7){n(f,P.sibling),c=l(P,p.props.children),c.return=f,f=c;break e}}else if(P.elementType===E||typeof E=="object"&&E!==null&&E.$$typeof===tt&&Gu(E)===P.type){n(f,P.sibling),c=l(P,p.props),c.ref=jn(f,P,p),c.return=f,f=c;break e}n(f,P);break}else t(f,P);P=P.sibling}p.type===Ht?(c=Ot(p.props.children,f.mode,k,p.key),c.return=f,f=c):(k=Kr(p.type,p.key,p.props,null,f.mode,k),k.ref=jn(f,c,p),k.return=f,f=k)}return i(f);case Wt:e:{for(P=p.key;c!==null;){if(c.key===P)if(c.tag===4&&c.stateNode.containerInfo===p.containerInfo&&c.stateNode.implementation===p.implementation){n(f,c.sibling),c=l(c,p.children||[]),c.return=f,f=c;break e}else{n(f,c);break}else t(f,c);c=c.sibling}c=so(p,f.mode,k),c.return=f,f=c}return i(f);case tt:return P=p._init,x(f,c,P(p._payload),k)}if(zn(p))return S(f,c,p,k);if(_n(p))return g(f,c,p,k);Tr(f,p)}return typeof p=="string"&&p!==""||typeof p=="number"?(p=""+p,c!==null&&c.tag===6?(n(f,c.sibling),c=l(c,p),c.return=f,f=c):(n(f,c),c=ao(p,f.mode,k),c.return=f,f=c),i(f)):n(f,c)}return x}var fn=Vs(!0),Ws=Vs(!1),il=St(null),ul=null,qt=null,Mi=null;function Di(){Mi=qt=ul=null}function Fi(e){var t=il.current;U(il),e._currentValue=t}function Vo(e,t,n){for(;e!==null;){var r=e.alternate;if((e.childLanes&t)!==t?(e.childLanes|=t,r!==null&&(r.childLanes|=t)):r!==null&&(r.childLanes&t)!==t&&(r.childLanes|=t),e===n)break;e=e.return}}function on(e,t){ul=e,Mi=qt=null,e=e.dependencies,e!==null&&e.firstContext!==null&&(e.lanes&t&&(de=!0),e.firstContext=null)}function Ne(e){var t=e._currentValue;if(Mi!==e)if(e={context:e,memoizedValue:t,next:null},qt===null){if(ul===null)throw Error(_(308));qt=e,ul.dependencies={lanes:0,firstContext:e}}else qt=qt.next=e;return t}var Lt=null;function Ii(e){Lt===null?Lt=[e]:Lt.push(e)}function Hs(e,t,n,r){var l=t.interleaved;return l===null?(n.next=n,Ii(t)):(n.next=l.next,l.next=n),t.interleaved=n,Xe(e,r)}function Xe(e,t){e.lanes|=t;var n=e.alternate;for(n!==null&&(n.lanes|=t),n=e,e=e.return;e!==null;)e.childLanes|=t,n=e.alternate,n!==null&&(n.childLanes|=t),n=e,e=e.return;return n.tag===3?n.stateNode:null}var nt=!1;function Ui(e){e.updateQueue={baseState:e.memoizedState,firstBaseUpdate:null,lastBaseUpdate:null,shared:{pending:null,interleaved:null,lanes:0},effects:null}}function Qs(e,t){e=e.updateQueue,t.updateQueue===e&&(t.updateQueue={baseState:e.baseState,firstBaseUpdate:e.firstBaseUpdate,lastBaseUpdate:e.lastBaseUpdate,shared:e.shared,effects:e.effects})}function Ke(e,t){return{eventTime:e,lane:t,tag:0,payload:null,callback:null,next:null}}function dt(e,t,n){var r=e.updateQueue;if(r===null)return null;if(r=r.shared,M&2){var l=r.pending;return l===null?t.next=t:(t.next=l.next,l.next=t),r.pending=t,Xe(e,n)}return l=r.interleaved,l===null?(t.next=t,Ii(r)):(t.next=l.next,l.next=t),r.interleaved=t,Xe(e,n)}function $r(e,t,n){if(t=t.updateQueue,t!==null&&(t=t.shared,(n&4194240)!==0)){var r=t.lanes;r&=e.pendingLanes,n|=r,t.lanes=n,_i(e,n)}}function Xu(e,t){var n=e.updateQueue,r=e.alternate;if(r!==null&&(r=r.updateQueue,n===r)){var l=null,o=null;if(n=n.firstBaseUpdate,n!==null){do{var i={eventTime:n.eventTime,lane:n.lane,tag:n.tag,payload:n.payload,callback:n.callback,next:null};o===null?l=o=i:o=o.next=i,n=n.next}while(n!==null);o===null?l=o=t:o=o.next=t}else l=o=t;n={baseState:r.baseState,firstBaseUpdate:l,lastBaseUpdate:o,shared:r.shared,effects:r.effects},e.updateQueue=n;return}e=n.lastBaseUpdate,e===null?n.firstBaseUpdate=t:e.next=t,n.lastBaseUpdate=t}function al(e,t,n,r){var l=e.updateQueue;nt=!1;var o=l.firstBaseUpdate,i=l.lastBaseUpdate,u=l.shared.pending;if(u!==null){l.shared.pending=null;var a=u,s=a.next;a.next=null,i===null?o=s:i.next=s,i=a;var h=e.alternate;h!==null&&(h=h.updateQueue,u=h.lastBaseUpdate,u!==i&&(u===null?h.firstBaseUpdate=s:u.next=s,h.lastBaseUpdate=a))}if(o!==null){var d=l.baseState;i=0,h=s=a=null,u=o;do{var m=u.lane,w=u.eventTime;if((r&m)===m){h!==null&&(h=h.next={eventTime:w,lane:0,tag:u.tag,payload:u.payload,callback:u.callback,next:null});e:{var S=e,g=u;switch(m=t,w=n,g.tag){case 1:if(S=g.payload,typeof S=="function"){d=S.call(w,d,m);break e}d=S;break e;case 3:S.flags=S.flags&-65537|128;case 0:if(S=g.payload,m=typeof S=="function"?S.call(w,d,m):S,m==null)break e;d=V({},d,m);break e;case 2:nt=!0}}u.callback!==null&&u.lane!==0&&(e.flags|=64,m=l.effects,m===null?l.effects=[u]:m.push(u))}else w={eventTime:w,lane:m,tag:u.tag,payload:u.payload,callback:u.callback,next:null},h===null?(s=h=w,a=d):h=h.next=w,i|=m;if(u=u.next,u===null){if(u=l.shared.pending,u===null)break;m=u,u=m.next,m.next=null,l.lastBaseUpdate=m,l.shared.pending=null}}while(!0);if(h===null&&(a=d),l.baseState=a,l.firstBaseUpdate=s,l.lastBaseUpdate=h,t=l.shared.interleaved,t!==null){l=t;do i|=l.lane,l=l.next;while(l!==t)}else o===null&&(l.shared.lanes=0);It|=i,e.lanes=i,e.memoizedState=d}}function Ju(e,t,n){if(e=t.effects,t.effects=null,e!==null)for(t=0;t<e.length;t++){var r=e[t],l=r.callback;if(l!==null){if(r.callback=null,r=n,typeof l!="function")throw Error(_(191,l));l.call(r)}}}var pr={},$e=St(pr),tr=St(pr),nr=St(pr);function Rt(e){if(e===pr)throw Error(_(174));return e}function Ai(e,t){switch(F(nr,t),F(tr,e),F($e,pr),e=t.nodeType,e){case 9:case 11:t=(t=t.documentElement)?t.namespaceURI:xo(null,"");break;default:e=e===8?t.parentNode:t,t=e.namespaceURI||null,e=e.tagName,t=xo(t,e)}U($e),F($e,t)}function dn(){U($e),U(tr),U(nr)}function Ks(e){Rt(nr.current);var t=Rt($e.current),n=xo(t,e.type);t!==n&&(F(tr,e),F($e,n))}function $i(e){tr.current===e&&(U($e),U(tr))}var $=St(0);function sl(e){for(var t=e;t!==null;){if(t.tag===13){var n=t.memoizedState;if(n!==null&&(n=n.dehydrated,n===null||n.data==="$?"||n.data==="$!"))return t}else if(t.tag===19&&t.memoizedProps.revealOrder!==void 0){if(t.flags&128)return t}else if(t.child!==null){t.child.return=t,t=t.child;continue}if(t===e)break;for(;t.sibling===null;){if(t.return===null||t.return===e)return null;t=t.return}t.sibling.return=t.return,t=t.sibling}return null}var no=[];function Bi(){for(var e=0;e<no.length;e++)no[e]._workInProgressVersionPrimary=null;no.length=0}var Br=Ze.ReactCurrentDispatcher,ro=Ze.ReactCurrentBatchConfig,Ft=0,B=null,X=null,q=null,cl=!1,$n=!1,rr=0,qd=0;function re(){throw Error(_(321))}function Vi(e,t){if(t===null)return!1;for(var n=0;n<t.length&&n<e.length;n++)if(!De(e[n],t[n]))return!1;return!0}function Wi(e,t,n,r,l,o){if(Ft=o,B=t,t.memoizedState=null,t.updateQueue=null,t.lanes=0,Br.current=e===null||e.memoizedState===null?np:rp,e=n(r,l),$n){o=0;do{if($n=!1,rr=0,25<=o)throw Error(_(301));o+=1,q=X=null,t.updateQueue=null,Br.current=lp,e=n(r,l)}while($n)}if(Br.current=fl,t=X!==null&&X.next!==null,Ft=0,q=X=B=null,cl=!1,t)throw Error(_(300));return e}function Hi(){var e=rr!==0;return rr=0,e}function Ie(){var e={memoizedState:null,baseState:null,baseQueue:null,queue:null,next:null};return q===null?B.memoizedState=q=e:q=q.next=e,q}function Pe(){if(X===null){var e=B.alternate;e=e!==null?e.memoizedState:null}else e=X.next;var t=q===null?B.memoizedState:q.next;if(t!==null)q=t,X=e;else{if(e===null)throw Error(_(310));X=e,e={memoizedState:X.memoizedState,baseState:X.baseState,baseQueue:X.baseQueue,queue:X.queue,next:null},q===null?B.memoizedState=q=e:q=q.next=e}return q}function lr(e,t){return typeof t=="function"?t(e):t}function lo(e){var t=Pe(),n=t.queue;if(n===null)throw Error(_(311));n.lastRenderedReducer=e;var r=X,l=r.baseQueue,o=n.pending;if(o!==null){if(l!==null){var i=l.next;l.next=o.next,o.next=i}r.baseQueue=l=o,n.pending=null}if(l!==null){o=l.next,r=r.baseState;var u=i=null,a=null,s=o;do{var h=s.lane;if((Ft&h)===h)a!==null&&(a=a.next={lane:0,action:s.action,hasEagerState:s.hasEagerState,eagerState:s.eagerState,next:null}),r=s.hasEagerState?s.eagerState:e(r,s.action);else{var d={lane:h,action:s.action,hasEagerState:s.hasEagerState,eagerState:s.eagerState,next:null};a===null?(u=a=d,i=r):a=a.next=d,B.lanes|=h,It|=h}s=s.next}while(s!==null&&s!==o);a===null?i=r:a.next=u,De(r,t.memoizedState)||(de=!0),t.memoizedState=r,t.baseState=i,t.baseQueue=a,n.lastRenderedState=r}if(e=n.interleaved,e!==null){l=e;do o=l.lane,B.lanes|=o,It|=o,l=l.next;while(l!==e)}else l===null&&(n.lanes=0);return[t.memoizedState,n.dispatch]}function oo(e){var t=Pe(),n=t.queue;if(n===null)throw Error(_(311));n.lastRenderedReducer=e;var r=n.dispatch,l=n.pending,o=t.memoizedState;if(l!==null){n.pending=null;var i=l=l.next;do o=e(o,i.action),i=i.next;while(i!==l);De(o,t.memoizedState)||(de=!0),t.memoizedState=o,t.baseQueue===null&&(t.baseState=o),n.lastRenderedState=o}return[o,r]}function Ys(){}function Gs(e,t){var n=B,r=Pe(),l=t(),o=!De(r.memoizedState,l);if(o&&(r.memoizedState=l,de=!0),r=r.queue,Qi(Zs.bind(null,n,r,e),[e]),r.getSnapshot!==t||o||q!==null&&q.memoizedState.tag&1){if(n.flags|=2048,or(9,Js.bind(null,n,r,l,t),void 0,null),b===null)throw Error(_(349));Ft&30||Xs(n,t,l)}return l}function Xs(e,t,n){e.flags|=16384,e={getSnapshot:t,value:n},t=B.updateQueue,t===null?(t={lastEffect:null,stores:null},B.updateQueue=t,t.stores=[e]):(n=t.stores,n===null?t.stores=[e]:n.push(e))}function Js(e,t,n,r){t.value=n,t.getSnapshot=r,qs(t)&&bs(e)}function Zs(e,t,n){return n(function(){qs(t)&&bs(e)})}function qs(e){var t=e.getSnapshot;e=e.value;try{var n=t();return!De(e,n)}catch{return!0}}function bs(e){var t=Xe(e,1);t!==null&&Me(t,e,1,-1)}function Zu(e){var t=Ie();return typeof e=="function"&&(e=e()),t.memoizedState=t.baseState=e,e={pending:null,interleaved:null,lanes:0,dispatch:null,lastRenderedReducer:lr,lastRenderedState:e},t.queue=e,e=e.dispatch=tp.bind(null,B,e),[t.memoizedState,e]}function or(e,t,n,r){return e={tag:e,create:t,destroy:n,deps:r,next:null},t=B.updateQueue,t===null?(t={lastEffect:null,stores:null},B.updateQueue=t,t.lastEffect=e.next=e):(n=t.lastEffect,n===null?t.lastEffect=e.next=e:(r=n.next,n.next=e,e.next=r,t.lastEffect=e)),e}function ec(){return Pe().memoizedState}function Vr(e,t,n,r){var l=Ie();B.flags|=e,l.memoizedState=or(1|t,n,void 0,r===void 0?null:r)}function Cl(e,t,n,r){var l=Pe();r=r===void 0?null:r;var o=void 0;if(X!==null){var i=X.memoizedState;if(o=i.destroy,r!==null&&Vi(r,i.deps)){l.memoizedState=or(t,n,o,r);return}}B.flags|=e,l.memoizedState=or(1|t,n,o,r)}function qu(e,t){return Vr(8390656,8,e,t)}function Qi(e,t){return Cl(2048,8,e,t)}function tc(e,t){return Cl(4,2,e,t)}function nc(e,t){return Cl(4,4,e,t)}function rc(e,t){if(typeof t=="function")return e=e(),t(e),function(){t(null)};if(t!=null)return e=e(),t.current=e,function(){t.current=null}}function lc(e,t,n){return n=n!=null?n.concat([e]):null,Cl(4,4,rc.bind(null,t,e),n)}function Ki(){}function oc(e,t){var n=Pe();t=t===void 0?null:t;var r=n.memoizedState;return r!==null&&t!==null&&Vi(t,r[1])?r[0]:(n.memoizedState=[e,t],e)}function ic(e,t){var n=Pe();t=t===void 0?null:t;var r=n.memoizedState;return r!==null&&t!==null&&Vi(t,r[1])?r[0]:(e=e(),n.memoizedState=[e,t],e)}function uc(e,t,n){return Ft&21?(De(n,t)||(n=ds(),B.lanes|=n,It|=n,e.baseState=!0),t):(e.baseState&&(e.baseState=!1,de=!0),e.memoizedState=n)}function bd(e,t){var n=D;D=n!==0&&4>n?n:4,e(!0);var r=ro.transition;ro.transition={};try{e(!1),t()}finally{D=n,ro.transition=r}}function ac(){return Pe().memoizedState}function ep(e,t,n){var r=ht(e);if(n={lane:r,action:n,hasEagerState:!1,eagerState:null,next:null},sc(e))cc(t,n);else if(n=Hs(e,t,n,r),n!==null){var l=ae();Me(n,e,r,l),fc(n,t,r)}}function tp(e,t,n){var r=ht(e),l={lane:r,action:n,hasEagerState:!1,eagerState:null,next:null};if(sc(e))cc(t,l);else{var o=e.alternate;if(e.lanes===0&&(o===null||o.lanes===0)&&(o=t.lastRenderedReducer,o!==null))try{var i=t.lastRenderedState,u=o(i,n);if(l.hasEagerState=!0,l.eagerState=u,De(u,i)){var a=t.interleaved;a===null?(l.next=l,Ii(t)):(l.next=a.next,a.next=l),t.interleaved=l;return}}catch{}finally{}n=Hs(e,t,l,r),n!==null&&(l=ae(),Me(n,e,r,l),fc(n,t,r))}}function sc(e){var t=e.alternate;return e===B||t!==null&&t===B}function cc(e,t){$n=cl=!0;var n=e.pending;n===null?t.next=t:(t.next=n.next,n.next=t),e.pending=t}function fc(e,t,n){if(n&4194240){var r=t.lanes;r&=e.pendingLanes,n|=r,t.lanes=n,_i(e,n)}}var fl={readContext:Ne,useCallback:re,useContext:re,useEffect:re,useImperativeHandle:re,useInsertionEffect:re,useLayoutEffect:re,useMemo:re,useReducer:re,useRef:re,useState:re,useDebugValue:re,useDeferredValue:re,useTransition:re,useMutableSource:re,useSyncExternalStore:re,useId:re,unstable_isNewReconciler:!1},np={readContext:Ne,useCallback:function(e,t){return Ie().memoizedState=[e,t===void 0?null:t],e},useContext:Ne,useEffect:qu,useImperativeHandle:function(e,t,n){return n=n!=null?n.concat([e]):null,Vr(4194308,4,rc.bind(null,t,e),n)},useLayoutEffect:function(e,t){return Vr(4194308,4,e,t)},useInsertionEffect:function(e,t){return Vr(4,2,e,t)},useMemo:function(e,t){var n=Ie();return t=t===void 0?null:t,e=e(),n.memoizedState=[e,t],e},useReducer:function(e,t,n){var r=Ie();return t=n!==void 0?n(t):t,r.memoizedState=r.baseState=t,e={pending:null,interleaved:null,lanes:0,dispatch:null,lastRenderedReducer:e,lastRenderedState:t},r.queue=e,e=e.dispatch=ep.bind(null,B,e),[r.memoizedState,e]},useRef:function(e){var t=Ie();return e={current:e},t.memoizedState=e},useState:Zu,useDebugValue:Ki,useDeferredValue:function(e){return Ie().memoizedState=e},useTransition:function(){var e=Zu(!1),t=e[0];return e=bd.bind(null,e[1]),Ie().memoizedState=e,[t,e]},useMutableSource:function(){},useSyncExternalStore:function(e,t,n){var r=B,l=Ie();if(A){if(n===void 0)throw Error(_(407));n=n()}else{if(n=t(),b===null)throw Error(_(349));Ft&30||Xs(r,t,n)}l.memoizedState=n;var o={value:n,getSnapshot:t};return l.queue=o,qu(Zs.bind(null,r,o,e),[e]),r.flags|=2048,or(9,Js.bind(null,r,o,n,t),void 0,null),n},useId:function(){var e=Ie(),t=b.identifierPrefix;if(A){var n=He,r=We;n=(r&~(1<<32-Oe(r)-1)).toString(32)+n,t=":"+t+"R"+n,n=rr++,0<n&&(t+="H"+n.toString(32)),t+=":"}else n=qd++,t=":"+t+"r"+n.toString(32)+":";return e.memoizedState=t},unstable_isNewReconciler:!1},rp={readContext:Ne,useCallback:oc,useContext:Ne,useEffect:Qi,useImperativeHandle:lc,useInsertionEffect:tc,useLayoutEffect:nc,useMemo:ic,useReducer:lo,useRef:ec,useState:function(){return lo(lr)},useDebugValue:Ki,useDeferredValue:function(e){var t=Pe();return uc(t,X.memoizedState,e)},useTransition:function(){var e=lo(lr)[0],t=Pe().memoizedState;return[e,t]},useMutableSource:Ys,useSyncExternalStore:Gs,useId:ac,unstable_isNewReconciler:!1},lp={readContext:Ne,useCallback:oc,useContext:Ne,useEffect:Qi,useImperativeHandle:lc,useInsertionEffect:tc,useLayoutEffect:nc,useMemo:ic,useReducer:oo,useRef:ec,useState:function(){return oo(lr)},useDebugValue:Ki,useDeferredValue:function(e){var t=Pe();return X===null?t.memoizedState=e:uc(t,X.memoizedState,e)},useTransition:function(){var e=oo(lr)[0],t=Pe().memoizedState;return[e,t]},useMutableSource:Ys,useSyncExternalStore:Gs,useId:ac,unstable_isNewReconciler:!1};function Le(e,t){if(e&&e.defaultProps){t=V({},t),e=e.defaultProps;for(var n in e)t[n]===void 0&&(t[n]=e[n]);return t}return t}function Wo(e,t,n,r){t=e.memoizedState,n=n(r,t),n=n==null?t:V({},t,n),e.memoizedState=n,e.lanes===0&&(e.updateQueue.baseState=n)}var Nl={isMounted:function(e){return(e=e._reactInternals)?$t(e)===e:!1},enqueueSetState:function(e,t,n){e=e._reactInternals;var r=ae(),l=ht(e),o=Ke(r,l);o.payload=t,n!=null&&(o.callback=n),t=dt(e,o,l),t!==null&&(Me(t,e,l,r),$r(t,e,l))},enqueueReplaceState:function(e,t,n){e=e._reactInternals;var r=ae(),l=ht(e),o=Ke(r,l);o.tag=1,o.payload=t,n!=null&&(o.callback=n),t=dt(e,o,l),t!==null&&(Me(t,e,l,r),$r(t,e,l))},enqueueForceUpdate:function(e,t){e=e._reactInternals;var n=ae(),r=ht(e),l=Ke(n,r);l.tag=2,t!=null&&(l.callback=t),t=dt(e,l,r),t!==null&&(Me(t,e,r,n),$r(t,e,r))}};function bu(e,t,n,r,l,o,i){return e=e.stateNode,typeof e.shouldComponentUpdate=="function"?e.shouldComponentUpdate(r,o,i):t.prototype&&t.prototype.isPureReactComponent?!Zn(n,r)||!Zn(l,o):!0}function dc(e,t,n){var r=!1,l=yt,o=t.contextType;return typeof o=="object"&&o!==null?o=Ne(o):(l=he(t)?Mt:ie.current,r=t.contextTypes,o=(r=r!=null)?sn(e,l):yt),t=new t(n,o),e.memoizedState=t.state!==null&&t.state!==void 0?t.state:null,t.updater=Nl,e.stateNode=t,t._reactInternals=e,r&&(e=e.stateNode,e.__reactInternalMemoizedUnmaskedChildContext=l,e.__reactInternalMemoizedMaskedChildContext=o),t}function ea(e,t,n,r){e=t.state,typeof t.componentWillReceiveProps=="function"&&t.componentWillReceiveProps(n,r),typeof t.UNSAFE_componentWillReceiveProps=="function"&&t.UNSAFE_componentWillReceiveProps(n,r),t.state!==e&&Nl.enqueueReplaceState(t,t.state,null)}function Ho(e,t,n,r){var l=e.stateNode;l.props=n,l.state=e.memoizedState,l.refs={},Ui(e);var o=t.contextType;typeof o=="object"&&o!==null?l.context=Ne(o):(o=he(t)?Mt:ie.current,l.context=sn(e,o)),l.state=e.memoizedState,o=t.getDerivedStateFromProps,typeof o=="function"&&(Wo(e,t,o,n),l.state=e.memoizedState),typeof t.getDerivedStateFromProps=="function"||typeof l.getSnapshotBeforeUpdate=="function"||typeof l.UNSAFE_componentWillMount!="function"&&typeof l.componentWillMount!="function"||(t=l.state,typeof l.componentWillMount=="function"&&l.componentWillMount(),typeof l.UNSAFE_componentWillMount=="function"&&l.UNSAFE_componentWillMount(),t!==l.state&&Nl.enqueueReplaceState(l,l.state,null),al(e,n,l,r),l.state=e.memoizedState),typeof l.componentDidMount=="function"&&(e.flags|=4194308)}function pn(e,t){try{var n="",r=t;do n+=zf(r),r=r.return;while(r);var l=n}catch(o){l=`
Error generating stack: `+o.message+`
`+o.stack}return{value:e,source:t,stack:l,digest:null}}function io(e,t,n){return{value:e,source:null,stack:n??null,digest:t??null}}function Qo(e,t){try{console.error(t.value)}catch(n){setTimeout(function(){throw n})}}var op=typeof WeakMap=="function"?WeakMap:Map;function pc(e,t,n){n=Ke(-1,n),n.tag=3,n.payload={element:null};var r=t.value;return n.callback=function(){pl||(pl=!0,ti=r),Qo(e,t)},n}function hc(e,t,n){n=Ke(-1,n),n.tag=3;var r=e.type.getDerivedStateFromError;if(typeof r=="function"){var l=t.value;n.payload=function(){return r(l)},n.callback=function(){Qo(e,t)}}var o=e.stateNode;return o!==null&&typeof o.componentDidCatch=="function"&&(n.callback=function(){Qo(e,t),typeof r!="function"&&(pt===null?pt=new Set([this]):pt.add(this));var i=t.stack;this.componentDidCatch(t.value,{componentStack:i!==null?i:""})}),n}function ta(e,t,n){var r=e.pingCache;if(r===null){r=e.pingCache=new op;var l=new Set;r.set(t,l)}else l=r.get(t),l===void 0&&(l=new Set,r.set(t,l));l.has(n)||(l.add(n),e=wp.bind(null,e,t,n),t.then(e,e))}function na(e){do{var t;if((t=e.tag===13)&&(t=e.memoizedState,t=t!==null?t.dehydrated!==null:!0),t)return e;e=e.return}while(e!==null);return null}function ra(e,t,n,r,l){return e.mode&1?(e.flags|=65536,e.lanes=l,e):(e===t?e.flags|=65536:(e.flags|=128,n.flags|=131072,n.flags&=-52805,n.tag===1&&(n.alternate===null?n.tag=17:(t=Ke(-1,1),t.tag=2,dt(n,t,1))),n.lanes|=1),e)}var ip=Ze.ReactCurrentOwner,de=!1;function ue(e,t,n,r){t.child=e===null?Ws(t,null,n,r):fn(t,e.child,n,r)}function la(e,t,n,r,l){n=n.render;var o=t.ref;return on(t,l),r=Wi(e,t,n,r,o,l),n=Hi(),e!==null&&!de?(t.updateQueue=e.updateQueue,t.flags&=-2053,e.lanes&=~l,Je(e,t,l)):(A&&n&&Ri(t),t.flags|=1,ue(e,t,r,l),t.child)}function oa(e,t,n,r,l){if(e===null){var o=n.type;return typeof o=="function"&&!eu(o)&&o.defaultProps===void 0&&n.compare===null&&n.defaultProps===void 0?(t.tag=15,t.type=o,mc(e,t,o,r,l)):(e=Kr(n.type,null,r,t,t.mode,l),e.ref=t.ref,e.return=t,t.child=e)}if(o=e.child,!(e.lanes&l)){var i=o.memoizedProps;if(n=n.compare,n=n!==null?n:Zn,n(i,r)&&e.ref===t.ref)return Je(e,t,l)}return t.flags|=1,e=mt(o,r),e.ref=t.ref,e.return=t,t.child=e}function mc(e,t,n,r,l){if(e!==null){var o=e.memoizedProps;if(Zn(o,r)&&e.ref===t.ref)if(de=!1,t.pendingProps=r=o,(e.lanes&l)!==0)e.flags&131072&&(de=!0);else return t.lanes=e.lanes,Je(e,t,l)}return Ko(e,t,n,r,l)}function vc(e,t,n){var r=t.pendingProps,l=r.children,o=e!==null?e.memoizedState:null;if(r.mode==="hidden")if(!(t.mode&1))t.memoizedState={baseLanes:0,cachePool:null,transitions:null},F(en,ve),ve|=n;else{if(!(n&1073741824))return e=o!==null?o.baseLanes|n:n,t.lanes=t.childLanes=1073741824,t.memoizedState={baseLanes:e,cachePool:null,transitions:null},t.updateQueue=null,F(en,ve),ve|=e,null;t.memoizedState={baseLanes:0,cachePool:null,transitions:null},r=o!==null?o.baseLanes:n,F(en,ve),ve|=r}else o!==null?(r=o.baseLanes|n,t.memoizedState=null):r=n,F(en,ve),ve|=r;return ue(e,t,l,n),t.child}function gc(e,t){var n=t.ref;(e===null&&n!==null||e!==null&&e.ref!==n)&&(t.flags|=512,t.flags|=2097152)}function Ko(e,t,n,r,l){var o=he(n)?Mt:ie.current;return o=sn(t,o),on(t,l),n=Wi(e,t,n,r,o,l),r=Hi(),e!==null&&!de?(t.updateQueue=e.updateQueue,t.flags&=-2053,e.lanes&=~l,Je(e,t,l)):(A&&r&&Ri(t),t.flags|=1,ue(e,t,n,l),t.child)}function ia(e,t,n,r,l){if(he(n)){var o=!0;rl(t)}else o=!1;if(on(t,l),t.stateNode===null)Wr(e,t),dc(t,n,r),Ho(t,n,r,l),r=!0;else if(e===null){var i=t.stateNode,u=t.memoizedProps;i.props=u;var a=i.context,s=n.contextType;typeof s=="object"&&s!==null?s=Ne(s):(s=he(n)?Mt:ie.current,s=sn(t,s));var h=n.getDerivedStateFromProps,d=typeof h=="function"||typeof i.getSnapshotBeforeUpdate=="function";d||typeof i.UNSAFE_componentWillReceiveProps!="function"&&typeof i.componentWillReceiveProps!="function"||(u!==r||a!==s)&&ea(t,i,r,s),nt=!1;var m=t.memoizedState;i.state=m,al(t,r,i,l),a=t.memoizedState,u!==r||m!==a||pe.current||nt?(typeof h=="function"&&(Wo(t,n,h,r),a=t.memoizedState),(u=nt||bu(t,n,u,r,m,a,s))?(d||typeof i.UNSAFE_componentWillMount!="function"&&typeof i.componentWillMount!="function"||(typeof i.componentWillMount=="function"&&i.componentWillMount(),typeof i.UNSAFE_componentWillMount=="function"&&i.UNSAFE_componentWillMount()),typeof i.componentDidMount=="function"&&(t.flags|=4194308)):(typeof i.componentDidMount=="function"&&(t.flags|=4194308),t.memoizedProps=r,t.memoizedState=a),i.props=r,i.state=a,i.context=s,r=u):(typeof i.componentDidMount=="function"&&(t.flags|=4194308),r=!1)}else{i=t.stateNode,Qs(e,t),u=t.memoizedProps,s=t.type===t.elementType?u:Le(t.type,u),i.props=s,d=t.pendingProps,m=i.context,a=n.contextType,typeof a=="object"&&a!==null?a=Ne(a):(a=he(n)?Mt:ie.current,a=sn(t,a));var w=n.getDerivedStateFromProps;(h=typeof w=="function"||typeof i.getSnapshotBeforeUpdate=="function")||typeof i.UNSAFE_componentWillReceiveProps!="function"&&typeof i.componentWillReceiveProps!="function"||(u!==d||m!==a)&&ea(t,i,r,a),nt=!1,m=t.memoizedState,i.state=m,al(t,r,i,l);var S=t.memoizedState;u!==d||m!==S||pe.current||nt?(typeof w=="function"&&(Wo(t,n,w,r),S=t.memoizedState),(s=nt||bu(t,n,s,r,m,S,a)||!1)?(h||typeof i.UNSAFE_componentWillUpdate!="function"&&typeof i.componentWillUpdate!="function"||(typeof i.componentWillUpdate=="function"&&i.componentWillUpdate(r,S,a),typeof i.UNSAFE_componentWillUpdate=="function"&&i.UNSAFE_componentWillUpdate(r,S,a)),typeof i.componentDidUpdate=="function"&&(t.flags|=4),typeof i.getSnapshotBeforeUpdate=="function"&&(t.flags|=1024)):(typeof i.componentDidUpdate!="function"||u===e.memoizedProps&&m===e.memoizedState||(t.flags|=4),typeof i.getSnapshotBeforeUpdate!="function"||u===e.memoizedProps&&m===e.memoizedState||(t.flags|=1024),t.memoizedProps=r,t.memoizedState=S),i.props=r,i.state=S,i.context=a,r=s):(typeof i.componentDidUpdate!="function"||u===e.memoizedProps&&m===e.memoizedState||(t.flags|=4),typeof i.getSnapshotBeforeUpdate!="function"||u===e.memoizedProps&&m===e.memoizedState||(t.flags|=1024),r=!1)}return Yo(e,t,n,r,o,l)}function Yo(e,t,n,r,l,o){gc(e,t);var i=(t.flags&128)!==0;if(!r&&!i)return l&&Qu(t,n,!1),Je(e,t,o);r=t.stateNode,ip.current=t;var u=i&&typeof n.getDerivedStateFromError!="function"?null:r.render();return t.flags|=1,e!==null&&i?(t.child=fn(t,e.child,null,o),t.child=fn(t,null,u,o)):ue(e,t,u,o),t.memoizedState=r.state,l&&Qu(t,n,!0),t.child}function yc(e){var t=e.stateNode;t.pendingContext?Hu(e,t.pendingContext,t.pendingContext!==t.context):t.context&&Hu(e,t.context,!1),Ai(e,t.containerInfo)}function ua(e,t,n,r,l){return cn(),Oi(l),t.flags|=256,ue(e,t,n,r),t.child}var Go={dehydrated:null,treeContext:null,retryLane:0};function Xo(e){return{baseLanes:e,cachePool:null,transitions:null}}function wc(e,t,n){var r=t.pendingProps,l=$.current,o=!1,i=(t.flags&128)!==0,u;if((u=i)||(u=e!==null&&e.memoizedState===null?!1:(l&2)!==0),u?(o=!0,t.flags&=-129):(e===null||e.memoizedState!==null)&&(l|=1),F($,l&1),e===null)return Bo(t),e=t.memoizedState,e!==null&&(e=e.dehydrated,e!==null)?(t.mode&1?e.data==="$!"?t.lanes=8:t.lanes=1073741824:t.lanes=1,null):(i=r.children,e=r.fallback,o?(r=t.mode,o=t.child,i={mode:"hidden",children:i},!(r&1)&&o!==null?(o.childLanes=0,o.pendingProps=i):o=Tl(i,r,0,null),e=Ot(e,r,n,null),o.return=t,e.return=t,o.sibling=e,t.child=o,t.child.memoizedState=Xo(n),t.memoizedState=Go,e):Yi(t,i));if(l=e.memoizedState,l!==null&&(u=l.dehydrated,u!==null))return up(e,t,i,r,u,l,n);if(o){o=r.fallback,i=t.mode,l=e.child,u=l.sibling;var a={mode:"hidden",children:r.children};return!(i&1)&&t.child!==l?(r=t.child,r.childLanes=0,r.pendingProps=a,t.deletions=null):(r=mt(l,a),r.subtreeFlags=l.subtreeFlags&14680064),u!==null?o=mt(u,o):(o=Ot(o,i,n,null),o.flags|=2),o.return=t,r.return=t,r.sibling=o,t.child=r,r=o,o=t.child,i=e.child.memoizedState,i=i===null?Xo(n):{baseLanes:i.baseLanes|n,cachePool:null,transitions:i.transitions},o.memoizedState=i,o.childLanes=e.childLanes&~n,t.memoizedState=Go,r}return o=e.child,e=o.sibling,r=mt(o,{mode:"visible",children:r.children}),!(t.mode&1)&&(r.lanes=n),r.return=t,r.sibling=null,e!==null&&(n=t.deletions,n===null?(t.deletions=[e],t.flags|=16):n.push(e)),t.child=r,t.memoizedState=null,r}function Yi(e,t){return t=Tl({mode:"visible",children:t},e.mode,0,null),t.return=e,e.child=t}function Lr(e,t,n,r){return r!==null&&Oi(r),fn(t,e.child,null,n),e=Yi(t,t.pendingProps.children),e.flags|=2,t.memoizedState=null,e}function up(e,t,n,r,l,o,i){if(n)return t.flags&256?(t.flags&=-257,r=io(Error(_(422))),Lr(e,t,i,r)):t.memoizedState!==null?(t.child=e.child,t.flags|=128,null):(o=r.fallback,l=t.mode,r=Tl({mode:"visible",children:r.children},l,0,null),o=Ot(o,l,i,null),o.flags|=2,r.return=t,o.return=t,r.sibling=o,t.child=r,t.mode&1&&fn(t,e.child,null,i),t.child.memoizedState=Xo(i),t.memoizedState=Go,o);if(!(t.mode&1))return Lr(e,t,i,null);if(l.data==="$!"){if(r=l.nextSibling&&l.nextSibling.dataset,r)var u=r.dgst;return r=u,o=Error(_(419)),r=io(o,r,void 0),Lr(e,t,i,r)}if(u=(i&e.childLanes)!==0,de||u){if(r=b,r!==null){switch(i&-i){case 4:l=2;break;case 16:l=8;break;case 64:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:case 4194304:case 8388608:case 16777216:case 33554432:case 67108864:l=32;break;case 536870912:l=268435456;break;default:l=0}l=l&(r.suspendedLanes|i)?0:l,l!==0&&l!==o.retryLane&&(o.retryLane=l,Xe(e,l),Me(r,e,l,-1))}return bi(),r=io(Error(_(421))),Lr(e,t,i,r)}return l.data==="$?"?(t.flags|=128,t.child=e.child,t=Sp.bind(null,e),l._reactRetry=t,null):(e=o.treeContext,ge=ft(l.nextSibling),ye=t,A=!0,ze=null,e!==null&&(xe[_e++]=We,xe[_e++]=He,xe[_e++]=Dt,We=e.id,He=e.overflow,Dt=t),t=Yi(t,r.children),t.flags|=4096,t)}function aa(e,t,n){e.lanes|=t;var r=e.alternate;r!==null&&(r.lanes|=t),Vo(e.return,t,n)}function uo(e,t,n,r,l){var o=e.memoizedState;o===null?e.memoizedState={isBackwards:t,rendering:null,renderingStartTime:0,last:r,tail:n,tailMode:l}:(o.isBackwards=t,o.rendering=null,o.renderingStartTime=0,o.last=r,o.tail=n,o.tailMode=l)}function Sc(e,t,n){var r=t.pendingProps,l=r.revealOrder,o=r.tail;if(ue(e,t,r.children,n),r=$.current,r&2)r=r&1|2,t.flags|=128;else{if(e!==null&&e.flags&128)e:for(e=t.child;e!==null;){if(e.tag===13)e.memoizedState!==null&&aa(e,n,t);else if(e.tag===19)aa(e,n,t);else if(e.child!==null){e.child.return=e,e=e.child;continue}if(e===t)break e;for(;e.sibling===null;){if(e.return===null||e.return===t)break e;e=e.return}e.sibling.return=e.return,e=e.sibling}r&=1}if(F($,r),!(t.mode&1))t.memoizedState=null;else switch(l){case"forwards":for(n=t.child,l=null;n!==null;)e=n.alternate,e!==null&&sl(e)===null&&(l=n),n=n.sibling;n=l,n===null?(l=t.child,t.child=null):(l=n.sibling,n.sibling=null),uo(t,!1,l,n,o);break;case"backwards":for(n=null,l=t.child,t.child=null;l!==null;){if(e=l.alternate,e!==null&&sl(e)===null){t.child=l;break}e=l.sibling,l.sibling=n,n=l,l=e}uo(t,!0,n,null,o);break;case"together":uo(t,!1,null,null,void 0);break;default:t.memoizedState=null}return t.child}function Wr(e,t){!(t.mode&1)&&e!==null&&(e.alternate=null,t.alternate=null,t.flags|=2)}function Je(e,t,n){if(e!==null&&(t.dependencies=e.dependencies),It|=t.lanes,!(n&t.childLanes))return null;if(e!==null&&t.child!==e.child)throw Error(_(153));if(t.child!==null){for(e=t.child,n=mt(e,e.pendingProps),t.child=n,n.return=t;e.sibling!==null;)e=e.sibling,n=n.sibling=mt(e,e.pendingProps),n.return=t;n.sibling=null}return t.child}function ap(e,t,n){switch(t.tag){case 3:yc(t),cn();break;case 5:Ks(t);break;case 1:he(t.type)&&rl(t);break;case 4:Ai(t,t.stateNode.containerInfo);break;case 10:var r=t.type._context,l=t.memoizedProps.value;F(il,r._currentValue),r._currentValue=l;break;case 13:if(r=t.memoizedState,r!==null)return r.dehydrated!==null?(F($,$.current&1),t.flags|=128,null):n&t.child.childLanes?wc(e,t,n):(F($,$.current&1),e=Je(e,t,n),e!==null?e.sibling:null);F($,$.current&1);break;case 19:if(r=(n&t.childLanes)!==0,e.flags&128){if(r)return Sc(e,t,n);t.flags|=128}if(l=t.memoizedState,l!==null&&(l.rendering=null,l.tail=null,l.lastEffect=null),F($,$.current),r)break;return null;case 22:case 23:return t.lanes=0,vc(e,t,n)}return Je(e,t,n)}var kc,Jo,xc,_c;kc=function(e,t){for(var n=t.child;n!==null;){if(n.tag===5||n.tag===6)e.appendChild(n.stateNode);else if(n.tag!==4&&n.child!==null){n.child.return=n,n=n.child;continue}if(n===t)break;for(;n.sibling===null;){if(n.return===null||n.return===t)return;n=n.return}n.sibling.return=n.return,n=n.sibling}};Jo=function(){};xc=function(e,t,n,r){var l=e.memoizedProps;if(l!==r){e=t.stateNode,Rt($e.current);var o=null;switch(n){case"input":l=yo(e,l),r=yo(e,r),o=[];break;case"select":l=V({},l,{value:void 0}),r=V({},r,{value:void 0}),o=[];break;case"textarea":l=ko(e,l),r=ko(e,r),o=[];break;default:typeof l.onClick!="function"&&typeof r.onClick=="function"&&(e.onclick=tl)}_o(n,r);var i;n=null;for(s in l)if(!r.hasOwnProperty(s)&&l.hasOwnProperty(s)&&l[s]!=null)if(s==="style"){var u=l[s];for(i in u)u.hasOwnProperty(i)&&(n||(n={}),n[i]="")}else s!=="dangerouslySetInnerHTML"&&s!=="children"&&s!=="suppressContentEditableWarning"&&s!=="suppressHydrationWarning"&&s!=="autoFocus"&&(Hn.hasOwnProperty(s)?o||(o=[]):(o=o||[]).push(s,null));for(s in r){var a=r[s];if(u=l!=null?l[s]:void 0,r.hasOwnProperty(s)&&a!==u&&(a!=null||u!=null))if(s==="style")if(u){for(i in u)!u.hasOwnProperty(i)||a&&a.hasOwnProperty(i)||(n||(n={}),n[i]="");for(i in a)a.hasOwnProperty(i)&&u[i]!==a[i]&&(n||(n={}),n[i]=a[i])}else n||(o||(o=[]),o.push(s,n)),n=a;else s==="dangerouslySetInnerHTML"?(a=a?a.__html:void 0,u=u?u.__html:void 0,a!=null&&u!==a&&(o=o||[]).push(s,a)):s==="children"?typeof a!="string"&&typeof a!="number"||(o=o||[]).push(s,""+a):s!=="suppressContentEditableWarning"&&s!=="suppressHydrationWarning"&&(Hn.hasOwnProperty(s)?(a!=null&&s==="onScroll"&&I("scroll",e),o||u===a||(o=[])):(o=o||[]).push(s,a))}n&&(o=o||[]).push("style",n);var s=o;(t.updateQueue=s)&&(t.flags|=4)}};_c=function(e,t,n,r){n!==r&&(t.flags|=4)};function Tn(e,t){if(!A)switch(e.tailMode){case"hidden":t=e.tail;for(var n=null;t!==null;)t.alternate!==null&&(n=t),t=t.sibling;n===null?e.tail=null:n.sibling=null;break;case"collapsed":n=e.tail;for(var r=null;n!==null;)n.alternate!==null&&(r=n),n=n.sibling;r===null?t||e.tail===null?e.tail=null:e.tail.sibling=null:r.sibling=null}}function le(e){var t=e.alternate!==null&&e.alternate.child===e.child,n=0,r=0;if(t)for(var l=e.child;l!==null;)n|=l.lanes|l.childLanes,r|=l.subtreeFlags&14680064,r|=l.flags&14680064,l.return=e,l=l.sibling;else for(l=e.child;l!==null;)n|=l.lanes|l.childLanes,r|=l.subtreeFlags,r|=l.flags,l.return=e,l=l.sibling;return e.subtreeFlags|=r,e.childLanes=n,t}function sp(e,t,n){var r=t.pendingProps;switch(zi(t),t.tag){case 2:case 16:case 15:case 0:case 11:case 7:case 8:case 12:case 9:case 14:return le(t),null;case 1:return he(t.type)&&nl(),le(t),null;case 3:return r=t.stateNode,dn(),U(pe),U(ie),Bi(),r.pendingContext&&(r.context=r.pendingContext,r.pendingContext=null),(e===null||e.child===null)&&(jr(t)?t.flags|=4:e===null||e.memoizedState.isDehydrated&&!(t.flags&256)||(t.flags|=1024,ze!==null&&(li(ze),ze=null))),Jo(e,t),le(t),null;case 5:$i(t);var l=Rt(nr.current);if(n=t.type,e!==null&&t.stateNode!=null)xc(e,t,n,r,l),e.ref!==t.ref&&(t.flags|=512,t.flags|=2097152);else{if(!r){if(t.stateNode===null)throw Error(_(166));return le(t),null}if(e=Rt($e.current),jr(t)){r=t.stateNode,n=t.type;var o=t.memoizedProps;switch(r[Ue]=t,r[er]=o,e=(t.mode&1)!==0,n){case"dialog":I("cancel",r),I("close",r);break;case"iframe":case"object":case"embed":I("load",r);break;case"video":case"audio":for(l=0;l<Mn.length;l++)I(Mn[l],r);break;case"source":I("error",r);break;case"img":case"image":case"link":I("error",r),I("load",r);break;case"details":I("toggle",r);break;case"input":gu(r,o),I("invalid",r);break;case"select":r._wrapperState={wasMultiple:!!o.multiple},I("invalid",r);break;case"textarea":wu(r,o),I("invalid",r)}_o(n,o),l=null;for(var i in o)if(o.hasOwnProperty(i)){var u=o[i];i==="children"?typeof u=="string"?r.textContent!==u&&(o.suppressHydrationWarning!==!0&&Pr(r.textContent,u,e),l=["children",u]):typeof u=="number"&&r.textContent!==""+u&&(o.suppressHydrationWarning!==!0&&Pr(r.textContent,u,e),l=["children",""+u]):Hn.hasOwnProperty(i)&&u!=null&&i==="onScroll"&&I("scroll",r)}switch(n){case"input":wr(r),yu(r,o,!0);break;case"textarea":wr(r),Su(r);break;case"select":case"option":break;default:typeof o.onClick=="function"&&(r.onclick=tl)}r=l,t.updateQueue=r,r!==null&&(t.flags|=4)}else{i=l.nodeType===9?l:l.ownerDocument,e==="http://www.w3.org/1999/xhtml"&&(e=Za(n)),e==="http://www.w3.org/1999/xhtml"?n==="script"?(e=i.createElement("div"),e.innerHTML="<script><\/script>",e=e.removeChild(e.firstChild)):typeof r.is=="string"?e=i.createElement(n,{is:r.is}):(e=i.createElement(n),n==="select"&&(i=e,r.multiple?i.multiple=!0:r.size&&(i.size=r.size))):e=i.createElementNS(e,n),e[Ue]=t,e[er]=r,kc(e,t,!1,!1),t.stateNode=e;e:{switch(i=Eo(n,r),n){case"dialog":I("cancel",e),I("close",e),l=r;break;case"iframe":case"object":case"embed":I("load",e),l=r;break;case"video":case"audio":for(l=0;l<Mn.length;l++)I(Mn[l],e);l=r;break;case"source":I("error",e),l=r;break;case"img":case"image":case"link":I("error",e),I("load",e),l=r;break;case"details":I("toggle",e),l=r;break;case"input":gu(e,r),l=yo(e,r),I("invalid",e);break;case"option":l=r;break;case"select":e._wrapperState={wasMultiple:!!r.multiple},l=V({},r,{value:void 0}),I("invalid",e);break;case"textarea":wu(e,r),l=ko(e,r),I("invalid",e);break;default:l=r}_o(n,l),u=l;for(o in u)if(u.hasOwnProperty(o)){var a=u[o];o==="style"?es(e,a):o==="dangerouslySetInnerHTML"?(a=a?a.__html:void 0,a!=null&&qa(e,a)):o==="children"?typeof a=="string"?(n!=="textarea"||a!=="")&&Qn(e,a):typeof a=="number"&&Qn(e,""+a):o!=="suppressContentEditableWarning"&&o!=="suppressHydrationWarning"&&o!=="autoFocus"&&(Hn.hasOwnProperty(o)?a!=null&&o==="onScroll"&&I("scroll",e):a!=null&&gi(e,o,a,i))}switch(n){case"input":wr(e),yu(e,r,!1);break;case"textarea":wr(e),Su(e);break;case"option":r.value!=null&&e.setAttribute("value",""+gt(r.value));break;case"select":e.multiple=!!r.multiple,o=r.value,o!=null?tn(e,!!r.multiple,o,!1):r.defaultValue!=null&&tn(e,!!r.multiple,r.defaultValue,!0);break;default:typeof l.onClick=="function"&&(e.onclick=tl)}switch(n){case"button":case"input":case"select":case"textarea":r=!!r.autoFocus;break e;case"img":r=!0;break e;default:r=!1}}r&&(t.flags|=4)}t.ref!==null&&(t.flags|=512,t.flags|=2097152)}return le(t),null;case 6:if(e&&t.stateNode!=null)_c(e,t,e.memoizedProps,r);else{if(typeof r!="string"&&t.stateNode===null)throw Error(_(166));if(n=Rt(nr.current),Rt($e.current),jr(t)){if(r=t.stateNode,n=t.memoizedProps,r[Ue]=t,(o=r.nodeValue!==n)&&(e=ye,e!==null))switch(e.tag){case 3:Pr(r.nodeValue,n,(e.mode&1)!==0);break;case 5:e.memoizedProps.suppressHydrationWarning!==!0&&Pr(r.nodeValue,n,(e.mode&1)!==0)}o&&(t.flags|=4)}else r=(n.nodeType===9?n:n.ownerDocument).createTextNode(r),r[Ue]=t,t.stateNode=r}return le(t),null;case 13:if(U($),r=t.memoizedState,e===null||e.memoizedState!==null&&e.memoizedState.dehydrated!==null){if(A&&ge!==null&&t.mode&1&&!(t.flags&128))Bs(),cn(),t.flags|=98560,o=!1;else if(o=jr(t),r!==null&&r.dehydrated!==null){if(e===null){if(!o)throw Error(_(318));if(o=t.memoizedState,o=o!==null?o.dehydrated:null,!o)throw Error(_(317));o[Ue]=t}else cn(),!(t.flags&128)&&(t.memoizedState=null),t.flags|=4;le(t),o=!1}else ze!==null&&(li(ze),ze=null),o=!0;if(!o)return t.flags&65536?t:null}return t.flags&128?(t.lanes=n,t):(r=r!==null,r!==(e!==null&&e.memoizedState!==null)&&r&&(t.child.flags|=8192,t.mode&1&&(e===null||$.current&1?J===0&&(J=3):bi())),t.updateQueue!==null&&(t.flags|=4),le(t),null);case 4:return dn(),Jo(e,t),e===null&&qn(t.stateNode.containerInfo),le(t),null;case 10:return Fi(t.type._context),le(t),null;case 17:return he(t.type)&&nl(),le(t),null;case 19:if(U($),o=t.memoizedState,o===null)return le(t),null;if(r=(t.flags&128)!==0,i=o.rendering,i===null)if(r)Tn(o,!1);else{if(J!==0||e!==null&&e.flags&128)for(e=t.child;e!==null;){if(i=sl(e),i!==null){for(t.flags|=128,Tn(o,!1),r=i.updateQueue,r!==null&&(t.updateQueue=r,t.flags|=4),t.subtreeFlags=0,r=n,n=t.child;n!==null;)o=n,e=r,o.flags&=14680066,i=o.alternate,i===null?(o.childLanes=0,o.lanes=e,o.child=null,o.subtreeFlags=0,o.memoizedProps=null,o.memoizedState=null,o.updateQueue=null,o.dependencies=null,o.stateNode=null):(o.childLanes=i.childLanes,o.lanes=i.lanes,o.child=i.child,o.subtreeFlags=0,o.deletions=null,o.memoizedProps=i.memoizedProps,o.memoizedState=i.memoizedState,o.updateQueue=i.updateQueue,o.type=i.type,e=i.dependencies,o.dependencies=e===null?null:{lanes:e.lanes,firstContext:e.firstContext}),n=n.sibling;return F($,$.current&1|2),t.child}e=e.sibling}o.tail!==null&&K()>hn&&(t.flags|=128,r=!0,Tn(o,!1),t.lanes=4194304)}else{if(!r)if(e=sl(i),e!==null){if(t.flags|=128,r=!0,n=e.updateQueue,n!==null&&(t.updateQueue=n,t.flags|=4),Tn(o,!0),o.tail===null&&o.tailMode==="hidden"&&!i.alternate&&!A)return le(t),null}else 2*K()-o.renderingStartTime>hn&&n!==1073741824&&(t.flags|=128,r=!0,Tn(o,!1),t.lanes=4194304);o.isBackwards?(i.sibling=t.child,t.child=i):(n=o.last,n!==null?n.sibling=i:t.child=i,o.last=i)}return o.tail!==null?(t=o.tail,o.rendering=t,o.tail=t.sibling,o.renderingStartTime=K(),t.sibling=null,n=$.current,F($,r?n&1|2:n&1),t):(le(t),null);case 22:case 23:return qi(),r=t.memoizedState!==null,e!==null&&e.memoizedState!==null!==r&&(t.flags|=8192),r&&t.mode&1?ve&1073741824&&(le(t),t.subtreeFlags&6&&(t.flags|=8192)):le(t),null;case 24:return null;case 25:return null}throw Error(_(156,t.tag))}function cp(e,t){switch(zi(t),t.tag){case 1:return he(t.type)&&nl(),e=t.flags,e&65536?(t.flags=e&-65537|128,t):null;case 3:return dn(),U(pe),U(ie),Bi(),e=t.flags,e&65536&&!(e&128)?(t.flags=e&-65537|128,t):null;case 5:return $i(t),null;case 13:if(U($),e=t.memoizedState,e!==null&&e.dehydrated!==null){if(t.alternate===null)throw Error(_(340));cn()}return e=t.flags,e&65536?(t.flags=e&-65537|128,t):null;case 19:return U($),null;case 4:return dn(),null;case 10:return Fi(t.type._context),null;case 22:case 23:return qi(),null;case 24:return null;default:return null}}var Rr=!1,oe=!1,fp=typeof WeakSet=="function"?WeakSet:Set,C=null;function bt(e,t){var n=e.ref;if(n!==null)if(typeof n=="function")try{n(null)}catch(r){W(e,t,r)}else n.current=null}function Zo(e,t,n){try{n()}catch(r){W(e,t,r)}}var sa=!1;function dp(e,t){if(Mo=qr,e=js(),Li(e)){if("selectionStart"in e)var n={start:e.selectionStart,end:e.selectionEnd};else e:{n=(n=e.ownerDocument)&&n.defaultView||window;var r=n.getSelection&&n.getSelection();if(r&&r.rangeCount!==0){n=r.anchorNode;var l=r.anchorOffset,o=r.focusNode;r=r.focusOffset;try{n.nodeType,o.nodeType}catch{n=null;break e}var i=0,u=-1,a=-1,s=0,h=0,d=e,m=null;t:for(;;){for(var w;d!==n||l!==0&&d.nodeType!==3||(u=i+l),d!==o||r!==0&&d.nodeType!==3||(a=i+r),d.nodeType===3&&(i+=d.nodeValue.length),(w=d.firstChild)!==null;)m=d,d=w;for(;;){if(d===e)break t;if(m===n&&++s===l&&(u=i),m===o&&++h===r&&(a=i),(w=d.nextSibling)!==null)break;d=m,m=d.parentNode}d=w}n=u===-1||a===-1?null:{start:u,end:a}}else n=null}n=n||{start:0,end:0}}else n=null;for(Do={focusedElem:e,selectionRange:n},qr=!1,C=t;C!==null;)if(t=C,e=t.child,(t.subtreeFlags&1028)!==0&&e!==null)e.return=t,C=e;else for(;C!==null;){t=C;try{var S=t.alternate;if(t.flags&1024)switch(t.tag){case 0:case 11:case 15:break;case 1:if(S!==null){var g=S.memoizedProps,x=S.memoizedState,f=t.stateNode,c=f.getSnapshotBeforeUpdate(t.elementType===t.type?g:Le(t.type,g),x);f.__reactInternalSnapshotBeforeUpdate=c}break;case 3:var p=t.stateNode.containerInfo;p.nodeType===1?p.textContent="":p.nodeType===9&&p.documentElement&&p.removeChild(p.documentElement);break;case 5:case 6:case 4:case 17:break;default:throw Error(_(163))}}catch(k){W(t,t.return,k)}if(e=t.sibling,e!==null){e.return=t.return,C=e;break}C=t.return}return S=sa,sa=!1,S}function Bn(e,t,n){var r=t.updateQueue;if(r=r!==null?r.lastEffect:null,r!==null){var l=r=r.next;do{if((l.tag&e)===e){var o=l.destroy;l.destroy=void 0,o!==void 0&&Zo(t,n,o)}l=l.next}while(l!==r)}}function Pl(e,t){if(t=t.updateQueue,t=t!==null?t.lastEffect:null,t!==null){var n=t=t.next;do{if((n.tag&e)===e){var r=n.create;n.destroy=r()}n=n.next}while(n!==t)}}function qo(e){var t=e.ref;if(t!==null){var n=e.stateNode;switch(e.tag){case 5:e=n;break;default:e=n}typeof t=="function"?t(e):t.current=e}}function Ec(e){var t=e.alternate;t!==null&&(e.alternate=null,Ec(t)),e.child=null,e.deletions=null,e.sibling=null,e.tag===5&&(t=e.stateNode,t!==null&&(delete t[Ue],delete t[er],delete t[Uo],delete t[Gd],delete t[Xd])),e.stateNode=null,e.return=null,e.dependencies=null,e.memoizedProps=null,e.memoizedState=null,e.pendingProps=null,e.stateNode=null,e.updateQueue=null}function Cc(e){return e.tag===5||e.tag===3||e.tag===4}function ca(e){e:for(;;){for(;e.sibling===null;){if(e.return===null||Cc(e.return))return null;e=e.return}for(e.sibling.return=e.return,e=e.sibling;e.tag!==5&&e.tag!==6&&e.tag!==18;){if(e.flags&2||e.child===null||e.tag===4)continue e;e.child.return=e,e=e.child}if(!(e.flags&2))return e.stateNode}}function bo(e,t,n){var r=e.tag;if(r===5||r===6)e=e.stateNode,t?n.nodeType===8?n.parentNode.insertBefore(e,t):n.insertBefore(e,t):(n.nodeType===8?(t=n.parentNode,t.insertBefore(e,n)):(t=n,t.appendChild(e)),n=n._reactRootContainer,n!=null||t.onclick!==null||(t.onclick=tl));else if(r!==4&&(e=e.child,e!==null))for(bo(e,t,n),e=e.sibling;e!==null;)bo(e,t,n),e=e.sibling}function ei(e,t,n){var r=e.tag;if(r===5||r===6)e=e.stateNode,t?n.insertBefore(e,t):n.appendChild(e);else if(r!==4&&(e=e.child,e!==null))for(ei(e,t,n),e=e.sibling;e!==null;)ei(e,t,n),e=e.sibling}var ee=null,Re=!1;function be(e,t,n){for(n=n.child;n!==null;)Nc(e,t,n),n=n.sibling}function Nc(e,t,n){if(Ae&&typeof Ae.onCommitFiberUnmount=="function")try{Ae.onCommitFiberUnmount(wl,n)}catch{}switch(n.tag){case 5:oe||bt(n,t);case 6:var r=ee,l=Re;ee=null,be(e,t,n),ee=r,Re=l,ee!==null&&(Re?(e=ee,n=n.stateNode,e.nodeType===8?e.parentNode.removeChild(n):e.removeChild(n)):ee.removeChild(n.stateNode));break;case 18:ee!==null&&(Re?(e=ee,n=n.stateNode,e.nodeType===8?eo(e.parentNode,n):e.nodeType===1&&eo(e,n),Xn(e)):eo(ee,n.stateNode));break;case 4:r=ee,l=Re,ee=n.stateNode.containerInfo,Re=!0,be(e,t,n),ee=r,Re=l;break;case 0:case 11:case 14:case 15:if(!oe&&(r=n.updateQueue,r!==null&&(r=r.lastEffect,r!==null))){l=r=r.next;do{var o=l,i=o.destroy;o=o.tag,i!==void 0&&(o&2||o&4)&&Zo(n,t,i),l=l.next}while(l!==r)}be(e,t,n);break;case 1:if(!oe&&(bt(n,t),r=n.stateNode,typeof r.componentWillUnmount=="function"))try{r.props=n.memoizedProps,r.state=n.memoizedState,r.componentWillUnmount()}catch(u){W(n,t,u)}be(e,t,n);break;case 21:be(e,t,n);break;case 22:n.mode&1?(oe=(r=oe)||n.memoizedState!==null,be(e,t,n),oe=r):be(e,t,n);break;default:be(e,t,n)}}function fa(e){var t=e.updateQueue;if(t!==null){e.updateQueue=null;var n=e.stateNode;n===null&&(n=e.stateNode=new fp),t.forEach(function(r){var l=kp.bind(null,e,r);n.has(r)||(n.add(r),r.then(l,l))})}}function Te(e,t){var n=t.deletions;if(n!==null)for(var r=0;r<n.length;r++){var l=n[r];try{var o=e,i=t,u=i;e:for(;u!==null;){switch(u.tag){case 5:ee=u.stateNode,Re=!1;break e;case 3:ee=u.stateNode.containerInfo,Re=!0;break e;case 4:ee=u.stateNode.containerInfo,Re=!0;break e}u=u.return}if(ee===null)throw Error(_(160));Nc(o,i,l),ee=null,Re=!1;var a=l.alternate;a!==null&&(a.return=null),l.return=null}catch(s){W(l,t,s)}}if(t.subtreeFlags&12854)for(t=t.child;t!==null;)Pc(t,e),t=t.sibling}function Pc(e,t){var n=e.alternate,r=e.flags;switch(e.tag){case 0:case 11:case 14:case 15:if(Te(t,e),Fe(e),r&4){try{Bn(3,e,e.return),Pl(3,e)}catch(g){W(e,e.return,g)}try{Bn(5,e,e.return)}catch(g){W(e,e.return,g)}}break;case 1:Te(t,e),Fe(e),r&512&&n!==null&&bt(n,n.return);break;case 5:if(Te(t,e),Fe(e),r&512&&n!==null&&bt(n,n.return),e.flags&32){var l=e.stateNode;try{Qn(l,"")}catch(g){W(e,e.return,g)}}if(r&4&&(l=e.stateNode,l!=null)){var o=e.memoizedProps,i=n!==null?n.memoizedProps:o,u=e.type,a=e.updateQueue;if(e.updateQueue=null,a!==null)try{u==="input"&&o.type==="radio"&&o.name!=null&&Xa(l,o),Eo(u,i);var s=Eo(u,o);for(i=0;i<a.length;i+=2){var h=a[i],d=a[i+1];h==="style"?es(l,d):h==="dangerouslySetInnerHTML"?qa(l,d):h==="children"?Qn(l,d):gi(l,h,d,s)}switch(u){case"input":wo(l,o);break;case"textarea":Ja(l,o);break;case"select":var m=l._wrapperState.wasMultiple;l._wrapperState.wasMultiple=!!o.multiple;var w=o.value;w!=null?tn(l,!!o.multiple,w,!1):m!==!!o.multiple&&(o.defaultValue!=null?tn(l,!!o.multiple,o.defaultValue,!0):tn(l,!!o.multiple,o.multiple?[]:"",!1))}l[er]=o}catch(g){W(e,e.return,g)}}break;case 6:if(Te(t,e),Fe(e),r&4){if(e.stateNode===null)throw Error(_(162));l=e.stateNode,o=e.memoizedProps;try{l.nodeValue=o}catch(g){W(e,e.return,g)}}break;case 3:if(Te(t,e),Fe(e),r&4&&n!==null&&n.memoizedState.isDehydrated)try{Xn(t.containerInfo)}catch(g){W(e,e.return,g)}break;case 4:Te(t,e),Fe(e);break;case 13:Te(t,e),Fe(e),l=e.child,l.flags&8192&&(o=l.memoizedState!==null,l.stateNode.isHidden=o,!o||l.alternate!==null&&l.alternate.memoizedState!==null||(Ji=K())),r&4&&fa(e);break;case 22:if(h=n!==null&&n.memoizedState!==null,e.mode&1?(oe=(s=oe)||h,Te(t,e),oe=s):Te(t,e),Fe(e),r&8192){if(s=e.memoizedState!==null,(e.stateNode.isHidden=s)&&!h&&e.mode&1)for(C=e,h=e.child;h!==null;){for(d=C=h;C!==null;){switch(m=C,w=m.child,m.tag){case 0:case 11:case 14:case 15:Bn(4,m,m.return);break;case 1:bt(m,m.return);var S=m.stateNode;if(typeof S.componentWillUnmount=="function"){r=m,n=m.return;try{t=r,S.props=t.memoizedProps,S.state=t.memoizedState,S.componentWillUnmount()}catch(g){W(r,n,g)}}break;case 5:bt(m,m.return);break;case 22:if(m.memoizedState!==null){pa(d);continue}}w!==null?(w.return=m,C=w):pa(d)}h=h.sibling}e:for(h=null,d=e;;){if(d.tag===5){if(h===null){h=d;try{l=d.stateNode,s?(o=l.style,typeof o.setProperty=="function"?o.setProperty("display","none","important"):o.display="none"):(u=d.stateNode,a=d.memoizedProps.style,i=a!=null&&a.hasOwnProperty("display")?a.display:null,u.style.display=ba("display",i))}catch(g){W(e,e.return,g)}}}else if(d.tag===6){if(h===null)try{d.stateNode.nodeValue=s?"":d.memoizedProps}catch(g){W(e,e.return,g)}}else if((d.tag!==22&&d.tag!==23||d.memoizedState===null||d===e)&&d.child!==null){d.child.return=d,d=d.child;continue}if(d===e)break e;for(;d.sibling===null;){if(d.return===null||d.return===e)break e;h===d&&(h=null),d=d.return}h===d&&(h=null),d.sibling.return=d.return,d=d.sibling}}break;case 19:Te(t,e),Fe(e),r&4&&fa(e);break;case 21:break;default:Te(t,e),Fe(e)}}function Fe(e){var t=e.flags;if(t&2){try{e:{for(var n=e.return;n!==null;){if(Cc(n)){var r=n;break e}n=n.return}throw Error(_(160))}switch(r.tag){case 5:var l=r.stateNode;r.flags&32&&(Qn(l,""),r.flags&=-33);var o=ca(e);ei(e,o,l);break;case 3:case 4:var i=r.stateNode.containerInfo,u=ca(e);bo(e,u,i);break;default:throw Error(_(161))}}catch(a){W(e,e.return,a)}e.flags&=-3}t&4096&&(e.flags&=-4097)}function pp(e,t,n){C=e,jc(e)}function jc(e,t,n){for(var r=(e.mode&1)!==0;C!==null;){var l=C,o=l.child;if(l.tag===22&&r){var i=l.memoizedState!==null||Rr;if(!i){var u=l.alternate,a=u!==null&&u.memoizedState!==null||oe;u=Rr;var s=oe;if(Rr=i,(oe=a)&&!s)for(C=l;C!==null;)i=C,a=i.child,i.tag===22&&i.memoizedState!==null?ha(l):a!==null?(a.return=i,C=a):ha(l);for(;o!==null;)C=o,jc(o),o=o.sibling;C=l,Rr=u,oe=s}da(e)}else l.subtreeFlags&8772&&o!==null?(o.return=l,C=o):da(e)}}function da(e){for(;C!==null;){var t=C;if(t.flags&8772){var n=t.alternate;try{if(t.flags&8772)switch(t.tag){case 0:case 11:case 15:oe||Pl(5,t);break;case 1:var r=t.stateNode;if(t.flags&4&&!oe)if(n===null)r.componentDidMount();else{var l=t.elementType===t.type?n.memoizedProps:Le(t.type,n.memoizedProps);r.componentDidUpdate(l,n.memoizedState,r.__reactInternalSnapshotBeforeUpdate)}var o=t.updateQueue;o!==null&&Ju(t,o,r);break;case 3:var i=t.updateQueue;if(i!==null){if(n=null,t.child!==null)switch(t.child.tag){case 5:n=t.child.stateNode;break;case 1:n=t.child.stateNode}Ju(t,i,n)}break;case 5:var u=t.stateNode;if(n===null&&t.flags&4){n=u;var a=t.memoizedProps;switch(t.type){case"button":case"input":case"select":case"textarea":a.autoFocus&&n.focus();break;case"img":a.src&&(n.src=a.src)}}break;case 6:break;case 4:break;case 12:break;case 13:if(t.memoizedState===null){var s=t.alternate;if(s!==null){var h=s.memoizedState;if(h!==null){var d=h.dehydrated;d!==null&&Xn(d)}}}break;case 19:case 17:case 21:case 22:case 23:case 25:break;default:throw Error(_(163))}oe||t.flags&512&&qo(t)}catch(m){W(t,t.return,m)}}if(t===e){C=null;break}if(n=t.sibling,n!==null){n.return=t.return,C=n;break}C=t.return}}function pa(e){for(;C!==null;){var t=C;if(t===e){C=null;break}var n=t.sibling;if(n!==null){n.return=t.return,C=n;break}C=t.return}}function ha(e){for(;C!==null;){var t=C;try{switch(t.tag){case 0:case 11:case 15:var n=t.return;try{Pl(4,t)}catch(a){W(t,n,a)}break;case 1:var r=t.stateNode;if(typeof r.componentDidMount=="function"){var l=t.return;try{r.componentDidMount()}catch(a){W(t,l,a)}}var o=t.return;try{qo(t)}catch(a){W(t,o,a)}break;case 5:var i=t.return;try{qo(t)}catch(a){W(t,i,a)}}}catch(a){W(t,t.return,a)}if(t===e){C=null;break}var u=t.sibling;if(u!==null){u.return=t.return,C=u;break}C=t.return}}var hp=Math.ceil,dl=Ze.ReactCurrentDispatcher,Gi=Ze.ReactCurrentOwner,Ce=Ze.ReactCurrentBatchConfig,M=0,b=null,G=null,te=0,ve=0,en=St(0),J=0,ir=null,It=0,jl=0,Xi=0,Vn=null,fe=null,Ji=0,hn=1/0,Be=null,pl=!1,ti=null,pt=null,zr=!1,it=null,hl=0,Wn=0,ni=null,Hr=-1,Qr=0;function ae(){return M&6?K():Hr!==-1?Hr:Hr=K()}function ht(e){return e.mode&1?M&2&&te!==0?te&-te:Zd.transition!==null?(Qr===0&&(Qr=ds()),Qr):(e=D,e!==0||(e=window.event,e=e===void 0?16:ws(e.type)),e):1}function Me(e,t,n,r){if(50<Wn)throw Wn=0,ni=null,Error(_(185));cr(e,n,r),(!(M&2)||e!==b)&&(e===b&&(!(M&2)&&(jl|=n),J===4&&lt(e,te)),me(e,r),n===1&&M===0&&!(t.mode&1)&&(hn=K()+500,El&&kt()))}function me(e,t){var n=e.callbackNode;Zf(e,t);var r=Zr(e,e===b?te:0);if(r===0)n!==null&&_u(n),e.callbackNode=null,e.callbackPriority=0;else if(t=r&-r,e.callbackPriority!==t){if(n!=null&&_u(n),t===1)e.tag===0?Jd(ma.bind(null,e)):Us(ma.bind(null,e)),Kd(function(){!(M&6)&&kt()}),n=null;else{switch(ps(r)){case 1:n=xi;break;case 4:n=cs;break;case 16:n=Jr;break;case 536870912:n=fs;break;default:n=Jr}n=Fc(n,Tc.bind(null,e))}e.callbackPriority=t,e.callbackNode=n}}function Tc(e,t){if(Hr=-1,Qr=0,M&6)throw Error(_(327));var n=e.callbackNode;if(un()&&e.callbackNode!==n)return null;var r=Zr(e,e===b?te:0);if(r===0)return null;if(r&30||r&e.expiredLanes||t)t=ml(e,r);else{t=r;var l=M;M|=2;var o=Rc();(b!==e||te!==t)&&(Be=null,hn=K()+500,zt(e,t));do try{gp();break}catch(u){Lc(e,u)}while(!0);Di(),dl.current=o,M=l,G!==null?t=0:(b=null,te=0,t=J)}if(t!==0){if(t===2&&(l=To(e),l!==0&&(r=l,t=ri(e,l))),t===1)throw n=ir,zt(e,0),lt(e,r),me(e,K()),n;if(t===6)lt(e,r);else{if(l=e.current.alternate,!(r&30)&&!mp(l)&&(t=ml(e,r),t===2&&(o=To(e),o!==0&&(r=o,t=ri(e,o))),t===1))throw n=ir,zt(e,0),lt(e,r),me(e,K()),n;switch(e.finishedWork=l,e.finishedLanes=r,t){case 0:case 1:throw Error(_(345));case 2:Pt(e,fe,Be);break;case 3:if(lt(e,r),(r&130023424)===r&&(t=Ji+500-K(),10<t)){if(Zr(e,0)!==0)break;if(l=e.suspendedLanes,(l&r)!==r){ae(),e.pingedLanes|=e.suspendedLanes&l;break}e.timeoutHandle=Io(Pt.bind(null,e,fe,Be),t);break}Pt(e,fe,Be);break;case 4:if(lt(e,r),(r&4194240)===r)break;for(t=e.eventTimes,l=-1;0<r;){var i=31-Oe(r);o=1<<i,i=t[i],i>l&&(l=i),r&=~o}if(r=l,r=K()-r,r=(120>r?120:480>r?480:1080>r?1080:1920>r?1920:3e3>r?3e3:4320>r?4320:1960*hp(r/1960))-r,10<r){e.timeoutHandle=Io(Pt.bind(null,e,fe,Be),r);break}Pt(e,fe,Be);break;case 5:Pt(e,fe,Be);break;default:throw Error(_(329))}}}return me(e,K()),e.callbackNode===n?Tc.bind(null,e):null}function ri(e,t){var n=Vn;return e.current.memoizedState.isDehydrated&&(zt(e,t).flags|=256),e=ml(e,t),e!==2&&(t=fe,fe=n,t!==null&&li(t)),e}function li(e){fe===null?fe=e:fe.push.apply(fe,e)}function mp(e){for(var t=e;;){if(t.flags&16384){var n=t.updateQueue;if(n!==null&&(n=n.stores,n!==null))for(var r=0;r<n.length;r++){var l=n[r],o=l.getSnapshot;l=l.value;try{if(!De(o(),l))return!1}catch{return!1}}}if(n=t.child,t.subtreeFlags&16384&&n!==null)n.return=t,t=n;else{if(t===e)break;for(;t.sibling===null;){if(t.return===null||t.return===e)return!0;t=t.return}t.sibling.return=t.return,t=t.sibling}}return!0}function lt(e,t){for(t&=~Xi,t&=~jl,e.suspendedLanes|=t,e.pingedLanes&=~t,e=e.expirationTimes;0<t;){var n=31-Oe(t),r=1<<n;e[n]=-1,t&=~r}}function ma(e){if(M&6)throw Error(_(327));un();var t=Zr(e,0);if(!(t&1))return me(e,K()),null;var n=ml(e,t);if(e.tag!==0&&n===2){var r=To(e);r!==0&&(t=r,n=ri(e,r))}if(n===1)throw n=ir,zt(e,0),lt(e,t),me(e,K()),n;if(n===6)throw Error(_(345));return e.finishedWork=e.current.alternate,e.finishedLanes=t,Pt(e,fe,Be),me(e,K()),null}function Zi(e,t){var n=M;M|=1;try{return e(t)}finally{M=n,M===0&&(hn=K()+500,El&&kt())}}function Ut(e){it!==null&&it.tag===0&&!(M&6)&&un();var t=M;M|=1;var n=Ce.transition,r=D;try{if(Ce.transition=null,D=1,e)return e()}finally{D=r,Ce.transition=n,M=t,!(M&6)&&kt()}}function qi(){ve=en.current,U(en)}function zt(e,t){e.finishedWork=null,e.finishedLanes=0;var n=e.timeoutHandle;if(n!==-1&&(e.timeoutHandle=-1,Qd(n)),G!==null)for(n=G.return;n!==null;){var r=n;switch(zi(r),r.tag){case 1:r=r.type.childContextTypes,r!=null&&nl();break;case 3:dn(),U(pe),U(ie),Bi();break;case 5:$i(r);break;case 4:dn();break;case 13:U($);break;case 19:U($);break;case 10:Fi(r.type._context);break;case 22:case 23:qi()}n=n.return}if(b=e,G=e=mt(e.current,null),te=ve=t,J=0,ir=null,Xi=jl=It=0,fe=Vn=null,Lt!==null){for(t=0;t<Lt.length;t++)if(n=Lt[t],r=n.interleaved,r!==null){n.interleaved=null;var l=r.next,o=n.pending;if(o!==null){var i=o.next;o.next=l,r.next=i}n.pending=r}Lt=null}return e}function Lc(e,t){do{var n=G;try{if(Di(),Br.current=fl,cl){for(var r=B.memoizedState;r!==null;){var l=r.queue;l!==null&&(l.pending=null),r=r.next}cl=!1}if(Ft=0,q=X=B=null,$n=!1,rr=0,Gi.current=null,n===null||n.return===null){J=1,ir=t,G=null;break}e:{var o=e,i=n.return,u=n,a=t;if(t=te,u.flags|=32768,a!==null&&typeof a=="object"&&typeof a.then=="function"){var s=a,h=u,d=h.tag;if(!(h.mode&1)&&(d===0||d===11||d===15)){var m=h.alternate;m?(h.updateQueue=m.updateQueue,h.memoizedState=m.memoizedState,h.lanes=m.lanes):(h.updateQueue=null,h.memoizedState=null)}var w=na(i);if(w!==null){w.flags&=-257,ra(w,i,u,o,t),w.mode&1&&ta(o,s,t),t=w,a=s;var S=t.updateQueue;if(S===null){var g=new Set;g.add(a),t.updateQueue=g}else S.add(a);break e}else{if(!(t&1)){ta(o,s,t),bi();break e}a=Error(_(426))}}else if(A&&u.mode&1){var x=na(i);if(x!==null){!(x.flags&65536)&&(x.flags|=256),ra(x,i,u,o,t),Oi(pn(a,u));break e}}o=a=pn(a,u),J!==4&&(J=2),Vn===null?Vn=[o]:Vn.push(o),o=i;do{switch(o.tag){case 3:o.flags|=65536,t&=-t,o.lanes|=t;var f=pc(o,a,t);Xu(o,f);break e;case 1:u=a;var c=o.type,p=o.stateNode;if(!(o.flags&128)&&(typeof c.getDerivedStateFromError=="function"||p!==null&&typeof p.componentDidCatch=="function"&&(pt===null||!pt.has(p)))){o.flags|=65536,t&=-t,o.lanes|=t;var k=hc(o,u,t);Xu(o,k);break e}}o=o.return}while(o!==null)}Oc(n)}catch(E){t=E,G===n&&n!==null&&(G=n=n.return);continue}break}while(!0)}function Rc(){var e=dl.current;return dl.current=fl,e===null?fl:e}function bi(){(J===0||J===3||J===2)&&(J=4),b===null||!(It&268435455)&&!(jl&268435455)||lt(b,te)}function ml(e,t){var n=M;M|=2;var r=Rc();(b!==e||te!==t)&&(Be=null,zt(e,t));do try{vp();break}catch(l){Lc(e,l)}while(!0);if(Di(),M=n,dl.current=r,G!==null)throw Error(_(261));return b=null,te=0,J}function vp(){for(;G!==null;)zc(G)}function gp(){for(;G!==null&&!Vf();)zc(G)}function zc(e){var t=Dc(e.alternate,e,ve);e.memoizedProps=e.pendingProps,t===null?Oc(e):G=t,Gi.current=null}function Oc(e){var t=e;do{var n=t.alternate;if(e=t.return,t.flags&32768){if(n=cp(n,t),n!==null){n.flags&=32767,G=n;return}if(e!==null)e.flags|=32768,e.subtreeFlags=0,e.deletions=null;else{J=6,G=null;return}}else if(n=sp(n,t,ve),n!==null){G=n;return}if(t=t.sibling,t!==null){G=t;return}G=t=e}while(t!==null);J===0&&(J=5)}function Pt(e,t,n){var r=D,l=Ce.transition;try{Ce.transition=null,D=1,yp(e,t,n,r)}finally{Ce.transition=l,D=r}return null}function yp(e,t,n,r){do un();while(it!==null);if(M&6)throw Error(_(327));n=e.finishedWork;var l=e.finishedLanes;if(n===null)return null;if(e.finishedWork=null,e.finishedLanes=0,n===e.current)throw Error(_(177));e.callbackNode=null,e.callbackPriority=0;var o=n.lanes|n.childLanes;if(qf(e,o),e===b&&(G=b=null,te=0),!(n.subtreeFlags&2064)&&!(n.flags&2064)||zr||(zr=!0,Fc(Jr,function(){return un(),null})),o=(n.flags&15990)!==0,n.subtreeFlags&15990||o){o=Ce.transition,Ce.transition=null;var i=D;D=1;var u=M;M|=4,Gi.current=null,dp(e,n),Pc(n,e),Ud(Do),qr=!!Mo,Do=Mo=null,e.current=n,pp(n),Wf(),M=u,D=i,Ce.transition=o}else e.current=n;if(zr&&(zr=!1,it=e,hl=l),o=e.pendingLanes,o===0&&(pt=null),Kf(n.stateNode),me(e,K()),t!==null)for(r=e.onRecoverableError,n=0;n<t.length;n++)l=t[n],r(l.value,{componentStack:l.stack,digest:l.digest});if(pl)throw pl=!1,e=ti,ti=null,e;return hl&1&&e.tag!==0&&un(),o=e.pendingLanes,o&1?e===ni?Wn++:(Wn=0,ni=e):Wn=0,kt(),null}function un(){if(it!==null){var e=ps(hl),t=Ce.transition,n=D;try{if(Ce.transition=null,D=16>e?16:e,it===null)var r=!1;else{if(e=it,it=null,hl=0,M&6)throw Error(_(331));var l=M;for(M|=4,C=e.current;C!==null;){var o=C,i=o.child;if(C.flags&16){var u=o.deletions;if(u!==null){for(var a=0;a<u.length;a++){var s=u[a];for(C=s;C!==null;){var h=C;switch(h.tag){case 0:case 11:case 15:Bn(8,h,o)}var d=h.child;if(d!==null)d.return=h,C=d;else for(;C!==null;){h=C;var m=h.sibling,w=h.return;if(Ec(h),h===s){C=null;break}if(m!==null){m.return=w,C=m;break}C=w}}}var S=o.alternate;if(S!==null){var g=S.child;if(g!==null){S.child=null;do{var x=g.sibling;g.sibling=null,g=x}while(g!==null)}}C=o}}if(o.subtreeFlags&2064&&i!==null)i.return=o,C=i;else e:for(;C!==null;){if(o=C,o.flags&2048)switch(o.tag){case 0:case 11:case 15:Bn(9,o,o.return)}var f=o.sibling;if(f!==null){f.return=o.return,C=f;break e}C=o.return}}var c=e.current;for(C=c;C!==null;){i=C;var p=i.child;if(i.subtreeFlags&2064&&p!==null)p.return=i,C=p;else e:for(i=c;C!==null;){if(u=C,u.flags&2048)try{switch(u.tag){case 0:case 11:case 15:Pl(9,u)}}catch(E){W(u,u.return,E)}if(u===i){C=null;break e}var k=u.sibling;if(k!==null){k.return=u.return,C=k;break e}C=u.return}}if(M=l,kt(),Ae&&typeof Ae.onPostCommitFiberRoot=="function")try{Ae.onPostCommitFiberRoot(wl,e)}catch{}r=!0}return r}finally{D=n,Ce.transition=t}}return!1}function va(e,t,n){t=pn(n,t),t=pc(e,t,1),e=dt(e,t,1),t=ae(),e!==null&&(cr(e,1,t),me(e,t))}function W(e,t,n){if(e.tag===3)va(e,e,n);else for(;t!==null;){if(t.tag===3){va(t,e,n);break}else if(t.tag===1){var r=t.stateNode;if(typeof t.type.getDerivedStateFromError=="function"||typeof r.componentDidCatch=="function"&&(pt===null||!pt.has(r))){e=pn(n,e),e=hc(t,e,1),t=dt(t,e,1),e=ae(),t!==null&&(cr(t,1,e),me(t,e));break}}t=t.return}}function wp(e,t,n){var r=e.pingCache;r!==null&&r.delete(t),t=ae(),e.pingedLanes|=e.suspendedLanes&n,b===e&&(te&n)===n&&(J===4||J===3&&(te&130023424)===te&&500>K()-Ji?zt(e,0):Xi|=n),me(e,t)}function Mc(e,t){t===0&&(e.mode&1?(t=xr,xr<<=1,!(xr&130023424)&&(xr=4194304)):t=1);var n=ae();e=Xe(e,t),e!==null&&(cr(e,t,n),me(e,n))}function Sp(e){var t=e.memoizedState,n=0;t!==null&&(n=t.retryLane),Mc(e,n)}function kp(e,t){var n=0;switch(e.tag){case 13:var r=e.stateNode,l=e.memoizedState;l!==null&&(n=l.retryLane);break;case 19:r=e.stateNode;break;default:throw Error(_(314))}r!==null&&r.delete(t),Mc(e,n)}var Dc;Dc=function(e,t,n){if(e!==null)if(e.memoizedProps!==t.pendingProps||pe.current)de=!0;else{if(!(e.lanes&n)&&!(t.flags&128))return de=!1,ap(e,t,n);de=!!(e.flags&131072)}else de=!1,A&&t.flags&1048576&&As(t,ol,t.index);switch(t.lanes=0,t.tag){case 2:var r=t.type;Wr(e,t),e=t.pendingProps;var l=sn(t,ie.current);on(t,n),l=Wi(null,t,r,e,l,n);var o=Hi();return t.flags|=1,typeof l=="object"&&l!==null&&typeof l.render=="function"&&l.$$typeof===void 0?(t.tag=1,t.memoizedState=null,t.updateQueue=null,he(r)?(o=!0,rl(t)):o=!1,t.memoizedState=l.state!==null&&l.state!==void 0?l.state:null,Ui(t),l.updater=Nl,t.stateNode=l,l._reactInternals=t,Ho(t,r,e,n),t=Yo(null,t,r,!0,o,n)):(t.tag=0,A&&o&&Ri(t),ue(null,t,l,n),t=t.child),t;case 16:r=t.elementType;e:{switch(Wr(e,t),e=t.pendingProps,l=r._init,r=l(r._payload),t.type=r,l=t.tag=_p(r),e=Le(r,e),l){case 0:t=Ko(null,t,r,e,n);break e;case 1:t=ia(null,t,r,e,n);break e;case 11:t=la(null,t,r,e,n);break e;case 14:t=oa(null,t,r,Le(r.type,e),n);break e}throw Error(_(306,r,""))}return t;case 0:return r=t.type,l=t.pendingProps,l=t.elementType===r?l:Le(r,l),Ko(e,t,r,l,n);case 1:return r=t.type,l=t.pendingProps,l=t.elementType===r?l:Le(r,l),ia(e,t,r,l,n);case 3:e:{if(yc(t),e===null)throw Error(_(387));r=t.pendingProps,o=t.memoizedState,l=o.element,Qs(e,t),al(t,r,null,n);var i=t.memoizedState;if(r=i.element,o.isDehydrated)if(o={element:r,isDehydrated:!1,cache:i.cache,pendingSuspenseBoundaries:i.pendingSuspenseBoundaries,transitions:i.transitions},t.updateQueue.baseState=o,t.memoizedState=o,t.flags&256){l=pn(Error(_(423)),t),t=ua(e,t,r,n,l);break e}else if(r!==l){l=pn(Error(_(424)),t),t=ua(e,t,r,n,l);break e}else for(ge=ft(t.stateNode.containerInfo.firstChild),ye=t,A=!0,ze=null,n=Ws(t,null,r,n),t.child=n;n;)n.flags=n.flags&-3|4096,n=n.sibling;else{if(cn(),r===l){t=Je(e,t,n);break e}ue(e,t,r,n)}t=t.child}return t;case 5:return Ks(t),e===null&&Bo(t),r=t.type,l=t.pendingProps,o=e!==null?e.memoizedProps:null,i=l.children,Fo(r,l)?i=null:o!==null&&Fo(r,o)&&(t.flags|=32),gc(e,t),ue(e,t,i,n),t.child;case 6:return e===null&&Bo(t),null;case 13:return wc(e,t,n);case 4:return Ai(t,t.stateNode.containerInfo),r=t.pendingProps,e===null?t.child=fn(t,null,r,n):ue(e,t,r,n),t.child;case 11:return r=t.type,l=t.pendingProps,l=t.elementType===r?l:Le(r,l),la(e,t,r,l,n);case 7:return ue(e,t,t.pendingProps,n),t.child;case 8:return ue(e,t,t.pendingProps.children,n),t.child;case 12:return ue(e,t,t.pendingProps.children,n),t.child;case 10:e:{if(r=t.type._context,l=t.pendingProps,o=t.memoizedProps,i=l.value,F(il,r._currentValue),r._currentValue=i,o!==null)if(De(o.value,i)){if(o.children===l.children&&!pe.current){t=Je(e,t,n);break e}}else for(o=t.child,o!==null&&(o.return=t);o!==null;){var u=o.dependencies;if(u!==null){i=o.child;for(var a=u.firstContext;a!==null;){if(a.context===r){if(o.tag===1){a=Ke(-1,n&-n),a.tag=2;var s=o.updateQueue;if(s!==null){s=s.shared;var h=s.pending;h===null?a.next=a:(a.next=h.next,h.next=a),s.pending=a}}o.lanes|=n,a=o.alternate,a!==null&&(a.lanes|=n),Vo(o.return,n,t),u.lanes|=n;break}a=a.next}}else if(o.tag===10)i=o.type===t.type?null:o.child;else if(o.tag===18){if(i=o.return,i===null)throw Error(_(341));i.lanes|=n,u=i.alternate,u!==null&&(u.lanes|=n),Vo(i,n,t),i=o.sibling}else i=o.child;if(i!==null)i.return=o;else for(i=o;i!==null;){if(i===t){i=null;break}if(o=i.sibling,o!==null){o.return=i.return,i=o;break}i=i.return}o=i}ue(e,t,l.children,n),t=t.child}return t;case 9:return l=t.type,r=t.pendingProps.children,on(t,n),l=Ne(l),r=r(l),t.flags|=1,ue(e,t,r,n),t.child;case 14:return r=t.type,l=Le(r,t.pendingProps),l=Le(r.type,l),oa(e,t,r,l,n);case 15:return mc(e,t,t.type,t.pendingProps,n);case 17:return r=t.type,l=t.pendingProps,l=t.elementType===r?l:Le(r,l),Wr(e,t),t.tag=1,he(r)?(e=!0,rl(t)):e=!1,on(t,n),dc(t,r,l),Ho(t,r,l,n),Yo(null,t,r,!0,e,n);case 19:return Sc(e,t,n);case 22:return vc(e,t,n)}throw Error(_(156,t.tag))};function Fc(e,t){return ss(e,t)}function xp(e,t,n,r){this.tag=e,this.key=n,this.sibling=this.child=this.return=this.stateNode=this.type=this.elementType=null,this.index=0,this.ref=null,this.pendingProps=t,this.dependencies=this.memoizedState=this.updateQueue=this.memoizedProps=null,this.mode=r,this.subtreeFlags=this.flags=0,this.deletions=null,this.childLanes=this.lanes=0,this.alternate=null}function Ee(e,t,n,r){return new xp(e,t,n,r)}function eu(e){return e=e.prototype,!(!e||!e.isReactComponent)}function _p(e){if(typeof e=="function")return eu(e)?1:0;if(e!=null){if(e=e.$$typeof,e===wi)return 11;if(e===Si)return 14}return 2}function mt(e,t){var n=e.alternate;return n===null?(n=Ee(e.tag,t,e.key,e.mode),n.elementType=e.elementType,n.type=e.type,n.stateNode=e.stateNode,n.alternate=e,e.alternate=n):(n.pendingProps=t,n.type=e.type,n.flags=0,n.subtreeFlags=0,n.deletions=null),n.flags=e.flags&14680064,n.childLanes=e.childLanes,n.lanes=e.lanes,n.child=e.child,n.memoizedProps=e.memoizedProps,n.memoizedState=e.memoizedState,n.updateQueue=e.updateQueue,t=e.dependencies,n.dependencies=t===null?null:{lanes:t.lanes,firstContext:t.firstContext},n.sibling=e.sibling,n.index=e.index,n.ref=e.ref,n}function Kr(e,t,n,r,l,o){var i=2;if(r=e,typeof e=="function")eu(e)&&(i=1);else if(typeof e=="string")i=5;else e:switch(e){case Ht:return Ot(n.children,l,o,t);case yi:i=8,l|=8;break;case ho:return e=Ee(12,n,t,l|2),e.elementType=ho,e.lanes=o,e;case mo:return e=Ee(13,n,t,l),e.elementType=mo,e.lanes=o,e;case vo:return e=Ee(19,n,t,l),e.elementType=vo,e.lanes=o,e;case Ka:return Tl(n,l,o,t);default:if(typeof e=="object"&&e!==null)switch(e.$$typeof){case Ha:i=10;break e;case Qa:i=9;break e;case wi:i=11;break e;case Si:i=14;break e;case tt:i=16,r=null;break e}throw Error(_(130,e==null?e:typeof e,""))}return t=Ee(i,n,t,l),t.elementType=e,t.type=r,t.lanes=o,t}function Ot(e,t,n,r){return e=Ee(7,e,r,t),e.lanes=n,e}function Tl(e,t,n,r){return e=Ee(22,e,r,t),e.elementType=Ka,e.lanes=n,e.stateNode={isHidden:!1},e}function ao(e,t,n){return e=Ee(6,e,null,t),e.lanes=n,e}function so(e,t,n){return t=Ee(4,e.children!==null?e.children:[],e.key,t),t.lanes=n,t.stateNode={containerInfo:e.containerInfo,pendingChildren:null,implementation:e.implementation},t}function Ep(e,t,n,r,l){this.tag=t,this.containerInfo=e,this.finishedWork=this.pingCache=this.current=this.pendingChildren=null,this.timeoutHandle=-1,this.callbackNode=this.pendingContext=this.context=null,this.callbackPriority=0,this.eventTimes=Wl(0),this.expirationTimes=Wl(-1),this.entangledLanes=this.finishedLanes=this.mutableReadLanes=this.expiredLanes=this.pingedLanes=this.suspendedLanes=this.pendingLanes=0,this.entanglements=Wl(0),this.identifierPrefix=r,this.onRecoverableError=l,this.mutableSourceEagerHydrationData=null}function tu(e,t,n,r,l,o,i,u,a){return e=new Ep(e,t,n,u,a),t===1?(t=1,o===!0&&(t|=8)):t=0,o=Ee(3,null,null,t),e.current=o,o.stateNode=e,o.memoizedState={element:r,isDehydrated:n,cache:null,transitions:null,pendingSuspenseBoundaries:null},Ui(o),e}function Cp(e,t,n){var r=3<arguments.length&&arguments[3]!==void 0?arguments[3]:null;return{$$typeof:Wt,key:r==null?null:""+r,children:e,containerInfo:t,implementation:n}}function Ic(e){if(!e)return yt;e=e._reactInternals;e:{if($t(e)!==e||e.tag!==1)throw Error(_(170));var t=e;do{switch(t.tag){case 3:t=t.stateNode.context;break e;case 1:if(he(t.type)){t=t.stateNode.__reactInternalMemoizedMergedChildContext;break e}}t=t.return}while(t!==null);throw Error(_(171))}if(e.tag===1){var n=e.type;if(he(n))return Is(e,n,t)}return t}function Uc(e,t,n,r,l,o,i,u,a){return e=tu(n,r,!0,e,l,o,i,u,a),e.context=Ic(null),n=e.current,r=ae(),l=ht(n),o=Ke(r,l),o.callback=t??null,dt(n,o,l),e.current.lanes=l,cr(e,l,r),me(e,r),e}function Ll(e,t,n,r){var l=t.current,o=ae(),i=ht(l);return n=Ic(n),t.context===null?t.context=n:t.pendingContext=n,t=Ke(o,i),t.payload={element:e},r=r===void 0?null:r,r!==null&&(t.callback=r),e=dt(l,t,i),e!==null&&(Me(e,l,i,o),$r(e,l,i)),i}function vl(e){if(e=e.current,!e.child)return null;switch(e.child.tag){case 5:return e.child.stateNode;default:return e.child.stateNode}}function ga(e,t){if(e=e.memoizedState,e!==null&&e.dehydrated!==null){var n=e.retryLane;e.retryLane=n!==0&&n<t?n:t}}function nu(e,t){ga(e,t),(e=e.alternate)&&ga(e,t)}function Np(){return null}var Ac=typeof reportError=="function"?reportError:function(e){console.error(e)};function ru(e){this._internalRoot=e}Rl.prototype.render=ru.prototype.render=function(e){var t=this._internalRoot;if(t===null)throw Error(_(409));Ll(e,t,null,null)};Rl.prototype.unmount=ru.prototype.unmount=function(){var e=this._internalRoot;if(e!==null){this._internalRoot=null;var t=e.containerInfo;Ut(function(){Ll(null,e,null,null)}),t[Ge]=null}};function Rl(e){this._internalRoot=e}Rl.prototype.unstable_scheduleHydration=function(e){if(e){var t=vs();e={blockedOn:null,target:e,priority:t};for(var n=0;n<rt.length&&t!==0&&t<rt[n].priority;n++);rt.splice(n,0,e),n===0&&ys(e)}};function lu(e){return!(!e||e.nodeType!==1&&e.nodeType!==9&&e.nodeType!==11)}function zl(e){return!(!e||e.nodeType!==1&&e.nodeType!==9&&e.nodeType!==11&&(e.nodeType!==8||e.nodeValue!==" react-mount-point-unstable "))}function ya(){}function Pp(e,t,n,r,l){if(l){if(typeof r=="function"){var o=r;r=function(){var s=vl(i);o.call(s)}}var i=Uc(t,r,e,0,null,!1,!1,"",ya);return e._reactRootContainer=i,e[Ge]=i.current,qn(e.nodeType===8?e.parentNode:e),Ut(),i}for(;l=e.lastChild;)e.removeChild(l);if(typeof r=="function"){var u=r;r=function(){var s=vl(a);u.call(s)}}var a=tu(e,0,!1,null,null,!1,!1,"",ya);return e._reactRootContainer=a,e[Ge]=a.current,qn(e.nodeType===8?e.parentNode:e),Ut(function(){Ll(t,a,n,r)}),a}function Ol(e,t,n,r,l){var o=n._reactRootContainer;if(o){var i=o;if(typeof l=="function"){var u=l;l=function(){var a=vl(i);u.call(a)}}Ll(t,i,e,l)}else i=Pp(n,t,e,l,r);return vl(i)}hs=function(e){switch(e.tag){case 3:var t=e.stateNode;if(t.current.memoizedState.isDehydrated){var n=On(t.pendingLanes);n!==0&&(_i(t,n|1),me(t,K()),!(M&6)&&(hn=K()+500,kt()))}break;case 13:Ut(function(){var r=Xe(e,1);if(r!==null){var l=ae();Me(r,e,1,l)}}),nu(e,1)}};Ei=function(e){if(e.tag===13){var t=Xe(e,134217728);if(t!==null){var n=ae();Me(t,e,134217728,n)}nu(e,134217728)}};ms=function(e){if(e.tag===13){var t=ht(e),n=Xe(e,t);if(n!==null){var r=ae();Me(n,e,t,r)}nu(e,t)}};vs=function(){return D};gs=function(e,t){var n=D;try{return D=e,t()}finally{D=n}};No=function(e,t,n){switch(t){case"input":if(wo(e,n),t=n.name,n.type==="radio"&&t!=null){for(n=e;n.parentNode;)n=n.parentNode;for(n=n.querySelectorAll("input[name="+JSON.stringify(""+t)+'][type="radio"]'),t=0;t<n.length;t++){var r=n[t];if(r!==e&&r.form===e.form){var l=_l(r);if(!l)throw Error(_(90));Ga(r),wo(r,l)}}}break;case"textarea":Ja(e,n);break;case"select":t=n.value,t!=null&&tn(e,!!n.multiple,t,!1)}};rs=Zi;ls=Ut;var jp={usingClientEntryPoint:!1,Events:[dr,Gt,_l,ts,ns,Zi]},Ln={findFiberByHostInstance:Tt,bundleType:0,version:"18.3.1",rendererPackageName:"react-dom"},Tp={bundleType:Ln.bundleType,version:Ln.version,rendererPackageName:Ln.rendererPackageName,rendererConfig:Ln.rendererConfig,overrideHookState:null,overrideHookStateDeletePath:null,overrideHookStateRenamePath:null,overrideProps:null,overridePropsDeletePath:null,overridePropsRenamePath:null,setErrorHandler:null,setSuspenseHandler:null,scheduleUpdate:null,currentDispatcherRef:Ze.ReactCurrentDispatcher,findHostInstanceByFiber:function(e){return e=us(e),e===null?null:e.stateNode},findFiberByHostInstance:Ln.findFiberByHostInstance||Np,findHostInstancesForRefresh:null,scheduleRefresh:null,scheduleRoot:null,setRefreshHandler:null,getCurrentFiber:null,reconcilerVersion:"18.3.1-next-f1338f8080-20240426"};if(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__<"u"){var Or=__REACT_DEVTOOLS_GLOBAL_HOOK__;if(!Or.isDisabled&&Or.supportsFiber)try{wl=Or.inject(Tp),Ae=Or}catch{}}Se.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=jp;Se.createPortal=function(e,t){var n=2<arguments.length&&arguments[2]!==void 0?arguments[2]:null;if(!lu(t))throw Error(_(200));return Cp(e,t,null,n)};Se.createRoot=function(e,t){if(!lu(e))throw Error(_(299));var n=!1,r="",l=Ac;return t!=null&&(t.unstable_strictMode===!0&&(n=!0),t.identifierPrefix!==void 0&&(r=t.identifierPrefix),t.onRecoverableError!==void 0&&(l=t.onRecoverableError)),t=tu(e,1,!1,null,null,n,!1,r,l),e[Ge]=t.current,qn(e.nodeType===8?e.parentNode:e),new ru(t)};Se.findDOMNode=function(e){if(e==null)return null;if(e.nodeType===1)return e;var t=e._reactInternals;if(t===void 0)throw typeof e.render=="function"?Error(_(188)):(e=Object.keys(e).join(","),Error(_(268,e)));return e=us(t),e=e===null?null:e.stateNode,e};Se.flushSync=function(e){return Ut(e)};Se.hydrate=function(e,t,n){if(!zl(t))throw Error(_(200));return Ol(null,e,t,!0,n)};Se.hydrateRoot=function(e,t,n){if(!lu(e))throw Error(_(405));var r=n!=null&&n.hydratedSources||null,l=!1,o="",i=Ac;if(n!=null&&(n.unstable_strictMode===!0&&(l=!0),n.identifierPrefix!==void 0&&(o=n.identifierPrefix),n.onRecoverableError!==void 0&&(i=n.onRecoverableError)),t=Uc(t,null,e,1,n??null,l,!1,o,i),e[Ge]=t.current,qn(e),r)for(e=0;e<r.length;e++)n=r[e],l=n._getVersion,l=l(n._source),t.mutableSourceEagerHydrationData==null?t.mutableSourceEagerHydrationData=[n,l]:t.mutableSourceEagerHydrationData.push(n,l);return new Rl(t)};Se.render=function(e,t,n){if(!zl(t))throw Error(_(200));return Ol(null,e,t,!1,n)};Se.unmountComponentAtNode=function(e){if(!zl(e))throw Error(_(40));return e._reactRootContainer?(Ut(function(){Ol(null,null,e,!1,function(){e._reactRootContainer=null,e[Ge]=null})}),!0):!1};Se.unstable_batchedUpdates=Zi;Se.unstable_renderSubtreeIntoContainer=function(e,t,n,r){if(!zl(n))throw Error(_(200));if(e==null||e._reactInternals===void 0)throw Error(_(38));return Ol(e,t,n,!1,r)};Se.version="18.3.1-next-f1338f8080-20240426";function $c(){if(!(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__>"u"||typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE!="function"))try{__REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE($c)}catch(e){console.error(e)}}$c(),$a.exports=Se;var Lp=$a.exports,wa=Lp;fo.createRoot=wa.createRoot,fo.hydrateRoot=wa.hydrateRoot;/**
 * @remix-run/router v1.23.0
 *
 * Copyright (c) Remix Software Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE.md file in the root directory of this source tree.
 *
 * @license MIT
 */function ur(){return ur=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},ur.apply(this,arguments)}var ut;(function(e){e.Pop="POP",e.Push="PUSH",e.Replace="REPLACE"})(ut||(ut={}));const Sa="popstate";function Rp(e){e===void 0&&(e={});function t(r,l){let{pathname:o,search:i,hash:u}=r.location;return oi("",{pathname:o,search:i,hash:u},l.state&&l.state.usr||null,l.state&&l.state.key||"default")}function n(r,l){return typeof l=="string"?l:gl(l)}return Op(t,n,null,e)}function Y(e,t){if(e===!1||e===null||typeof e>"u")throw new Error(t)}function Bc(e,t){if(!e){typeof console<"u"&&console.warn(t);try{throw new Error(t)}catch{}}}function zp(){return Math.random().toString(36).substr(2,8)}function ka(e,t){return{usr:e.state,key:e.key,idx:t}}function oi(e,t,n,r){return n===void 0&&(n=null),ur({pathname:typeof e=="string"?e:e.pathname,search:"",hash:""},typeof t=="string"?yn(t):t,{state:n,key:t&&t.key||r||zp()})}function gl(e){let{pathname:t="/",search:n="",hash:r=""}=e;return n&&n!=="?"&&(t+=n.charAt(0)==="?"?n:"?"+n),r&&r!=="#"&&(t+=r.charAt(0)==="#"?r:"#"+r),t}function yn(e){let t={};if(e){let n=e.indexOf("#");n>=0&&(t.hash=e.substr(n),e=e.substr(0,n));let r=e.indexOf("?");r>=0&&(t.search=e.substr(r),e=e.substr(0,r)),e&&(t.pathname=e)}return t}function Op(e,t,n,r){r===void 0&&(r={});let{window:l=document.defaultView,v5Compat:o=!1}=r,i=l.history,u=ut.Pop,a=null,s=h();s==null&&(s=0,i.replaceState(ur({},i.state,{idx:s}),""));function h(){return(i.state||{idx:null}).idx}function d(){u=ut.Pop;let x=h(),f=x==null?null:x-s;s=x,a&&a({action:u,location:g.location,delta:f})}function m(x,f){u=ut.Push;let c=oi(g.location,x,f);s=h()+1;let p=ka(c,s),k=g.createHref(c);try{i.pushState(p,"",k)}catch(E){if(E instanceof DOMException&&E.name==="DataCloneError")throw E;l.location.assign(k)}o&&a&&a({action:u,location:g.location,delta:1})}function w(x,f){u=ut.Replace;let c=oi(g.location,x,f);s=h();let p=ka(c,s),k=g.createHref(c);i.replaceState(p,"",k),o&&a&&a({action:u,location:g.location,delta:0})}function S(x){let f=l.location.origin!=="null"?l.location.origin:l.location.href,c=typeof x=="string"?x:gl(x);return c=c.replace(/ $/,"%20"),Y(f,"No window.location.(origin|href) available to create URL for href: "+c),new URL(c,f)}let g={get action(){return u},get location(){return e(l,i)},listen(x){if(a)throw new Error("A history only accepts one active listener");return l.addEventListener(Sa,d),a=x,()=>{l.removeEventListener(Sa,d),a=null}},createHref(x){return t(l,x)},createURL:S,encodeLocation(x){let f=S(x);return{pathname:f.pathname,search:f.search,hash:f.hash}},push:m,replace:w,go(x){return i.go(x)}};return g}var xa;(function(e){e.data="data",e.deferred="deferred",e.redirect="redirect",e.error="error"})(xa||(xa={}));function Mp(e,t,n){return n===void 0&&(n="/"),Dp(e,t,n)}function Dp(e,t,n,r){let l=typeof t=="string"?yn(t):t,o=ou(l.pathname||"/",n);if(o==null)return null;let i=Vc(e);Fp(i);let u=null;for(let a=0;u==null&&a<i.length;++a){let s=Gp(o);u=Qp(i[a],s)}return u}function Vc(e,t,n,r){t===void 0&&(t=[]),n===void 0&&(n=[]),r===void 0&&(r="");let l=(o,i,u)=>{let a={relativePath:u===void 0?o.path||"":u,caseSensitive:o.caseSensitive===!0,childrenIndex:i,route:o};a.relativePath.startsWith("/")&&(Y(a.relativePath.startsWith(r),'Absolute route path "'+a.relativePath+'" nested under path '+('"'+r+'" is not valid. An absolute child route path ')+"must start with the combined path of all its parent routes."),a.relativePath=a.relativePath.slice(r.length));let s=vt([r,a.relativePath]),h=n.concat(a);o.children&&o.children.length>0&&(Y(o.index!==!0,"Index routes must not have child routes. Please remove "+('all child routes from route path "'+s+'".')),Vc(o.children,t,h,s)),!(o.path==null&&!o.index)&&t.push({path:s,score:Wp(s,o.index),routesMeta:h})};return e.forEach((o,i)=>{var u;if(o.path===""||!((u=o.path)!=null&&u.includes("?")))l(o,i);else for(let a of Wc(o.path))l(o,i,a)}),t}function Wc(e){let t=e.split("/");if(t.length===0)return[];let[n,...r]=t,l=n.endsWith("?"),o=n.replace(/\?$/,"");if(r.length===0)return l?[o,""]:[o];let i=Wc(r.join("/")),u=[];return u.push(...i.map(a=>a===""?o:[o,a].join("/"))),l&&u.push(...i),u.map(a=>e.startsWith("/")&&a===""?"/":a)}function Fp(e){e.sort((t,n)=>t.score!==n.score?n.score-t.score:Hp(t.routesMeta.map(r=>r.childrenIndex),n.routesMeta.map(r=>r.childrenIndex)))}const Ip=/^:[\w-]+$/,Up=3,Ap=2,$p=1,Bp=10,Vp=-2,_a=e=>e==="*";function Wp(e,t){let n=e.split("/"),r=n.length;return n.some(_a)&&(r+=Vp),t&&(r+=Ap),n.filter(l=>!_a(l)).reduce((l,o)=>l+(Ip.test(o)?Up:o===""?$p:Bp),r)}function Hp(e,t){return e.length===t.length&&e.slice(0,-1).every((r,l)=>r===t[l])?e[e.length-1]-t[t.length-1]:0}function Qp(e,t,n){let{routesMeta:r}=e,l={},o="/",i=[];for(let u=0;u<r.length;++u){let a=r[u],s=u===r.length-1,h=o==="/"?t:t.slice(o.length)||"/",d=Kp({path:a.relativePath,caseSensitive:a.caseSensitive,end:s},h),m=a.route;if(!d)return null;Object.assign(l,d.params),i.push({params:l,pathname:vt([o,d.pathname]),pathnameBase:qp(vt([o,d.pathnameBase])),route:m}),d.pathnameBase!=="/"&&(o=vt([o,d.pathnameBase]))}return i}function Kp(e,t){typeof e=="string"&&(e={path:e,caseSensitive:!1,end:!0});let[n,r]=Yp(e.path,e.caseSensitive,e.end),l=t.match(n);if(!l)return null;let o=l[0],i=o.replace(/(.)\/+$/,"$1"),u=l.slice(1);return{params:r.reduce((s,h,d)=>{let{paramName:m,isOptional:w}=h;if(m==="*"){let g=u[d]||"";i=o.slice(0,o.length-g.length).replace(/(.)\/+$/,"$1")}const S=u[d];return w&&!S?s[m]=void 0:s[m]=(S||"").replace(/%2F/g,"/"),s},{}),pathname:o,pathnameBase:i,pattern:e}}function Yp(e,t,n){t===void 0&&(t=!1),n===void 0&&(n=!0),Bc(e==="*"||!e.endsWith("*")||e.endsWith("/*"),'Route path "'+e+'" will be treated as if it were '+('"'+e.replace(/\*$/,"/*")+'" because the `*` character must ')+"always follow a `/` in the pattern. To get rid of this warning, "+('please change the route path to "'+e.replace(/\*$/,"/*")+'".'));let r=[],l="^"+e.replace(/\/*\*?$/,"").replace(/^\/*/,"/").replace(/[\\.*+^${}|()[\]]/g,"\\$&").replace(/\/:([\w-]+)(\?)?/g,(i,u,a)=>(r.push({paramName:u,isOptional:a!=null}),a?"/?([^\\/]+)?":"/([^\\/]+)"));return e.endsWith("*")?(r.push({paramName:"*"}),l+=e==="*"||e==="/*"?"(.*)$":"(?:\\/(.+)|\\/*)$"):n?l+="\\/*$":e!==""&&e!=="/"&&(l+="(?:(?=\\/|$))"),[new RegExp(l,t?void 0:"i"),r]}function Gp(e){try{return e.split("/").map(t=>decodeURIComponent(t).replace(/\//g,"%2F")).join("/")}catch(t){return Bc(!1,'The URL path "'+e+'" could not be decoded because it is is a malformed URL segment. This is probably due to a bad percent '+("encoding ("+t+").")),e}}function ou(e,t){if(t==="/")return e;if(!e.toLowerCase().startsWith(t.toLowerCase()))return null;let n=t.endsWith("/")?t.length-1:t.length,r=e.charAt(n);return r&&r!=="/"?null:e.slice(n)||"/"}function Xp(e,t){t===void 0&&(t="/");let{pathname:n,search:r="",hash:l=""}=typeof e=="string"?yn(e):e;return{pathname:n?n.startsWith("/")?n:Jp(n,t):t,search:bp(r),hash:eh(l)}}function Jp(e,t){let n=t.replace(/\/+$/,"").split("/");return e.split("/").forEach(l=>{l===".."?n.length>1&&n.pop():l!=="."&&n.push(l)}),n.length>1?n.join("/"):"/"}function co(e,t,n,r){return"Cannot include a '"+e+"' character in a manually specified "+("`to."+t+"` field ["+JSON.stringify(r)+"].  Please separate it out to the ")+("`to."+n+"` field. Alternatively you may provide the full path as ")+'a string in <Link to="..."> and the router will parse it for you.'}function Zp(e){return e.filter((t,n)=>n===0||t.route.path&&t.route.path.length>0)}function iu(e,t){let n=Zp(e);return t?n.map((r,l)=>l===n.length-1?r.pathname:r.pathnameBase):n.map(r=>r.pathnameBase)}function uu(e,t,n,r){r===void 0&&(r=!1);let l;typeof e=="string"?l=yn(e):(l=ur({},e),Y(!l.pathname||!l.pathname.includes("?"),co("?","pathname","search",l)),Y(!l.pathname||!l.pathname.includes("#"),co("#","pathname","hash",l)),Y(!l.search||!l.search.includes("#"),co("#","search","hash",l)));let o=e===""||l.pathname==="",i=o?"/":l.pathname,u;if(i==null)u=n;else{let d=t.length-1;if(!r&&i.startsWith("..")){let m=i.split("/");for(;m[0]==="..";)m.shift(),d-=1;l.pathname=m.join("/")}u=d>=0?t[d]:"/"}let a=Xp(l,u),s=i&&i!=="/"&&i.endsWith("/"),h=(o||i===".")&&n.endsWith("/");return!a.pathname.endsWith("/")&&(s||h)&&(a.pathname+="/"),a}const vt=e=>e.join("/").replace(/\/\/+/g,"/"),qp=e=>e.replace(/\/+$/,"").replace(/^\/*/,"/"),bp=e=>!e||e==="?"?"":e.startsWith("?")?e:"?"+e,eh=e=>!e||e==="#"?"":e.startsWith("#")?e:"#"+e;function th(e){return e!=null&&typeof e.status=="number"&&typeof e.statusText=="string"&&typeof e.internal=="boolean"&&"data"in e}const Hc=["post","put","patch","delete"];new Set(Hc);const nh=["get",...Hc];new Set(nh);/**
 * React Router v6.30.1
 *
 * Copyright (c) Remix Software Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE.md file in the root directory of this source tree.
 *
 * @license MIT
 */function ar(){return ar=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},ar.apply(this,arguments)}const au=y.createContext(null),rh=y.createContext(null),xt=y.createContext(null),Ml=y.createContext(null),qe=y.createContext({outlet:null,matches:[],isDataRoute:!1}),Qc=y.createContext(null);function lh(e,t){let{relative:n}=t===void 0?{}:t;wn()||Y(!1);let{basename:r,navigator:l}=y.useContext(xt),{hash:o,pathname:i,search:u}=Yc(e,{relative:n}),a=i;return r!=="/"&&(a=i==="/"?r:vt([r,i])),l.createHref({pathname:a,search:u,hash:o})}function wn(){return y.useContext(Ml)!=null}function Bt(){return wn()||Y(!1),y.useContext(Ml).location}function Kc(e){y.useContext(xt).static||y.useLayoutEffect(e)}function Sn(){let{isDataRoute:e}=y.useContext(qe);return e?wh():oh()}function oh(){wn()||Y(!1);let e=y.useContext(au),{basename:t,future:n,navigator:r}=y.useContext(xt),{matches:l}=y.useContext(qe),{pathname:o}=Bt(),i=JSON.stringify(iu(l,n.v7_relativeSplatPath)),u=y.useRef(!1);return Kc(()=>{u.current=!0}),y.useCallback(function(s,h){if(h===void 0&&(h={}),!u.current)return;if(typeof s=="number"){r.go(s);return}let d=uu(s,JSON.parse(i),o,h.relative==="path");e==null&&t!=="/"&&(d.pathname=d.pathname==="/"?t:vt([t,d.pathname])),(h.replace?r.replace:r.push)(d,h.state,h)},[t,r,i,o,e])}const ih=y.createContext(null);function uh(e){let t=y.useContext(qe).outlet;return t&&y.createElement(ih.Provider,{value:e},t)}function Yc(e,t){let{relative:n}=t===void 0?{}:t,{future:r}=y.useContext(xt),{matches:l}=y.useContext(qe),{pathname:o}=Bt(),i=JSON.stringify(iu(l,r.v7_relativeSplatPath));return y.useMemo(()=>uu(e,JSON.parse(i),o,n==="path"),[e,i,o,n])}function ah(e,t){return sh(e,t)}function sh(e,t,n,r){wn()||Y(!1);let{navigator:l}=y.useContext(xt),{matches:o}=y.useContext(qe),i=o[o.length-1],u=i?i.params:{};i&&i.pathname;let a=i?i.pathnameBase:"/";i&&i.route;let s=Bt(),h;if(t){var d;let x=typeof t=="string"?yn(t):t;a==="/"||(d=x.pathname)!=null&&d.startsWith(a)||Y(!1),h=x}else h=s;let m=h.pathname||"/",w=m;if(a!=="/"){let x=a.replace(/^\//,"").split("/");w="/"+m.replace(/^\//,"").split("/").slice(x.length).join("/")}let S=Mp(e,{pathname:w}),g=hh(S&&S.map(x=>Object.assign({},x,{params:Object.assign({},u,x.params),pathname:vt([a,l.encodeLocation?l.encodeLocation(x.pathname).pathname:x.pathname]),pathnameBase:x.pathnameBase==="/"?a:vt([a,l.encodeLocation?l.encodeLocation(x.pathnameBase).pathname:x.pathnameBase])})),o,n,r);return t&&g?y.createElement(Ml.Provider,{value:{location:ar({pathname:"/",search:"",hash:"",state:null,key:"default"},h),navigationType:ut.Pop}},g):g}function ch(){let e=yh(),t=th(e)?e.status+" "+e.statusText:e instanceof Error?e.message:JSON.stringify(e),n=e instanceof Error?e.stack:null,l={padding:"0.5rem",backgroundColor:"rgba(200,200,200, 0.5)"};return y.createElement(y.Fragment,null,y.createElement("h2",null,"Unexpected Application Error!"),y.createElement("h3",{style:{fontStyle:"italic"}},t),n?y.createElement("pre",{style:l},n):null,null)}const fh=y.createElement(ch,null);class dh extends y.Component{constructor(t){super(t),this.state={location:t.location,revalidation:t.revalidation,error:t.error}}static getDerivedStateFromError(t){return{error:t}}static getDerivedStateFromProps(t,n){return n.location!==t.location||n.revalidation!=="idle"&&t.revalidation==="idle"?{error:t.error,location:t.location,revalidation:t.revalidation}:{error:t.error!==void 0?t.error:n.error,location:n.location,revalidation:t.revalidation||n.revalidation}}componentDidCatch(t,n){console.error("React Router caught the following error during render",t,n)}render(){return this.state.error!==void 0?y.createElement(qe.Provider,{value:this.props.routeContext},y.createElement(Qc.Provider,{value:this.state.error,children:this.props.component})):this.props.children}}function ph(e){let{routeContext:t,match:n,children:r}=e,l=y.useContext(au);return l&&l.static&&l.staticContext&&(n.route.errorElement||n.route.ErrorBoundary)&&(l.staticContext._deepestRenderedBoundaryId=n.route.id),y.createElement(qe.Provider,{value:t},r)}function hh(e,t,n,r){var l;if(t===void 0&&(t=[]),n===void 0&&(n=null),r===void 0&&(r=null),e==null){var o;if(!n)return null;if(n.errors)e=n.matches;else if((o=r)!=null&&o.v7_partialHydration&&t.length===0&&!n.initialized&&n.matches.length>0)e=n.matches;else return null}let i=e,u=(l=n)==null?void 0:l.errors;if(u!=null){let h=i.findIndex(d=>d.route.id&&(u==null?void 0:u[d.route.id])!==void 0);h>=0||Y(!1),i=i.slice(0,Math.min(i.length,h+1))}let a=!1,s=-1;if(n&&r&&r.v7_partialHydration)for(let h=0;h<i.length;h++){let d=i[h];if((d.route.HydrateFallback||d.route.hydrateFallbackElement)&&(s=h),d.route.id){let{loaderData:m,errors:w}=n,S=d.route.loader&&m[d.route.id]===void 0&&(!w||w[d.route.id]===void 0);if(d.route.lazy||S){a=!0,s>=0?i=i.slice(0,s+1):i=[i[0]];break}}}return i.reduceRight((h,d,m)=>{let w,S=!1,g=null,x=null;n&&(w=u&&d.route.id?u[d.route.id]:void 0,g=d.route.errorElement||fh,a&&(s<0&&m===0?(Sh("route-fallback"),S=!0,x=null):s===m&&(S=!0,x=d.route.hydrateFallbackElement||null)));let f=t.concat(i.slice(0,m+1)),c=()=>{let p;return w?p=g:S?p=x:d.route.Component?p=y.createElement(d.route.Component,null):d.route.element?p=d.route.element:p=h,y.createElement(ph,{match:d,routeContext:{outlet:h,matches:f,isDataRoute:n!=null},children:p})};return n&&(d.route.ErrorBoundary||d.route.errorElement||m===0)?y.createElement(dh,{location:n.location,revalidation:n.revalidation,component:g,error:w,children:c(),routeContext:{outlet:null,matches:f,isDataRoute:!0}}):c()},null)}var Gc=function(e){return e.UseBlocker="useBlocker",e.UseRevalidator="useRevalidator",e.UseNavigateStable="useNavigate",e}(Gc||{}),Xc=function(e){return e.UseBlocker="useBlocker",e.UseLoaderData="useLoaderData",e.UseActionData="useActionData",e.UseRouteError="useRouteError",e.UseNavigation="useNavigation",e.UseRouteLoaderData="useRouteLoaderData",e.UseMatches="useMatches",e.UseRevalidator="useRevalidator",e.UseNavigateStable="useNavigate",e.UseRouteId="useRouteId",e}(Xc||{});function mh(e){let t=y.useContext(au);return t||Y(!1),t}function vh(e){let t=y.useContext(rh);return t||Y(!1),t}function gh(e){let t=y.useContext(qe);return t||Y(!1),t}function Jc(e){let t=gh(),n=t.matches[t.matches.length-1];return n.route.id||Y(!1),n.route.id}function yh(){var e;let t=y.useContext(Qc),n=vh(),r=Jc();return t!==void 0?t:(e=n.errors)==null?void 0:e[r]}function wh(){let{router:e}=mh(Gc.UseNavigateStable),t=Jc(Xc.UseNavigateStable),n=y.useRef(!1);return Kc(()=>{n.current=!0}),y.useCallback(function(l,o){o===void 0&&(o={}),n.current&&(typeof l=="number"?e.navigate(l):e.navigate(l,ar({fromRouteId:t},o)))},[e,t])}const Ea={};function Sh(e,t,n){Ea[e]||(Ea[e]=!0)}function kh(e,t){e==null||e.v7_startTransition,e==null||e.v7_relativeSplatPath}function su(e){let{to:t,replace:n,state:r,relative:l}=e;wn()||Y(!1);let{future:o,static:i}=y.useContext(xt),{matches:u}=y.useContext(qe),{pathname:a}=Bt(),s=Sn(),h=uu(t,iu(u,o.v7_relativeSplatPath),a,l==="path"),d=JSON.stringify(h);return y.useEffect(()=>s(JSON.parse(d),{replace:n,state:r,relative:l}),[s,d,l,n,r]),null}function xh(e){return uh(e.context)}function et(e){Y(!1)}function _h(e){let{basename:t="/",children:n=null,location:r,navigationType:l=ut.Pop,navigator:o,static:i=!1,future:u}=e;wn()&&Y(!1);let a=t.replace(/^\/*/,"/"),s=y.useMemo(()=>({basename:a,navigator:o,static:i,future:ar({v7_relativeSplatPath:!1},u)}),[a,u,o,i]);typeof r=="string"&&(r=yn(r));let{pathname:h="/",search:d="",hash:m="",state:w=null,key:S="default"}=r,g=y.useMemo(()=>{let x=ou(h,a);return x==null?null:{location:{pathname:x,search:d,hash:m,state:w,key:S},navigationType:l}},[a,h,d,m,w,S,l]);return g==null?null:y.createElement(xt.Provider,{value:s},y.createElement(Ml.Provider,{children:n,value:g}))}function Eh(e){let{children:t,location:n}=e;return ah(ii(t),n)}new Promise(()=>{});function ii(e,t){t===void 0&&(t=[]);let n=[];return y.Children.forEach(e,(r,l)=>{if(!y.isValidElement(r))return;let o=[...t,l];if(r.type===y.Fragment){n.push.apply(n,ii(r.props.children,o));return}r.type!==et&&Y(!1),!r.props.index||!r.props.children||Y(!1);let i={id:r.props.id||o.join("-"),caseSensitive:r.props.caseSensitive,element:r.props.element,Component:r.props.Component,index:r.props.index,path:r.props.path,loader:r.props.loader,action:r.props.action,errorElement:r.props.errorElement,ErrorBoundary:r.props.ErrorBoundary,hasErrorBoundary:r.props.ErrorBoundary!=null||r.props.errorElement!=null,shouldRevalidate:r.props.shouldRevalidate,handle:r.props.handle,lazy:r.props.lazy};r.props.children&&(i.children=ii(r.props.children,o)),n.push(i)}),n}/**
 * React Router DOM v6.30.1
 *
 * Copyright (c) Remix Software Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE.md file in the root directory of this source tree.
 *
 * @license MIT
 */function ui(){return ui=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},ui.apply(this,arguments)}function Ch(e,t){if(e==null)return{};var n={},r=Object.keys(e),l,o;for(o=0;o<r.length;o++)l=r[o],!(t.indexOf(l)>=0)&&(n[l]=e[l]);return n}function Nh(e){return!!(e.metaKey||e.altKey||e.ctrlKey||e.shiftKey)}function Ph(e,t){return e.button===0&&(!t||t==="_self")&&!Nh(e)}const jh=["onClick","relative","reloadDocument","replace","state","target","to","preventScrollReset","viewTransition"],Th="6";try{window.__reactRouterVersion=Th}catch{}const Lh="startTransition",Ca=wf[Lh];function Rh(e){let{basename:t,children:n,future:r,window:l}=e,o=y.useRef();o.current==null&&(o.current=Rp({window:l,v5Compat:!0}));let i=o.current,[u,a]=y.useState({action:i.action,location:i.location}),{v7_startTransition:s}=r||{},h=y.useCallback(d=>{s&&Ca?Ca(()=>a(d)):a(d)},[a,s]);return y.useLayoutEffect(()=>i.listen(h),[i,h]),y.useEffect(()=>kh(r),[r]),y.createElement(_h,{basename:t,children:n,location:u.location,navigationType:u.action,navigator:i,future:r})}const zh=typeof window<"u"&&typeof window.document<"u"&&typeof window.document.createElement<"u",Oh=/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i,Qe=y.forwardRef(function(t,n){let{onClick:r,relative:l,reloadDocument:o,replace:i,state:u,target:a,to:s,preventScrollReset:h,viewTransition:d}=t,m=Ch(t,jh),{basename:w}=y.useContext(xt),S,g=!1;if(typeof s=="string"&&Oh.test(s)&&(S=s,zh))try{let p=new URL(window.location.href),k=s.startsWith("//")?new URL(p.protocol+s):new URL(s),E=ou(k.pathname,w);k.origin===p.origin&&E!=null?s=E+k.search+k.hash:g=!0}catch{}let x=lh(s,{relative:l}),f=Mh(s,{replace:i,state:u,target:a,preventScrollReset:h,relative:l,viewTransition:d});function c(p){r&&r(p),p.defaultPrevented||f(p)}return y.createElement("a",ui({},m,{href:S||x,onClick:g||o?r:c,ref:n,target:a}))});var Na;(function(e){e.UseScrollRestoration="useScrollRestoration",e.UseSubmit="useSubmit",e.UseSubmitFetcher="useSubmitFetcher",e.UseFetcher="useFetcher",e.useViewTransitionState="useViewTransitionState"})(Na||(Na={}));var Pa;(function(e){e.UseFetcher="useFetcher",e.UseFetchers="useFetchers",e.UseScrollRestoration="useScrollRestoration"})(Pa||(Pa={}));function Mh(e,t){let{target:n,replace:r,state:l,preventScrollReset:o,relative:i,viewTransition:u}=t===void 0?{}:t,a=Sn(),s=Bt(),h=Yc(e,{relative:i});return y.useCallback(d=>{if(Ph(d,n)){d.preventDefault();let m=r!==void 0?r:gl(s)===gl(h);a(e,{replace:m,state:l,preventScrollReset:o,relative:i,viewTransition:u})}},[s,a,h,r,l,n,e,o,i,u])}function Dh(e){const t=document.cookie.split("; ").find(n=>n.startsWith(e+"="));return t?decodeURIComponent(t.split("=")[1]):null}async function jt(e,{method:t="GET",data:n,headers:r}={}){const l=t.toUpperCase(),o=!["GET","HEAD","OPTIONS"].includes(l),i={"Content-Type":"application/json",...r||{}};if(o){const s=Dh("csrf_token");s&&(i["X-CSRF-Token"]=s)}const u=await fetch(e,{method:l,headers:i,credentials:"include",body:n?JSON.stringify(n):void 0});if(!u.ok){let s="Request failed";try{s=(await u.json()).detail||s}catch{}throw new Error(s)}return(u.headers.get("content-type")||"").includes("application/json")?u.json():u.text()}async function Mr(){try{await jt("/auth/csrf")}catch(e){console.warn("Failed to establish CSRF cookie",e)}}const ai="pending-registration";function Fh(){if(typeof window>"u")return null;try{const e=window.sessionStorage.getItem(ai);return e?JSON.parse(e):null}catch(e){return console.warn("Failed to parse stored registration state",e),null}}function Ih(e){if(!(typeof window>"u"))try{e?window.sessionStorage.setItem(ai,JSON.stringify(e)):window.sessionStorage.removeItem(ai)}catch(t){console.warn("Failed to persist registration state",t)}}const Zc=y.createContext(null);function Uh({children:e}){const[t,n]=y.useState(null),[r,l]=y.useState(!0),[o,i]=y.useState(()=>Fh());y.useEffect(()=>{Ih(o)},[o]);const u=y.useCallback(async()=>{try{const g=await jt("/auth/me");n(g)}catch{n(null)}finally{l(!1)}},[]);y.useEffect(()=>{let g=!1;async function x(){try{await Mr(),g||await u()}catch{g||l(!1)}}return x(),()=>{g=!0}},[u]);const a=y.useCallback(async(g,x)=>{const f=g.trim().toLowerCase();await Mr();const c=await jt("/auth/register",{method:"POST",data:{email:f,password:x}}),p={email:f,stage:"verify",registrationToken:c.registration_token,mockCode:c.mock_verification_code??null};return i(p),p},[]),s=y.useCallback(async(g,x={})=>{const f=x.registrationToken??(o==null?void 0:o.registrationToken)??null,c=x.email??(o==null?void 0:o.email)??null;if(!f&&!c)throw new Error("Account details required to verify code.");const p={code:g};f&&(p.registration_token=f),c&&(p.email=c);const k=await jt("/auth/verify-code",{method:"POST",data:p});if(k.username_required){if(!k.registration_token)throw new Error("Missing registration token for username setup.");i({email:c,stage:"username",registrationToken:k.registration_token,mockCode:null})}else i(null);return k},[o]),h=y.useCallback(async(g,x={})=>{const f=x.registrationToken??(o==null?void 0:o.registrationToken)??null;if(!f)throw new Error("Registration token required to complete username.");const c=await jt("/auth/username",{method:"POST",data:{username:g,registration_token:f}});return i(null),c},[o]),d=y.useCallback(async(g,x)=>{await Mr(),await jt("/auth/login",{method:"POST",data:{email:g,password:x}}),await u()},[u]),m=y.useCallback(async()=>{await Mr(),await jt("/auth/logout",{method:"POST"}),n(null)},[]),w=y.useCallback(()=>{i(null)},[]),S=y.useMemo(()=>({me:t,loading:r,pendingRegistration:o,register:a,verifyCode:s,completeUsername:h,login:d,logout:m,refresh:u,clearPendingRegistration:w}),[w,h,r,d,m,t,o,u,a,s]);return v.jsx(Zc.Provider,{value:S,children:e})}function hr(){const e=y.useContext(Zc);if(!e)throw new Error("useAuth must be used within an AuthProvider");return e}const Ah={verify:"/verify",username:"/username-setup"},$h=()=>{var g;const{me:e,loading:t,logout:n,pendingRegistration:r}=hr(),l=Sn(),o=Bt(),[i,u]=y.useState(!1),a=y.useRef(null),s=y.useRef(null);if(y.useEffect(()=>{u(!1)},[o.pathname]),y.useEffect(()=>{if(!i)return;function x(c){!s.current||!a.current||!s.current.contains(c.target)&&!a.current.contains(c.target)&&u(!1)}function f(c){var p;c.key==="Escape"&&(u(!1),(p=a.current)==null||p.focus())}return document.addEventListener("mousedown",x),document.addEventListener("keydown",f),()=>{document.removeEventListener("mousedown",x),document.removeEventListener("keydown",f)}},[i]),t)return v.jsx("div",{className:"account-menu__placeholder","aria-hidden":"true"});const h=e?((g=(e.username||e.email||"?")[0])==null?void 0:g.toUpperCase())||"?":"👤",d=(r==null?void 0:r.stage)??null,m=(r==null?void 0:r.email)??null,w=x=>{u(!1),l(x)},S=async()=>{try{await n(),u(!1)}catch(x){console.error("Failed to log out",x)}};return v.jsxs("div",{className:"account-menu",children:[v.jsxs("button",{ref:a,type:"button",className:"account-menu__button","aria-haspopup":"menu","aria-expanded":i?"true":"false",onClick:()=>u(x=>!x),children:[v.jsx("span",{className:"account-menu__avatar","aria-hidden":"true",children:h}),v.jsx("span",{className:"sr-only",children:"Account"})]}),i?v.jsx("div",{className:"account-menu__dropdown",role:"menu",ref:s,children:e?v.jsxs(v.Fragment,{children:[v.jsxs("div",{className:"account-menu__summary",children:[v.jsx("div",{className:"account-menu__avatar account-menu__avatar--inline","aria-hidden":"true",children:h}),v.jsxs("div",{children:[v.jsx("p",{className:"account-menu__summary-name",children:e.username||"No username set"}),v.jsx("p",{className:"account-menu__summary-email",children:e.email})]})]}),v.jsx("button",{type:"button",className:"account-menu__item",onClick:S,children:"Log out"})]}):v.jsxs(v.Fragment,{children:[d?v.jsxs("div",{className:"account-menu__pending",children:[v.jsx("p",{children:"Finish signing up"}),v.jsx("p",{className:"account-menu__pending-email",children:m}),v.jsx("button",{type:"button",className:"account-menu__item account-menu__item--primary",onClick:()=>w(Ah[d]??"/register"),children:"Continue"})]}):null,v.jsx("button",{type:"button",className:"account-menu__item",onClick:()=>w("/login"),children:"Log in"}),v.jsx("button",{type:"button",className:"account-menu__item",onClick:()=>w("/register"),children:"Create account"})]})}):null]})},Bh=()=>v.jsxs("div",{className:"app-shell",children:[v.jsxs("header",{className:"app-header",children:[v.jsxs("div",{children:[v.jsx("p",{className:"app-header__eyebrow",children:"Local events (mock)"}),v.jsx("h1",{children:"Community calendar"}),v.jsx("p",{className:"app-header__subtitle",children:"Discover what's happening around town this month — curated highlights for inspiration."})]}),v.jsx($h,{})]}),v.jsx("main",{className:"app-main",children:v.jsx(xh,{})})]}),Vh=new Intl.DateTimeFormat(void 0,{weekday:"short"}),Wh=new Intl.DateTimeFormat(void 0,{month:"long",year:"numeric"}),Hh=new Intl.DateTimeFormat(void 0,{day:"numeric"}),ja=new Intl.DateTimeFormat(void 0,{hour:"numeric",minute:"2-digit"}),Qh=()=>{const e=new Date(Date.UTC(2023,0,1));return Array.from({length:7},(t,n)=>{const r=new Date(e);return r.setUTCDate(e.getUTCDate()+n),Vh.format(r)})},Kh=e=>Wh.format(e),Yh=(e,t)=>e.getFullYear()===t.getFullYear()&&e.getMonth()===t.getMonth()&&e.getDate()===t.getDate(),Gh=e=>new Date(e.getFullYear(),e.getMonth(),1),Xh=e=>new Date(e.getFullYear(),e.getMonth()+1,0),Jh=(e=new Date)=>{const t=Gh(e),n=Xh(e),r=new Date(t);r.setDate(t.getDate()-t.getDay()),new Date(n).setDate(n.getDate()+(6-n.getDay()));const o=[],i=new Date(r),u=new Date;for(;o.length<42;)o.push({date:new Date(i),iso:i.toISOString(),isCurrentMonth:i.getMonth()===e.getMonth()&&i.getFullYear()===e.getFullYear(),isToday:Yh(i,u)}),i.setDate(i.getDate()+1);return o},Zh=e=>Hh.format(e),si=(e,t)=>`${ja.format(e)} – ${ja.format(t)}`,qh=(e,{isToday:t=!1}={})=>{const r=new Intl.DateTimeFormat(void 0,{weekday:"long",month:"long",day:"numeric",year:"numeric"}).format(e);return t?`${r}, Today`:r},qc=hi.forwardRef(({event:e,onSelect:t},n)=>{const{title:r,startsAt:l,endsAt:o,categoryMeta:i}=e,u=`${r} ${si(l,o)}`,a=(i==null?void 0:i.color)??"#e5e7eb",s=(i==null?void 0:i.textColor)??"#1f2937";return v.jsxs("button",{ref:n,type:"button",className:"event-chip",style:{backgroundColor:a,color:s},onClick:()=>t(e),"aria-haspopup":"dialog","aria-controls":"event-panel","aria-label":u,children:[v.jsx("span",{className:"event-chip__title",children:r}),v.jsx("span",{className:"event-chip__time",children:si(l,o)})]})});qc.displayName="EventChip";const bh=({day:e,events:t,onSelectEvent:n,registerTrigger:r})=>{const{date:l,isCurrentMonth:o,isToday:i}=e,u=Zh(l),a=qh(l,{isToday:i});return v.jsxs("div",{className:`day-cell${o?"":" day-cell--muted"}${i?" day-cell--today":""}`,role:"gridcell","aria-label":a,children:[v.jsxs("div",{className:"day-cell__header",children:[v.jsx("span",{className:"day-cell__number","aria-hidden":"true",children:u}),t.length>0&&v.jsx("span",{className:"day-cell__count","aria-hidden":"true",children:t.length})]}),v.jsx("div",{className:"day-cell__events",children:t.map(s=>v.jsx(qc,{event:s,onSelect:n,ref:h=>r(s.id,h)},s.id))})]})},em=({days:e,eventsByDay:t,weekdayLabels:n,onSelectEvent:r,registerTrigger:l})=>v.jsxs("div",{className:"calendar-card",role:"region","aria-label":"Monthly calendar",children:[v.jsx("div",{className:"weekday-row",role:"row",children:n.map(o=>v.jsx("div",{className:"weekday",role:"columnheader","aria-label":o,children:o},o))}),v.jsx("div",{className:"calendar-grid",role:"grid",children:e.map(o=>v.jsx(bh,{day:o,events:t.get(o.date.toDateString())??[],onSelectEvent:r,registerTrigger:l},o.iso))})]}),tm=e=>{if(!e)return[];const t=["a[href]","button:not([disabled])","textarea:not([disabled])",'input:not([type="hidden"]):not([disabled])',"select:not([disabled])",'[tabindex]:not([tabindex="-1"])'].join(",");return Array.from(e.querySelectorAll(t)).filter(n=>!n.hasAttribute("aria-hidden")&&n.offsetParent!==null)},nm=(e,t)=>{if(e.key!=="Tab"||!t)return;const n=tm(t);if(!n.length){e.preventDefault();return}const r=n[0],l=n[n.length-1],o=e.shiftKey,i=document.activeElement;!o&&i===l?(e.preventDefault(),r.focus()):o&&i===r&&(e.preventDefault(),l.focus())},rm=({event:e,open:t,onClose:n})=>{const r=y.useRef(null),l=y.useRef(null);if(y.useEffect(()=>{t&&l.current&&l.current.focus()},[t]),y.useEffect(()=>{if(!t)return;const w=S=>{S.key==="Escape"?(S.preventDefault(),n()):nm(S,r.current)};return document.addEventListener("keydown",w),()=>document.removeEventListener("keydown",w)},[t,n]),y.useEffect(()=>{if(!t)return;const w=document.body.style.overflow;return document.body.style.overflow="hidden",()=>{document.body.style.overflow=w}},[t]),!t||!e)return null;const{title:o,description:i,startsAt:u,endsAt:a,location:s,organizer:h,categoryMeta:d,category:m}=e;return v.jsxs("div",{className:"event-panel__portal",role:"presentation",children:[v.jsx("div",{className:"event-panel__backdrop",onClick:n,"aria-hidden":"true"}),v.jsxs("aside",{id:"event-panel",className:"event-panel",role:"dialog","aria-modal":"true","aria-label":o,ref:r,onClick:w=>w.stopPropagation(),children:[v.jsxs("header",{className:"event-panel__header",children:[v.jsx("h2",{children:o}),v.jsx("button",{type:"button",ref:l,className:"event-panel__close",onClick:n,"aria-label":"Close event details",children:"×"})]}),v.jsxs("div",{className:"event-panel__meta",children:[d&&v.jsx("span",{className:"event-panel__badge",style:{backgroundColor:d.color,color:d.textColor},children:d.label}),v.jsx("span",{className:"event-panel__time",children:si(u,a)})]}),v.jsx("p",{className:"event-panel__description",children:i}),v.jsxs("dl",{className:"event-panel__details",children:[v.jsxs("div",{children:[v.jsx("dt",{children:"When"}),v.jsx("dd",{children:u.toLocaleString(void 0,{dateStyle:"full",timeStyle:"short"})})]}),v.jsxs("div",{children:[v.jsx("dt",{children:"Where"}),v.jsx("dd",{children:s})]}),v.jsxs("div",{children:[v.jsx("dt",{children:"Organizer"}),v.jsx("dd",{children:h})]})]}),v.jsxs("p",{className:"event-panel__footnote","aria-label":"Mock data note",children:["Mock data for MVP · Category: ",m]})]})]})},lm={market:{label:"Market",color:"#dbeafe",textColor:"#1d4ed8"},civic:{label:"Civic",color:"#fef3c7",textColor:"#b45309"},tech:{label:"Tech",color:"#ede9fe",textColor:"#6d28d9"},rec:{label:"Recreation",color:"#dcfce7",textColor:"#047857"},volunteer:{label:"Volunteer",color:"#fee2e2",textColor:"#b91c1c"},maker:{label:"Maker",color:"#fff1f2",textColor:"#be123c"},library:{label:"Library",color:"#fdf2f8",textColor:"#a21caf"}},bc=new Date,om=bc.getMonth(),im=bc.getFullYear(),um=(e,t,n=0)=>new Date(im,om,e,t,n),Ct=(e,t,n,r,l,o)=>{const i=um(t,n,r),u=new Date(i.getTime()+l*60*1e3);return{id:e,startsAt:i,endsAt:u,...o}},am=[Ct("market-1",3,9,0,120,{title:"Riverside Farmers Market",description:"Browse seasonal produce, artisan breads, and small-batch goods from local growers.",location:"Riverside Park Plaza",category:"market",organizer:"City Markets Cooperative"}),Ct("civic-1",6,18,30,90,{title:"Neighborhood Council Forum",description:"Discuss upcoming zoning updates and community initiatives with council members.",location:"Civic Hall Auditorium",category:"civic",organizer:"5th Ward Council"}),Ct("tech-1",11,12,0,75,{title:"Lunchtime Tech Talk: Intro to Web Accessibility",description:"A friendly primer on building inclusive interfaces, led by local accessibility advocates.",location:"Innovation Hub, 3rd Floor Lab",category:"tech",organizer:"Midtown Tech Guild"}),Ct("rec-1",15,7,30,60,{title:"Sunrise Mindful Movement",description:"An easy-going blend of stretching and breathing to welcome the day beside the gardens.",location:"Botanical Conservatory Lawn",category:"rec",organizer:"City Parks & Wellness"}),Ct("volunteer-1",19,10,0,150,{title:"Community Garden Volunteer Day",description:"Help refresh garden beds, plant pollinator flowers, and connect with fellow volunteers.",location:"Maple & 9th Community Garden",category:"volunteer",organizer:"Green Sprouts Collective"}),Ct("maker-1",24,17,0,120,{title:"Makerspace Open Build Night",description:"Bring a project or collaborate on group builds with access to tools and mentors.",location:"Foundry Makerspace",category:"maker",organizer:"Foundry Mentors"}),Ct("library-1",28,14,0,60,{title:"Library Author Spotlight: Voices of the River",description:"A moderated discussion with local authors exploring storytelling and place.",location:"Downtown Library Reading Room",category:"library",organizer:"Downtown Library Association"})].map(e=>({...e,categoryMeta:lm[e.category]??null})),sm=()=>{const[e]=y.useState(()=>new Date),[t,n]=y.useState(null),[r,l]=y.useState(null),o=y.useRef(new Map),i=y.useMemo(()=>Qh(),[]),u=y.useMemo(()=>Kh(e),[e]),a=y.useMemo(()=>Jh(e),[e]),s=y.useMemo(()=>am,[]),h=y.useMemo(()=>{const g=new Map;return s.forEach(x=>{const f=x.startsAt.toDateString();g.has(f)||g.set(f,[]),g.get(f).push(x)}),g.forEach(x=>x.sort((f,c)=>f.startsAt-c.startsAt)),g},[s]),d=y.useMemo(()=>s.find(g=>g.id===t)??null,[s,t]),m=y.useCallback(g=>{l(g.id),n(g.id)},[]),w=y.useCallback((g,x)=>{x?o.current.set(g,x):o.current.delete(g)},[]),S=y.useCallback(()=>{n(null)},[]);return y.useEffect(()=>{if(t===null&&r){const g=o.current.get(r);g&&g.focus(),l(null)}},[t,r]),v.jsxs(v.Fragment,{children:[v.jsxs("div",{className:"calendar-card",children:[v.jsx("header",{className:"calendar-card__header",children:v.jsxs("div",{children:[v.jsx("h2",{className:"calendar-card__title",children:u}),v.jsx("p",{className:"calendar-card__subtitle",children:"Mock data to demonstrate the layout. Events are refreshed monthly."})]})}),v.jsx(em,{days:a,eventsByDay:h,weekdayLabels:i,onSelectEvent:m,registerTrigger:w})]}),v.jsx(rm,{event:d,open:!!d,onClose:S})]})},cm=()=>{var g;const{me:e,loading:t,login:n}=hr(),r=Sn(),l=Bt(),[o,i]=y.useState(""),[u,a]=y.useState(""),[s,h]=y.useState(""),[d,m]=y.useState(!1),w=((g=l.state)==null?void 0:g.from)??"/";if(y.useEffect(()=>{h("")},[o,u]),!t&&e)return v.jsx(su,{to:"/",replace:!0});const S=async x=>{x.preventDefault(),m(!0),h("");try{await n(o,u),r(w,{replace:!0})}catch(f){h(f.message||"Unable to log in")}finally{m(!1)}};return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Log in"}),v.jsx("p",{className:"auth-card__intro",children:"Enter your credentials to access the calendar."}),v.jsxs("form",{className:"auth-form",onSubmit:S,children:[v.jsxs("label",{className:"auth-form__field",children:[v.jsx("span",{children:"Email"}),v.jsx("input",{type:"email",value:o,onChange:x=>i(x.target.value),required:!0,autoComplete:"email"})]}),v.jsxs("label",{className:"auth-form__field",children:[v.jsx("span",{children:"Password"}),v.jsx("input",{type:"password",value:u,onChange:x=>a(x.target.value),required:!0,autoComplete:"current-password"})]}),s?v.jsx("p",{className:"auth-form__message auth-form__message--error",role:"alert",children:s}):null,v.jsx("button",{type:"submit",className:"auth-form__submit",disabled:d,children:d?"Signing in…":"Log in"})]}),v.jsxs("p",{className:"auth-card__footer",children:["No account yet?"," ",v.jsx(Qe,{to:"/register",className:"auth-link",children:"Sign up"})]})]})},fm=()=>{const{me:e,loading:t,register:n,pendingRegistration:r}=hr(),l=Sn(),[o,i]=y.useState(""),[u,a]=y.useState(""),[s,h]=y.useState(""),[d,m]=y.useState(!1);if(y.useEffect(()=>{(r==null?void 0:r.stage)!=="verify"&&(r==null?void 0:r.stage)==="username"&&l("/username-setup",{replace:!0})},[r,l]),y.useEffect(()=>{h("")},[o,u]),!t&&e)return v.jsx(su,{to:"/",replace:!0});const w=async g=>{g.preventDefault(),m(!0),h("");try{await n(o,u),l("/verify",{replace:!1})}catch(x){h(x.message||"Unable to register")}finally{m(!1)}},S=(r==null?void 0:r.mockCode)??null;return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Create account"}),v.jsx("p",{className:"auth-card__intro",children:"Start by entering your email and a password. We will send a verification code to continue."}),v.jsxs("form",{className:"auth-form",onSubmit:w,children:[v.jsxs("label",{className:"auth-form__field",children:[v.jsx("span",{children:"Email"}),v.jsx("input",{type:"email",value:o,onChange:g=>i(g.target.value),required:!0,autoComplete:"email"})]}),v.jsxs("label",{className:"auth-form__field",children:[v.jsx("span",{children:"Password"}),v.jsx("input",{type:"password",value:u,onChange:g=>a(g.target.value),required:!0,autoComplete:"new-password"})]}),s?v.jsx("p",{className:"auth-form__message auth-form__message--error",role:"alert",children:s}):null,v.jsx("button",{type:"submit",className:"auth-form__submit",disabled:d,children:d?"Submitting…":"Register"})]}),v.jsxs("p",{className:"auth-card__footer",children:["Already registered?"," ",v.jsx(Qe,{to:"/login",className:"auth-link",children:"Log in"})]}),S?v.jsxs("p",{className:"auth-card__mock-code","aria-live":"polite",children:["Dev verification code: ",v.jsx("span",{children:S})]}):null]})},dm=()=>{const{me:e,loading:t,pendingRegistration:n,verifyCode:r}=hr(),l=Sn(),[o,i]=y.useState(""),[u,a]=y.useState(""),[s,h]=y.useState(!1);if(y.useEffect(()=>{n!=null&&n.mockCode&&!o&&i(n.mockCode)},[n,o]),y.useEffect(()=>{a("")},[o]),y.useEffect(()=>{(n==null?void 0:n.stage)==="username"&&l("/username-setup",{replace:!0})},[n,l]),!t&&e)return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Already verified"}),v.jsx("p",{className:"auth-card__intro",children:"Your account is active. You can head back to the calendar."}),v.jsx(Qe,{to:"/",className:"auth-form__submit--link",children:"Back to calendar"})]});if(!n)return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Need an account?"}),v.jsx("p",{className:"auth-card__intro",children:"Start by registering with your email and password so we know where to send your verification code."}),v.jsx(Qe,{to:"/register",className:"auth-form__submit--link",children:"Register now"})]});const d=async m=>{m.preventDefault(),h(!0),a("");try{(await r(o)).username_required?l("/username-setup",{replace:!0}):l("/login",{replace:!0})}catch(w){a(w.message||"Verification failed")}finally{h(!1)}};return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Check your email"}),v.jsxs("p",{className:"auth-card__intro",children:["Enter the 6-digit code we sent to ",v.jsx("strong",{children:n.email}),"."]}),v.jsxs("form",{className:"auth-form",onSubmit:d,children:[v.jsxs("label",{className:"auth-form__field",children:[v.jsx("span",{children:"Verification code"}),v.jsx("input",{inputMode:"numeric",pattern:"[0-9]*",maxLength:6,value:o,onChange:m=>i(m.target.value),required:!0})]}),u?v.jsx("p",{className:"auth-form__message auth-form__message--error",role:"alert",children:u}):null,v.jsx("button",{type:"submit",className:"auth-form__submit",disabled:s,children:s?"Verifying…":"Verify"})]}),v.jsxs("p",{className:"auth-card__footer",children:["Didn't get an email?"," ",v.jsx(Qe,{to:"/register",className:"auth-link",children:"Try registering again"})]})]})},pm=()=>{const{me:e,loading:t,pendingRegistration:n,completeUsername:r}=hr(),[l,o]=y.useState(""),[i,u]=y.useState(""),[a,s]=y.useState(!1),[h,d]=y.useState(!1);if(y.useEffect(()=>{(n==null?void 0:n.stage)!=="username"&&!t&&!e&&d(!1)},[n,t,e]),!t&&e)return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Username already set"}),v.jsx("p",{className:"auth-card__intro",children:"You can go straight to the calendar."}),v.jsx(Qe,{to:"/",className:"auth-form__submit auth-form__submit--link",children:"Back to calendar"})]});if(!n||(n==null?void 0:n.stage)!=="username")return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"You're almost there"}),v.jsx("p",{className:"auth-card__intro",children:"Finish registration by verifying your email first so we know it's really you."}),v.jsx(Qe,{to:"/verify",className:"auth-form__submit auth-form__submit--link",children:"Enter verification code"})]});const m=async w=>{w.preventDefault(),s(!0),u("");try{await r(l),d(!0)}catch(S){u(S.message||"Unable to save username")}finally{s(!1)}};return v.jsxs("div",{className:"auth-card",children:[v.jsx("h2",{className:"auth-card__title",children:"Choose a username"}),v.jsx("p",{className:"auth-card__intro",children:"Usernames help friends find you. They must be 3–30 characters with letters, numbers, or underscores."}),v.jsxs("form",{className:"auth-form",onSubmit:m,children:[v.jsxs("label",{className:"auth-form__field",children:[v.jsx("span",{children:"Username"}),v.jsx("input",{type:"text",value:l,onChange:w=>o(w.target.value),required:!0,minLength:3,maxLength:30,autoComplete:"username"})]}),i?v.jsx("p",{className:"auth-form__message auth-form__message--error",role:"alert",children:i}):null,h?v.jsx("p",{className:"auth-form__message auth-form__message--success",role:"status",children:"Saved! You can log in now."}):null,v.jsx("button",{type:"submit",className:"auth-form__submit",disabled:a,children:a?"Saving…":"Save username"})]}),v.jsxs("div",{className:"auth-card__footer auth-card__footer--stack",children:[v.jsxs("p",{children:["Ready to sign in?"," ",v.jsx(Qe,{to:"/login",className:"auth-link",children:"Log in"})]}),v.jsxs("p",{children:["Need a different email?"," ",v.jsx(Qe,{to:"/register",className:"auth-link",children:"Start over"})]})]})]})},hm=()=>v.jsx(Eh,{children:v.jsxs(et,{element:v.jsx(Bh,{}),children:[v.jsx(et,{index:!0,element:v.jsx(sm,{})}),v.jsx(et,{path:"login",element:v.jsx(cm,{})}),v.jsx(et,{path:"register",element:v.jsx(fm,{})}),v.jsx(et,{path:"verify",element:v.jsx(dm,{})}),v.jsx(et,{path:"username-setup",element:v.jsx(pm,{})}),v.jsx(et,{path:"*",element:v.jsx(su,{to:"/",replace:!0})})]})});fo.createRoot(document.getElementById("root")).render(v.jsx(hi.StrictMode,{children:v.jsx(Rh,{children:v.jsx(Uh,{children:v.jsx(hm,{})})})}));


File: frontend\dist\index.html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Local Events Calendar</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
    <script type="module" crossorigin src="/assets/index-oDZKR0nZ.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-B6gKFgHG.css">
  </head>
  <body>
    <div id="root"></div>

  </body>
</html>


File: frontend\index.html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Local Events Calendar</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>


File: frontend\package.json
{
  "name": "calendar-mvp",
  "version": "0.0.1",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.23.1"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.38",
    "vite": "^5.2.0"
  }
}


File: frontend\postcss.config.cjs
module.exports = {
  plugins: {
    autoprefixer: {}
  }
};


File: frontend\src\App.jsx
import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import AppLayout from '@/layouts/AppLayout.jsx';
import CalendarPage from '@/pages/CalendarPage.jsx';
import LoginPage from '@/pages/LoginPage.jsx';
import RegisterPage from '@/pages/RegisterPage.jsx';
import VerifyPage from '@/pages/VerifyPage.jsx';
import UsernameSetupPage from '@/pages/UsernameSetupPage.jsx';

const App = () => (
  <Routes>
    <Route element={<AppLayout />}>
      <Route index element={<CalendarPage />} />
      <Route path="login" element={<LoginPage />} />
      <Route path="register" element={<RegisterPage />} />
      <Route path="verify" element={<VerifyPage />} />
      <Route path="username-setup" element={<UsernameSetupPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes>
);

export default App;


File: frontend\src\components\AccountMenu.jsx
import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const routesByStage = {
  verify: '/verify',
  username: '/username-setup'
};

const AccountMenu = () => {
  const { me, loading, logout, pendingRegistration } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const triggerRef = useRef(null);
  const menuRef = useRef(null);

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    function handleClick(event) {
      if (!menuRef.current || !triggerRef.current) {
        return;
      }
      if (
        !menuRef.current.contains(event.target) &&
        !triggerRef.current.contains(event.target)
      ) {
        setOpen(false);
      }
    }

    function handleKeyDown(event) {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }

    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  if (loading) {
    return <div className="account-menu__placeholder" aria-hidden="true" />;
  }

  const initials = me
    ? (me.username || me.email || '?')[0]?.toUpperCase() || '?'
    : '👤';

  const pendingStage = pendingRegistration?.stage ?? null;
  const pendingEmail = pendingRegistration?.email ?? null;

  const goTo = (path) => {
    setOpen(false);
    navigate(path);
  };

  const handleLogout = async () => {
    try {
      await logout();
      setOpen(false);
    } catch (error) {
      console.error('Failed to log out', error);
    }
  };

  return (
    <div className="account-menu">
      <button
        ref={triggerRef}
        type="button"
        className="account-menu__button"
        aria-haspopup="menu"
        aria-expanded={open ? 'true' : 'false'}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="account-menu__avatar" aria-hidden="true">
          {initials}
        </span>
        <span className="sr-only">Account</span>
      </button>
      {open ? (
        <div className="account-menu__dropdown" role="menu" ref={menuRef}>
          {me ? (
            <>
              <div className="account-menu__summary">
                <div className="account-menu__avatar account-menu__avatar--inline" aria-hidden="true">
                  {initials}
                </div>
                <div>
                  <p className="account-menu__summary-name">{me.username || 'No username set'}</p>
                  <p className="account-menu__summary-email">{me.email}</p>
                </div>
              </div>
              <button type="button" className="account-menu__item" onClick={handleLogout}>
                Log out
              </button>
            </>
          ) : (
            <>
              {pendingStage ? (
                <div className="account-menu__pending">
                  <p>Finish signing up</p>
                  <p className="account-menu__pending-email">{pendingEmail}</p>
                  <button
                    type="button"
                    className="account-menu__item account-menu__item--primary"
                    onClick={() => goTo(routesByStage[pendingStage] ?? '/register')}
                  >
                    Continue
                  </button>
                </div>
              ) : null}
              <button
                type="button"
                className="account-menu__item"
                onClick={() => goTo('/login')}
              >
                Log in
              </button>
              <button
                type="button"
                className="account-menu__item"
                onClick={() => goTo('/register')}
              >
                Create account
              </button>
            </>
          )}
        </div>
      ) : null}
    </div>
  );
};

export default AccountMenu;


File: frontend\src\components\CalendarGrid.jsx
import React from 'react';
import DayCell from './DayCell.jsx';

const CalendarGrid = ({ days, eventsByDay, weekdayLabels, onSelectEvent, registerTrigger }) => (
  <div className="calendar-card" role="region" aria-label="Monthly calendar">
    <div className="weekday-row" role="row">
      {weekdayLabels.map((label) => (
        <div key={label} className="weekday" role="columnheader" aria-label={label}>
          {label}
        </div>
      ))}
    </div>
    <div className="calendar-grid" role="grid">
      {days.map((day) => (
        <DayCell
          key={day.iso}
          day={day}
          events={eventsByDay.get(day.date.toDateString()) ?? []}
          onSelectEvent={onSelectEvent}
          registerTrigger={registerTrigger}
        />
      ))}
    </div>
  </div>
);

export default CalendarGrid;


File: frontend\src\components\DayCell.jsx
import React from 'react';
import EventChip from './EventChip.jsx';
import { formatDayNumber, getAccessibleDayLabel } from '@/utils/dates';

const DayCell = ({ day, events, onSelectEvent, registerTrigger }) => {
  const { date, isCurrentMonth, isToday } = day;
  const dayNumber = formatDayNumber(date);
  const accessibleLabel = getAccessibleDayLabel(date, { isToday });

  return (
    <div
      className={`day-cell${isCurrentMonth ? '' : ' day-cell--muted'}${isToday ? ' day-cell--today' : ''}`}
      role="gridcell"
      aria-label={accessibleLabel}
    >
      <div className="day-cell__header">
        <span className="day-cell__number" aria-hidden="true">
          {dayNumber}
        </span>
        {events.length > 0 && (
          <span className="day-cell__count" aria-hidden="true">
            {events.length}
          </span>
        )}
      </div>
      <div className="day-cell__events">
        {events.map((event) => (
          <EventChip
            key={event.id}
            event={event}
            onSelect={onSelectEvent}
            ref={(node) => registerTrigger(event.id, node)}
          />
        ))}
      </div>
    </div>
  );
};

export default DayCell;


File: frontend\src\components\EventChip.jsx
import React from 'react';
import { formatTimeRange } from '@/utils/dates';

const EventChip = React.forwardRef(({ event, onSelect }, ref) => {
  const { title, startsAt, endsAt, categoryMeta } = event;
  const label = `${title} ${formatTimeRange(startsAt, endsAt)}`;
  const background = categoryMeta?.color ?? '#e5e7eb';
  const textColor = categoryMeta?.textColor ?? '#1f2937';

  return (
    <button
      ref={ref}
      type="button"
      className="event-chip"
      style={{ backgroundColor: background, color: textColor }}
      onClick={() => onSelect(event)}
      aria-haspopup="dialog"
      aria-controls="event-panel"
      aria-label={label}
    >
      <span className="event-chip__title">{title}</span>
      <span className="event-chip__time">{formatTimeRange(startsAt, endsAt)}</span>
    </button>
  );
});

EventChip.displayName = 'EventChip';

export default EventChip;


File: frontend\src\components\EventPanel.jsx
import React, { useEffect, useRef } from 'react';
import { formatTimeRange } from '@/utils/dates';
import { trapFocus } from '@/utils/a11y';

const EventPanel = ({ event, open, onClose }) => {
  const panelRef = useRef(null);
  const closeButtonRef = useRef(null);

  useEffect(() => {
    if (open && closeButtonRef.current) {
      closeButtonRef.current.focus();
    }
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      } else {
        trapFocus(event, panelRef.current);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) return undefined;
    const original = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = original;
    };
  }, [open]);

  if (!open || !event) return null;

  const { title, description, startsAt, endsAt, location, organizer, categoryMeta, category } = event;

  return (
    <div className="event-panel__portal" role="presentation">
      <div className="event-panel__backdrop" onClick={onClose} aria-hidden="true" />
      <aside
        id="event-panel"
        className="event-panel"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={panelRef}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="event-panel__header">
          <h2>{title}</h2>
          <button
            type="button"
            ref={closeButtonRef}
            className="event-panel__close"
            onClick={onClose}
            aria-label="Close event details"
          >
            ×
          </button>
        </header>
        <div className="event-panel__meta">
          {categoryMeta && (
            <span
              className="event-panel__badge"
              style={{ backgroundColor: categoryMeta.color, color: categoryMeta.textColor }}
            >
              {categoryMeta.label}
            </span>
          )}
          <span className="event-panel__time">{formatTimeRange(startsAt, endsAt)}</span>
        </div>
        <p className="event-panel__description">{description}</p>
        <dl className="event-panel__details">
          <div>
            <dt>When</dt>
            <dd>{startsAt.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' })}</dd>
          </div>
          <div>
            <dt>Where</dt>
            <dd>{location}</dd>
          </div>
          <div>
            <dt>Organizer</dt>
            <dd>{organizer}</dd>
          </div>
        </dl>
        <p className="event-panel__footnote" aria-label="Mock data note">
          Mock data for MVP · Category: {category}
        </p>
      </aside>
    </div>
  );
};

export default EventPanel;


File: frontend\src\context\AuthContext.jsx
import React, { createContext, useCallback, useEffect, useMemo, useState } from 'react';

import { api, ensureCsrf } from '@/utils/api';

const STORAGE_KEY = 'pending-registration';

function readStoredPending() {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (error) {
    console.warn('Failed to parse stored registration state', error);
    return null;
  }
}

function persistPending(pending) {
  if (typeof window === 'undefined') {
    return;
  }
  try {
    if (pending) {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(pending));
    } else {
      window.sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch (error) {
    console.warn('Failed to persist registration state', error);
  }
}

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [pendingRegistration, setPendingRegistration] = useState(() => readStoredPending());

  useEffect(() => {
    persistPending(pendingRegistration);
  }, [pendingRegistration]);

  const refresh = useCallback(async () => {
    try {
      const data = await api('/auth/me');
      setMe(data);
    } catch (error) {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function boot() {
      try {
        await ensureCsrf();
        if (!cancelled) {
          await refresh();
        }
      } catch (error) {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    boot();
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  const register = useCallback(
    async (email, password) => {
      const normalizedEmail = email.trim().toLowerCase();
      await ensureCsrf();
      const data = await api('/auth/register', {
        method: 'POST',
        data: { email: normalizedEmail, password }
      });
      const next = {
        email: normalizedEmail,
        stage: 'verify',
        registrationToken: data.registration_token,
        mockCode: data.mock_verification_code ?? null
      };
      setPendingRegistration(next);
      return next;
    },
    []
  );

  const verifyCode = useCallback(
    async (code, overrides = {}) => {
      const token = overrides.registrationToken ?? pendingRegistration?.registrationToken ?? null;
      const email = overrides.email ?? pendingRegistration?.email ?? null;

      if (!token && !email) {
        throw new Error('Account details required to verify code.');
      }

      const payload = { code };
      if (token) payload.registration_token = token;
      if (email) payload.email = email;

      const data = await api('/auth/verify-code', { method: 'POST', data: payload });

      if (data.username_required) {
        if (!data.registration_token) {
          throw new Error('Missing registration token for username setup.');
        }
        setPendingRegistration({
          email,
          stage: 'username',
          registrationToken: data.registration_token,
          mockCode: null
        });
      } else {
        setPendingRegistration(null);
      }

      return data;
    },
    [pendingRegistration]
  );

  const completeUsername = useCallback(
    async (username, overrides = {}) => {
      const token = overrides.registrationToken ?? pendingRegistration?.registrationToken ?? null;
      if (!token) {
        throw new Error('Registration token required to complete username.');
      }
      const data = await api('/auth/username', {
        method: 'POST',
        data: { username, registration_token: token }
      });
      setPendingRegistration(null);
      return data;
    },
    [pendingRegistration]
  );

  const login = useCallback(
    async (email, password) => {
      await ensureCsrf();
      await api('/auth/login', { method: 'POST', data: { email, password } });
      await refresh();
    },
    [refresh]
  );

  const logout = useCallback(async () => {
    await ensureCsrf();
    await api('/auth/logout', { method: 'POST' });
    setMe(null);
  }, []);

  const clearPendingRegistration = useCallback(() => {
    setPendingRegistration(null);
  }, []);

  const value = useMemo(
    () => ({
      me,
      loading,
      pendingRegistration,
      register,
      verifyCode,
      completeUsername,
      login,
      logout,
      refresh,
      clearPendingRegistration
    }),
    [
      clearPendingRegistration,
      completeUsername,
      loading,
      login,
      logout,
      me,
      pendingRegistration,
      refresh,
      register,
      verifyCode
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}


File: frontend\src\data\mockEvents.js
const categories = {
  market: { label: 'Market', color: '#dbeafe', textColor: '#1d4ed8' },
  civic: { label: 'Civic', color: '#fef3c7', textColor: '#b45309' },
  tech: { label: 'Tech', color: '#ede9fe', textColor: '#6d28d9' },
  rec: { label: 'Recreation', color: '#dcfce7', textColor: '#047857' },
  volunteer: { label: 'Volunteer', color: '#fee2e2', textColor: '#b91c1c' },
  maker: { label: 'Maker', color: '#fff1f2', textColor: '#be123c' },
  library: { label: 'Library', color: '#fdf2f8', textColor: '#a21caf' }
};

const current = new Date();
const currentMonth = current.getMonth();
const currentYear = current.getFullYear();

const createDateTime = (dayOfMonth, hour, minute = 0) =>
  new Date(currentYear, currentMonth, dayOfMonth, hour, minute);

const createEvent = (id, day, startHour, startMinute, durationMinutes, overrides) => {
  const startsAt = createDateTime(day, startHour, startMinute);
  const endsAt = new Date(startsAt.getTime() + durationMinutes * 60 * 1000);
  return {
    id,
    startsAt,
    endsAt,
    ...overrides
  };
};

export const mockEvents = [
  createEvent('market-1', 3, 9, 0, 120, {
    title: 'Riverside Farmers Market',
    description: 'Browse seasonal produce, artisan breads, and small-batch goods from local growers.',
    location: 'Riverside Park Plaza',
    category: 'market',
    organizer: 'City Markets Cooperative'
  }),
  createEvent('civic-1', 6, 18, 30, 90, {
    title: 'Neighborhood Council Forum',
    description: 'Discuss upcoming zoning updates and community initiatives with council members.',
    location: 'Civic Hall Auditorium',
    category: 'civic',
    organizer: '5th Ward Council'
  }),
  createEvent('tech-1', 11, 12, 0, 75, {
    title: 'Lunchtime Tech Talk: Intro to Web Accessibility',
    description: 'A friendly primer on building inclusive interfaces, led by local accessibility advocates.',
    location: 'Innovation Hub, 3rd Floor Lab',
    category: 'tech',
    organizer: 'Midtown Tech Guild'
  }),
  createEvent('rec-1', 15, 7, 30, 60, {
    title: 'Sunrise Mindful Movement',
    description: 'An easy-going blend of stretching and breathing to welcome the day beside the gardens.',
    location: 'Botanical Conservatory Lawn',
    category: 'rec',
    organizer: 'City Parks & Wellness'
  }),
  createEvent('volunteer-1', 19, 10, 0, 150, {
    title: 'Community Garden Volunteer Day',
    description: 'Help refresh garden beds, plant pollinator flowers, and connect with fellow volunteers.',
    location: 'Maple & 9th Community Garden',
    category: 'volunteer',
    organizer: 'Green Sprouts Collective'
  }),
  createEvent('maker-1', 24, 17, 0, 120, {
    title: 'Makerspace Open Build Night',
    description: 'Bring a project or collaborate on group builds with access to tools and mentors.',
    location: 'Foundry Makerspace',
    category: 'maker',
    organizer: 'Foundry Mentors'
  }),
  createEvent('library-1', 28, 14, 0, 60, {
    title: 'Library Author Spotlight: Voices of the River',
    description: 'A moderated discussion with local authors exploring storytelling and place.',
    location: 'Downtown Library Reading Room',
    category: 'library',
    organizer: 'Downtown Library Association'
  })
].map((event) => ({
  ...event,
  categoryMeta: categories[event.category] ?? null
}));

export const getEventCategoryMeta = (category) => categories[category] ?? null;


File: frontend\src\hooks\useAuth.js
import { useContext } from 'react';

import { AuthContext } from '@/context/AuthContext.jsx';

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}


File: frontend\src\layouts\AppLayout.jsx
import React from 'react';
import { Outlet } from 'react-router-dom';

import AccountMenu from '@/components/AccountMenu.jsx';

const AppLayout = () => (
  <div className="app-shell">
    <header className="app-header">
      <div>
        <p className="app-header__eyebrow">Local events (mock)</p>
        <h1>Community calendar</h1>
        <p className="app-header__subtitle">
          Discover what&apos;s happening around town this month — curated highlights for inspiration.
        </p>
      </div>
      <AccountMenu />
    </header>
    <main className="app-main">
      <Outlet />
    </main>
  </div>
);

export default AppLayout;


File: frontend\src\main.jsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import App from './App.jsx';
import { AuthProvider } from '@/context/AuthContext.jsx';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);


File: frontend\src\pages\CalendarPage.jsx
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import CalendarGrid from '@/components/CalendarGrid.jsx';
import EventPanel from '@/components/EventPanel.jsx';
import { mockEvents } from '@/data/mockEvents';
import { generateMonthGrid, getMonthLabel, getWeekdayLabels } from '@/utils/dates';

const CalendarPage = () => {
  const [today] = useState(() => new Date());
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [activeTriggerId, setActiveTriggerId] = useState(null);
  const triggerRefs = useRef(new Map());

  const weekdayLabels = useMemo(() => getWeekdayLabels(), []);
  const monthLabel = useMemo(() => getMonthLabel(today), [today]);
  const calendarDays = useMemo(() => generateMonthGrid(today), [today]);

  const events = useMemo(() => mockEvents, []);

  const eventsByDay = useMemo(() => {
    const map = new Map();
    events.forEach((event) => {
      const key = event.startsAt.toDateString();
      if (!map.has(key)) {
        map.set(key, []);
      }
      map.get(key).push(event);
    });
    map.forEach((list) => list.sort((a, b) => a.startsAt - b.startsAt));
    return map;
  }, [events]);

  const selectedEvent = useMemo(
    () => events.find((event) => event.id === selectedEventId) ?? null,
    [events, selectedEventId]
  );

  const handleSelectEvent = useCallback((event) => {
    setActiveTriggerId(event.id);
    setSelectedEventId(event.id);
  }, []);

  const registerTrigger = useCallback((eventId, node) => {
    if (!node) {
      triggerRefs.current.delete(eventId);
    } else {
      triggerRefs.current.set(eventId, node);
    }
  }, []);

  const handleClosePanel = useCallback(() => {
    setSelectedEventId(null);
  }, []);

  useEffect(() => {
    if (selectedEventId === null && activeTriggerId) {
      const trigger = triggerRefs.current.get(activeTriggerId);
      if (trigger) {
        trigger.focus();
      }
      setActiveTriggerId(null);
    }
  }, [selectedEventId, activeTriggerId]);

  return (
    <>
      <div className="calendar-card">
        <header className="calendar-card__header">
          <div>
            <h2 className="calendar-card__title">{monthLabel}</h2>
            <p className="calendar-card__subtitle">
              Mock data to demonstrate the layout. Events are refreshed monthly.
            </p>
          </div>
        </header>
        <CalendarGrid
          days={calendarDays}
          eventsByDay={eventsByDay}
          weekdayLabels={weekdayLabels}
          onSelectEvent={handleSelectEvent}
          registerTrigger={registerTrigger}
        />
      </div>
      <EventPanel event={selectedEvent} open={Boolean(selectedEvent)} onClose={handleClosePanel} />
    </>
  );
};

export default CalendarPage;


File: frontend\src\pages\LoginPage.jsx
import React, { useEffect, useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const LoginPage = () => {
  const { me, loading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const destination = location.state?.from ?? '/';

  useEffect(() => {
    setError('');
  }, [email, password]);

  if (!loading && me) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await login(email, password);
      navigate(destination, { replace: true });
    } catch (err) {
      setError(err.message || 'Unable to log in');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Log in</h2>
      <p className="auth-card__intro">Enter your credentials to access the calendar.</p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            autoComplete="email"
          />
        </label>
        <label className="auth-form__field">
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            autoComplete="current-password"
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Log in'}
        </button>
      </form>
      <p className="auth-card__footer">
        No account yet?{' '}
        <Link to="/register" className="auth-link">
          Sign up
        </Link>
      </p>
    </div>
  );
};

export default LoginPage;


File: frontend\src\pages\RegisterPage.jsx
import React, { useEffect, useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const RegisterPage = () => {
  const { me, loading, register, pendingRegistration } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (pendingRegistration?.stage === 'verify') {
      return;
    }
    if (pendingRegistration?.stage === 'username') {
      navigate('/username-setup', { replace: true });
    }
  }, [pendingRegistration, navigate]);

  useEffect(() => {
    setError('');
  }, [email, password]);

  if (!loading && me) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await register(email, password);
      navigate('/verify', { replace: false });
    } catch (err) {
      setError(err.message || 'Unable to register');
    } finally {
      setSubmitting(false);
    }
  };

  const mockCode = pendingRegistration?.mockCode ?? null;

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Create account</h2>
      <p className="auth-card__intro">
        Start by entering your email and a password. We will send a verification code to continue.
      </p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            autoComplete="email"
          />
        </label>
        <label className="auth-form__field">
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            autoComplete="new-password"
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Submitting…' : 'Register'}
        </button>
      </form>
      <p className="auth-card__footer">
        Already registered?{' '}
        <Link to="/login" className="auth-link">
          Log in
        </Link>
      </p>
      {mockCode ? (
        <p className="auth-card__mock-code" aria-live="polite">
          Dev verification code: <span>{mockCode}</span>
        </p>
      ) : null}
    </div>
  );
};

export default RegisterPage;


File: frontend\src\pages\UsernameSetupPage.jsx
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const UsernameSetupPage = () => {
  const { me, loading, pendingRegistration, completeUsername } = useAuth();
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (pendingRegistration?.stage !== 'username' && !loading && !me) {
      setSuccess(false);
    }
  }, [pendingRegistration, loading, me]);

  if (!loading && me) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Username already set</h2>
        <p className="auth-card__intro">You can go straight to the calendar.</p>
        <Link to="/" className="auth-form__submit auth-form__submit--link">
          Back to calendar
        </Link>
      </div>
    );
  }

  if (!pendingRegistration || pendingRegistration?.stage !== 'username') {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">You&apos;re almost there</h2>
        <p className="auth-card__intro">
          Finish registration by verifying your email first so we know it&apos;s really you.
        </p>
        <Link to="/verify" className="auth-form__submit auth-form__submit--link">
          Enter verification code
        </Link>
      </div>
    );
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await completeUsername(username);
      setSuccess(true);
    } catch (err) {
      setError(err.message || 'Unable to save username');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Choose a username</h2>
      <p className="auth-card__intro">
        Usernames help friends find you. They must be 3–30 characters with letters, numbers, or underscores.
      </p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
            minLength={3}
            maxLength={30}
            autoComplete="username"
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        {success ? (
          <p className="auth-form__message auth-form__message--success" role="status">
            Saved! You can log in now.
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Saving…' : 'Save username'}
        </button>
      </form>
      <div className="auth-card__footer auth-card__footer--stack">
        <p>
          Ready to sign in?{' '}
          <Link to="/login" className="auth-link">
            Log in
          </Link>
        </p>
        <p>
          Need a different email?{' '}
          <Link to="/register" className="auth-link">
            Start over
          </Link>
        </p>
      </div>
    </div>
  );
};

export default UsernameSetupPage;


File: frontend\src\pages\VerifyPage.jsx
import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const VerifyPage = () => {
  const { me, loading, pendingRegistration, verifyCode } = useAuth();
  const navigate = useNavigate();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (pendingRegistration?.mockCode && !code) {
      setCode(pendingRegistration.mockCode);
    }
  }, [pendingRegistration, code]);

  useEffect(() => {
    setError('');
  }, [code]);

  useEffect(() => {
    if (pendingRegistration?.stage === 'username') {
      navigate('/username-setup', { replace: true });
    }
  }, [pendingRegistration, navigate]);

  if (!loading && me) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Already verified</h2>
        <p className="auth-card__intro">Your account is active. You can head back to the calendar.</p>
        <Link to="/" className="auth-form__submit--link">
          Back to calendar
        </Link>
      </div>
    );
  }

  if (!pendingRegistration) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Need an account?</h2>
        <p className="auth-card__intro">
          Start by registering with your email and password so we know where to send your verification code.
        </p>
        <Link to="/register" className="auth-form__submit--link">
          Register now
        </Link>
      </div>
    );
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const result = await verifyCode(code);
      if (result.username_required) {
        navigate('/username-setup', { replace: true });
      } else {
        navigate('/login', { replace: true });
      }
    } catch (err) {
      setError(err.message || 'Verification failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Check your email</h2>
      <p className="auth-card__intro">
        Enter the 6-digit code we sent to <strong>{pendingRegistration.email}</strong>.
      </p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Verification code</span>
          <input
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            value={code}
            onChange={(event) => setCode(event.target.value)}
            required
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Verifying…' : 'Verify'}
        </button>
      </form>
      <p className="auth-card__footer">
        Didn&apos;t get an email?{' '}
        <Link to="/register" className="auth-link">
          Try registering again
        </Link>
      </p>
    </div>
  );
};

export default VerifyPage;


File: frontend\src\styles.css
:root {
  color-scheme: light;
  --bg-gradient-start: #f6f7fb;
  --bg-gradient-end: #ffffff;
  --card-bg: #ffffff;
  --card-radius: 18px;
  --chip-radius: 10px;
  --shadow-soft: 0 20px 45px -28px rgba(15, 23, 42, 0.45);
  --text-primary: #1f2937;
  --text-secondary: #4b5563;
  --accent: #2563eb;
  --accent-soft: rgba(37, 99, 235, 0.12);
  --muted: #e5e7eb;
  --today-bg: #2563eb;
  --today-ring: rgba(37, 99, 235, 0.16);
  --backdrop: rgba(15, 23, 42, 0.28);
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

*, *::before, *::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background: linear-gradient(180deg, var(--bg-gradient-start), var(--bg-gradient-end));
  color: var(--text-primary);
}

button {
  font-family: inherit;
}

a {
  color: inherit;
}

#root {
  min-height: 100vh;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

:focus-visible {
  outline: 3px solid var(--accent);
  outline-offset: 2px;
}

@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}

.app-shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  padding: 48px 32px 64px;
}

.app-header {
  margin: 0 auto 36px;
  max-width: 1180px;
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
}

.app-header h1 {
  margin: 6px 0 0;
  font-size: clamp(32px, 4vw, 40px);
  font-weight: 600;
}

.app-header__eyebrow {
  margin: 0;
  font-size: 15px;
  font-weight: 500;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.app-header__subtitle {
  margin: 0;
  max-width: 420px;
  font-size: 16px;
  color: var(--text-secondary);
  line-height: 1.5;
}

.account-menu {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  min-width: 52px;
}

.account-menu__placeholder {
  width: 44px;
  height: 44px;
  border-radius: 999px;
  background: var(--muted);
  opacity: 0.35;
}

.account-menu__button {
  border: none;
  background: var(--card-bg);
  border-radius: 999px;
  width: 48px;
  height: 48px;
  display: grid;
  place-items: center;
  cursor: pointer;
  box-shadow: 0 12px 30px -18px rgba(15, 23, 42, 0.4);
  transition: transform 120ms ease, box-shadow 120ms ease;
}

.account-menu__button:hover,
.account-menu__button:focus-visible {
  transform: translateY(-1px);
  box-shadow: 0 16px 38px -18px rgba(15, 23, 42, 0.5);
}

.account-menu__avatar {
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: 999px;
  background: var(--accent);
  color: #fff;
  font-weight: 600;
  font-size: 16px;
}

.account-menu__avatar--inline {
  width: 40px;
  height: 40px;
  font-size: 18px;
}

.account-menu__dropdown {
  position: absolute;
  top: 58px;
  right: 0;
  width: max-content;
  min-width: 240px;
  background: var(--card-bg);
  border-radius: 18px;
  box-shadow: var(--shadow-soft);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  z-index: 50;
}

.account-menu__summary {
  display: flex;
  align-items: center;
  gap: 12px;
}

.account-menu__summary-name {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.account-menu__summary-email {
  margin: 4px 0 0;
  font-size: 14px;
  color: var(--text-secondary);
}

.account-menu__item {
  border: none;
  background: rgba(37, 99, 235, 0.08);
  color: var(--accent);
  font-weight: 600;
  padding: 10px 14px;
  border-radius: 12px;
  cursor: pointer;
  text-align: left;
  transition: background 120ms ease, transform 120ms ease;
}

.account-menu__item:hover,
.account-menu__item:focus-visible {
  background: rgba(37, 99, 235, 0.16);
  transform: translateY(-1px);
}

.account-menu__item--primary {
  background: var(--accent);
  color: #fff;
}

.account-menu__item--primary:hover,
.account-menu__item--primary:focus-visible {
  background: #1d4ed8;
}

.account-menu__pending {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.account-menu__pending p {
  margin: 0;
  font-size: 14px;
}

.account-menu__pending-email {
  color: var(--text-secondary);
}

.app-main {
  display: flex;
  justify-content: center;
  align-items: flex-start;
  padding: 0 16px;
}

.calendar-card {
  background: var(--card-bg);
  box-shadow: var(--shadow-soft);
  border-radius: var(--card-radius);
  padding: 28px;
  max-width: 1180px;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.calendar-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.calendar-card__title {
  margin: 0;
  font-size: clamp(26px, 3vw, 32px);
  font-weight: 600;
}

.calendar-card__subtitle {
  margin: 6px 0 0;
  font-size: 14px;
  color: var(--text-secondary);
}

.weekday-row {
  display: grid;
  grid-template-columns: repeat(7, minmax(0, 1fr));
  font-size: 14px;
  font-weight: 600;
  color: var(--text-secondary);
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.weekday {
  padding: 0 12px 8px;
}

.calendar-grid {
  display: grid;
  grid-template-columns: repeat(7, minmax(0, 1fr));
  gap: 8px;
}

.day-cell {
  background: linear-gradient(180deg, rgba(249, 250, 251, 0.7), #fff);
  border-radius: 14px;
  padding: 12px;
  min-height: 120px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  border: 1px solid rgba(226, 232, 240, 0.7);
  position: relative;
  transition: border 150ms ease-in-out, box-shadow 150ms ease-in-out;
}

.day-cell--muted {
  opacity: 0.55;
}

.day-cell--today {
  border-color: var(--today-bg);
  box-shadow: 0 0 0 2px var(--today-ring);
}

.day-cell__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 14px;
}

.day-cell__number {
  font-weight: 600;
}

.day-cell__count {
  font-size: 12px;
  background: rgba(15, 23, 42, 0.08);
  color: var(--text-secondary);
  border-radius: 999px;
  padding: 2px 6px;
}

.day-cell__events {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.event-chip {
  border: none;
  border-radius: var(--chip-radius);
  padding: 8px 10px;
  text-align: left;
  cursor: pointer;
  transition: transform 150ms ease-in-out, box-shadow 150ms ease-in-out;
  box-shadow: 0 10px 22px -18px rgba(15, 23, 42, 0.75);
}

.event-chip:hover,
.event-chip:focus-visible {
  transform: translateY(-1px);
  box-shadow: 0 14px 30px -20px rgba(15, 23, 42, 0.8);
}

.event-chip__title {
  display: block;
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 2px;
}

.event-chip__time {
  display: block;
  font-size: 13px;
  opacity: 0.9;
}

.event-panel__portal {
  position: fixed;
  inset: 0;
  display: flex;
  justify-content: flex-end;
  align-items: stretch;
  z-index: 1000;
}

.event-panel__backdrop {
  flex: 1;
  background: var(--backdrop);
  backdrop-filter: blur(2px);
  animation: fadeIn 220ms ease;
}

.event-panel {
  width: min(420px, 90vw);
  background: #ffffff;
  padding: 32px;
  box-shadow: -18px 0 30px -24px rgba(15, 23, 42, 0.35);
  display: flex;
  flex-direction: column;
  gap: 24px;
  overflow-y: auto;
  animation: slideIn 280ms ease-out;
}

.event-panel__header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}

.event-panel__header h2 {
  margin: 0;
  font-size: 24px;
}

.event-panel__close {
  background: none;
  border: none;
  font-size: 32px;
  line-height: 1;
  cursor: pointer;
  color: var(--text-secondary);
  padding: 0;
  border-radius: 8px;
  transition: background 150ms ease;
}

.event-panel__close:hover,
.event-panel__close:focus-visible {
  background: rgba(148, 163, 184, 0.16);
}

.event-panel__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  font-size: 15px;
  color: var(--text-secondary);
}

.event-panel__badge {
  border-radius: 999px;
  padding: 6px 12px;
  font-weight: 600;
  font-size: 13px;
}

.event-panel__time {
  font-weight: 500;
}

.event-panel__description {
  margin: 0;
  font-size: 16px;
  line-height: 1.6;
  color: var(--text-primary);
}

.event-panel__details {
  margin: 0;
  display: grid;
  gap: 16px;
  font-size: 15px;
}

.event-panel__details div {
  display: grid;
  gap: 4px;
}

.event-panel__details dt {
  font-weight: 600;
  color: var(--text-secondary);
}

.event-panel__details dd {
  margin: 0;
}

.event-panel__footnote {
  margin: 0;
  font-size: 13px;
  color: var(--text-secondary);
}

.auth-card {
  background: var(--card-bg);
  box-shadow: var(--shadow-soft);
  border-radius: var(--card-radius);
  padding: 32px;
  max-width: 420px;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.auth-card__title {
  margin: 0;
  font-size: clamp(26px, 3vw, 32px);
  font-weight: 600;
}

.auth-card__intro {
  margin: 0;
  color: var(--text-secondary);
  line-height: 1.5;
}

.auth-card__footer {
  margin: 0;
  font-size: 14px;
  color: var(--text-secondary);
}

.auth-card__footer--stack {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.auth-card__mock-code {
  margin: 0;
  font-size: 14px;
  background: #1f2937;
  color: #ffffff;
  border-radius: 12px;
  padding: 10px 14px;
  align-self: flex-start;
}

.auth-card__mock-code span {
  font-weight: 600;
  letter-spacing: 0.24em;
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.auth-form__field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 14px;
  color: var(--text-secondary);
}

.auth-form__field input {
  border: 1px solid rgba(148, 163, 184, 0.5);
  border-radius: 10px;
  padding: 12px 14px;
  font-size: 16px;
  transition: border 120ms ease, box-shadow 120ms ease;
}

.auth-form__field input:focus-visible {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.18);
  outline: none;
}

.auth-form__message {
  margin: 0;
  font-size: 14px;
  padding: 10px 12px;
  border-radius: 10px;
}

.auth-form__message--error {
  background: rgba(239, 68, 68, 0.12);
  color: #b91c1c;
}

.auth-form__message--success {
  background: rgba(16, 185, 129, 0.12);
  color: #047857;
}

.auth-form__submit {
  border: none;
  background: var(--accent);
  color: #ffffff;
  border-radius: 12px;
  padding: 12px 16px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: transform 120ms ease, box-shadow 120ms ease;
}

.auth-form__submit:hover,
.auth-form__submit:focus-visible {
  transform: translateY(-1px);
  box-shadow: 0 16px 44px -22px rgba(37, 99, 235, 0.6);
}

.auth-form__submit:disabled {
  opacity: 0.7;
  cursor: wait;
  transform: none;
  box-shadow: none;
}

.auth-form__submit--link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  background: rgba(37, 99, 235, 0.08);
  color: var(--accent);
  text-decoration: none;
  font-weight: 600;
  padding: 11px 16px;
  border-radius: 12px;
  transition: background 120ms ease;
}

.auth-form__submit--link:hover,
.auth-form__submit--link:focus-visible {
  background: rgba(37, 99, 235, 0.16);
}

.auth-link {
  color: var(--accent);
  font-weight: 600;
  text-decoration: none;
}

.auth-link:hover,
.auth-link:focus-visible {
  text-decoration: underline;
}

@keyframes slideIn {
  from {
    transform: translateX(40px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

@keyframes fadeIn {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}

@media (max-width: 960px) {
  .app-shell {
    padding: 32px 20px 48px;
  }

  .app-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .app-main {
    padding: 0;
  }
}

@media (max-width: 680px) {
  .calendar-card {
    padding: 20px;
  }

  .calendar-grid {
    gap: 6px;
  }

  .day-cell {
    padding: 10px;
  }
}


File: frontend\src\utils\a11y.js
export const getFocusableElements = (container) => {
  if (!container) return [];
  const selector = [
    'a[href]',
    'button:not([disabled])',
    'textarea:not([disabled])',
    'input:not([type="hidden"]):not([disabled])',
    'select:not([disabled])',
    '[tabindex]:not([tabindex="-1"])'
  ].join(',');

  return Array.from(container.querySelectorAll(selector)).filter(
    (element) => !element.hasAttribute('aria-hidden') && element.offsetParent !== null
  );
};

export const trapFocus = (event, container) => {
  if (event.key !== 'Tab' || !container) return;
  const focusable = getFocusableElements(container);
  if (!focusable.length) {
    event.preventDefault();
    return;
  }

  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const isShift = event.shiftKey;
  const active = document.activeElement;

  if (!isShift && active === last) {
    event.preventDefault();
    first.focus();
  } else if (isShift && active === first) {
    event.preventDefault();
    last.focus();
  }
};


File: frontend\src\utils\api.js
function readCookie(name) {
  const item = document.cookie.split('; ').find(row => row.startsWith(name + '='));
  return item ? decodeURIComponent(item.split('=')[1]) : null;
}

export async function api(path, { method = 'GET', data, headers } = {}) {
  const verb = method.toUpperCase();
  const isMutating = !['GET', 'HEAD', 'OPTIONS'].includes(verb);
  const baseHeaders = { 'Content-Type': 'application/json', ...(headers || {}) };

  if (isMutating) {
    const csrf = readCookie('csrf_token');
    if (csrf) {
      baseHeaders['X-CSRF-Token'] = csrf;
    }
  }

  const response = await fetch(path, {
    method: verb,
    headers: baseHeaders,
    credentials: 'include',
    body: data ? JSON.stringify(data) : undefined
  });

  if (!response.ok) {
    let message = 'Request failed';
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch (err) {
      /* ignore JSON parse errors */
    }
    throw new Error(message);
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

export async function ensureCsrf() {
  try {
    await api('/auth/csrf');
  } catch (err) {
    console.warn('Failed to establish CSRF cookie', err);
  }
}


File: frontend\src\utils\dates.js
const WEEKDAY_FORMATTER = new Intl.DateTimeFormat(undefined, {
  weekday: 'short'
});

const MONTH_FORMATTER = new Intl.DateTimeFormat(undefined, {
  month: 'long',
  year: 'numeric'
});

const DAY_NUMBER_FORMATTER = new Intl.DateTimeFormat(undefined, {
  day: 'numeric'
});

const TIME_FORMATTER = new Intl.DateTimeFormat(undefined, {
  hour: 'numeric',
  minute: '2-digit'
});

export const getWeekdayLabels = () => {
  const baseSunday = new Date(Date.UTC(2023, 0, 1));
  return Array.from({ length: 7 }, (_, index) => {
    const date = new Date(baseSunday);
    date.setUTCDate(baseSunday.getUTCDate() + index);
    return WEEKDAY_FORMATTER.format(date);
  });
};

export const getMonthLabel = (date) => MONTH_FORMATTER.format(date);

export const isSameDay = (a, b) =>
  a.getFullYear() === b.getFullYear() &&
  a.getMonth() === b.getMonth() &&
  a.getDate() === b.getDate();

const startOfMonth = (date) => new Date(date.getFullYear(), date.getMonth(), 1);
const endOfMonth = (date) => new Date(date.getFullYear(), date.getMonth() + 1, 0);

export const generateMonthGrid = (date = new Date()) => {
  const firstOfMonth = startOfMonth(date);
  const lastOfMonth = endOfMonth(date);
  const startDay = new Date(firstOfMonth);
  startDay.setDate(firstOfMonth.getDate() - firstOfMonth.getDay());

  const endDay = new Date(lastOfMonth);
  endDay.setDate(lastOfMonth.getDate() + (6 - lastOfMonth.getDay()));

  const days = [];
  const current = new Date(startDay);
  const today = new Date();

  while (days.length < 42) {
    days.push({
      date: new Date(current),
      iso: current.toISOString(),
      isCurrentMonth:
        current.getMonth() === date.getMonth() && current.getFullYear() === date.getFullYear(),
      isToday: isSameDay(current, today)
    });
    current.setDate(current.getDate() + 1);
  }

  return days;
};

export const formatDayNumber = (date) => DAY_NUMBER_FORMATTER.format(date);

export const formatTimeRange = (start, end) => `${TIME_FORMATTER.format(start)} – ${TIME_FORMATTER.format(end)}`;

export const getAccessibleDayLabel = (date, { isToday = false } = {}) => {
  const formatter = new Intl.DateTimeFormat(undefined, {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric'
  });
  const base = formatter.format(date);
  return isToday ? `${base}, Today` : base;
};


File: frontend\vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  },
  server: {
    proxy: {
      '/auth': 'http://localhost:8000',
      '/healthz': 'http://localhost:8000'
    }
  }
});


File: migrations\postgres_add_username.sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username) WHERE username IS NOT NULL;

ALTER TABLE email_verification_tokens DROP CONSTRAINT IF EXISTS email_verification_tokens_token_hash_key;

DROP INDEX IF EXISTS ix_evt_valid;
CREATE INDEX ix_evt_valid ON email_verification_tokens (user_id, token_hash, used);


File: migrations\sqlite_add_username.sql
ALTER TABLE users ADD COLUMN username TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username) WHERE username IS NOT NULL;


File: migrations\sqlite_rebuild_email_verification_tokens.sql
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


File: templates\index.html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local Events Calendar</title>
    <style>
      body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: #f8fafc;
        color: #0f172a;
      }
      .placeholder {
        max-width: 480px;
        padding: 32px;
        text-align: center;
        background: white;
        border-radius: 18px;
        box-shadow: 0 24px 60px -30px rgba(15, 23, 42, 0.45);
      }
      .placeholder h1 {
        font-size: 24px;
        margin-bottom: 16px;
      }
      .placeholder p {
        margin: 0;
        line-height: 1.6;
      }
      code {
        background: rgba(148, 163, 184, 0.16);
        padding: 4px 8px;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <div class="placeholder">
      <h1>Calendar build pending</h1>
      <p>
        The production bundle has not been generated yet. Run
        <code>npm install &amp;&amp; npm run build</code> inside <code>frontend/</code> to produce the
        static assets, then reload.
      </p>
    </div>
  </body>
</html>


```