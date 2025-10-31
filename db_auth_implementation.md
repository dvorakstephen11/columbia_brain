# db_auth_implementation.md

What you’ll get

Email + password auth with:

Registration → email verification (single‑use, time‑limited token)

Login → HttpOnly cookie session (JWT signed)

Logout, /auth/me, and basic CSRF protection (double‑submit cookie)

Mocked transactional email: emails are stored in DB and viewable via a dev‑only endpoint + console logs. No provider account required.

Works with SQLite locally and Postgres on Render.

Fits your current FastAPI + React (Vite) layout.

High‑level design (decisions you’re making)

Sessions: Signed JWT in HttpOnly cookie (SameSite=Lax, Secure in prod). Server validates on every request. No token in localStorage.

Email verification: We store only a hash of the token, mark it used when consumed, and expire it after 24 hours.

Mock email: In dev, we persist emails to DB and expose a dev-only JSON viewer. In prod, you’ll flip a single env var to use a real provider later.

CSRF: Double‑submit cookie—a non‑HttpOnly csrf_token cookie must match the X-CSRF-Token header on state‑changing requests.

0) Dependencies (add to requirements.txt)
fastapi
uvicorn[standard]
SQLAlchemy>=2.0
passlib[bcrypt]
python-jose[cryptography]
email-validator
httpx


If you haven’t already, add a Postgres driver when you move to Render:
psycopg2-binary (for SQLAlchemy 1/2 classic URL) or psycopg[binary] (then use postgresql+psycopg://…).

1) Backend – new files
1.1 app/config.py

Centralized config & sane defaults.

import os

def env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip() in ("1", "true", "TRUE", "yes", "on")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")  # set in Render
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", str(60*60*24*7)))  # 7 days
COOKIE_SECURE = env_bool("COOKIE_SECURE", True)  # True in prod, False in local dev
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g. https://your-app.onrender.com

# Email backend
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "mock")  # "mock" or "resend" (later)
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@example.com")

# Dev mode toggles dev-only endpoints
DEV_MODE = env_bool("DEV_MODE", True)

1.2 app/db.py

Engine + Base + session factory; normalizes Postgres URL.

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

def normalize_db_url(url: str) -> str:
    # Render/Heroku sometimes uses postgres://
    return url.replace("postgres://", "postgresql://", 1) if url.startswith("postgres://") else url

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

1.3 app/models.py

Users, verification tokens, and stored outbound emails (mock mailbox).

import datetime as dt
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(320), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow, nullable=False)

class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash = Column(String(128), unique=True, nullable=False)  # sha256 hex
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)

Index("ix_evt_valid", EmailVerificationToken.token_hash, EmailVerificationToken.used)

class OutboundEmail(Base):
    __tablename__ = "outbound_emails"
    id = Column(Integer, primary_key=True)
    to_email = Column(String(320), index=True, nullable=False)
    subject = Column(String(255), nullable=False)
    html = Column(Text, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)

1.4 app/security.py

Password hashing, session JWT, email token, and CSRF helpers.

import os, secrets, hashlib, hmac, datetime as dt
from typing import Optional, Tuple
from jose import jwt, JWTError
from passlib.hash import bcrypt
from .config import SECRET_KEY, SESSION_MAX_AGE

JWT_ALG = "HS256"

# Passwords
def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.verify(password, password_hash)
    except Exception:
        return False

# Sessions (JWT in cookie)
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

# Email verification
def make_email_token() -> Tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, sha256_hex(raw)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

# CSRF (double submit cookie)
def make_csrf_token() -> str:
    return secrets.token_urlsafe(32)

1.5 app/email.py

A tiny abstraction: mock provider now, real provider later.

from typing import Iterable, List
import httpx
from sqlalchemy.orm import Session
from .models import OutboundEmail
from .config import EMAIL_BACKEND, FROM_EMAIL
import os

RESEND_API_KEY = os.getenv("RESEND_API_KEY")  # for later if EMAIL_BACKEND="resend"

def send_email(db: Session, *, to: str, subject: str, html: str) -> None:
    """
    Mock in dev: persist to DB + print to console.
    Later: switch EMAIL_BACKEND="resend" and configure RESEND_API_KEY.
    """
    if EMAIL_BACKEND == "resend" and RESEND_API_KEY:
        headers = {"Authorization": f"Bearer {RESEND_API_KEY}"}
        data = {"from": FROM_EMAIL, "to": [to], "subject": subject, "html": html}
        with httpx.Client(timeout=10) as client:
            r = client.post("https://api.resend.com/emails", json=data, headers=headers)
            r.raise_for_status()
        return

    # MOCK path: persist and log
    rec = OutboundEmail(to_email=to, subject=subject, html=html)
    db.add(rec)
    db.commit()
    print(f"[MOCK EMAIL] To: {to} | Subject: {subject}\n{html}\n")

1.6 app/auth.py (router)

Registration, verification, login, logout, me, CSRF issuance, and dev mailbox viewers.

import datetime as dt
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import User, EmailVerificationToken, OutboundEmail
from .security import hash_password, verify_password, make_email_token, sha256_hex, safe_eq
from .security import create_session_jwt, decode_session_jwt, make_csrf_token
from .config import COOKIE_SECURE, PUBLIC_BASE_URL, DEV_MODE
from .email import send_email

router = APIRouter(prefix="/auth", tags=["auth"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def set_session_cookie(resp: Response, token: str):
    resp.set_cookie(
        key="session",
        value=token,
        max_age=60 * 60 * 24 * 7,  # keep in sync with SESSION_MAX_AGE
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )

def clear_session_cookie(resp: Response):
    resp.delete_cookie("session", path="/")

def set_csrf_cookie(resp: Response, token: str):
    # CSRF cookie must be readable by JS (not HttpOnly), Lax is OK.
    resp.set_cookie(
        key="csrf_token",
        value=token,
        max_age=60 * 60 * 2,  # 2h
        httponly=False,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )

def require_csrf(request: Request):
    # Double-submit cookie: cookie must match header on modifying requests
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        cookie = request.cookies.get("csrf_token")
        header = request.headers.get("X-CSRF-Token")
        if not cookie or not header or not safe_eq(cookie, header):
            raise HTTPException(status_code=403, detail="CSRF check failed")

# ---------- Schemas ----------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class MeResponse(BaseModel):
    id: int
    email: EmailStr
    is_email_verified: bool

# ---------- Routes ----------
@router.get("/csrf")
def csrf(response: Response):
    token = make_csrf_token()
    set_csrf_cookie(response, token)
    return {"csrf": "ok"}

@router.post("/register")
def register(req: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    require_csrf(request)

    email_norm = req.email.strip().lower()
    existing = db.query(User).filter(User.email == email_norm).one_or_none()
    if existing:
        # Behave identically to avoid user enumeration.
        return {"ok": True}

    user = User(email=email_norm, password_hash=hash_password(req.password))
    db.add(user)
    db.flush()  # to get user.id

    raw_token, token_hash = make_email_token()
    db.add(EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=dt.datetime.utcnow() + dt.timedelta(hours=24),
    ))
    db.commit()

    # Build verification link
    if PUBLIC_BASE_URL:
        verify_url = f"{PUBLIC_BASE_URL}/auth/verify?token={raw_token}"
    else:
        # local dev fallback – will use current host
        verify_url = f"/auth/verify?token={raw_token}"

    subject = "Verify your email"
    html = f"<p>Welcome! Click to verify your email:</p><p><a href='{verify_url}'>Verify Email</a></p>"
    send_email(db, to=email_norm, subject=subject, html=html)

    return {"ok": True}

@router.get("/verify")
def verify(token: str, db: Session = Depends(get_db)):
    token_hash = sha256_hex(token)
    rec = db.query(EmailVerificationToken).filter(EmailVerificationToken.token_hash == token_hash).one_or_none()
    now = dt.datetime.utcnow()
    if not rec or rec.used or rec.expires_at < now:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.get(User, rec.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.is_email_verified = True
    rec.used = True
    db.commit()

    return HTMLResponse("<p>Email verified. You can close this tab and return to the app.</p>")

@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    require_csrf(request)

    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).one_or_none()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

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
    session = request.cookies.get("session")
    if not session:
        raise HTTPException(status_code=401)
    user_id = decode_session_jwt(session)
    if not user_id:
        raise HTTPException(status_code=401)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401)
    return MeResponse(id=user.id, email=user.email, is_email_verified=user.is_email_verified)

# ---------- Dev-only mailbox viewers ----------
if DEV_MODE:
    @router.get("/dev/emails")
    def list_emails(db: Session = Depends(get_db)):
        rows = db.query(OutboundEmail).order_by(OutboundEmail.id.desc()).limit(50).all()
        return [{"id": r.id, "to": r.to_email, "subject": r.subject, "created_at": r.created_at.isoformat()} for r in rows]

    @router.get("/dev/emails/{email_id}")
    def get_email(email_id: int, db: Session = Depends(get_db)):
        r = db.get(OutboundEmail, email_id)
        if not r:
            raise HTTPException(status_code=404)
        return {"id": r.id, "to": r.to_email, "subject": r.subject, "html": r.html, "created_at": r.created_at.isoformat()}

2) Backend – wire it up (edit existing file)
2.1 app/main.py

Mount the router, create tables once, and keep your secure headers & CORS.

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .db import engine, Base
from .auth import router as auth_router

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory="templates")

# Create tables (OK for MVP; migrate to Alembic later)
Base.metadata.create_all(bind=engine)

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

allowed_hosts_default = "testserver,localhost,127.0.0.1,0.0.0.0,*.onrender.com"
allowed_hosts = [host.strip() for host in os.environ.get("ALLOWED_HOSTS", allowed_hosts_default).split(",") if host.strip()]
if allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# CORS: dev-only if you call API from Vite directly. If you use Vite proxy (recommended), you may not need this.
frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],
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

# Mount auth routes
app.include_router(auth_router)

3) Frontend – minimal glue
3.1 Vite dev proxy (recommended)

This keeps API calls same‑origin during dev, so cookies with SameSite=Lax will flow without SameSite=None.

Edit frontend/vite.config.js:

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
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    proxy: {
      // All API calls stay same-origin at :5173 and are proxied to FastAPI
      '/auth': 'http://localhost:8000',
      '/healthz': 'http://localhost:8000'
    }
  }
});


If you choose not to use the proxy and call http://localhost:8000 from http://localhost:5173, the session cookie won’t be sent with SameSite=Lax. You’d need SameSite=None; Secure and HTTPS in dev. The proxy is simpler.

3.2 frontend/src/utils/api.js

A tiny fetch helper that adds the CSRF header automatically.

function readCookie(name) {
  const v = document.cookie.split('; ').find(row => row.startsWith(name + '='));
  return v ? decodeURIComponent(v.split('=')[1]) : null;
}

export async function api(path, { method = 'GET', data, headers } = {}) {
  const isMutating = !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
  const baseHeaders = { 'Content-Type': 'application/json', ...(headers || {}) };

  // CSRF double-submit cookie: attach header for mutating requests
  if (isMutating) {
    const csrf = readCookie('csrf_token');
    if (csrf) baseHeaders['X-CSRF-Token'] = csrf;
  }

  const res = await fetch(path, {
    method,
    headers: baseHeaders,
    credentials: 'include',   // send cookies
    body: data ? JSON.stringify(data) : undefined
  });

  if (!res.ok) {
    let message = 'Request failed';
    try { message = (await res.json()).detail || message; } catch {}
    throw new Error(message);
  }

  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

// Acquire CSRF cookie (call this once on app start or before first POST)
export async function ensureCsrf() {
  try { await api('/auth/csrf'); } catch {}
}

3.3 frontend/src/hooks/useAuth.js

Lightweight client state for me, login, logout, register.

import { useEffect, useState, useCallback } from 'react';
import { api, ensureCsrf } from '@/utils/api';

export function useAuth() {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const data = await api('/auth/me');
      setMe(data);
    } catch {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    ensureCsrf().then(refresh);
  }, [refresh]);

  const register = useCallback(async (email, password) => {
    await ensureCsrf();
    await api('/auth/register', { method: 'POST', data: { email, password } });
  }, []);

  const login = useCallback(async (email, password) => {
    await ensureCsrf();
    await api('/auth/login', { method: 'POST', data: { email, password } });
    await refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    await ensureCsrf();
    await api('/auth/logout', { method: 'POST' });
    setMe(null);
  }, []);

  return { me, loading, register, login, logout, refresh };
}

3.4 frontend/src/components/AuthPanel.jsx

Minimal UI to register/login/log out. (Style however you like.)

import React, { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';

const AuthPanel = () => {
  const { me, loading, register, login, logout } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [msg, setMsg] = useState('');

  if (loading) return null;

  async function handleSubmit(e) {
    e.preventDefault();
    setMsg('');
    try {
      if (mode === 'register') {
        await register(email, password);
        setMsg('Registration received. Check your email for a verification link (mock).');
      } else {
        await login(email, password);
      }
    } catch (err) {
      setMsg(err.message || 'Something went wrong.');
    }
  }

  if (me) {
    return (
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <span>Signed in as <strong>{me.email}</strong>{me.is_email_verified ? '' : ' (unverified)'}</span>
        <button type="button" onClick={() => logout()}>Log out</button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
      <select value={mode} onChange={e => setMode(e.target.value)}>
        <option value="login">Log in</option>
        <option value="register">Register</option>
      </select>
      <input type="email" required placeholder="email" value={email} onChange={e => setEmail(e.target.value)} />
      <input type="password" required placeholder="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button type="submit">{mode === 'register' ? 'Register' : 'Log in'}</button>
      {msg && <span aria-live="polite" style={{ marginLeft: 8 }}>{msg}</span>}
    </form>
  );
};

export default AuthPanel;

3.5 Add the panel to your header (edit frontend/src/App.jsx)

Drop it into the header region so you can interact immediately.

// ...
import AuthPanel from '@/components/AuthPanel.jsx';

const App = () => {
  // ... existing code ...
  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="app-header__eyebrow">Local events (mock)</p>
          <h1>{monthLabel}</h1>
        </div>
        {/* Add auth UI here */}
        <AuthPanel />
      </header>
      {/* ... rest unchanged ... */}

4) Environment variables

Local dev (.env or shell):

SECRET_KEY=dev-super-long-random
COOKIE_SECURE=0
DEV_MODE=1
# DATABASE_URL not required locally (falls back to sqlite:///./dev.db)


Render service → Environment:

DATABASE_URL=<Render Postgres Internal URL>
SECRET_KEY=<long random 64+ chars>
PUBLIC_BASE_URL=https://<your-service>.onrender.com
COOKIE_SECURE=1
DEV_MODE=0               # hide dev mailbox routes
EMAIL_BACKEND=mock       # keep mock until you flip to a provider later
FROM_EMAIL=noreply@yourdomain.com


When you sign up for a provider later: set EMAIL_BACKEND=resend and add RESEND_API_KEY.

5) Local run checklist

Install deps & run API:

pip install -r requirements.txt
uvicorn app.main:app --reload


Dev UI:

cd frontend
npm install
npm run dev


Visit http://localhost:5173 → register, check the mock email.

Mock mailbox (dev only):

List: GET http://localhost:8000/auth/dev/emails

Inspect: GET http://localhost:8000/auth/dev/emails/<id>

OR just watch your API logs for [MOCK EMAIL].

6) Quick cURL test script (end‑to‑end)

With Vite proxy enabled, run these against http://localhost:5173 so cookies are same‑origin.

# 1) Get CSRF cookie
curl -i -c cookies.txt -b cookies.txt http://localhost:5173/auth/csrf

# 2) Register (watch API logs for the verification URL)
curl -i -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -d '{"email":"alice@example.com","password":"secret123"}' \
  http://localhost:5173/auth/register

# 3) In API logs, copy the URL after "Verify Email" (mock).
#    Example: http://localhost:8000/auth/verify?token=....  Visit it once.

# 4) Login
curl -i -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -d '{"email":"alice@example.com","password":"secret123"}' \
  http://localhost:5173/auth/login

# 5) Me
curl -i -c cookies.txt -b cookies.txt http://localhost:5173/auth/me

# 6) Logout
curl -i -c cookies.txt -b cookies.txt \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -X POST http://localhost:5173/auth/logout

7) Security notes & next hardening steps

Passwords: enforce minimum length & common password blacklist at the API (you can add a simple validator in RegisterRequest).

Rate limiting: add simple IP‑based limits on /auth/login & /auth/register (e.g., slowapi or a tiny in‑memory counter for MVP).

CSRF: You’re already protected on mutating endpoints. Keep SameSite=Lax and avoid cross‑site calls in prod.

Migrations: move from Base.metadata.create_all to Alembic once you’re happy with the schema.

Session invalidation: with JWT cookies you typically use short max age (7d here). If you need immediate invalidation, switch to DB‑backed sessions or add a token blacklist store.

Email provider: when you flip to real email, keep the same API (send_email). Only env vars change.

8) SPA vs SSG & this auth

This setup works unchanged for SPA or SSG. The frontend still calls /auth/*, cookies flow, SSR/SSG pages hydrate and become interactive. For any server‑rendered protected pages later, ensure your API still enforces authorization; don’t rely on client gating.