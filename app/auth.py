import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .config import COOKIE_SECURE, DEV_MODE, PUBLIC_BASE_URL, SESSION_MAX_AGE
from .db import SessionLocal
from .email import send_email
from .models import EmailVerificationToken, OutboundEmail, User
from .security import (
    create_session_jwt,
    decode_session_jwt,
    hash_password,
    make_csrf_token,
    make_email_token,
    safe_eq,
    sha256_hex,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


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

    raw_token, token_hash = make_email_token()
    token_row = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=dt.datetime.utcnow() + dt.timedelta(hours=24),
    )
    db.add(token_row)
    db.commit()

    if PUBLIC_BASE_URL:
        verify_url = f"{PUBLIC_BASE_URL}/auth/verify?token={raw_token}"
    else:
        verify_url = f"/auth/verify?token={raw_token}"

    subject = "Verify your email"
    html = "<p>Welcome! Click to verify your email:</p><p><a href='{}'>Verify Email</a></p>".format(verify_url)
    send_email(db, to=email_norm, subject=subject, html=html)

    return {"ok": True}


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


@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    require_csrf(request)

    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).one_or_none()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")
    if not user.is_email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")

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
    session_token = request.cookies.get("session")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user_id = decode_session_jwt(session_token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    return MeResponse(id=user.id, email=user.email, is_email_verified=user.is_email_verified)


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
