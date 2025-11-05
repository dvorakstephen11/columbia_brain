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
