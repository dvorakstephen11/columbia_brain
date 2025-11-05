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


def make_email_token() -> Tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, sha256_hex(raw)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def make_csrf_token() -> str:
    return secrets.token_urlsafe(32)
