import os

def env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip() in ("1", "true", "TRUE", "yes", "on")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", str(60 * 60 * 24 * 7)))
COOKIE_SECURE = env_bool("COOKIE_SECURE", True)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")

EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "mock")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@example.com")

DEV_MODE = env_bool("DEV_MODE", True)
