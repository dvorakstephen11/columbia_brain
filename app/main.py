import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import create_engine, text

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent.parent

templates = Jinja2Templates(directory="templates")

db_url = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")
engine = create_engine(db_url, pool_pre_ping=True)

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
