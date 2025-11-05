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
