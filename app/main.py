import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import create_engine, text

app = FastAPI()
templates = Jinja2Templates(directory="templates")

db_url = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")
engine = create_engine(db_url, pool_pre_ping=True)

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
    response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; script-src 'self'"
    return response

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/time", response_class=PlainTextResponse)
def time():
    import datetime as dt
    return dt.datetime.utcnow().isoformat()

@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return "ok"
