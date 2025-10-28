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
    