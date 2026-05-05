"""
app/main.py
───────────
FastAPI application entrypoint for the BAC Scanner API.

CORS configuration
──────────────────
allow_origins includes every origin the React dev server might use
(Vite defaults: 5173, 5174) plus common alternatives so that both the
frontend and Swagger UI work without 403 pre-flight failures.

Swagger / OpenAPI
─────────────────
security.py configures OAuth2PasswordBearer with tokenUrl="/api/auth/token".
That makes the padlock in Swagger UI call POST /api/auth/token (form-encoded),
which returns {"access_token": "...", "token_type": "bearer"}.  After that
every Swagger request automatically carries the correct Authorization header.

Startup
───────
create_tables() is called inside the lifespan context manager so that tables
are created (if missing) before the first request arrives.
"""

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import create_tables
from app.api.auth import router as auth_router
from app.api.projects import router as projects_router
from app.api.scans import router as scans_router, requests_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting BAC Scanner API…")
    await create_tables()
    logger.info("Database tables ready.")
    yield
    logger.info("Shutting down BAC Scanner API.")


app = FastAPI(
    title="BAC Scanner API",
    description=(
        "**Broken Access Control Scanner** — detects IDOR, auth bypass, "
        "privilege escalation, method manipulation, and more.\n\n"
        "### How to authorise in Swagger\n"
        "1. Click the 🔒 **Authorize** button.\n"
        "2. Enter your e-mail in the **username** field and your password.\n"
        "3. Click **Authorize** — Swagger will call `POST /api/auth/token` "
        "and store your JWT automatically.\n"
        "4. Every subsequent request in Swagger will carry "
        "`Authorization: Bearer <token>`."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow any localhost/127.0.0.1 port to facilitate development and testing.
# This prevents 403 Forbidden / Preflight failures when the frontend or
# demo target run on non-standard ports.
CORS_ORIGIN_REGEX = r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(requests_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to the BAC Scanner API",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": "BAC Scanner API", "version": "1.0.0"}
