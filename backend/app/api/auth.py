"""
app/api/auth.py
───────────────
Authentication endpoints for the BAC Scanner API.

Endpoints
─────────
  POST /api/auth/register  — Create a new account (JSON body)
  POST /api/auth/login     — Authenticate; returns JWT (JSON body)
  POST /api/auth/token     — OAuth2 form-encoded login for Swagger UI padlock
  GET  /api/auth/me        — Return authenticated user's profile

Security notes
──────────────
• Passwords are hashed with bcrypt via passlib – never stored in plaintext.
• JWTs carry `sub` (user_id as string) and `role` so the scanner's IDOR
  probes can craft targeted requests at different privilege levels.
• Every field returned to the client is explicitly cast to a primitive type
  (str, int) to prevent Pydantic from trying to serialise a SQLAlchemy
  mapped value and raising a 500 error.
• The /token endpoint speaks the OAuth2 password-flow dialect expected by
  Swagger UI's "Authorize" padlock, while /login speaks JSON for the React
  frontend. Both produce identical JWT payloads.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas import TokenResponse, UserCreate, UserLogin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Auth"])


# ─────────────────────────────────────────────────────────────────────────────
# REGISTER
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/register", status_code=201)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Create a new user account.

    • Rejects duplicate e-mail with 400 (not 500).
    • Hashes the password with bcrypt before persisting.
    • Returns a plain dict with only primitive types so Pydantic never
      encounters a SQLAlchemy-mapped attribute it cannot serialise.
    """
    # ── Duplicate e-mail guard ────────────────────────────────────────────
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # ── Hash password ─────────────────────────────────────────────────────
    try:
        hashed = hash_password(payload.password)
    except Exception as exc:
        logger.exception("bcrypt hashing failed")
        raise HTTPException(status_code=500, detail=f"Password hashing error: {exc}")

    # ── Persist user ──────────────────────────────────────────────────────
    user = User(
        email=payload.email,
        hashed_password=hashed,
        full_name=payload.full_name,
        # role defaults to "user" via the column default; set it explicitly
        # so the value is immediately available without a DB round-trip.
        role="user",
    )
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except Exception as exc:
        await db.rollback()
        logger.exception("DB commit failed during registration")
        raise HTTPException(status_code=500, detail=f"Registration failed: {exc}")

    # ── Build response with only JSON-safe primitives ─────────────────────
    # str(user.role)         → prevents Pydantic crash if role is somehow an Enum
    # isoformat() / str()    → converts datetime to a JSON-serialisable string
    created_at_str = (
        user.created_at.isoformat()
        if hasattr(user.created_at, "isoformat")
        else str(user.created_at)
    )
    return {
        "id": int(user.id),
        "email": str(user.email),
        "full_name": str(user.full_name) if user.full_name else None,
        "role": str(user.role),
        "created_at": created_at_str,
        "message": "Account created successfully",
    }


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN  (JSON body — used by the React frontend)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticate with e-mail + password (JSON body).

    Returns a signed JWT whose payload contains:
      • `sub`  — user_id as a string  (IDOR probe anchor)
      • `role` — privilege level       (privilege-escalation test claim)

    The TokenResponse schema accepts only `str` for role, so no Pydantic
    crash can occur regardless of what the DB column returns.
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Both claims are explicitly cast to str — safe even if an Enum sneaks in
    token = create_access_token({
        "sub": str(user.id),    # IDOR probe target: change this to test user isolation
        "role": str(user.role), # privilege claim: "user" vs "admin" escalation tests
    })

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user_id=int(user.id),
        email=str(user.email),
        role=str(user.role),
    )


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN  (OAuth2 form-encoded — consumed ONLY by Swagger UI padlock)
# ─────────────────────────────────────────────────────────────────────────────
@router.post(
    "/token",
    include_in_schema=True,
    tags=["Auth"],
    summary="Swagger UI OAuth2 login (form-encoded)",
)
async def swagger_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth2 password-flow endpoint consumed exclusively by Swagger UI's
    'Authorize' padlock dialog.

    The form fields are:
      • `username` — the user's e-mail address
      • `password` — plain-text password

    Returns `{"access_token": "...", "token_type": "bearer"}` which is
    exactly what the OAuth2 spec and Swagger expect.

    After authorising here, Swagger will automatically inject
    `Authorization: Bearer <token>` on every protected endpoint test.
    """
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({
        "sub": str(user.id),
        "role": str(user.role),
    })

    # OAuth2 spec mandates exactly these two fields
    return {"access_token": token, "token_type": "bearer"}


# ─────────────────────────────────────────────────────────────────────────────
# ME  (authenticated profile)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/me", summary="Get authenticated user profile")
async def me(current_user: User = Depends(get_current_user)):
    """
    Return the authenticated user's profile.
    Requires a valid `Authorization: Bearer <token>` header.

    Use this endpoint to verify the Swagger padlock is working correctly —
    if you get a 200 response, your token is valid and properly transmitted.
    """
    return {
        "id": int(current_user.id),
        "email": str(current_user.email),
        "full_name": str(current_user.full_name) if current_user.full_name else None,
        "role": str(current_user.role),
        "created_at": (
            current_user.created_at.isoformat()
            if hasattr(current_user.created_at, "isoformat")
            else str(current_user.created_at)
        ),
    }