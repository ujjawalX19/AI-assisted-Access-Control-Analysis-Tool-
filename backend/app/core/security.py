from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# tokenUrl points to the OAuth2-compatible form endpoint used ONLY by Swagger UI.
# Our main login (/api/auth/login) accepts JSON; Swagger uses /api/auth/token (form-encoded).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# Fallback bearer extractor for when OAuth2PasswordBearer is too strict
http_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a plain-text password using bcrypt via passlib."""
    # Bcrypt has a 72-byte limit. We truncate by bytes and decode back to string
    # so passlib's internal encoders don't double-trigger the limit.
    truncated_pwd = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(truncated_pwd)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    truncated_pwd = plain.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.verify(truncated_pwd, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT that encodes user_id (as 'sub') and role.
    The scanner uses these claims to test IDOR across privilege levels.
    """
    to_encode = data.copy()
    # Always ensure sub and role are present strings
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])
    if "role" in to_encode:
        to_encode["role"] = str(to_encode["role"])
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    # python-jose may return bytes on older versions — ensure str
    return encoded if isinstance(encoded, str) else encoded.decode("utf-8")


def decode_token(token: str) -> dict:
    """Decode and validate a JWT, raising 401 on any failure."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    """
    Dependency that validates the Bearer token and returns the authenticated User.
    Works with both the Swagger padlock (OAuth2 form flow via /api/auth/token)
    and direct API calls with Authorization: Bearer <jwt>.
    """
    from app.models.user import User  # local import avoids circular dependency

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    user_id: str = payload.get("sub")
    if not user_id:
        raise credentials_exception

    try:
        uid = int(user_id)
    except (ValueError, TypeError):
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception
    return user


async def require_admin(current_user=Depends(get_current_user)):
    """Dependency that enforces admin-only access for privileged scanner operations."""
    if str(current_user.role).lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user
