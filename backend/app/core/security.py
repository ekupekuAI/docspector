from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import jwt

from app.core.config import get_settings

if TYPE_CHECKING:
    from app.db.models.user import User

settings = get_settings()


def create_access_token(user: "User") -> str:
    """Create a signed JWT access token for a synthetic authenticated user."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    payload: dict[str, Any] = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": now,
        "exp": expire,
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token using configured algorithm and secret."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except jwt.PyJWTError as exc:
        raise ValueError("Could not validate credentials") from exc
