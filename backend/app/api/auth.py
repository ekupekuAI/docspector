from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.core.rate_limit import login_rate_limiter
from app.core.security import create_access_token
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.auth import LoginRequest, TokenResponse, UserIdentity

settings = get_settings()

router = APIRouter(prefix=f"{settings.api_v1_prefix}/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    login_req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Mock login endpoint for synthetic demo users with in-process abuse throttling."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    raw_username = login_req.username.strip().lower()
    rate_key = login_rate_limiter.hash_key("login", client_ip, raw_username)

    # 1. Check if client/account combination is currently rate-limited
    is_limited, _, retry_after = login_rate_limiter.is_rate_limited(
        rate_key,
        max_attempts=settings.login_rate_limit_max_attempts,
        window_seconds=float(settings.login_rate_limit_window_seconds),
    )
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please retry after {int(retry_after)} seconds.",
            headers={"Retry-After": str(int(retry_after))},
        )

    # 2. Look up user
    user = db.query(User).filter(User.username == login_req.username).first()
    if user is None or not user.is_active:
        # Record failed attempt
        login_rate_limiter.record_attempt(
            rate_key,
            window_seconds=float(settings.login_rate_limit_window_seconds),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Successful authentication clears failed attempt history
    login_rate_limiter.reset(rate_key)

    access_token = create_access_token(user)
    expires_in_seconds = settings.jwt_access_token_expire_minutes * 60

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
    )


@router.get("/me", response_model=UserIdentity)
def get_me(current_user: User = Depends(get_current_user)) -> UserIdentity:
    """Return the synthetic identity of the currently authenticated user."""
    return UserIdentity.model_validate(current_user)
