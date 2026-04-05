"""Console authentication endpoints: login, refresh, logout (APEP-105)."""

import logging
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException

from app.db import mongodb as db_module
from app.models.console_user import (
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserInfo,
)
from app.services.jwt_auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    revoke_token,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/console", tags=["console-auth"])

CONSOLE_USERS = "console_users"


async def get_current_user(authorization: str = Header(...)) -> dict:
    """Extract and validate the current user from the Authorization header."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization.removeprefix("Bearer ")
    payload = decode_token(token)
    if payload is None or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    return payload


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Require the current user to have the Admin role."""
    roles = user.get("roles", [])
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    """Authenticate a console user and return JWT tokens."""
    db = db_module.get_database()
    user = await db[CONSOLE_USERS].find_one({"username": body.username})

    if user is None or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.get("enabled", True):
        raise HTTPException(status_code=403, detail="Account is disabled")

    jti = str(uuid4())
    token_data = {
        "sub": user["username"],
        "tenant_id": user.get("tenant_id", "default"),
        "roles": user.get("roles", []),
        "jti": jti,
    }

    from app.core.config import settings

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest):
    """Issue new tokens from a valid refresh token."""
    payload = decode_token(body.refresh_token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Revoke old refresh token
    old_jti = payload.get("jti")
    if old_jti:
        revoke_token(old_jti)

    new_jti = str(uuid4())
    token_data = {
        "sub": payload["sub"],
        "tenant_id": payload.get("tenant_id", "default"),
        "roles": payload.get("roles", []),
        "jti": new_jti,
    }

    from app.core.config import settings

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/logout")
async def logout(user: dict = Depends(get_current_user)):
    """Revoke the current access token."""
    jti = user.get("jti")
    if jti:
        revoke_token(jti)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserInfo)
async def me(user: dict = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return UserInfo(
        username=user["sub"],
        email=user.get("email", ""),
        roles=user.get("roles", []),
        tenant_id=user.get("tenant_id", "default"),
    )


@router.post("/seed", include_in_schema=False)
async def seed_admin():
    """Create a default admin user if none exists. For development only."""
    from app.core.config import settings

    if not settings.debug:
        raise HTTPException(
            status_code=403,
            detail="Seed endpoint is only available in debug mode",
        )

    db = db_module.get_database()

    # First-run protection: only allow seeding when no admin users exist at all
    admin_count = await db[CONSOLE_USERS].count_documents({"roles": "Admin"})
    if admin_count > 0:
        raise HTTPException(
            status_code=403,
            detail="Seed endpoint is only available when no admin users exist",
        )

    import secrets

    generated_password = secrets.token_urlsafe(16)
    await db[CONSOLE_USERS].insert_one(
        {
            "username": "admin",
            "email": "admin@agentpep.local",
            "hashed_password": hash_password(generated_password),
            "roles": ["Admin"],
            "tenant_id": "default",
            "enabled": True,
        }
    )
    return {
        "message": "Admin user created",
        "username": "admin",
        "password": generated_password,
        "warning": "Change this password immediately",
    }
