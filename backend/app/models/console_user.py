"""Pydantic models for Policy Console users and RBAC."""

from datetime import datetime, timezone, UTC
from enum import Enum

from pydantic import BaseModel, EmailStr, Field


class ConsoleRole(str, Enum):
    """RBAC roles for Policy Console users (APEP-107)."""

    ADMIN = "Admin"
    POLICY_AUTHOR = "PolicyAuthor"
    ANALYST = "Analyst"
    APPROVER = "Approver"


class ConsoleUser(BaseModel):
    """A user who can log in to the Policy Console."""

    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    hashed_password: str = Field(..., min_length=1)
    roles: list[ConsoleRole] = Field(default_factory=lambda: [ConsoleRole.ANALYST])
    tenant_id: str = "default"
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --- Request / Response Schemas ---


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserInfo(BaseModel):
    username: str
    email: str
    roles: list[ConsoleRole]
    tenant_id: str
