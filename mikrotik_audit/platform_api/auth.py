"""Implementation details for platform_api auth."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from .config import AuthConfig

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", scheme_name="Bearer")


def _pad_base64(value: str) -> bytes:
    """Internal helper for pad base64."""
    padding = "=" * (-len(value) % 4)
    return (value + padding).encode("ascii")


def _secret(request: Request) -> bytes:
    """Internal helper for secret."""
    auth_config: AuthConfig = request.app.state.auth_config
    return auth_config.secret.encode("utf-8")


def _sign(payload: str, secret: bytes) -> str:
    """Internal helper for sign."""
    signature = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _encode_token(claims: dict[str, Any], secret: bytes) -> str:
    """Internal helper for encode token."""
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")
    signature = _sign(payload_b64, secret)
    return f"{payload_b64}.{signature}"


def _decode_token(token: str, secret: bytes) -> dict[str, Any]:
    """Internal helper for decode token."""
    try:
        payload_b64, signature = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization token")

    expected = _sign(payload_b64, secret)
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization token")

    try:
        payload_json = base64.urlsafe_b64decode(_pad_base64(payload_b64)).decode("utf-8")
        payload = json.loads(payload_json)
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization token")

    if not isinstance(payload, dict) or "exp" not in payload or "sub" not in payload or "type" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization token")

    if int(payload["exp"]) < int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization token has expired")

    return payload


def _validate_credentials(username: str, password: str, auth_config: AuthConfig) -> bool:
    """Internal helper for validate credentials."""
    return secrets.compare_digest(username, auth_config.username) and secrets.compare_digest(password, auth_config.password)


def authenticate_credentials(request: Request, username: str, password: str) -> str:
    """Handle authenticate credentials."""
    auth_config: AuthConfig = request.app.state.auth_config
    if not _validate_credentials(username, password, auth_config):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return username


class TokenResponse(BaseModel):
    """Define the tokenresponse schema."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Define the refreshrequest schema."""
    refresh_token: str


class LoginRequest(BaseModel):
    """Define the loginrequest schema."""
    username: str
    password: str


def create_access_token(username: str, request: Request) -> str:
    """Create access token."""
    auth_config: AuthConfig = request.app.state.auth_config
    expires = datetime.now(timezone.utc) + timedelta(seconds=auth_config.access_token_expires_seconds)
    return _encode_token(
        {
            "sub": username,
            "type": "access",
            "exp": int(expires.timestamp()),
        },
        _secret(request),
    )


def create_refresh_token(username: str, request: Request) -> str:
    """Create refresh token."""
    auth_config: AuthConfig = request.app.state.auth_config
    expires = datetime.now(timezone.utc) + timedelta(seconds=auth_config.refresh_token_expires_seconds)
    return _encode_token(
        {
            "sub": username,
            "type": "refresh",
            "exp": int(expires.timestamp()),
        },
        _secret(request),
    )


def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> str:
    """Get current user."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = _decode_token(token, _secret(request))
    if payload["type"] != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return payload["sub"]


def verify_refresh_token(request: Request, refresh_token: str) -> str:
    """Handle verify refresh token."""
    payload = _decode_token(refresh_token, _secret(request))
    if payload["type"] != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if refresh_token not in request.app.state.refresh_tokens:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token is not recognized")
    return payload["sub"]


def require_login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request | None = None) -> tuple[str, Request]:
    """Handle require login."""
    if request is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Request context is not available")
    username = authenticate_credentials(request, form_data.username, form_data.password)
    return username, request
