"""JWT auth helpers (Người 3 - D1 Auth Gateway).

Every protected endpoint validates a bearer token issued by the scope-auth
service. Tokens carry subject + role claims.
"""
from __future__ import annotations

import time
from typing import Optional

import jwt
from fastapi import Header, HTTPException

from .config import settings


class AuthError(Exception):
    pass


def create_token(subject: str, role: str = "operator", ttl: Optional[int] = None) -> str:
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + (ttl or settings.JWT_TTL_SECONDS),
        "iss": "vts-scope-auth",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALG],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError as exc:  # pragma: no cover - thin wrapper
        raise AuthError(str(exc)) from exc


async def require_auth(authorization: str = Header(default="")) -> dict:
    """FastAPI dependency: validate `Authorization: Bearer <jwt>`."""
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return decode_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}") from exc


def require_role(claims: dict, roles: tuple[str, ...]) -> dict:
    """Assert the token carries one of `roles` (used e.g. for the C2 approval
    gate, where only 'approver'/'admin' may approve/execute)."""
    if claims.get("role") not in roles:
        raise HTTPException(status_code=403,
                            detail=f"requires role in {roles}")
    return claims
