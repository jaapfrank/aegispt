from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from fastapi import Depends, Header, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import get_settings
from api.app.db import get_session
from api.app.models import ApiKey

X_ACTOR_DEPRECATION_WARNING = (
    '299 AegisPT "X-Actor fallback is deprecated; use Authorization: Bearer API key"'
)

API_KEY_ROLES = {"admin", "operator", "reviewer"}


@dataclass(frozen=True)
class CurrentActor:
    name: str
    role: str
    auth_method: str


def hash_api_key(raw_key: str) -> str:
    return sha256(raw_key.encode("utf-8")).hexdigest()


def _bearer_token(authorization: str | None) -> str | None:
    value = str(authorization or "").strip()
    if not value:
        return None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="invalid bearer authorization header")
    return token.strip()


def normalize_api_role(role: str | None) -> str:
    normalized = str(role or "operator").strip().lower()
    if normalized not in API_KEY_ROLES:
        raise HTTPException(status_code=422, detail="role must be one of admin, operator, reviewer")
    return normalized


def get_current_principal(
    response: Response,
    authorization: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> CurrentActor:
    token = _bearer_token(authorization)
    if token is not None:
        key_hash = hash_api_key(token)
        api_key = session.scalar(
            select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.revoked_at.is_(None))
        )
        if api_key is None:
            raise HTTPException(status_code=401, detail="invalid or revoked API key")
        api_key.last_used_at = datetime.now(tz=UTC)
        session.commit()
        return CurrentActor(
            name=api_key.actor_name,
            role=normalize_api_role(api_key.role),
            auth_method="api_key",
        )

    settings = get_settings()
    if not (settings.allow_x_actor_fallback and settings.is_local_dev_environment):
        raise HTTPException(
            status_code=401,
            detail=(
                "Authentication required. Use Authorization: Bearer <api-key>. "
                "X-Actor fallback is disabled in production-style environments."
            ),
        )
    response.headers.setdefault("Warning", X_ACTOR_DEPRECATION_WARNING)
    response.headers.setdefault("X-AegisPT-Auth-Warning", "x-actor-deprecated")
    return CurrentActor(name=x_actor or "local-dev", role="admin", auth_method="x_actor_fallback")


def get_current_actor(principal: CurrentActor = Depends(get_current_principal)) -> str:
    return principal.name


def require_roles(*allowed_roles: str):
    allowed = {normalize_api_role(role) for role in allowed_roles}

    def dependency(principal: CurrentActor = Depends(get_current_principal)) -> str:
        if principal.role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"role '{principal.role}' is not allowed for this operation",
            )
        return principal.name

    return dependency
