from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from secrets import token_urlsafe
from threading import Lock, Thread
from urllib.parse import parse_qs, urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import API_KEY_ROLES, CurrentActor, get_current_principal, hash_api_key, require_roles
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import ApiKey
from api.app.services.chatgpt_oauth import (
    ChatGPTOAuthConfigurationError,
    ChatGPTOAuthError,
    chatgpt_oauth_status,
    complete_chatgpt_authorization,
    reuse_existing_chatgpt_oauth_token_set,
    start_chatgpt_authorization,
)
from api.app.services.tenancy import get_current_tenant_id, load_engagement_for_tenant

router = APIRouter(tags=["auth"])

_callback_listener_lock = Lock()
_callback_listener_server: ThreadingHTTPServer | None = None
_callback_listener_thread: Thread | None = None


class ApiKeyCreate(BaseModel):
    actor_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: str = Field(default="operator", min_length=1, max_length=50)

    @field_validator("actor_name", "role")
    @classmethod
    def reject_null_bytes(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("field must not contain null bytes")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in API_KEY_ROLES:
            raise ValueError("role must be one of admin, operator, reviewer")
        return normalized


class ApiKeyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_name: str
    role: str
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiKeyCreateRead(ApiKeyRead):
    api_key: str
    token_exposed_once: bool = True


class CurrentActorRead(BaseModel):
    actor_name: str
    role: str
    auth_method: str


@router.get("/api/v1/auth/me", response_model=CurrentActorRead)
def get_authenticated_actor(
    principal: CurrentActor = Depends(get_current_principal),
) -> CurrentActorRead:
    return CurrentActorRead(
        actor_name=principal.name,
        role=principal.role,
        auth_method=principal.auth_method,
    )


@router.post("/api/v1/auth/keys", response_model=ApiKeyCreateRead, status_code=201)
def create_api_key(
    payload: ApiKeyCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
) -> ApiKeyCreateRead:
    now = datetime.now(tz=UTC)
    raw_key = f"aegispt_{token_urlsafe(32)}"
    record = ApiKey(
        key_hash=hash_api_key(raw_key),
        actor_name=(payload.actor_name or actor).strip(),
        role=payload.role,
        created_at=now,
        updated_at=now,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return ApiKeyCreateRead(
        **ApiKeyRead.model_validate(record).model_dump(),
        api_key=raw_key,
    )


@router.get("/api/v1/auth/keys", response_model=list[ApiKeyRead])
def list_api_keys(
    session: Session = Depends(get_session),
    _actor: str = Depends(require_roles("admin")),
) -> list[ApiKeyRead]:
    records = session.scalars(select(ApiKey).order_by(ApiKey.created_at.desc(), ApiKey.id.desc())).all()
    return [ApiKeyRead.model_validate(record) for record in records]


@router.post("/api/v1/auth/keys/{key_id}/revoke", response_model=ApiKeyRead)
def revoke_api_key(
    key_id: UUID,
    session: Session = Depends(get_session),
    _actor: str = Depends(require_roles("admin")),
) -> ApiKeyRead:
    record = session.get(ApiKey, key_id)
    if record is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if record.revoked_at is None:
        record.revoked_at = datetime.now(tz=UTC)
    session.commit()
    session.refresh(record)
    return ApiKeyRead.model_validate(record)


@router.get("/api/v1/auth/chatgpt/authorize")
def authorize_chatgpt_oauth(
    request: Request,
    engagement_id: UUID = Query(...),
    return_to: str | None = Query(default=None),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, object]:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        reused_status = reuse_existing_chatgpt_oauth_token_set(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
        )
        if reused_status is not None:
            session.commit()
            return {
                "provider": "chatgpt_oauth",
                "reused": True,
                "authorization_url": None,
                "local_callback_listener": {"active": False, "reason": "reused_existing_session"},
                "status": asdict(reused_status),
                "token_exposed": False,
                "message": "Existing encrypted ChatGPT OAuth session reused for this engagement.",
            }
        authorization = start_chatgpt_authorization(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
            return_to=return_to,
        )
    except ChatGPTOAuthConfigurationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ChatGPTOAuthError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session.commit()
    listener_status = _ensure_local_callback_listener(
        request=request,
        settings=settings,
        redirect_uri=authorization.redirect_uri,
    )
    return {
        "provider": "chatgpt_oauth",
        "authorization_url": authorization.authorization_url,
        "state": authorization.state,
        "redirect_uri": authorization.redirect_uri,
        "local_callback_listener": listener_status,
        "token_exposed": False,
    }


@router.get("/api/v1/auth/chatgpt/callback")
def complete_chatgpt_oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    try:
        status = complete_chatgpt_authorization(
            session=session,
            code=code,
            state=state,
            settings=settings,
        )
    except ChatGPTOAuthConfigurationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ChatGPTOAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session.commit()
    return {
        **asdict(status),
        "status": "connected",
        "message": "ChatGPT OAuth account connected. Tokens are stored only as encrypted secret material.",
    }


@router.get("/api/v1/auth/chatgpt/status")
def get_chatgpt_oauth_status(
    engagement_id: UUID = Query(...),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, object]:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    status = chatgpt_oauth_status(session=session, engagement_id=engagement_id, settings=settings)
    return asdict(status)


def _ensure_local_callback_listener(
    *,
    request: Request,
    settings: Settings,
    redirect_uri: str,
) -> dict[str, object]:
    if not settings.chatgpt_oauth_local_callback_enabled:
        return {"active": False, "reason": "disabled"}

    parsed = urlparse(redirect_uri)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"} or not parsed.port:
        return {"active": False, "reason": "redirect_uri_not_localhost"}

    session_factory = request.app.state.session_factory
    callback_path = parsed.path or "/auth/callback"

    class ChatGPTOAuthCallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            callback = urlparse(self.path)
            if callback.path != callback_path:
                self.send_error(404, "callback path not found")
                return

            params = parse_qs(callback.query)
            code = (params.get("code") or [""])[0]
            state = (params.get("state") or [""])[0]
            if not code or not state:
                self._send_html(
                    400,
                    "ChatGPT OAuth callback was missing code or state.",
                )
                return

            with session_factory() as callback_session:
                try:
                    status = complete_chatgpt_authorization(
                        session=callback_session,
                        code=code,
                        state=state,
                        settings=settings,
                    )
                    callback_session.commit()
                except Exception as exc:  # pragma: no cover - exercised by live OAuth only
                    callback_session.rollback()
                    self._send_html(
                        400,
                        f"ChatGPT OAuth failed: {exc}",
                    )
                    return

            account = escape(status.account_id or "connected account")
            self._send_html(
                200,
                f"ChatGPT OAuth connected for {account}. You can return to AegisPT.",
            )

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _send_html(self, status_code: int, message: str) -> None:
            body = (
                "<!doctype html><html><head><title>AegisPT ChatGPT OAuth</title></head>"
                "<body style=\"font-family: sans-serif; max-width: 720px; margin: 48px auto; line-height: 1.5;\">"
                f"<h1>AegisPT ChatGPT OAuth</h1><p>{escape(message)}</p>"
                "<p>No token material is shown in this browser page.</p>"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    global _callback_listener_server, _callback_listener_thread
    with _callback_listener_lock:
        if _callback_listener_server is not None:
            server_host, server_port = _callback_listener_server.server_address
            if int(server_port) == int(parsed.port):
                return {
                    "active": True,
                    "url": f"http://localhost:{server_port}{callback_path}",
                    "already_running": True,
                }
            _callback_listener_server.shutdown()
            _callback_listener_server.server_close()
            _callback_listener_server = None
            _callback_listener_thread = None

        try:
            server = ThreadingHTTPServer(("127.0.0.1", int(parsed.port)), ChatGPTOAuthCallbackHandler)
        except OSError as exc:
            return {"active": False, "reason": "port_unavailable", "message": str(exc)}

        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _callback_listener_server = server
        _callback_listener_thread = thread
        return {
            "active": True,
            "url": f"http://localhost:{parsed.port}{callback_path}",
            "already_running": False,
        }
