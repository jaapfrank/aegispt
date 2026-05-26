from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import Finding, Run, SecretRef
from api.app.services.secrets import (
    ENCRYPTED_SECRET_BACKENDS,
    decrypt_secret_value,
    direct_secret_storage_backend,
    encrypt_secret_value,
)

logger = logging.getLogger(__name__)

CHATGPT_OAUTH_PROVIDER = "chatgpt_oauth"
CHATGPT_OAUTH_PENDING_PURPOSE = "chatgpt_oauth.pkce_state"
CHATGPT_OAUTH_TOKEN_PURPOSE = "ai_provider.chatgpt_oauth"
DISABLED_PROVIDER_NAMES = {"", "disabled", "none", "off"}


class ChatGPTOAuthError(RuntimeError):
    pass


class ChatGPTOAuthConfigurationError(ChatGPTOAuthError):
    pass


class ChatGPTOAuthKillSwitchError(ChatGPTOAuthError):
    pass


@dataclass(frozen=True, slots=True)
class ChatGPTOAuthAuthorization:
    authorization_url: str
    state: str
    engagement_id: uuid.UUID
    redirect_uri: str


@dataclass(frozen=True, slots=True)
class ChatGPTOAuthStatus:
    provider: str
    configured: bool
    connected: bool
    account_id: str | None = None
    expires_at: str | None = None
    token_secret_ref_id: str | None = None
    token_exposed: bool = False
    reusable_session_available: bool = False
    reusable_account_id: str | None = None


@dataclass(frozen=True, slots=True)
class ChatGPTOAuthTokenMaterial:
    secret_ref: SecretRef
    token_set: dict[str, Any]
    refreshed: bool = False


def effective_ai_provider_name(settings: Settings, feature_provider: str | None) -> str:
    """Use AI_PROVIDER as the shared provider selector when a feature did not choose one."""

    specific = str(feature_provider or "").strip().lower()
    global_provider = str(settings.ai_provider or "").strip().lower()
    if specific in DISABLED_PROVIDER_NAMES and global_provider not in DISABLED_PROVIDER_NAMES:
        return global_provider
    return specific


def generate_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.decode("ascii").rstrip("=")


def chatgpt_oauth_redirect_uri(settings: Settings) -> str:
    configured = str(settings.chatgpt_oauth_redirect_uri or "").strip()
    if configured:
        return configured
    return str(settings.chatgpt_oauth_local_callback_url or "http://localhost:1455/auth/callback").strip()


def start_chatgpt_authorization(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
    return_to: str | None = None,
) -> ChatGPTOAuthAuthorization:
    client_id = _configured_client_id(settings)
    verifier, challenge = generate_pkce_pair()
    secret_ref_id = uuid.uuid4()
    nonce = secrets.token_urlsafe(24)
    state = f"{secret_ref_id}.{nonce}"
    redirect_uri = chatgpt_oauth_redirect_uri(settings)
    storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
    created_at = datetime.now(tz=UTC).isoformat()

    secret_ref = SecretRef(
        id=secret_ref_id,
        engagement_id=engagement_id,
        vault_pointer=f"aegispt://secret-ref/{secret_ref_id}",
        purpose=CHATGPT_OAUTH_PENDING_PURPOSE,
        secret_kind="oauth_pkce_verifier",
        storage_backend=storage_backend,
        display_label="ChatGPT OAuth pending verifier",
        encrypted_value=encrypt_secret_value(
            _json_dumps(
                {
                    "code_verifier": verifier,
                    "state": state,
                    "redirect_uri": redirect_uri,
                    "return_to": return_to,
                    "created_at": created_at,
                }
            ),
            settings,
            storage_backend=storage_backend,
        ),
        metadata_json={
            "provider": CHATGPT_OAUTH_PROVIDER,
            "state_nonce": nonce,
            "status": "pending",
            "created_at": created_at,
            "raw_secret_material_exposed": False,
            "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
        },
    )
    session.add(secret_ref)
    session.flush()

    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": str(settings.chatgpt_oauth_originator or "aegispt").strip() or "aegispt",
        "state": state,
    }
    scopes = str(settings.chatgpt_oauth_scopes or "").strip()
    if scopes:
        query["scope"] = scopes

    return ChatGPTOAuthAuthorization(
        authorization_url=f"{settings.chatgpt_oauth_authorize_url}?{urlencode(query)}",
        state=state,
        engagement_id=engagement_id,
        redirect_uri=redirect_uri,
    )


def complete_chatgpt_authorization(
    *,
    session: Session,
    code: str,
    state: str,
    settings: Settings,
) -> ChatGPTOAuthStatus:
    client_id = _configured_client_id(settings)
    pending_ref, state_payload = _load_pending_state(session=session, state=state, settings=settings)
    response = httpx.post(
        settings.chatgpt_oauth_token_url,
        headers={"Accept": "application/json"},
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": _required_text(state_payload, "code_verifier"),
            "redirect_uri": _required_text(state_payload, "redirect_uri"),
        },
        timeout=settings.chatgpt_oauth_timeout_seconds,
    )
    response.raise_for_status()
    token_response = response.json()
    if not isinstance(token_response, dict):
        raise ChatGPTOAuthError("ChatGPT OAuth token response was not a JSON object")

    token_set = _normalize_token_response(token_response)
    if not token_set.get("account_id"):
        raise ChatGPTOAuthError("ChatGPT OAuth access token did not contain accountId")

    secret_ref = store_chatgpt_oauth_token_set(
        session=session,
        engagement_id=pending_ref.engagement_id,
        settings=settings,
        token_set=token_set,
        source="oauth_callback",
    )
    session.delete(pending_ref)
    session.flush()
    return _status_from_secret_ref(secret_ref)


def chatgpt_oauth_status(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
) -> ChatGPTOAuthStatus:
    material = load_chatgpt_oauth_token_set(session=session, engagement_id=engagement_id, settings=settings)
    if material is None:
        reusable = _latest_reusable_token_secret_ref(session=session, engagement_id=engagement_id)
        return ChatGPTOAuthStatus(
            provider=CHATGPT_OAUTH_PROVIDER,
            configured=bool(str(settings.chatgpt_oauth_client_id or "").strip()),
            connected=False,
            token_exposed=False,
            reusable_session_available=reusable is not None,
            reusable_account_id=_metadata_account_id(reusable),
        )
    return _status_from_secret_ref(material.secret_ref, configured=bool(str(settings.chatgpt_oauth_client_id or "").strip()))


def reuse_existing_chatgpt_oauth_token_set(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
) -> ChatGPTOAuthStatus | None:
    existing = _latest_token_secret_ref(session=session, engagement_id=engagement_id)
    if existing is not None:
        return _status_from_secret_ref(existing, configured=bool(str(settings.chatgpt_oauth_client_id or "").strip()))

    reusable = _latest_reusable_token_secret_ref(session=session, engagement_id=engagement_id)
    if reusable is None:
        return None
    if reusable.storage_backend not in ENCRYPTED_SECRET_BACKENDS or not reusable.encrypted_value:
        raise ChatGPTOAuthError("Reusable ChatGPT OAuth token set is not stored in an encrypted secret backend")

    token_set = _json_loads(
        decrypt_secret_value(
            reusable.encrypted_value,
            settings,
            storage_backend=reusable.storage_backend,
        )
    )
    secret_ref = store_chatgpt_oauth_token_set(
        session=session,
        engagement_id=engagement_id,
        settings=settings,
        token_set=token_set,
        source="oauth_reuse",
    )
    return _status_from_secret_ref(secret_ref, configured=bool(str(settings.chatgpt_oauth_client_id or "").strip()))


def load_chatgpt_oauth_token_set(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
) -> ChatGPTOAuthTokenMaterial | None:
    secret_ref = _latest_token_secret_ref(session=session, engagement_id=engagement_id)
    if secret_ref is None:
        return None
    if secret_ref.storage_backend not in ENCRYPTED_SECRET_BACKENDS or not secret_ref.encrypted_value:
        raise ChatGPTOAuthError("ChatGPT OAuth token set is not stored in an encrypted secret backend")
    token_set = _json_loads(
        decrypt_secret_value(
            secret_ref.encrypted_value,
            settings,
            storage_backend=secret_ref.storage_backend,
        )
    )
    return ChatGPTOAuthTokenMaterial(secret_ref=secret_ref, token_set=token_set, refreshed=False)


def refresh_chatgpt_oauth_token_if_needed(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
    force: bool = False,
) -> ChatGPTOAuthTokenMaterial:
    if settings.execution_kill_switch:
        raise ChatGPTOAuthKillSwitchError("execution kill switch blocks ChatGPT OAuth provider calls")

    material = load_chatgpt_oauth_token_set(session=session, engagement_id=engagement_id, settings=settings)
    if material is None:
        reused_status = reuse_existing_chatgpt_oauth_token_set(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
        )
        if reused_status is None:
            raise ChatGPTOAuthError("ChatGPT OAuth account is not connected for this engagement")
        material = load_chatgpt_oauth_token_set(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
        )
        if material is None:
            raise ChatGPTOAuthError("ChatGPT OAuth reusable session could not be loaded")

    expires_at = _parse_datetime(str(material.token_set.get("expires_at") or ""))
    refresh_margin = timedelta(seconds=max(int(settings.chatgpt_oauth_refresh_margin_seconds), 0))
    if not force and expires_at > datetime.now(tz=UTC) + refresh_margin:
        return material

    refresh_token = str(material.token_set.get("refresh_token") or "").strip()
    if not refresh_token:
        raise ChatGPTOAuthError("ChatGPT OAuth token set does not contain a refresh token")

    response = httpx.post(
        settings.chatgpt_oauth_token_url,
        headers={"Accept": "application/json"},
        data={
            "grant_type": "refresh_token",
            "client_id": _configured_client_id(settings),
            "refresh_token": refresh_token,
        },
        timeout=settings.chatgpt_oauth_timeout_seconds,
    )
    response.raise_for_status()
    refresh_payload = response.json()
    if not isinstance(refresh_payload, dict):
        raise ChatGPTOAuthError("ChatGPT OAuth refresh response was not a JSON object")

    token_set = _normalize_token_response(refresh_payload, previous=material.token_set)
    secret_ref = store_chatgpt_oauth_token_set(
        session=session,
        engagement_id=engagement_id,
        settings=settings,
        token_set=token_set,
        source="oauth_refresh",
    )
    return ChatGPTOAuthTokenMaterial(secret_ref=secret_ref, token_set=token_set, refreshed=True)


def store_chatgpt_oauth_token_set(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
    token_set: dict[str, Any],
    source: str,
) -> SecretRef:
    normalized = {
        "access_token": _required_text(token_set, "access_token"),
        "refresh_token": str(token_set.get("refresh_token") or ""),
        "expires_at": _parse_datetime(str(token_set.get("expires_at") or "")).isoformat(),
        "account_id": _required_text(token_set, "account_id"),
        "token_type": str(token_set.get("token_type") or "Bearer"),
    }
    existing = _latest_token_secret_ref(session=session, engagement_id=engagement_id)
    if existing is not None and existing.storage_backend in ENCRYPTED_SECRET_BACKENDS:
        secret_ref = existing
        storage_backend = existing.storage_backend
        fallback_to_local = bool((existing.metadata_json or {}).get("fallback_to_local_secret_key"))
    else:
        secret_ref = SecretRef(
            id=uuid.uuid4(),
            engagement_id=engagement_id,
            vault_pointer="",
            purpose=CHATGPT_OAUTH_TOKEN_PURPOSE,
            secret_kind="oauth_token_set",
            storage_backend="encrypted_local",
            display_label=None,
            encrypted_value=None,
            metadata_json={},
        )
        secret_ref.vault_pointer = f"aegispt://secret-ref/{secret_ref.id}"
        storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
        secret_ref.storage_backend = storage_backend
        session.add(secret_ref)

    secret_ref.purpose = CHATGPT_OAUTH_TOKEN_PURPOSE
    secret_ref.secret_kind = "oauth_token_set"
    secret_ref.display_label = f"ChatGPT OAuth session for {normalized['account_id']}"
    secret_ref.encrypted_value = encrypt_secret_value(
        _json_dumps(normalized),
        settings,
        storage_backend=storage_backend,
    )
    secret_ref.metadata_json = {
        "provider": CHATGPT_OAUTH_PROVIDER,
        "account_id": normalized["account_id"],
        "expires_at": normalized["expires_at"],
        "source": source,
        "token_fields": ["access_token", "refresh_token", "expires_at", "account_id"],
        "token_exposed": False,
        "raw_secret_material_exposed": False,
        "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
    }
    session.flush()
    return secret_ref


def send_chatgpt_backend_request(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
    feature: str,
    model: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    material = refresh_chatgpt_oauth_token_if_needed(
        session=session,
        engagement_id=engagement_id,
        settings=settings,
    )
    url = _backend_url(settings)
    response = httpx.post(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {material.token_set['access_token']}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "feature": feature,
            "input": payload,
            "provider": CHATGPT_OAUTH_PROVIDER,
            "guardrails": {
                "operator_review_required": True,
                "scope_expansion_allowed": False,
                "dispatches_work": False,
            },
        },
        timeout=settings.chatgpt_oauth_timeout_seconds,
    )
    response.raise_for_status()
    response_payload = response.json()
    if not isinstance(response_payload, dict):
        raise ChatGPTOAuthError("ChatGPT backend response was not a JSON object")
    return response_payload


def send_chatgpt_backend_streaming_json_request(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
    model: str,
    instructions: str,
    input_items: list[dict[str, Any]],
) -> dict[str, Any]:
    material = refresh_chatgpt_oauth_token_if_needed(
        session=session,
        engagement_id=engagement_id,
        settings=settings,
    )
    url = _backend_url(settings)
    output_chunks: list[str] = []
    # Reasoning effort: only attach if explicitly set + non-empty. The
    # /codex/responses endpoint returns 400 on certain field shapes
    # (empirically observed 2026-05-22 with effort=high on gpt-5.4 +
    # 23KB picker prompt). Operators can opt-in via the setting.
    effort = str(getattr(settings, "chatgpt_oauth_reasoning_effort", "") or "").strip().lower()
    service_tier = str(getattr(settings, "chatgpt_oauth_service_tier", "") or "").strip().lower()
    verbosity = str(getattr(settings, "chatgpt_oauth_verbosity", "") or "").strip().lower()
    payload: dict[str, Any] = {
        "model": model,
        "store": False,
        "stream": True,
        "instructions": instructions,
        "input": input_items,
    }
    # gpt-5.5 valid effort values (empirically confirmed 2026-05-22):
    # none, low, medium, high, xhigh. "minimal" returns 400 with the
    # actual supported-values list in the body.
    if effort in {"none", "low", "medium", "high", "xhigh"}:
        payload["reasoning"] = {"effort": effort}
    # text.verbosity: low | medium | high. Separates output length from
    # reasoning depth. For JSON-schema-strict picker output, low matches
    # the actual response shape (one decision dict). OpenAI cookbook
    # recommendation: pair high reasoning + low verbosity for "well-
    # considered concise answers". Hypothesis-ranking maps cleanly.
    if verbosity in {"low", "medium", "high"}:
        payload["text"] = {"verbosity": verbosity}
    # service_tier: gpt-5.5's models.json declares one service tier with
    # id="priority", name="Fast", description="1.5x speed, increased
    # usage" — i.e. Codex CLI's `/fast` toggle and `service_tier = "fast"`
    # in config.toml are UI labels for `id=priority` in the actual API
    # request. Empirically: `priority` returns 200; `fast`/`flex`/`auto`
    # return 400 on /codex/responses.
    if service_tier in {"priority"}:
        payload["service_tier"] = service_tier
    with httpx.stream(
        "POST",
        url,
        headers={
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {material.token_set['access_token']}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=max(settings.chatgpt_oauth_timeout_seconds, 30.0),
    ) as response:
        # Capture the actual response body on 4xx/5xx so we can see EXACTLY
        # what the backend complained about (operator-corrected investigation
        # 2026-05-22: my earlier "reasoning is rejected" conclusion was
        # premature — need to read the real body to know).
        if response.status_code >= 400:
            body_chunks: list[bytes] = []
            for raw_line in response.iter_bytes():
                body_chunks.append(raw_line)
                if sum(len(c) for c in body_chunks) > 8 * 1024:
                    break
            body_text = b"".join(body_chunks).decode("utf-8", errors="replace")[:2000]
            logger.warning(
                "chatgpt_oauth backend %d on model=%s effort=%s body=%s",
                response.status_code, model, effort or "(none)", body_text,
            )
        response.raise_for_status()
        # gpt-5.5 with reasoning=xhigh emits MOST text via the `response.completed`
        # final event rather than incremental `response.output_text.delta`
        # deltas — empirical 2026-05-26 smoke 41: 200 OK + 0 delta events + 1
        # response.completed event holding the full message in
        # response.output[*].content[*].text. Earlier gpt-5.4 picker calls
        # (smoke 33) DID emit deltas, so the parser had only ever needed the
        # delta path until the model upgrade. Keep both: deltas accumulate
        # when emitted, fallback extracts from response.completed otherwise.
        completed_event: dict[str, Any] | None = None
        error_payload: dict[str, Any] | None = None
        event_type_counts: dict[str, int] = {}
        for raw_line in response.iter_lines():
            line = str(raw_line or "").strip()
            if not line or not line.startswith("data: "):
                continue
            payload_text = line[6:]
            if payload_text == "[DONE]":
                continue
            try:
                event = json.loads(payload_text)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event_type = str(event.get("type") or "")
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
            if event_type == "response.output_text.delta":
                output_chunks.append(str(event.get("delta") or ""))
            elif event_type == "response.completed":
                completed_event = event
            elif event_type in {"error", "response.failed"}:
                # SSE returned HTTP 200 but the model run failed mid-stream
                # (empirical 2026-05-26 smoke 43: gpt-5.5 + xhigh reasoning
                # + heavy cpg_seeded_cea prompt → response.failed event with
                # an OpenAI-side error payload). Capture the FIRST error so
                # we can surface its actual reason rather than "empty output".
                if error_payload is None:
                    error_payload = event
    output_text = "".join(output_chunks).strip()
    if not output_text and completed_event is not None:
        output_text = _extract_text_from_completed_event(completed_event).strip()
    if not output_text:
        error_reason = _format_oauth_error_payload(error_payload)
        logger.warning(
            "chatgpt_oauth: empty output on model=%s effort=%s event_counts=%s error=%s",
            model, effort or "(none)", event_type_counts, error_reason,
        )
        raise ChatGPTOAuthError(
            f"ChatGPT streaming backend response did not contain output text "
            f"(events={event_type_counts}; error={error_reason})"
        )
    return _json_object_from_model_output(output_text)


def _format_oauth_error_payload(event: dict[str, Any] | None) -> str:
    if not event:
        return "none"
    if event.get("type") == "response.failed":
        response_obj = event.get("response") or {}
        err = response_obj.get("error") or {}
        if isinstance(err, dict):
            return f"{err.get('code') or err.get('type') or 'unknown'}: {err.get('message') or ''}"[:240]
        return str(err)[:240]
    err = event.get("error") or {}
    if isinstance(err, dict):
        return f"{err.get('code') or err.get('type') or 'unknown'}: {err.get('message') or ''}"[:240]
    return str(err)[:240]


def _extract_text_from_completed_event(event: dict[str, Any]) -> str:
    """Pull text out of a response.completed SSE event.

    Shape (gpt-5.5 / Codex Responses API):
      {"type": "response.completed",
       "response": {
         "output": [{"type": "message",
                      "content": [{"type": "output_text", "text": "..."}, ...]},
                     ...]}}
    """
    response_obj = event.get("response") or {}
    output_items = response_obj.get("output") or []
    chunks: list[str] = []
    for item in output_items:
        if not isinstance(item, dict):
            continue
        content = item.get("content") or []
        for piece in content:
            if not isinstance(piece, dict):
                continue
            text = piece.get("text")
            if isinstance(text, str) and text:
                chunks.append(text)
    return "".join(chunks)


def stream_chatgpt_backend_text_request(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    settings: Settings,
    model: str,
    instructions: str,
    input_items: list[dict[str, Any]],
):
    material = refresh_chatgpt_oauth_token_if_needed(
        session=session,
        engagement_id=engagement_id,
        settings=settings,
    )
    url = _backend_url(settings)
    with httpx.stream(
        "POST",
        url,
        headers={
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {material.token_set['access_token']}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "store": False,
            "stream": True,
            "instructions": instructions,
            "input": input_items,
        },
        timeout=max(settings.chatgpt_oauth_timeout_seconds, 30.0),
    ) as response:
        response.raise_for_status()
        for raw_line in response.iter_lines():
            line = str(raw_line or "").strip()
            if not line or not line.startswith("data: "):
                continue
            payload_text = line[6:]
            if payload_text == "[DONE]":
                continue
            try:
                event = json.loads(payload_text)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("type") == "response.output_text.delta":
                chunk = str(event.get("delta") or "")
                if chunk:
                    yield chunk


class ChatGPTOAuthFindingEnrichmentProvider:
    name = CHATGPT_OAUTH_PROVIDER

    def __init__(self, *, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def enrich(self, finding: Finding):
        from api.app.services.ai_enrichment import FindingEnrichmentResult

        run = finding.run
        if run is None and finding.run_id is not None:
            run = self.session.get(Run, finding.run_id)
        if run is None:
            raise ChatGPTOAuthError("ChatGPT OAuth finding enrichment requires a persisted run")

        response = send_chatgpt_backend_request(
            session=self.session,
            engagement_id=run.engagement_id,
            settings=self.settings,
            feature="finding_enrichment",
            model=_chatgpt_model(self.settings, self.settings.ai_finding_enrichment_model),
            payload={
                "finding": {
                    "id": str(finding.id) if finding.id else None,
                    "title": finding.title,
                    "severity": finding.severity,
                    "target_id": finding.target_id,
                    "evidence_ref": finding.evidence_ref,
                    "status": finding.status,
                    "summary": finding.summary,
                    "methodology_tags": list(finding.methodology_tags or []),
                    "ptes_phase": finding.ptes_phase,
                    "nist_phase": finding.nist_phase,
                    "wstg_id": finding.wstg_id,
                    "wstg_version": finding.wstg_version,
                    "asvs_reference": finding.asvs_reference,
                    "control_family": finding.control_family,
                    "finding_origin": finding.finding_origin,
                    "cvss_score": finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                },
                "output_contract": {
                    "business_impact": (
                        "Short evidence-grounded business impact in customer/operator language; "
                        "do not change severity or claim breach impact beyond stored evidence."
                    ),
                    "technical_context": "Reference stored evidence, target, methodology tags, and proof boundary.",
                    "remediation_narrative": (
                        "Concrete numbered remediation steps. Make steps stack-aware when the finding summary, "
                        "target, evidence, or methodology identifies a product, protocol, framework, or platform. "
                        "Do not include exploit commands, credential abuse, destructive commands, or scope expansion."
                    ),
                },
            },
        )
        result_payload = response.get("enrichment") if isinstance(response.get("enrichment"), dict) else response
        return FindingEnrichmentResult(
            business_impact=_required_text(result_payload, "business_impact"),
            technical_context=_required_text(result_payload, "technical_context"),
            remediation_narrative=_required_text(result_payload, "remediation_narrative"),
            metadata={
                "provider_mode": CHATGPT_OAUTH_PROVIDER,
                "backend_status": response.get("status"),
                "model": response.get("model") or _chatgpt_model(
                    self.settings,
                    self.settings.ai_finding_enrichment_model,
                ),
                "token_exposed": False,
            },
        )


class ChatGPTOAuthPostTaskAnalysisProvider:
    name = CHATGPT_OAUTH_PROVIDER

    def __init__(self, *, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def analyze(self, context: dict[str, Any]):
        from api.app.services.ai_agent import AgentProposalDraft, PostTaskAnalysisResult
        from api.app.services.ai_memory import build_ai_context_with_memory, store_memory

        run_context = context.get("run") if isinstance(context.get("run"), dict) else {}
        engagement_id = _uuid_from_text(run_context.get("engagement_id"))
        run_id = _uuid_from_text(run_context.get("id"))
        if engagement_id is None:
            raise ChatGPTOAuthError("ChatGPT OAuth post-task analysis requires engagement context")

        # Build scope allowlist for safe fetching
        scope_allowlist = run_context.get("scope_allowlist") or {}

        # Collect target URLs from task context for live page fetching
        task_context = context.get("task") if isinstance(context.get("task"), dict) else {}
        target_urls = []
        raw_target = str(task_context.get("target_id") or "").strip()
        if raw_target.startswith("http"):
            target_urls.append(raw_target)

        # Fetch live page context + recall engagement memory
        ai_context = build_ai_context_with_memory(
            self.session,
            engagement_id=engagement_id,
            run_id=run_id,
            target_urls=target_urls,
            scope_allowlist=scope_allowlist,
            fetch_targets=bool(target_urls),
        )

        response = send_chatgpt_backend_streaming_json_request(
            session=self.session,
            engagement_id=engagement_id,
            settings=self.settings,
            model=_chatgpt_model(self.settings, self.settings.ai_agent_post_task_analysis_model),
            instructions=(
                "You are AegisPT AI Signal — an expert penetration tester reasoning step-by-step. "
                "Think through the attack chain before proposing next steps. "
                "\n\nSTEP 1 — OBSERVE: What did this task find? Review findings, stdout, and severity. "
                "\nSTEP 2 — CHAIN: How does this connect to what is already known (engagement_memory)? "
                "Is this a link in an attack chain? What access does this confirm or enable? "
                "\nSTEP 3 — HYPOTHESIZE: What is the next logical step an attacker would take? "
                "What deeper surface is now reachable? What is the highest-impact follow-up? "
                "\nSTEP 4 — PROPOSE: Return bounded follow-up suggestions as proposals. "
                "Each proposal needs: proposed_tool, proposed_target, proposed_params, "
                "reasoning_text, risk_tier (passive/active/intrusive), priority (integer 1-100, lower=higher priority), "
                "confidence_score (0.0-1.0), metadata. "
                "\nSTEP 5 — REMEMBER: In memory_updates, list key facts to remember (key/value pairs). "
                "\n\nReturn an object. Return ONLY JSON with key 'analysis' containing: "
                "summary_text, thought_text, action_text, observations[], hypotheses[], proposals[], memory_updates[]. "
                "Never propose credential theft, arbitrary code execution, or scope expansion. "
                "If ai_loop run mode: prefer passive and active proposals over intrusive ones. "
                "Use empty proposals when no safe useful follow-up exists."
            ),
            input_items=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": _json_dumps({
                                "task_context": context,
                                "engagement_memory": ai_context["engagement_memory"],
                                "live_page_context": ai_context["live_page_context"],
                            }),
                        }
                    ],
                }
            ],
        )
        result_payload = response.get("analysis") if isinstance(response.get("analysis"), dict) else response

        # Store memory updates from AI response
        memory_updates = result_payload.get("memory_updates") if isinstance(result_payload.get("memory_updates"), list) else []
        for update in memory_updates:
            if isinstance(update, dict) and update.get("key") and update.get("value"):
                try:
                    store_memory(
                        self.session,
                        engagement_id=engagement_id,
                        run_id=run_id,
                        key=str(update["key"])[:255],
                        value=str(update["value"])[:4000],
                        memory_type=str(update.get("type") or "fact"),
                        confidence=float(update.get("confidence") or 1.0),
                        source="ai_post_task_analysis",
                    )
                except Exception:
                    pass

        proposals = [
            AgentProposalDraft(
                proposed_tool=_required_text(item, "proposed_tool"),
                proposed_target=_required_text(item, "proposed_target"),
                proposed_params=_safe_dict(item.get("proposed_params")),
                reasoning_text=str(item.get("reasoning_text") or "") or None,
                risk_tier=str(item.get("risk_tier") or "passive"),
                priority=_priority_int(item.get("priority")),
                confidence_score=_float_or_none(item.get("confidence_score")),
                metadata={**_safe_dict(item.get("metadata")), "provider": CHATGPT_OAUTH_PROVIDER},
            )
            for item in _dict_list(result_payload.get("proposals"))
        ]
        return PostTaskAnalysisResult(
            summary_text=str(result_payload.get("summary_text") or "") or None,
            thought_text=str(result_payload.get("thought_text") or "") or None,
            action_text=str(result_payload.get("action_text") or "") or None,
            observations=_dict_list(result_payload.get("observations")),
            hypotheses=_dict_list(result_payload.get("hypotheses")),
            proposals=proposals,
            model=str(
                response.get("model")
                or result_payload.get("model")
                or _chatgpt_model(self.settings, self.settings.ai_agent_post_task_analysis_model)
            ),
            llm_tokens_used=_int_or_none(result_payload.get("llm_tokens_used")),
            confidence_score=_float_or_none(result_payload.get("confidence_score")),
            metadata={
                **_safe_dict(result_payload.get("metadata")),
                "provider_mode": CHATGPT_OAUTH_PROVIDER,
                "token_exposed": False,
            },
        )


class ChatGPTOAuthIntakeInterpretationProvider:
    name = CHATGPT_OAUTH_PROVIDER

    def __init__(self, *, session: Session, settings: Settings, engagement_id: uuid.UUID | None) -> None:
        self.session = session
        self.settings = settings
        self.engagement_id = engagement_id

    def interpret(
        self,
        *,
        question_id: str,
        answer: str,
        configuration: dict[str, Any],
    ) -> dict[str, Any]:
        if self.engagement_id is None:
            raise ChatGPTOAuthError("ChatGPT OAuth intake interpretation requires an engagement id")

        response = send_chatgpt_backend_request(
            session=self.session,
            engagement_id=self.engagement_id,
            settings=self.settings,
            feature="intake_interpretation",
            model=_chatgpt_model(self.settings, self.settings.ai_intake_interpretation_model),
            payload={
                "question_id": question_id,
                "answer": answer,
                "configuration": configuration,
            },
        )
        result_payload = response.get("interpretation") if isinstance(response.get("interpretation"), dict) else response
        return {
            **_safe_dict(result_payload),
            "provider_metadata": {
                **_safe_dict(result_payload.get("provider_metadata")),
                "provider_mode": CHATGPT_OAUTH_PROVIDER,
                "token_exposed": False,
            },
        }


def extract_account_id(access_token: str) -> str | None:
    parts = str(access_token or "").split(".")
    if len(parts) < 2:
        return None
    try:
        payload_segment = parts[1]
        padding = "=" * (-len(payload_segment) % 4)
        decoded = base64.urlsafe_b64decode(f"{payload_segment}{padding}".encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
    except Exception:
        return None
    for key in ("accountId", "account_id", "https://api.openai.com/account_id", "sub"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _configured_client_id(settings: Settings) -> str:
    client_id = str(settings.chatgpt_oauth_client_id or "").strip()
    if not client_id:
        raise ChatGPTOAuthConfigurationError("CHATGPT_OAUTH_CLIENT_ID is required before starting ChatGPT OAuth")
    return client_id


def _load_pending_state(
    *,
    session: Session,
    state: str,
    settings: Settings,
) -> tuple[SecretRef, dict[str, Any]]:
    try:
        secret_ref_id_text, nonce = str(state or "").split(".", 1)
        secret_ref_id = uuid.UUID(secret_ref_id_text)
    except (ValueError, TypeError) as exc:
        raise ChatGPTOAuthError("invalid ChatGPT OAuth state") from exc

    secret_ref = session.get(SecretRef, secret_ref_id)
    if (
        secret_ref is None
        or secret_ref.purpose != CHATGPT_OAUTH_PENDING_PURPOSE
        or secret_ref.secret_kind != "oauth_pkce_verifier"
    ):
        raise ChatGPTOAuthError("ChatGPT OAuth state was not found")
    metadata = dict(secret_ref.metadata_json or {})
    if metadata.get("state_nonce") != nonce or metadata.get("status") != "pending":
        raise ChatGPTOAuthError("ChatGPT OAuth state did not match the pending verifier")
    if secret_ref.storage_backend not in ENCRYPTED_SECRET_BACKENDS or not secret_ref.encrypted_value:
        raise ChatGPTOAuthError("ChatGPT OAuth pending verifier is not encrypted")
    payload = _json_loads(
        decrypt_secret_value(
            secret_ref.encrypted_value,
            settings,
            storage_backend=secret_ref.storage_backend,
        )
    )
    if payload.get("state") != state:
        raise ChatGPTOAuthError("ChatGPT OAuth verifier payload did not match state")
    return secret_ref, payload


def _normalize_token_response(payload: dict[str, Any], previous: dict[str, Any] | None = None) -> dict[str, Any]:
    previous = previous or {}
    access_token = str(payload.get("access_token") or previous.get("access_token") or "").strip()
    if not access_token:
        raise ChatGPTOAuthError("ChatGPT OAuth token response did not include access_token")
    refresh_token = str(payload.get("refresh_token") or previous.get("refresh_token") or "").strip()
    id_token = str(payload.get("id_token") or "").strip()
    account_id = (
        str(payload.get("account_id") or payload.get("accountId") or "").strip()
        or extract_account_id(id_token)
        or extract_account_id(access_token)
        or str(previous.get("account_id") or "").strip()
    )
    expires_at = _expires_at_from_payload(payload, access_token=access_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at.isoformat(),
        "account_id": account_id,
        "token_type": str(payload.get("token_type") or previous.get("token_type") or "Bearer"),
    }


def _expires_at_from_payload(payload: dict[str, Any], *, access_token: str) -> datetime:
    for key in ("expires_at", "expires"):
        raw_value = payload.get(key)
        if isinstance(raw_value, str) and raw_value.strip():
            try:
                return _parse_datetime(raw_value)
            except ChatGPTOAuthError:
                pass
        if isinstance(raw_value, (int, float)):
            value = float(raw_value)
            if value > 10_000_000_000:
                value = value / 1000
            return datetime.fromtimestamp(value, tz=UTC)

    expires_in = payload.get("expires_in")
    if isinstance(expires_in, (int, float)):
        return datetime.now(tz=UTC) + timedelta(seconds=max(int(expires_in), 0))

    token_exp = _jwt_expiry(access_token)
    if token_exp is not None:
        return token_exp
    return datetime.now(tz=UTC) + timedelta(hours=1)


def _jwt_expiry(access_token: str) -> datetime | None:
    parts = str(access_token or "").split(".")
    if len(parts) < 2:
        return None
    try:
        payload_segment = parts[1]
        padding = "=" * (-len(payload_segment) % 4)
        decoded = base64.urlsafe_b64decode(f"{payload_segment}{padding}".encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            return datetime.fromtimestamp(float(exp), tz=UTC)
    except Exception:
        return None
    return None


def _latest_token_secret_ref(*, session: Session, engagement_id: uuid.UUID) -> SecretRef | None:
    return session.scalar(
        select(SecretRef)
        .where(
            SecretRef.engagement_id == engagement_id,
            SecretRef.purpose == CHATGPT_OAUTH_TOKEN_PURPOSE,
            SecretRef.secret_kind == "oauth_token_set",
        )
        .order_by(SecretRef.updated_at.desc(), SecretRef.created_at.desc(), SecretRef.id.desc())
        .limit(1)
    )


def _latest_reusable_token_secret_ref(*, session: Session, engagement_id: uuid.UUID) -> SecretRef | None:
    return session.scalar(
        select(SecretRef)
        .where(
            SecretRef.engagement_id != engagement_id,
            SecretRef.purpose == CHATGPT_OAUTH_TOKEN_PURPOSE,
            SecretRef.secret_kind == "oauth_token_set",
        )
        .order_by(SecretRef.updated_at.desc(), SecretRef.created_at.desc(), SecretRef.id.desc())
        .limit(1)
    )


def _metadata_account_id(secret_ref: SecretRef | None) -> str | None:
    if secret_ref is None:
        return None
    metadata = dict(secret_ref.metadata_json or {})
    return str(metadata.get("account_id") or "") or None


def _status_from_secret_ref(secret_ref: SecretRef, *, configured: bool = True) -> ChatGPTOAuthStatus:
    metadata = dict(secret_ref.metadata_json or {})
    return ChatGPTOAuthStatus(
        provider=CHATGPT_OAUTH_PROVIDER,
        configured=configured,
        connected=True,
        account_id=str(metadata.get("account_id") or "") or None,
        expires_at=str(metadata.get("expires_at") or "") or None,
        token_secret_ref_id=str(secret_ref.id),
        token_exposed=False,
    )


def _backend_url(settings: Settings) -> str:
    base = str(settings.chatgpt_oauth_backend_api_url or "https://chatgpt.com/backend-api").rstrip("/")
    path = str(settings.chatgpt_oauth_backend_api_path or "").strip()
    if not path:
        return base
    return f"{base}/{path.lstrip('/')}"


def _chatgpt_model(settings: Settings, feature_model: str | None) -> str:
    model = str(settings.chatgpt_oauth_model or "").strip()
    if model:
        return model
    return str(feature_model or "gpt-5.4").strip() or "gpt-5.4"


def _parse_datetime(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ChatGPTOAuthError("missing datetime value")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ChatGPTOAuthError(f"invalid datetime value: {text}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _required_text(payload: Any, key: str) -> str:
    value = payload.get(key) if isinstance(payload, dict) else None
    text = str(value or "").strip()
    if not text:
        raise ChatGPTOAuthError(f"ChatGPT OAuth response missing required field: {key}")
    return text


def _json_object_from_model_output(output_text: str) -> dict[str, Any]:
    text = str(output_text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ChatGPTOAuthError("ChatGPT streaming backend output was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ChatGPTOAuthError("ChatGPT streaming backend output was not a JSON object")
    return payload


def _json_dumps(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_loads(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ChatGPTOAuthError("encrypted ChatGPT OAuth secret was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ChatGPTOAuthError("encrypted ChatGPT OAuth secret was not a JSON object")
    return payload


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


_PRIORITY_LABEL_MAP = {"critical": 5, "high": 10, "medium": 20, "low": 30, "info": 50}


def _priority_int(value: Any) -> int:
    if value is None:
        return 100
    if isinstance(value, (int, float)):
        return max(1, int(value))
    label = str(value).strip().lower()
    if label in _PRIORITY_LABEL_MAP:
        return _PRIORITY_LABEL_MAP[label]
    try:
        return max(1, int(label))
    except (TypeError, ValueError):
        return 100


def _uuid_from_text(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None
