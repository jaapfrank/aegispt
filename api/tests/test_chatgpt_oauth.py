from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select


@contextmanager
def build_client_with_env(tmp_path, monkeypatch, **env_overrides: str) -> Iterator[TestClient]:
    database_path = tmp_path / "aegispt-chatgpt-oauth.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "manual")
    monkeypatch.setenv("APP_PUBLIC_BASE_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("CHATGPT_OAUTH_CLIENT_ID", "test-chatgpt-client")
    monkeypatch.setenv("CHATGPT_OAUTH_LOCAL_CALLBACK_ENABLED", "false")
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()


def create_engagement_with_scope(client: TestClient) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={"name": "ChatGPT OAuth Validation", "client": "Acme Corp", "roe_ref": "ROE-OAUTH"},
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"urls": ["https://example.com"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    return engagement_id


def test_authorize_returns_pkce_url_and_stores_verifier_as_encrypted_secret(tmp_path, monkeypatch) -> None:
    with build_client_with_env(tmp_path, monkeypatch) as client:
        engagement_id = create_engagement_with_scope(client)
        response = client.get(f"/api/v1/auth/chatgpt/authorize?engagement_id={engagement_id}")

        assert response.status_code == 200
        payload = response.json()
        assert payload["provider"] == "chatgpt_oauth"
        assert payload["token_exposed"] is False
        assert "code_verifier" not in response.text

        parsed = urlparse(payload["authorization_url"])
        query = parse_qs(parsed.query)
        assert parsed.scheme == "https"
        assert parsed.netloc == "auth.openai.com"
        assert parsed.path == "/oauth/authorize"
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["test-chatgpt-client"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == ["http://localhost:1455/auth/callback"]
        assert query["state"] == [payload["state"]]
        assert query["id_token_add_organizations"] == ["true"]
        assert query["codex_cli_simplified_flow"] == ["true"]
        assert query["originator"] == ["aegispt"]
        assert query["code_challenge"][0]

        from api.app.models import SecretRef

        with client.app.state.session_factory() as session:
            secret_ref = session.scalar(
                select(SecretRef).where(
                    SecretRef.engagement_id == UUID(engagement_id),
                    SecretRef.purpose == "chatgpt_oauth.pkce_state",
                )
            )
            assert secret_ref is not None
            assert secret_ref.storage_backend in {"encrypted_local", "deployment_key_encrypted"}
            assert secret_ref.encrypted_value
            assert "code_verifier" not in secret_ref.encrypted_value
            assert secret_ref.metadata_json["raw_secret_material_exposed"] is False


def test_callback_exchanges_code_and_stores_token_set_without_exposing_tokens(tmp_path, monkeypatch) -> None:
    access_token = _jwt({"accountId": "acct_chatgpt_123", "exp": _epoch_seconds(minutes=20)})
    refresh_token = "refresh-secret-token"

    class FakeResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 1200,
                "token_type": "Bearer",
            }

    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        return FakeResponse()

    with build_client_with_env(tmp_path, monkeypatch) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.post", fake_post)
        engagement_id = create_engagement_with_scope(client)
        authorization = client.get(f"/api/v1/auth/chatgpt/authorize?engagement_id={engagement_id}").json()
        response = client.get(
            "/api/v1/auth/chatgpt/callback",
            params={"code": "oauth-code", "state": authorization["state"]},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "connected"
        assert payload["connected"] is True
        assert payload["account_id"] == "acct_chatgpt_123"
        assert payload["token_exposed"] is False
        assert access_token not in response.text
        assert refresh_token not in response.text
        assert calls[0]["url"] == "https://auth.openai.com/oauth/token"
        assert calls[0]["data"]["grant_type"] == "authorization_code"
        assert calls[0]["data"]["code_verifier"]

        status = client.get(f"/api/v1/auth/chatgpt/status?engagement_id={engagement_id}").json()
        assert status["connected"] is True
        assert status["account_id"] == "acct_chatgpt_123"
        assert access_token not in json.dumps(status)
        assert refresh_token not in json.dumps(status)

        from api.app.models import SecretRef

        with client.app.state.session_factory() as session:
            token_ref = session.scalar(
                select(SecretRef).where(
                    SecretRef.engagement_id == UUID(engagement_id),
                    SecretRef.purpose == "ai_provider.chatgpt_oauth",
                )
            )
            pending_ref = session.scalar(
                select(SecretRef).where(
                    SecretRef.engagement_id == UUID(engagement_id),
                    SecretRef.purpose == "chatgpt_oauth.pkce_state",
                )
            )
            assert token_ref is not None
            assert pending_ref is None
            assert token_ref.metadata_json["account_id"] == "acct_chatgpt_123"
            assert token_ref.metadata_json["raw_secret_material_exposed"] is False
            assert access_token not in token_ref.encrypted_value
            assert refresh_token not in token_ref.encrypted_value


def test_authorize_reuses_existing_encrypted_session_for_new_engagement_without_new_login(
    tmp_path,
    monkeypatch,
) -> None:
    access_token = _jwt({"accountId": "acct_reusable", "exp": _epoch_seconds(minutes=30)})
    refresh_token = "refresh-token-reusable"

    class FakeResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 1800,
                "token_type": "Bearer",
            }

    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        return FakeResponse()

    with build_client_with_env(tmp_path, monkeypatch) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.post", fake_post)
        first_engagement_id = create_engagement_with_scope(client)
        authorization = client.get(
            f"/api/v1/auth/chatgpt/authorize?engagement_id={first_engagement_id}"
        ).json()
        callback = client.get(
            "/api/v1/auth/chatgpt/callback",
            params={"code": "oauth-code", "state": authorization["state"]},
        )
        assert callback.status_code == 200

        second_engagement_id = create_engagement_with_scope(client)
        second_status = client.get(
            f"/api/v1/auth/chatgpt/status?engagement_id={second_engagement_id}"
        ).json()
        assert second_status["connected"] is False
        assert second_status["reusable_session_available"] is True
        assert second_status["reusable_account_id"] == "acct_reusable"

        reused = client.get(
            f"/api/v1/auth/chatgpt/authorize?engagement_id={second_engagement_id}"
        )
        assert reused.status_code == 200
        reused_payload = reused.json()
        assert reused_payload["reused"] is True
        assert reused_payload["authorization_url"] is None
        assert reused_payload["status"]["connected"] is True
        assert reused_payload["status"]["account_id"] == "acct_reusable"
        assert len(calls) == 1
        assert access_token not in reused.text
        assert refresh_token not in reused.text

        final_status = client.get(
            f"/api/v1/auth/chatgpt/status?engagement_id={second_engagement_id}"
        ).json()
        assert final_status["connected"] is True
        assert final_status["account_id"] == "acct_reusable"

        from api.app.models import SecretRef

        with client.app.state.session_factory() as session:
            token_refs = list(
                session.scalars(
                    select(SecretRef).where(SecretRef.purpose == "ai_provider.chatgpt_oauth")
                ).all()
            )
        assert len(token_refs) == 2
        assert {ref.engagement_id for ref in token_refs} == {
            UUID(first_engagement_id),
            UUID(second_engagement_id),
        }


def test_provider_calls_auto_reuse_existing_encrypted_session_for_new_engagement(
    tmp_path,
    monkeypatch,
) -> None:
    access_token = _jwt({"accountId": "acct_provider_reuse", "exp": _epoch_seconds(minutes=30)})
    refresh_token = "refresh-token-provider-reuse"

    class FakeResponse:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload
            self.status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        if url == "https://auth.openai.com/oauth/token":
            return FakeResponse(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": 1800,
                    "token_type": "Bearer",
                }
            )
        assert url.startswith("https://chatgpt.com/backend-api")
        assert kwargs["headers"]["Authorization"] == f"Bearer {access_token}"
        return FakeResponse({"analysis": {"observations": [], "hypotheses": [], "proposals": []}})

    with build_client_with_env(tmp_path, monkeypatch) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.post", fake_post)
        first_engagement_id = create_engagement_with_scope(client)
        authorization = client.get(
            f"/api/v1/auth/chatgpt/authorize?engagement_id={first_engagement_id}"
        ).json()
        callback = client.get(
            "/api/v1/auth/chatgpt/callback",
            params={"code": "oauth-code", "state": authorization["state"]},
        )
        assert callback.status_code == 200

        second_engagement_id = create_engagement_with_scope(client)
        from api.app.config import get_settings
        from api.app.models import SecretRef
        from api.app.services.chatgpt_oauth import send_chatgpt_backend_request

        with client.app.state.session_factory() as session:
            response = send_chatgpt_backend_request(
                session=session,
                engagement_id=UUID(second_engagement_id),
                settings=get_settings(),
                feature="post_task_analysis",
                model="gpt-5.4",
                payload={"run": {"engagement_id": second_engagement_id}},
            )
            assert response["analysis"]["proposals"] == []
            token_refs = list(
                session.scalars(
                    select(SecretRef).where(SecretRef.purpose == "ai_provider.chatgpt_oauth")
                ).all()
            )

        assert len(token_refs) == 2
        assert {ref.engagement_id for ref in token_refs} == {
            UUID(first_engagement_id),
            UUID(second_engagement_id),
        }
        assert len([call for call in calls if call["url"] == "https://auth.openai.com/oauth/token"]) == 1
        assert any(call["url"].startswith("https://chatgpt.com/backend-api") for call in calls)


def test_post_task_chatgpt_oauth_provider_uses_streaming_codex_response_shape(
    tmp_path,
    monkeypatch,
) -> None:
    access_token = _jwt({"accountId": "acct_post_task", "exp": _epoch_seconds(minutes=30)})
    refresh_token = "refresh-token-post-task"

    class TokenResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 1800,
                "token_type": "Bearer",
            }

    class StreamResponse:
        status_code = 200

        def __init__(self, payload: dict[str, Any]) -> None:
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_lines(self):
            text = json.dumps(self.payload)
            yield "data: " + json.dumps({"type": "response.output_text.delta", "delta": text})
            yield "data: [DONE]"

    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        assert url == "https://auth.openai.com/oauth/token"
        return TokenResponse()

    def fake_stream(method: str, url: str, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        assert method == "POST"
        assert url == "https://chatgpt.com/backend-api/codex/responses"
        assert kwargs["headers"]["Accept"] == "text/event-stream"
        assert kwargs["headers"]["Authorization"] == f"Bearer {access_token}"
        body = kwargs["json"]
        assert body["store"] is False
        assert body["stream"] is True
        assert isinstance(body["instructions"], str) and "Return an object" in body["instructions"]
        assert "summary_text" in body["instructions"]
        assert "thought_text" in body["instructions"]
        assert "action_text" in body["instructions"]
        assert isinstance(body["input"], list)
        return StreamResponse(
            {
                "analysis": {
                    "summary_text": "Stored stdout has been reviewed.",
                    "thought_text": "The discovered HTTP service is worth a bounded passive follow-up.",
                    "action_text": "Ask the operator to review an httpx follow-up before queueing.",
                    "observations": [{"summary": "Stored stdout has been reviewed."}],
                    "hypotheses": [],
                    "proposals": [
                        {
                            "proposed_tool": "httpx",
                            "proposed_target": "https://example.com",
                            "proposed_params": {"review_required": True},
                            "reasoning_text": "Check the discovered HTTP surface.",
                            "risk_tier": "passive",
                            "priority": 30,
                            "confidence_score": 0.77,
                            "metadata": {"source": "streaming-test"},
                        }
                    ],
                    "model": "gpt-5.4",
                }
            }
        )

    with build_client_with_env(tmp_path, monkeypatch) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.post", fake_post)
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.stream", fake_stream)
        engagement_id = create_engagement_with_scope(client)
        authorization = client.get(
            f"/api/v1/auth/chatgpt/authorize?engagement_id={engagement_id}"
        ).json()
        callback = client.get(
            "/api/v1/auth/chatgpt/callback",
            params={"code": "oauth-code", "state": authorization["state"]},
        )
        assert callback.status_code == 200

        from api.app.config import get_settings
        from api.app.services.chatgpt_oauth import ChatGPTOAuthPostTaskAnalysisProvider

        with client.app.state.session_factory() as session:
            provider = ChatGPTOAuthPostTaskAnalysisProvider(session=session, settings=get_settings())
            result = provider.analyze(
                {
                    "run": {"engagement_id": engagement_id, "id": "run-id"},
                    "task": {"id": "task-id", "tool": "nmap", "target_id": "https://example.com"},
                }
            )

        assert len(calls) == 1
        assert result.model == "gpt-5.4"
        assert result.summary_text == "Stored stdout has been reviewed."
        assert result.thought_text == "The discovered HTTP service is worth a bounded passive follow-up."
        assert result.action_text == "Ask the operator to review an httpx follow-up before queueing."
        assert result.observations[0]["summary"] == "Stored stdout has been reviewed."
        assert result.proposals[0].proposed_tool == "httpx"


def test_chatgpt_oauth_provider_refreshes_before_backend_call_and_keeps_tokens_secret(
    tmp_path,
    monkeypatch,
) -> None:
    initial_access = _jwt({"accountId": "acct_refresh", "exp": _epoch_seconds(minutes=-5)})
    refreshed_access = _jwt({"accountId": "acct_refresh", "exp": _epoch_seconds(minutes=30)})
    refresh_token = "refresh-token-before-expiry"

    class TokenResponse:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload
            self.status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    class BackendResponse(TokenResponse):
        pass

    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        if url == "https://auth.openai.com/oauth/token" and kwargs.get("data", {}).get("grant_type") == "authorization_code":
            return TokenResponse(
                {
                    "access_token": initial_access,
                    "refresh_token": refresh_token,
                    "expires_in": 0,
                }
            )
        if url == "https://auth.openai.com/oauth/token" and kwargs.get("data", {}).get("grant_type") == "refresh_token":
            return TokenResponse(
                {
                    "access_token": refreshed_access,
                    "refresh_token": refresh_token,
                    "expires_in": 1800,
                }
            )
        assert url.startswith("https://chatgpt.com/backend-api")
        assert kwargs["headers"]["Authorization"] == f"Bearer {refreshed_access}"
        assert kwargs["json"]["model"] == "gpt-5.4"
        return BackendResponse(
            {
                "enrichment": {
                    "business_impact": "Review impact from stored evidence only.",
                    "technical_context": "Technical context is grounded in the finding summary.",
                    "remediation_narrative": "Remediate and retest through the existing finding flow.",
                },
                "model": "chatgpt-oauth-mock",
            }
        )

    with build_client_with_env(
        tmp_path,
        monkeypatch,
        AI_PROVIDER="chatgpt_oauth",
        AI_FINDING_ENRICHMENT_ENABLED="true",
    ) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.post", fake_post)
        engagement_id = create_engagement_with_scope(client)
        authorization = client.get(f"/api/v1/auth/chatgpt/authorize?engagement_id={engagement_id}").json()
        callback = client.get(
            "/api/v1/auth/chatgpt/callback",
            params={"code": "oauth-code", "state": authorization["state"]},
        )
        assert callback.status_code == 200

        run_id = _create_run(client, engagement_id)
        from api.app.config import get_settings
        from api.app.models import Finding, SecretRef
        from api.app.services.ai_enrichment import store_ai_enrichment_for_finding

        with client.app.state.session_factory() as session:
            finding = Finding(
                run_id=UUID(run_id),
                title="Mock ChatGPT OAuth finding",
                severity="medium",
                target_id="https://example.com",
                evidence_ref="artifact://mock",
                status="open",
                summary="Stored finding summary for provider context.",
                methodology_tags=["OWASP-WSTG"],
            )
            session.add(finding)
            session.flush()
            enrichment = store_ai_enrichment_for_finding(
                session=session,
                finding=finding,
                settings=get_settings(),
            )
            session.commit()

            token_ref = session.scalar(
                select(SecretRef).where(
                    SecretRef.engagement_id == UUID(engagement_id),
                    SecretRef.purpose == "ai_provider.chatgpt_oauth",
                )
            )

        assert enrichment is not None
        assert enrichment.status == "succeeded"
        assert enrichment.provider == "chatgpt_oauth"
        assert any(call["data"]["grant_type"] == "refresh_token" for call in calls if "data" in call)
        assert any(call["url"].startswith("https://chatgpt.com/backend-api") for call in calls)
        assert token_ref is not None
        assert refreshed_access not in token_ref.encrypted_value
        assert refresh_token not in token_ref.encrypted_value


def test_kill_switch_blocks_chatgpt_oauth_provider_calls(tmp_path, monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        raise AssertionError("kill switch should block OAuth provider HTTP calls")

    with build_client_with_env(
        tmp_path,
        monkeypatch,
        AI_PROVIDER="chatgpt_oauth",
        AI_FINDING_ENRICHMENT_ENABLED="true",
        EXECUTION_KILL_SWITCH="true",
    ) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.post", fake_post)
        engagement_id = create_engagement_with_scope(client)
        run_id = _create_run(client, engagement_id)

        from api.app.config import get_settings
        from api.app.models import Finding
        from api.app.services.ai_enrichment import store_ai_enrichment_for_finding

        with client.app.state.session_factory() as session:
            finding = Finding(
                run_id=UUID(run_id),
                title="Kill switch blocked finding",
                severity="low",
                target_id="https://example.com",
                evidence_ref="artifact://mock",
                status="open",
                summary="Provider should not run.",
                methodology_tags=[],
            )
            session.add(finding)
            session.flush()
            enrichment = store_ai_enrichment_for_finding(
                session=session,
                finding=finding,
                settings=get_settings(),
            )
            session.commit()

        assert enrichment is not None
        assert enrichment.status == "failed"
        assert "kill switch" in enrichment.failure_reason.lower()
        assert calls == []


def _create_run(client: TestClient, engagement_id: str) -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator-ui"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://example.com"]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _epoch_seconds(*, minutes: int) -> int:
    return int((datetime.now(tz=UTC) + timedelta(minutes=minutes)).timestamp())


def _jwt(payload: dict[str, Any]) -> str:
    def encode(value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode({'alg': 'none', 'typ': 'JWT'})}.{encode(payload)}."
