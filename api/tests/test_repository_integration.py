from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app.models import (
    AuditEvent,
    Finding,
    FindingRepositoryLink,
    RepositoryIntegration,
    Run,
    SecretRef,
)


@contextmanager
def build_client_with_env(tmp_path, monkeypatch, **env_overrides: str) -> Iterator[TestClient]:
    database_path = tmp_path / "aegispt-repository-integration.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "manual")
    monkeypatch.setenv("APP_PUBLIC_BASE_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "github-client-id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "github-client-secret")
    monkeypatch.setenv("GITLAB_OAUTH_CLIENT_ID", "gitlab-client-id")
    monkeypatch.setenv("GITLAB_OAUTH_CLIENT_SECRET", "gitlab-client-secret")
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


def _create_engagement(client: TestClient) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "repo-tester"},
        json={
            "name": "Repository Integration Engagement",
            "client": "Acme Corp",
            "roe_ref": "ROE-REPO-1",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _seed_run_and_finding(client: TestClient, engagement_id: str, *, title: str, autofix_json: dict[str, Any] | None = None) -> str:
    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            requested_by="repo-tester",
            status="completed",
            configuration_json={"assessment_type": "Website / Web App"},
        )
        session.add(run)
        session.flush()
        finding = Finding(
            run_id=run.id,
            title=title,
            severity="high",
            target_id="https://app.example.test/users",
            evidence_ref="artifact://repo-finding",
            status="open",
            summary="Repository-linked code path should be rendered in the finding theater.",
            autofix_json=autofix_json,
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _store_repository_token(
    client: TestClient,
    *,
    engagement_id: str,
    provider: str,
    repository_url: str,
    repository_path: str,
    token_value: str = "repo-secret-token",
) -> str:
    from api.app.config import get_settings
    from api.app.services.secrets import encrypt_secret_value

    settings = get_settings()
    with client.app.state.session_factory() as session:
        secret_ref = SecretRef(
            id=uuid4(),
            engagement_id=UUID(engagement_id),
            vault_pointer="",
            purpose=f"repository_oauth.token.{provider}",
            secret_kind="oauth_token_set",
            storage_backend="encrypted_local",
            display_label=f"{provider} repository token",
            encrypted_value=encrypt_secret_value(
                json.dumps({"access_token": token_value, "token_type": "Bearer"}),
                settings,
                storage_backend="encrypted_local",
            ),
            metadata_json={"provider": provider, "token_exposed": False},
        )
        secret_ref.vault_pointer = f"aegispt://secret-ref/{secret_ref.id}"
        session.add(secret_ref)
        session.flush()
        integration = RepositoryIntegration(
            engagement_id=UUID(engagement_id),
            token_secret_ref_id=secret_ref.id,
            provider=provider,
            repository_url=repository_url,
            repository_path=repository_path,
            default_branch="main",
            account_login="repo-user",
            status="connected",
            metadata_json={"html_url": repository_url, "token_exposed": False},
        )
        session.add(integration)
        session.commit()
        return str(integration.id)


def test_repository_authorize_stores_pending_state_as_encrypted_secret(tmp_path, monkeypatch) -> None:
    cases = [
        (
            "github",
            "https://github.com/acme/portal",
            "github.com",
            "/login/oauth/authorize",
            "repository_oauth.pending.github",
            "acme/portal",
        ),
        (
            "gitlab",
            "https://gitlab.com/acme/platform/portal",
            "gitlab.com",
            "/oauth/authorize",
            "repository_oauth.pending.gitlab",
            "acme/platform/portal",
        ),
    ]

    for provider, repository_url, host, path, purpose, repository_path in cases:
        with build_client_with_env(tmp_path, monkeypatch) as client:
            engagement_id = _create_engagement(client)
            response = client.get(
                f"/api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/authorize",
                params={"repository_url": repository_url},
            )

            assert response.status_code == 200
            payload = response.json()
            assert payload["provider"] == provider
            assert payload["token_exposed"] is False
            assert "client_secret" not in response.text

            parsed = urlparse(payload["authorization_url"])
            query = parse_qs(parsed.query)
            assert parsed.netloc == host
            assert parsed.path == path
            assert query["client_id"]
            assert query["redirect_uri"] == [
                f"http://127.0.0.1:8000/api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/callback"
            ]
            assert query["state"] == [payload["state"]]

            with client.app.state.session_factory() as session:
                secret_ref = session.scalar(
                    select(SecretRef).where(
                        SecretRef.engagement_id == UUID(engagement_id),
                        SecretRef.purpose == purpose,
                    )
                )
                assert secret_ref is not None
                assert secret_ref.storage_backend in {"encrypted_local", "deployment_key_encrypted"}
                assert secret_ref.encrypted_value
                assert repository_path not in (secret_ref.encrypted_value or "")
                assert secret_ref.metadata_json["raw_secret_material_exposed"] is False


def test_repository_callback_stores_encrypted_token_and_connected_repo_for_github_and_gitlab(
    tmp_path,
    monkeypatch,
) -> None:
    cases = [
        (
            "github",
            "https://github.com/acme/portal",
            "repository_oauth.token.github",
            "acme/portal",
            "https://api.github.com/user",
            "https://api.github.com/repos/acme/portal",
        ),
        (
            "gitlab",
            "https://gitlab.com/acme/platform/portal",
            "repository_oauth.token.gitlab",
            "acme/platform/portal",
            "https://gitlab.com/api/v4/user",
            "https://gitlab.com/api/v4/projects/acme%2Fplatform%2Fportal",
        ),
    ]

    class FakeResponse:
        def __init__(self, payload: Any, status_code: int = 200) -> None:
            self._payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

        def json(self) -> Any:
            return self._payload

    for provider, repository_url, purpose, repository_path, user_url, repo_url in cases:
        calls: list[dict[str, Any]] = []

        def make_fakes(c, p, u_url, r_url, rep_url):
            def _fake_post(url: str, **kwargs):
                c.append({"method": "POST", "url": url, **kwargs})
                return FakeResponse({"access_token": f"{p}-access-token", "token_type": "Bearer", "scope": "repo"})

            def _fake_get(url: str, **kwargs):
                c.append({"method": "GET", "url": url, **kwargs})
                if url == u_url:
                    payload = {"login": "repo-user"} if p == "github" else {"username": "repo-user"}
                    return FakeResponse(payload)
                if url == r_url:
                    if p == "github":
                        return FakeResponse({"id": 42, "html_url": rep_url, "default_branch": "main"})
                    return FakeResponse({"id": 77, "web_url": rep_url, "default_branch": "main"})
                raise AssertionError(f"unexpected GET {url}")
            return _fake_post, _fake_get

        fake_post, fake_get = make_fakes(calls, provider, user_url, repo_url, repository_url)

        with build_client_with_env(tmp_path, monkeypatch) as client:
            monkeypatch.setattr("api.app.services.repository_integration.httpx.post", fake_post)
            monkeypatch.setattr("api.app.services.repository_integration.httpx.get", fake_get)
            engagement_id = _create_engagement(client)

            authorize = client.get(
                f"/api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/authorize",
                params={"repository_url": repository_url},
            )
            assert authorize.status_code == 200
            state = authorize.json()["state"]

            callback = client.get(
                f"/api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/callback",
                params={"code": "oauth-code", "state": state},
            )
            assert callback.status_code == 200
            payload = callback.json()
            assert payload["connected"] is True
            assert payload["provider"] == provider
            assert payload["repository_path"] == repository_path
            assert payload["account_login"] == "repo-user"
            assert payload["token_exposed"] is False
            assert f"{provider}-access-token" not in callback.text

            list_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/repositories")
            assert list_response.status_code == 200
            listed = list_response.json()
            assert len(listed) == 1
            assert listed[0]["provider"] == provider
            assert listed[0]["repository_path"] == repository_path
            assert listed[0]["token_exposed"] is False

            with client.app.state.session_factory() as session:
                token_ref = session.scalar(
                    select(SecretRef).where(
                        SecretRef.engagement_id == UUID(engagement_id),
                        SecretRef.purpose == purpose,
                    )
                )
                pending_ref = session.scalar(
                    select(SecretRef).where(
                        SecretRef.engagement_id == UUID(engagement_id),
                        SecretRef.purpose == f"repository_oauth.pending.{provider}",
                    )
                )
                integration = session.scalar(
                    select(RepositoryIntegration).where(RepositoryIntegration.engagement_id == UUID(engagement_id))
                )

            assert token_ref is not None
            assert pending_ref is None
            assert integration is not None
            assert integration.repository_path == repository_path
            assert integration.status == "connected"
            assert f"{provider}-access-token" not in (token_ref.encrypted_value or "")
            assert token_ref.metadata_json["token_exposed"] is False
            assert any(call["url"] == user_url for call in calls)
            assert any(call["url"] == repo_url for call in calls)


def test_finding_theater_exposes_repository_snippet_and_fix_pr_without_auto_merge(tmp_path, monkeypatch) -> None:
    file_content = "\n".join(
        [
            "from sqlalchemy import text",
            "",
            "def load_user(email, db):",
            "    query = f\"SELECT * FROM users WHERE email = '{email}'\"",
            "    return db.execute(query).fetchone()",
            "",
            "def healthcheck():",
            "    return True",
        ]
    )

    class FakeResponse:
        def __init__(self, payload: Any, status_code: int = 200) -> None:
            self._payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

        def json(self) -> Any:
            return self._payload

    calls: list[dict[str, Any]] = []

    def fake_get(url: str, **kwargs):
        calls.append({"method": "GET", "url": url, **kwargs})
        if url == "https://api.github.com/repos/acme/portal/contents/app/users.py":
            return FakeResponse(
                {
                    "content": base64.b64encode(file_content.encode("utf-8")).decode("utf-8"),
                    "sha": "blob-sha-1",
                    "html_url": "https://github.com/acme/portal/blob/main/app/users.py",
                }
            )
        if url == "https://api.github.com/repos/acme/portal/git/ref/heads/main":
            return FakeResponse({"object": {"sha": "base-sha-main"}})
        raise AssertionError(f"unexpected GET {url}")

    def fake_post(url: str, **kwargs):
        calls.append({"method": "POST", "url": url, **kwargs})
        if url == "https://api.github.com/repos/acme/portal/git/refs":
            assert kwargs["json"]["ref"].startswith("refs/heads/aegispt/autofix-")
            assert kwargs["json"]["sha"] == "base-sha-main"
            return FakeResponse({"ref": kwargs["json"]["ref"]}, status_code=201)
        if url == "https://api.github.com/repos/acme/portal/pulls":
            assert kwargs["json"]["base"] == "main"
            assert kwargs["json"]["head"].startswith("aegispt/autofix-")
            return FakeResponse({"html_url": "https://github.com/acme/portal/pull/9", "number": 9}, status_code=201)
        raise AssertionError(f"unexpected POST {url}")

    def fake_put(url: str, **kwargs):
        calls.append({"method": "PUT", "url": url, **kwargs})
        if url == "https://api.github.com/repos/acme/portal/contents/app/users.py":
            assert kwargs["json"]["branch"].startswith("aegispt/autofix-")
            patched = base64.b64decode(kwargs["json"]["content"]).decode("utf-8")
            assert "SELECT * FROM users WHERE email = :email" in patched
            return FakeResponse({"content": {"path": "app/users.py"}}, status_code=200)
        raise AssertionError(f"unexpected PUT {url}")

    with build_client_with_env(tmp_path, monkeypatch) as client:
        monkeypatch.setattr("api.app.services.repository_integration.httpx.get", fake_get)
        monkeypatch.setattr("api.app.services.repository_integration.httpx.post", fake_post)
        monkeypatch.setattr("api.app.services.repository_integration.httpx.put", fake_put)

        engagement_id = _create_engagement(client)
        finding_id = _seed_run_and_finding(
            client,
            engagement_id,
            title="SQL injection in app/users.py:4",
            autofix_json={
                "patch_language": "python",
                "patch_before": "query = f\"SELECT * FROM users WHERE email = '{email}'\"",
                "patch_after": "query = \"SELECT * FROM users WHERE email = :email\"",
                "patch_explanation": "Use parameterized SQL.",
                "verification_command": "pytest -q tests/security -k parameterized_query",
                "confidence": "high",
                "provider": "deterministic",
                "model": "openai-codex/gpt-5.4",
                "advisory_only": True,
                "auto_apply_allowed": False,
            },
        )
        _store_repository_token(
            client,
            engagement_id=engagement_id,
            provider="github",
            repository_url="https://github.com/acme/portal",
            repository_path="acme/portal",
        )

        theater = client.get(f"/api/v1/findings/{finding_id}/theater")
        assert theater.status_code == 200
        payload = theater.json()
        repo = payload["repository_context"]
        assert repo["available"] is True
        assert repo["provider"] == "github"
        assert repo["repository_path"] == "app/users.py"
        assert repo["highlighted_line"] == 4
        assert repo["external_url"].endswith("/blob/main/app/users.py#L4")
        assert "4:     query = f" in repo["snippet_text"]
        assert repo["pull_request_supported"] is True

        fix_pr = client.post(
            f"/api/v1/findings/{finding_id}/repository/fix-pr",
            headers={"X-Actor": "repo-operator"},
        )
        assert fix_pr.status_code == 200
        pr_payload = fix_pr.json()
        assert pr_payload["provider"] == "github"
        assert pr_payload["pull_request_url"] == "https://github.com/acme/portal/pull/9"
        assert pr_payload["auto_merge_enabled"] is False

        with client.app.state.session_factory() as session:
            link = session.scalar(select(FindingRepositoryLink).where(FindingRepositoryLink.finding_id == UUID(finding_id)))
            audit_event = session.scalar(
                select(AuditEvent)
                .where(AuditEvent.action == "finding.repository_fix_pr.created")
                .order_by(AuditEvent.created_at.desc())
            )

        assert link is not None
        assert link.metadata_json["latest_pull_request"]["pull_request_url"] == "https://github.com/acme/portal/pull/9"
        assert link.metadata_json["latest_pull_request"]["auto_merge_enabled"] is False
        assert audit_event is not None
        assert audit_event.metadata_json["auto_merge_enabled"] is False
        assert not any(call["url"].endswith("/merge") for call in calls)


def test_gitlab_fix_merge_request_is_ai_generated_and_review_only(tmp_path, monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, payload: Any, status_code: int = 200) -> None:
            self._payload = payload
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

        def json(self) -> Any:
            return self._payload

    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs):
        calls.append({"method": "POST", "url": url, **kwargs})
        if url == "https://gitlab.com/api/v4/projects/acme%2Fplatform%2Fportal/repository/branches":
            assert kwargs["data"]["branch"].startswith("aegispt/autofix-")
            assert kwargs["data"]["ref"] == "main"
            return FakeResponse({"name": kwargs["data"]["branch"]}, status_code=201)
        if url == "https://gitlab.com/api/v4/projects/acme%2Fplatform%2Fportal/merge_requests":
            assert kwargs["data"]["source_branch"].startswith("aegispt/autofix-")
            assert kwargs["data"]["target_branch"] == "main"
            assert "AI-generated" in kwargs["data"]["description"]
            assert "Human review is required" in kwargs["data"]["description"]
            return FakeResponse({"web_url": "https://gitlab.com/acme/platform/portal/-/merge_requests/7", "iid": 7}, status_code=201)
        raise AssertionError(f"unexpected POST {url}")

    def fake_put(url: str, **kwargs):
        calls.append({"method": "PUT", "url": url, **kwargs})
        if url == "https://gitlab.com/api/v4/projects/acme%2Fplatform%2Fportal/repository/files/app%2Fusers.py":
            assert kwargs["data"]["branch"].startswith("aegispt/autofix-")
            assert "SELECT * FROM users WHERE email = :email" in kwargs["data"]["content"]
            return FakeResponse({"file_path": "app/users.py"}, status_code=200)
        raise AssertionError(f"unexpected PUT {url}")

    with build_client_with_env(tmp_path, monkeypatch) as client:
        monkeypatch.setattr("api.app.services.repository_integration.httpx.post", fake_post)
        monkeypatch.setattr("api.app.services.repository_integration.httpx.put", fake_put)

        engagement_id = _create_engagement(client)
        finding_id = _seed_run_and_finding(
            client,
            engagement_id,
            title="SQL injection in app/users.py:4",
            autofix_json={
                "patch_language": "python",
                "patch_before": "query = f\"SELECT * FROM users WHERE email = '{email}'\"",
                "patch_after": "query = \"SELECT * FROM users WHERE email = :email\"",
                "patch_explanation": "Use parameterized SQL.",
                "verification_command": "pytest -q tests/security -k parameterized_query",
                "confidence": "high",
                "provider": "deterministic",
                "model": "openai-codex/gpt-5.4",
                "advisory_only": True,
                "auto_apply_allowed": False,
            },
        )
        integration_id = _store_repository_token(
            client,
            engagement_id=engagement_id,
            provider="gitlab",
            repository_url="https://gitlab.com/acme/platform/portal",
            repository_path="acme/platform/portal",
        )
        with client.app.state.session_factory() as session:
            session.add(
                FindingRepositoryLink(
                    finding_id=UUID(finding_id),
                    repo_integration_id=UUID(integration_id),
                    repository_path="app/users.py",
                    repository_branch="main",
                    line_start=2,
                    line_end=5,
                    highlighted_line=4,
                    snippet_language="python",
                    snippet_text="4: query = f\"SELECT * FROM users WHERE email = '{email}'\"",
                    external_url="https://gitlab.com/acme/platform/portal/-/blob/main/app/users.py#L4",
                    metadata_json={"pull_request_supported": True},
                )
            )
            session.commit()

        fix_pr = client.post(
            f"/api/v1/findings/{finding_id}/repository/fix-pr",
            headers={"X-Actor": "repo-operator"},
        )
        assert fix_pr.status_code == 200
        payload = fix_pr.json()
        assert payload["provider"] == "gitlab"
        assert payload["pull_request_url"] == "https://gitlab.com/acme/platform/portal/-/merge_requests/7"
        assert payload["auto_merge_enabled"] is False
        assert not any(call["url"].endswith("/merge") for call in calls)
