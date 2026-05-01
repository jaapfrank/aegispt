from __future__ import annotations

import base64
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote, urlencode, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    Finding,
    FindingRepositoryLink,
    RepositoryIntegration,
    Run,
    SecretRef,
    Task,
    ToolExecution,
)
from api.app.services.secrets import (
    ENCRYPTED_SECRET_BACKENDS,
    decrypt_secret_value,
    direct_secret_storage_backend,
    encrypt_secret_value,
)

SUPPORTED_REPOSITORY_PROVIDERS = {"github", "gitlab"}
REPOSITORY_PENDING_PURPOSE_PREFIX = "repository_oauth.pending"
REPOSITORY_TOKEN_PURPOSE_PREFIX = "repository_oauth.token"
PATH_HINT_PATTERN = re.compile(
    r"(?P<path>[\w./-]+\.(?:py|js|ts|tsx|jsx|java|php|rb|cs|go|sql|yaml|yml|json|html|css))(?:[:#](?P<line>\d+))?",
    flags=re.IGNORECASE,
)


class RepositoryIntegrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RepositoryAuthorizationStart:
    provider: Literal["github", "gitlab"]
    authorization_url: str
    redirect_uri: str
    state: str


@dataclass(frozen=True, slots=True)
class RepositoryAuthorizationComplete:
    provider: Literal["github", "gitlab"]
    repository_url: str
    repository_path: str
    default_branch: str
    account_login: str | None
    connected: bool = True
    token_exposed: bool = False


@dataclass(frozen=True, slots=True)
class RepositoryFixPullRequest:
    provider: Literal["github", "gitlab"]
    repository_url: str
    branch_name: str
    pull_request_url: str
    pull_request_id: str
    auto_merge_enabled: bool = False


def start_repository_authorization(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    provider: str,
    repository_url: str,
    default_branch: str | None,
    settings: Settings,
) -> RepositoryAuthorizationStart:
    provider_name = _normalized_provider(provider)
    spec = _provider_spec(provider_name, settings)
    descriptor = _parse_repository_url(provider_name, repository_url)
    state_ref_id = uuid.uuid4()
    nonce = secrets.token_urlsafe(24)
    state = f"{state_ref_id}.{nonce}"
    redirect_uri = repository_redirect_uri(settings=settings, engagement_id=engagement_id, provider=provider_name)
    storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
    payload = {
        "engagement_id": str(engagement_id),
        "provider": provider_name,
        "repository_url": descriptor["repository_url"],
        "repository_path": descriptor["repository_path"],
        "default_branch": str(default_branch or "main").strip() or "main",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    secret_ref = SecretRef(
        id=state_ref_id,
        engagement_id=engagement_id,
        vault_pointer=f"aegispt://secret-ref/{state_ref_id}",
        purpose=f"{REPOSITORY_PENDING_PURPOSE_PREFIX}.{provider_name}",
        secret_kind="oauth_state",
        storage_backend=storage_backend,
        display_label=f"{provider_name} repository OAuth pending state",
        encrypted_value=encrypt_secret_value(json.dumps(payload), settings, storage_backend=storage_backend),
        metadata_json={
            "provider": provider_name,
            "repository_path": descriptor["repository_path"],
            "state_nonce": nonce,
            "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
            "raw_secret_material_exposed": False,
        },
    )
    session.add(secret_ref)
    query = {
        "client_id": spec["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": spec["scope"],
    }
    return RepositoryAuthorizationStart(
        provider=provider_name,
        authorization_url=f"{spec['authorize_url']}?{urlencode(query)}",
        redirect_uri=redirect_uri,
        state=state,
    )


def complete_repository_authorization(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    provider: str,
    code: str,
    state: str,
    settings: Settings,
) -> RepositoryAuthorizationComplete:
    provider_name = _normalized_provider(provider)
    spec = _provider_spec(provider_name, settings)
    pending_ref, payload = _load_pending_state(
        session=session,
        engagement_id=engagement_id,
        provider=provider_name,
        state=state,
        settings=settings,
    )
    token_payload = _exchange_authorization_code(
        provider=provider_name,
        spec=spec,
        code=code,
        redirect_uri=str(payload["redirect_uri"]),
        state=state,
    )
    descriptor = _parse_repository_url(provider_name, str(payload["repository_url"]))
    account_login = _fetch_account_login(provider=provider_name, spec=spec, access_token=_required_text(token_payload, "access_token"))
    repository_meta = _fetch_repository_metadata(
        provider=provider_name,
        spec=spec,
        descriptor=descriptor,
        access_token=_required_text(token_payload, "access_token"),
    )
    token_ref = _store_repository_token_set(
        session=session,
        engagement_id=engagement_id,
        provider=provider_name,
        descriptor=descriptor,
        token_payload=token_payload,
        settings=settings,
    )
    integration = session.scalar(
        select(RepositoryIntegration).where(
            RepositoryIntegration.engagement_id == engagement_id,
            RepositoryIntegration.provider == provider_name,
            RepositoryIntegration.repository_url == descriptor["repository_url"],
        )
    )
    if integration is None:
        integration = RepositoryIntegration(
            engagement_id=engagement_id,
            provider=provider_name,
            repository_url=descriptor["repository_url"],
            repository_path=descriptor["repository_path"],
            token_secret_ref_id=token_ref.id,
            default_branch=str(payload.get("default_branch") or repository_meta.get("default_branch") or "main"),
            account_login=account_login,
            status="connected",
            metadata_json={},
        )
        session.add(integration)
    integration.token_secret_ref_id = token_ref.id
    integration.default_branch = str(payload.get("default_branch") or repository_meta.get("default_branch") or "main")
    integration.account_login = account_login
    integration.status = "connected"
    integration.metadata_json = {
        "provider_repo_id": repository_meta.get("repo_id"),
        "html_url": repository_meta.get("html_url"),
        "account_login": account_login,
        "token_exposed": False,
    }
    session.delete(pending_ref)
    session.flush()
    return RepositoryAuthorizationComplete(
        provider=provider_name,
        repository_url=integration.repository_url,
        repository_path=integration.repository_path,
        default_branch=integration.default_branch,
        account_login=integration.account_login,
    )


def list_repository_integrations(*, session: Session, engagement_id: uuid.UUID) -> list[RepositoryIntegration]:
    return list(
        session.scalars(
            select(RepositoryIntegration)
            .where(RepositoryIntegration.engagement_id == engagement_id)
            .order_by(RepositoryIntegration.created_at.desc(), RepositoryIntegration.id.desc())
        )
    )


def ensure_repository_link_for_finding(
    *,
    session: Session,
    finding: Finding,
    settings: Settings,
) -> FindingRepositoryLink | None:
    active_finding = _load_finding_for_repository_context(session=session, finding=finding)
    if active_finding.repository_links:
        return active_finding.repository_links[0]
    engagement_id = _finding_engagement_id(active_finding, session=session)
    if engagement_id is None:
        return None
    integration = session.scalar(
        select(RepositoryIntegration)
        .where(
            RepositoryIntegration.engagement_id == engagement_id,
            RepositoryIntegration.status == "connected",
        )
        .order_by(RepositoryIntegration.created_at.desc(), RepositoryIntegration.id.desc())
    )
    if integration is None:
        return None
    try:
        token = load_repository_token(session=session, integration=integration, settings=settings)
        if not token:
            return None
        path_hint, line_hint = _extract_repository_path_hint(active_finding)
        if not path_hint:
            tree_paths = _list_repository_tree(
                provider=integration.provider,
                settings=settings,
                integration=integration,
                access_token=token,
            )
            path_hint = _match_tree_path_to_finding(tree_paths=tree_paths, finding=active_finding)
        if not path_hint:
            return None
        file_payload = _fetch_repository_file(
            provider=integration.provider,
            settings=settings,
            integration=integration,
            repository_path=path_hint,
            access_token=token,
            branch=integration.default_branch,
        )
        line_number = line_hint or _best_guess_line_number(file_payload["content"], finding=active_finding)
        snippet_text, line_start, line_end, highlighted_line = _snippet_for_line(file_payload["content"], line_number)
        external_url = _repository_blob_url(
            provider=integration.provider,
            repository_url=integration.repository_url,
            repository_path=path_hint,
            branch=integration.default_branch,
            line=highlighted_line,
        )
        link = FindingRepositoryLink(
            finding_id=active_finding.id,
            repo_integration_id=integration.id,
            repository_path=path_hint,
            repository_branch=integration.default_branch,
            line_start=line_start,
            line_end=line_end,
            highlighted_line=highlighted_line,
            snippet_language=_language_for_path(path_hint),
            snippet_text=snippet_text,
            external_url=external_url,
            metadata_json={"view_url": external_url, "pull_request_supported": True},
        )
        session.add(link)
        session.flush()
        return link
    except (RepositoryIntegrationError, httpx.HTTPError, ValueError, json.JSONDecodeError):
        return None


def repository_context_for_finding(
    *,
    session: Session,
    finding: Finding,
    autofix_available: bool,
) -> dict[str, Any]:
    if finding.id is None:
        return repository_context_view(link=None, integration=None, autofix_available=autofix_available)
    link = session.scalar(
        select(FindingRepositoryLink)
        .options(selectinload(FindingRepositoryLink.repo_integration))
        .where(FindingRepositoryLink.finding_id == finding.id)
        .order_by(FindingRepositoryLink.created_at.desc(), FindingRepositoryLink.id.desc())
    )
    integration = link.repo_integration if link is not None else None
    return repository_context_view(link=link, integration=integration, autofix_available=autofix_available)


def repository_context_view(
    *,
    link: FindingRepositoryLink | None,
    integration: RepositoryIntegration | None,
    autofix_available: bool,
) -> dict[str, Any]:
    if link is None or integration is None:
        return {
            "available": False,
            "detail": "No connected repository snippet is available for this finding yet.",
            "pull_request_supported": False,
        }
    latest_pull_request = None
    latest_payload = dict(link.metadata_json or {}).get("latest_pull_request")
    if isinstance(latest_payload, dict):
        latest_pull_request = {
            "provider": integration.provider,
            "branch_name": str(latest_payload.get("branch_name") or ""),
            "pull_request_url": str(latest_payload.get("pull_request_url") or ""),
            "pull_request_id": str(latest_payload.get("pull_request_id") or ""),
            "auto_merge_enabled": bool(latest_payload.get("auto_merge_enabled")),
            "created_by": str(latest_payload.get("actor") or "") or None,
        }
    return {
        "available": True,
        "provider": integration.provider,
        "repository_url": integration.repository_url,
        "repository_path": link.repository_path,
        "repository_branch": link.repository_branch,
        "line_start": link.line_start,
        "line_end": link.line_end,
        "highlighted_line": link.highlighted_line,
        "snippet_language": link.snippet_language,
        "snippet_text": link.snippet_text,
        "external_url": link.external_url,
        "pull_request_supported": bool(autofix_available),
        "detail": "Connected repository context is linked to this finding for operator review.",
        "latest_pull_request": latest_pull_request,
    }


def create_fix_pr_for_finding(
    *,
    session: Session,
    finding: Finding,
    actor: str,
    settings: Settings,
) -> RepositoryFixPullRequest:
    active_finding = _load_finding_for_repository_context(session=session, finding=finding)
    if not isinstance(active_finding.autofix_json, dict):
        raise RepositoryIntegrationError("autofix is required before creating a fix pull request")
    if not active_finding.repository_links:
        raise RepositoryIntegrationError("repository context is required before creating a fix pull request")
    link = active_finding.repository_links[0]
    integration = link.repo_integration
    if integration is None:
        integration = session.get(RepositoryIntegration, link.repo_integration_id)
    if integration is None:
        raise RepositoryIntegrationError("repository integration not found")
    token = load_repository_token(session=session, integration=integration, settings=settings)
    if not token:
        raise RepositoryIntegrationError("repository access token is unavailable")
    branch_name = f"aegispt/autofix-{str(active_finding.id).split('-')[0]}-{datetime.now(tz=UTC).strftime('%H%M%S')}"
    try:
        pr = _provider_create_fix_pr(
            provider=integration.provider,
            settings=settings,
            integration=integration,
            access_token=token,
            repository_path=link.repository_path,
            branch_name=branch_name,
            base_branch=integration.default_branch,
            patch_after=str(active_finding.autofix_json.get("patch_after") or ""),
            finding_title=active_finding.title,
            actor=actor,
        )
    except httpx.HTTPError as exc:
        raise RepositoryIntegrationError("repository provider rejected fix pull request creation") from exc
    link.metadata_json = {
        **dict(link.metadata_json or {}),
        "latest_pull_request": {
            "pull_request_url": pr.pull_request_url,
            "pull_request_id": pr.pull_request_id,
            "branch_name": pr.branch_name,
            "actor": actor,
            "auto_merge_enabled": False,
        },
    }
    session.flush()
    return pr


def load_repository_token(
    *,
    session: Session,
    integration: RepositoryIntegration,
    settings: Settings,
) -> str | None:
    secret_ref = session.get(SecretRef, integration.token_secret_ref_id)
    if secret_ref is None or secret_ref.storage_backend not in ENCRYPTED_SECRET_BACKENDS or not secret_ref.encrypted_value:
        return None
    payload = json.loads(
        decrypt_secret_value(secret_ref.encrypted_value, settings, storage_backend=secret_ref.storage_backend)
    )
    return str(payload.get("access_token") or "").strip() or None


def repository_redirect_uri(*, settings: Settings, engagement_id: uuid.UUID, provider: str) -> str:
    base = str(settings.app_public_base_url or "http://127.0.0.1:8000").rstrip("/")
    return f"{base}/api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/callback"


def _normalized_provider(provider: str) -> Literal["github", "gitlab"]:
    normalized = str(provider or "").strip().lower()
    if normalized not in SUPPORTED_REPOSITORY_PROVIDERS:
        raise RepositoryIntegrationError(f"unsupported repository provider: {provider}")
    return normalized  # type: ignore[return-value]


def _provider_spec(provider: Literal["github", "gitlab"], settings: Settings) -> dict[str, str]:
    if provider == "github":
        client_id = str(settings.github_oauth_client_id or "").strip()
        client_secret = str(settings.github_oauth_client_secret or "").strip()
        if not client_id or not client_secret:
            raise RepositoryIntegrationError("GitHub OAuth client id and secret are required")
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "authorize_url": str(settings.github_oauth_authorize_url or "https://github.com/login/oauth/authorize").strip(),
            "token_url": str(settings.github_oauth_token_url or "https://github.com/login/oauth/access_token").strip(),
            "api_url": str(settings.github_api_url or "https://api.github.com").rstrip("/"),
            "scope": "repo",
        }
    client_id = str(settings.gitlab_oauth_client_id or "").strip()
    client_secret = str(settings.gitlab_oauth_client_secret or "").strip()
    if not client_id or not client_secret:
        raise RepositoryIntegrationError("GitLab OAuth client id and secret are required")
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "authorize_url": str(settings.gitlab_oauth_authorize_url or "https://gitlab.com/oauth/authorize").strip(),
        "token_url": str(settings.gitlab_oauth_token_url or "https://gitlab.com/oauth/token").strip(),
        "api_url": str(settings.gitlab_api_url or "https://gitlab.com/api/v4").rstrip("/"),
        "scope": "api read_repository write_repository",
    }


def _parse_repository_url(provider: Literal["github", "gitlab"], repository_url: str) -> dict[str, str]:
    normalized = str(repository_url or "").strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RepositoryIntegrationError("repository_url must be an http(s) repository URL")
    segments = [segment for segment in parsed.path.strip("/").split("/") if segment]
    if provider == "github":
        if len(segments) < 2:
            raise RepositoryIntegrationError("GitHub repository URLs must include owner/repo")
        repository_path = f"{segments[0]}/{segments[1].removesuffix('.git')}"
    else:
        if len(segments) < 2:
            raise RepositoryIntegrationError("GitLab repository URLs must include namespace/project")
        repository_path = "/".join(segment.removesuffix(".git") for segment in segments)
    return {
        "repository_url": normalized,
        "repository_path": repository_path,
    }


def _load_pending_state(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    provider: Literal["github", "gitlab"],
    state: str,
    settings: Settings,
) -> tuple[SecretRef, dict[str, Any]]:
    try:
        secret_ref_id_text, nonce = str(state or "").split(".", 1)
        secret_ref_id = uuid.UUID(secret_ref_id_text)
    except (TypeError, ValueError) as exc:
        raise RepositoryIntegrationError("invalid repository OAuth state") from exc
    secret_ref = session.get(SecretRef, secret_ref_id)
    if (
        secret_ref is None
        or secret_ref.engagement_id != engagement_id
        or secret_ref.purpose != f"{REPOSITORY_PENDING_PURPOSE_PREFIX}.{provider}"
        or secret_ref.secret_kind != "oauth_state"
    ):
        raise RepositoryIntegrationError("repository OAuth state was not found")
    metadata = dict(secret_ref.metadata_json or {})
    if metadata.get("state_nonce") != nonce:
        raise RepositoryIntegrationError("repository OAuth state did not match")
    payload = json.loads(
        decrypt_secret_value(secret_ref.encrypted_value or "", settings, storage_backend=secret_ref.storage_backend)
    )
    if str(payload.get("state") or "") != state:
        raise RepositoryIntegrationError("repository OAuth state payload was invalid")
    return secret_ref, payload


def _exchange_authorization_code(
    *,
    provider: Literal["github", "gitlab"],
    spec: dict[str, str],
    code: str,
    redirect_uri: str,
    state: str,
) -> dict[str, Any]:
    if provider == "github":
        response = httpx.post(
            spec["token_url"],
            headers={"Accept": "application/json"},
            data={
                "client_id": spec["client_id"],
                "client_secret": spec["client_secret"],
                "code": code,
                "redirect_uri": redirect_uri,
                "state": state,
            },
            timeout=10.0,
        )
    else:
        response = httpx.post(
            spec["token_url"],
            headers={"Accept": "application/json"},
            data={
                "client_id": spec["client_id"],
                "client_secret": spec["client_secret"],
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            timeout=10.0,
        )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RepositoryIntegrationError("repository token response was not a JSON object")
    return payload


def _store_repository_token_set(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    provider: Literal["github", "gitlab"],
    descriptor: dict[str, str],
    token_payload: dict[str, Any],
    settings: Settings,
) -> SecretRef:
    storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
    access_token = _required_text(token_payload, "access_token")
    secret_ref = SecretRef(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        vault_pointer="",
        purpose=f"{REPOSITORY_TOKEN_PURPOSE_PREFIX}.{provider}",
        secret_kind="oauth_token_set",
        storage_backend=storage_backend,
        display_label=f"{provider} repository token for {descriptor['repository_path']}",
        encrypted_value=encrypt_secret_value(
            json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": str(token_payload.get("refresh_token") or ""),
                    "scope": str(token_payload.get("scope") or ""),
                    "token_type": str(token_payload.get("token_type") or "Bearer"),
                }
            ),
            settings,
            storage_backend=storage_backend,
        ),
        metadata_json={
            "provider": provider,
            "repository_path": descriptor["repository_path"],
            "raw_secret_material_exposed": False,
            "token_exposed": False,
            "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
        },
    )
    secret_ref.vault_pointer = f"aegispt://secret-ref/{secret_ref.id}"
    session.add(secret_ref)
    session.flush()
    return secret_ref


def _fetch_account_login(*, provider: Literal["github", "gitlab"], spec: dict[str, str], access_token: str) -> str | None:
    if provider == "github":
        response = httpx.get(
            f"{spec['api_url']}/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        return str(payload.get("login") or "").strip() or None
    response = httpx.get(
        f"{spec['api_url']}/user",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10.0,
    )
    response.raise_for_status()
    payload = response.json()
    return str(payload.get("username") or payload.get("name") or "").strip() or None


def _fetch_repository_metadata(
    *,
    provider: Literal["github", "gitlab"],
    spec: dict[str, str],
    descriptor: dict[str, str],
    access_token: str,
) -> dict[str, Any]:
    if provider == "github":
        owner, repo = descriptor["repository_path"].split("/", 1)
        response = httpx.get(
            f"{spec['api_url']}/repos/{owner}/{repo}",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        return {
            "repo_id": payload.get("id"),
            "html_url": payload.get("html_url"),
            "default_branch": payload.get("default_branch") or "main",
        }
    encoded_project = quote(descriptor["repository_path"], safe="")
    response = httpx.get(
        f"{spec['api_url']}/projects/{encoded_project}",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10.0,
    )
    response.raise_for_status()
    payload = response.json()
    return {
        "repo_id": payload.get("id") or descriptor["repository_path"],
        "html_url": payload.get("web_url") or descriptor["repository_url"],
        "default_branch": payload.get("default_branch") or "main",
    }


def _load_finding_for_repository_context(*, session: Session, finding: Finding) -> Finding:
    if finding.id is None:
        raise RepositoryIntegrationError("finding must be persisted before repository linking")
    loaded = session.scalar(
        select(Finding)
        .options(
            selectinload(Finding.run)
            .selectinload(Run.tasks)
            .selectinload(Task.executions)
            .selectinload(ToolExecution.artifacts),
            selectinload(Finding.repository_links).selectinload(FindingRepositoryLink.repo_integration),
        )
        .where(Finding.id == finding.id)
    )
    if loaded is None:
        raise RepositoryIntegrationError("finding not found")
    return loaded


def _finding_engagement_id(finding: Finding, *, session: Session) -> uuid.UUID | None:
    if finding.run is not None and finding.run.engagement_id:
        return finding.run.engagement_id
    if finding.run_id is None:
        return None
    run = session.get(Run, finding.run_id)
    return run.engagement_id if run is not None else None


def _extract_repository_path_hint(finding: Finding) -> tuple[str | None, int | None]:
    texts = [finding.title, finding.summary, finding.evidence_ref]
    if finding.run is not None:
        for task in list(finding.run.tasks or []):
            for execution in list(task.executions or []):
                texts.append(execution.stdout_text)
                texts.append(execution.stderr_text)
    combined = "\n".join(str(text or "") for text in texts if text)
    match = PATH_HINT_PATTERN.search(combined)
    if not match:
        return None, None
    line = int(match.group("line")) if match.group("line") else None
    return match.group("path"), line


def _list_repository_tree(
    *,
    provider: str,
    settings: Settings,
    integration: RepositoryIntegration,
    access_token: str,
) -> list[str]:
    spec = _provider_spec(_normalized_provider(provider), settings)
    if provider == "github":
        owner, repo = integration.repository_path.split("/", 1)
        response = httpx.get(
            f"{spec['api_url']}/repos/{owner}/{repo}/git/trees/{integration.default_branch}",
            params={"recursive": "1"},
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        return [
            str(item.get("path") or "")
            for item in list(payload.get("tree") or [])
            if isinstance(item, dict) and item.get("path")
        ]
    encoded_project = quote(integration.repository_path, safe="")
    response = httpx.get(
        f"{spec['api_url']}/projects/{encoded_project}/repository/tree",
        params={"recursive": "true", "ref": integration.default_branch, "per_page": 100},
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10.0,
    )
    response.raise_for_status()
    payload = response.json()
    return [str(item.get("path") or "") for item in payload if isinstance(item, dict) and item.get("path")]


def _match_tree_path_to_finding(*, tree_paths: list[str], finding: Finding) -> str | None:
    target_path = urlparse(str(finding.target_id or "")).path.strip("/")
    segments = [segment for segment in target_path.split("/") if segment]
    for segment in reversed(segments):
        for candidate in tree_paths:
            if segment.lower() in candidate.lower():
                return candidate
    return tree_paths[0] if len(tree_paths) == 1 else None


def _fetch_repository_file(
    *,
    provider: str,
    settings: Settings,
    integration: RepositoryIntegration,
    repository_path: str,
    access_token: str,
    branch: str,
) -> dict[str, Any]:
    spec = _provider_spec(_normalized_provider(provider), settings)
    if provider == "github":
        owner, repo = integration.repository_path.split("/", 1)
        response = httpx.get(
            f"{spec['api_url']}/repos/{owner}/{repo}/contents/{repository_path}",
            params={"ref": branch},
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        content = base64.b64decode(str(payload.get("content") or "").encode("utf-8")).decode("utf-8")
        return {
            "content": content,
            "external_url": payload.get("html_url")
            or _repository_blob_url(
                provider=provider,
                repository_url=integration.repository_url,
                repository_path=repository_path,
                branch=branch,
            ),
            "sha": payload.get("sha"),
        }
    encoded_project = quote(integration.repository_path, safe="")
    encoded_path = quote(repository_path, safe="")
    response = httpx.get(
        f"{spec['api_url']}/projects/{encoded_project}/repository/files/{encoded_path}",
        params={"ref": branch},
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10.0,
    )
    response.raise_for_status()
    payload = response.json()
    content = base64.b64decode(str(payload.get("content") or "").encode("utf-8")).decode("utf-8")
    return {
        "content": content,
        "external_url": _repository_blob_url(
            provider=provider,
            repository_url=integration.repository_url,
            repository_path=repository_path,
            branch=branch,
        ),
        "sha": payload.get("blob_id"),
    }


def _best_guess_line_number(content: str, *, finding: Finding) -> int:
    lines = content.splitlines()
    keywords = [
        token.lower()
        for token in re.findall(r"[a-zA-Z_]{4,}", " ".join(str(item or "") for item in (finding.title, finding.summary)))
        if token.lower() not in {"with", "from", "that", "this", "login"}
    ]
    for index, line in enumerate(lines, start=1):
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords[:3]):
            return index
    return 1


def _snippet_for_line(content: str, line_number: int) -> tuple[str, int, int, int]:
    lines = content.splitlines() or [content]
    highlight = max(1, min(line_number, len(lines)))
    start = max(1, highlight - 3)
    end = min(len(lines), highlight + 3)
    snippet = "\n".join(
        f"{index}: {lines[index - 1]}"
        for index in range(start, end + 1)
    )
    return snippet, start, end, highlight


def _language_for_path(path: str) -> str:
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else "text"
    return {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "tsx": "tsx",
        "jsx": "jsx",
        "java": "java",
        "php": "php",
        "rb": "ruby",
        "cs": "csharp",
        "go": "go",
        "sql": "sql",
        "json": "json",
        "yml": "yaml",
        "yaml": "yaml",
    }.get(suffix, "text")


def _provider_create_fix_pr(
    *,
    provider: str,
    settings: Settings,
    integration: RepositoryIntegration,
    access_token: str,
    repository_path: str,
    branch_name: str,
    base_branch: str,
    patch_after: str,
    finding_title: str,
    actor: str,
) -> RepositoryFixPullRequest:
    spec = _provider_spec(_normalized_provider(provider), settings)
    if provider == "github":
        owner, repo = integration.repository_path.split("/", 1)
        ref_response = httpx.get(
            f"{spec['api_url']}/repos/{owner}/{repo}/git/ref/heads/{base_branch}",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        ref_response.raise_for_status()
        ref_payload = ref_response.json()
        base_sha = str(((ref_payload.get("object") or {}).get("sha")) or "")
        httpx.post(
            f"{spec['api_url']}/repos/{owner}/{repo}/git/refs",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            timeout=10.0,
        ).raise_for_status()
        existing_file = _fetch_repository_file(
            provider=provider,
            settings=settings,
            integration=integration,
            repository_path=repository_path,
            access_token=access_token,
            branch=base_branch,
        )
        httpx.put(
            f"{spec['api_url']}/repos/{owner}/{repo}/contents/{repository_path}",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            json={
                "message": f"AegisPT AutoFix: {finding_title}",
                "content": base64.b64encode(patch_after.encode("utf-8")).decode("utf-8"),
                "branch": branch_name,
                "sha": existing_file.get("sha"),
            },
            timeout=10.0,
        ).raise_for_status()
        pr_response = httpx.post(
            f"{spec['api_url']}/repos/{owner}/{repo}/pulls",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            json={
                "title": f"AegisPT AutoFix: {finding_title}",
                "head": branch_name,
                "base": base_branch,
                "body": f"Prepared by {actor}. Review the advisory patch before merge.",
            },
            timeout=10.0,
        )
        pr_response.raise_for_status()
        payload = pr_response.json()
        return RepositoryFixPullRequest(
            provider="github",
            repository_url=integration.repository_url,
            branch_name=branch_name,
            pull_request_url=str(payload.get("html_url") or ""),
            pull_request_id=str(payload.get("number") or payload.get("id") or ""),
        )
    encoded_project = quote(integration.repository_path, safe="")
    httpx.post(
        f"{spec['api_url']}/projects/{encoded_project}/repository/branches",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        data={"branch": branch_name, "ref": base_branch},
        timeout=10.0,
    ).raise_for_status()
    encoded_path = quote(repository_path, safe="")
    httpx.put(
        f"{spec['api_url']}/projects/{encoded_project}/repository/files/{encoded_path}",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        data={
            "branch": branch_name,
            "content": patch_after,
            "commit_message": f"AegisPT AutoFix: {finding_title}",
        },
        timeout=10.0,
    ).raise_for_status()
    pr_response = httpx.post(
        f"{spec['api_url']}/projects/{encoded_project}/merge_requests",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        data={
            "source_branch": branch_name,
            "target_branch": base_branch,
            "title": f"AegisPT AutoFix: {finding_title}",
            "description": f"Prepared by {actor}. Review the advisory patch before merge.",
        },
        timeout=10.0,
    )
    pr_response.raise_for_status()
    payload = pr_response.json()
    return RepositoryFixPullRequest(
        provider="gitlab",
        repository_url=integration.repository_url,
        branch_name=branch_name,
        pull_request_url=str(payload.get("web_url") or ""),
        pull_request_id=str(payload.get("iid") or payload.get("id") or ""),
    )


def _repository_blob_url(
    *,
    provider: str,
    repository_url: str,
    repository_path: str,
    branch: str,
    line: int | None = None,
) -> str:
    normalized_provider = _normalized_provider(provider)
    base_url = repository_url.rstrip("/")
    if normalized_provider == "github":
        url = f"{base_url}/blob/{branch}/{repository_path}"
    else:
        url = f"{base_url}/-/blob/{branch}/{repository_path}"
    if line is not None and line > 0:
        return f"{url}#L{line}"
    return url


def _required_text(payload: dict[str, Any], field_name: str) -> str:
    value = str(payload.get(field_name) or "").strip()
    if not value:
        raise RepositoryIntegrationError(f"missing repository OAuth field: {field_name}")
    return value
