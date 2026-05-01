from __future__ import annotations

import hashlib
import hmac
import json
from uuid import UUID

from sqlalchemy import select

from api.app.models import CicdTrigger, CicdTriggerEvent, Run, SecretRef, Task


def _create_engagement_with_scope(client) -> str:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "cicd-admin"},
        json={
            "name": "CI Trigger Engagement",
            "client": "Acme Corp",
            "roe_ref": "ROE-CICD-1",
        },
    )
    assert engagement.status_code == 201
    engagement_id = engagement.json()["id"]

    scope = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "cicd-admin"},
        json={
            "allowlist_json": {
                "urls": ["https://portal.example.test"],
                "domains": ["portal.example.test"],
            },
            "denylist_json": {},
        },
    )
    assert scope.status_code == 201
    return engagement_id


def _configure_trigger(
    client,
    *,
    engagement_id: str,
    source: str = "github",
    enabled_profiles: list[str] | None = None,
    branch_filters: list[str] | None = None,
    scope_override_allowed: bool = False,
    secret: str = "ci-shared-secret",
) -> dict:
    response = client.put(
        f"/api/v1/engagements/{engagement_id}/triggers/cicd/{source}",
        headers={"X-Actor": "cicd-admin"},
        json={
            "enabled": True,
            "enabled_profiles": enabled_profiles or ["passive-web-baseline"],
            "branch_filters": branch_filters or ["main"],
            "scope_override_allowed": scope_override_allowed,
            "webhook_secret": secret,
        },
    )
    assert response.status_code == 200
    return response.json()


def _signed_post(client, *, payload: dict, secret: str, source: str = "github", signature: str | None = None):
    raw_body = json.dumps(payload).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        {
            "github": "X-Hub-Signature-256",
            "gitlab": "X-Gitlab-Signature-256",
            "generic": "X-AegisPT-Signature-256",
        }[source]: signature or f"sha256={digest}",
    }
    return client.post("/api/v1/triggers/cicd", content=raw_body, headers=headers)


def test_cicd_trigger_configuration_encrypts_secret_and_surfaces_settings_history(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    response = _configure_trigger(
        client,
        engagement_id=engagement_id,
        enabled_profiles=["passive-web-baseline", "active-web-safe"],
        branch_filters=["main", "release/*"],
        scope_override_allowed=True,
        secret="github-trigger-secret",
    )

    assert response["trigger_source"] == "github"
    assert response["configured"] is True
    assert response["enabled_profiles"] == ["passive-web-baseline", "active-web-safe"]
    assert response["branch_filters"] == ["main", "release/*"]
    assert response["scope_override_allowed"] is True
    assert response["webhook_secret_configured"] is True
    assert "github-trigger-secret" not in json.dumps(response)

    settings_response = client.get(f"/api/v1/engagements/{engagement_id}/triggers/cicd")
    assert settings_response.status_code == 200
    settings_payload = settings_response.json()
    github_trigger = next(item for item in settings_payload["triggers"] if item["trigger_source"] == "github")
    assert github_trigger["configured"] is True
    assert github_trigger["webhook_secret_configured"] is True
    assert settings_payload["history"] == []

    with client.app.state.session_factory() as session:
        trigger = session.scalar(
            select(CicdTrigger).where(
                CicdTrigger.engagement_id == UUID(engagement_id),
                CicdTrigger.trigger_source == "github",
            )
        )
        secret_ref = session.scalar(
            select(SecretRef).where(
                SecretRef.engagement_id == UUID(engagement_id),
                SecretRef.purpose == "cicd_trigger.webhook_secret.github",
            )
        )

    assert trigger is not None
    assert trigger.enabled_profiles_json == ["passive-web-baseline", "active-web-safe"]
    assert trigger.branch_filters_json == ["main", "release/*"]
    assert secret_ref is not None
    assert secret_ref.secret_kind == "webhook_secret"
    assert secret_ref.encrypted_value
    assert "github-trigger-secret" not in (secret_ref.encrypted_value or "")


def test_cicd_trigger_rejects_invalid_signature_and_records_history(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    _configure_trigger(client, engagement_id=engagement_id, secret="github-trigger-secret")

    payload = {
        "engagement_id": engagement_id,
        "trigger_source": "github",
        "ref": "refs/heads/main",
        "commit_sha": "abc123def456",
    }
    response = _signed_post(
        client,
        payload=payload,
        secret="github-trigger-secret",
        source="github",
        signature="sha256=bad-signature",
    )

    assert response.status_code == 401
    assert "signature" in response.json()["detail"]

    history = client.get(f"/api/v1/engagements/{engagement_id}/triggers/cicd").json()["history"]
    assert history[0]["status"] == "invalid_signature"
    assert history[0]["signature_valid"] is False

    with client.app.state.session_factory() as session:
        runs = session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all()
    assert runs == []


def test_cicd_trigger_ignores_non_matching_branch_without_creating_run(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    _configure_trigger(
        client,
        engagement_id=engagement_id,
        secret="github-trigger-secret",
        branch_filters=["release/*"],
    )

    payload = {
        "engagement_id": engagement_id,
        "trigger_source": "github",
        "ref": "refs/heads/main",
        "commit_sha": "feedfacecafe",
    }
    response = _signed_post(client, payload=payload, secret="github-trigger-secret", source="github")

    assert response.status_code == 202
    receipt = response.json()
    assert receipt["accepted"] is True
    assert receipt["event_count"] == 1
    assert receipt["events"][0]["status"] == "ignored_branch"
    assert receipt["events"][0]["run_id"] is None

    with client.app.state.session_factory() as session:
        runs = session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all()
    assert runs == []


def test_cicd_trigger_dispatches_safe_profile_and_preserves_approval_gates(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    _configure_trigger(
        client,
        engagement_id=engagement_id,
        enabled_profiles=["passive-web-baseline", "active-web-safe"],
        branch_filters=["main"],
        scope_override_allowed=True,
        secret="github-trigger-secret",
    )

    payload = {
        "engagement_id": engagement_id,
        "trigger_source": "github",
        "ref": "refs/heads/main",
        "commit_sha": "0123456789abcdef",
        "target_url_override": "https://portal.example.test/login",
    }
    response = _signed_post(client, payload=payload, secret="github-trigger-secret", source="github")

    assert response.status_code == 202
    receipt = response.json()
    statuses = {(item["profile_name"], item["status"]) for item in receipt["events"]}
    assert statuses == {
        ("passive-web-baseline", "dispatched"),
        ("active-web-safe", "pending_approval"),
    }

    with client.app.state.session_factory() as session:
        runs = session.scalars(
            select(Run).where(Run.engagement_id == UUID(engagement_id)).order_by(Run.created_at.asc(), Run.id.asc())
        ).all()
        tasks = session.scalars(
            select(Task).join(Run, Task.run_id == Run.id).where(Run.engagement_id == UUID(engagement_id))
        ).all()
        events = session.scalars(
            select(CicdTriggerEvent)
            .join(CicdTrigger, CicdTriggerEvent.cicd_trigger_id == CicdTrigger.id)
            .where(CicdTrigger.engagement_id == UUID(engagement_id))
        ).all()

    assert len(runs) == 2
    passive_run = next(run for run in runs if run.status == "queued")
    assert any(task.tool == "httpx" for task in tasks)
    assert any(run.status == "pending_approval" for run in runs)
    assert any(run.status == "queued" for run in runs)
    assert len(events) == 2
    assert passive_run.configuration_json["targets"] == {"urls": ["https://portal.example.test/login"]}

    settings_payload = client.get(f"/api/v1/engagements/{engagement_id}/triggers/cicd").json()
    assert len(settings_payload["history"]) == 2
    assert {item["status"] for item in settings_payload["history"]} == {"dispatched", "pending_approval"}
