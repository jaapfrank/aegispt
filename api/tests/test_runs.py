from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import select


def create_engagement_with_scope(client) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Acme Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-002",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "domains": ["example.com"],
                "urls": ["https://example.com"],
            },
            "denylist_json": {"domains": ["admin.example.com"]},
        },
    )

    return engagement_id


@contextmanager
def build_client_with_env(tmp_path, monkeypatch, **env_overrides: str) -> Iterator[TestClient]:
    database_path = tmp_path / "aegispt-policy.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "inline")
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()


def test_list_run_profiles(client) -> None:
    response = client.get("/api/v1/run-profiles")

    assert response.status_code == 200
    payload = response.json()
    profile_names = [profile["name"] for profile in payload]
    assert profile_names == [
        "active-web-safe",
        "active-web-zap-active",
        "intrusive-validation",
        "passive-code-semgrep-audit",
        "passive-network-discovery",
        "passive-network-service-enumeration",
        "passive-web-baseline",
        "passive-web-nuclei-audit",
    ]


def test_passive_run_is_queued_with_tasks(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["required_approvals"] == 0
    assert payload["pending_approvals"] == 0
    assert len(payload["tasks"]) == 2
    assert {task["tool"] for task in payload["tasks"]} == {"httpx"}
    assert payload["updated_at"]
    assert all(task["updated_at"] for task in payload["tasks"])
    assert payload["findings"]["finding_count"] == 0
    assert payload["findings"]["findings_by_severity"] == {}
    assert payload["findings"]["findings_by_status"] == {}
    assert payload["configuration_json"] == {}


def test_run_configuration_and_inventory_binding_round_trip(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    inventory_response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["wizard-input"],
            "observations": [
                {
                    "tool": "wizard-input",
                    "kind": "inventory-seed",
                    "data": {
                        "hosts": ["example.com"],
                        "urls": ["https://example.com"],
                        "confidence": 0.8,
                    },
                }
            ],
            "environment_notes": ["Wizard-seeded inventory"],
            "assumptions": ["Assessment starts from reviewed wizard input"],
        },
    )
    inventory_id = inventory_response.json()["id"]

    configuration_json = {
        "assessment_type": "Mixed Assessment",
        "test_profile": "Adaptive Customer-Specific Mode",
        "execution_profile": "active-web-safe",
        "targets": {"domains": ["example.com"], "urls": ["https://example.com"]},
        "modules": {"discovery": True, "adaptive_ai_generated_tests": True},
        "safety": {"rate_limit_rps": 2, "concurrency": 2, "time_budget_minutes": 120},
        "eta": {"estimated_total_minutes": 120, "estimated_impact": "medium", "confidence": "medium"},
    }

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": configuration_json,
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["source_inventory_snapshot_id"] == inventory_id
    assert payload["configuration_json"]["assessment_type"] == "Mixed Assessment"
    assert payload["configuration_json"]["test_profile"] == "Adaptive Customer-Specific Mode"


def test_run_configuration_preserves_confirmation_summary(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    confirmation_summary = (
        "I am going to run an authenticated app assessment against https://example.com/login. "
        "I will prioritize authenticated review with the Authenticated Only profile and the active-web-safe execution lane. "
        "Estimated duration: 90 minutes with medium ETA confidence."
    )

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "intake": {
                    "mode": "conversational-ai-guided",
                    "confirmation_summary": confirmation_summary,
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    assert payload["configuration_json"]["intake"]["confirmation_summary"] == confirmation_summary

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    assert get_response.json()["configuration_json"]["intake"]["confirmation_summary"] == confirmation_summary


def test_run_configuration_preserves_engagement_route_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "API",
                "test_profile": "Adaptive Customer-Specific Mode",
                "targets": {"api_base_urls": ["https://api.example.com/v1"]},
                "intake": {
                    "mode": "conversational-ai-guided",
                    "engagement_route": "reuse-selected-engagement",
                    "engagement_context": {
                        "source": "selected-engagement",
                        "engagement_id": engagement_id,
                        "engagement_name": "Acme Validation",
                        "client": "Acme Corp",
                    },
                    "confirmation_summary": (
                        "I am going to run an api assessment against https://api.example.com/v1. "
                        'I will attach this run to the existing engagement dossier "Acme Validation" instead of creating a new customer dossier. '
                        "Estimated duration: 62 minutes with low ETA confidence."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    intake = payload["configuration_json"]["intake"]
    assert intake["engagement_route"] == "reuse-selected-engagement"
    assert intake["engagement_context"]["engagement_id"] == engagement_id
    assert intake["engagement_context"]["engagement_name"] == "Acme Validation"
    assert intake["engagement_context"]["roe_ref"] == "ROE-2026-002"

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_intake = get_response.json()["configuration_json"]["intake"]
    assert get_intake["engagement_route"] == "reuse-selected-engagement"
    assert get_intake["engagement_context"]["engagement_id"] == engagement_id
    assert get_intake["engagement_context"]["engagement_name"] == "Acme Validation"
    assert get_intake["engagement_context"]["roe_ref"] == "ROE-2026-002"


def test_run_configuration_preserves_new_engagement_route_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://portal.example.com"]},
                "intake": {
                    "mode": "conversational-ai-guided",
                    "engagement_route": "create-new-engagement",
                    "engagement_context": {
                        "source": "wizard-created-engagement",
                        "engagement_id": engagement_id,
                        "engagement_name": "Portal Assessment 2026",
                        "client": "Acme Corp",
                        "roe_ref": "ROE-2026-021",
                    },
                    "confirmation_summary": (
                        "I am going to run an authenticated app assessment against https://portal.example.com. "
                        'I will create a new engagement dossier named "Portal Assessment 2026" before this run begins. '
                        "Estimated duration: 75 minutes with medium ETA confidence."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    intake = payload["configuration_json"]["intake"]
    assert intake["engagement_route"] == "create-new-engagement"
    assert intake["engagement_context"]["engagement_id"] == engagement_id
    assert intake["engagement_context"]["engagement_name"] == "Portal Assessment 2026"
    assert intake["engagement_context"]["client"] == "Acme Corp"
    assert intake["engagement_context"]["roe_ref"] == "ROE-2026-021"

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_intake = get_response.json()["configuration_json"]["intake"]
    assert get_intake["engagement_route"] == "create-new-engagement"
    assert get_intake["engagement_context"]["engagement_id"] == engagement_id
    assert get_intake["engagement_context"]["engagement_name"] == "Portal Assessment 2026"
    assert get_intake["engagement_context"]["client"] == "Acme Corp"
    assert get_intake["engagement_context"]["roe_ref"] == "ROE-2026-021"


def test_run_configuration_preserves_scope_guardrail_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "targets": {"urls": ["https://portal.example.com"]},
                "exclusions": {
                    "urls": ["https://portal.example.com/admin"],
                    "notes": "Avoid billing and admin flows.",
                },
                "intake": {
                    "mode": "conversational-ai-guided",
                    "preferences": {
                        "primary_goal": "standard-assessment",
                        "output_style": "balanced-technical",
                        "boundary_handling": "custom-exclusions",
                    },
                    "confirmation_summary": (
                        "I am going to run a website / web app assessment against https://portal.example.com. "
                        "Scope guardrails: Custom Exclusions Recorded. 1 explicit exclusion remains outside this mission unless you revise the approved scope."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    assert payload["configuration_json"]["exclusions"]["urls"] == ["https://portal.example.com/admin"]
    assert payload["configuration_json"]["exclusions"]["notes"] == "Avoid billing and admin flows."
    assert payload["configuration_json"]["intake"]["preferences"]["boundary_handling"] == "custom-exclusions"
    assert payload["configuration_json"]["intake"]["preferences"]["output_style"] == "balanced-technical"

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_payload = get_response.json()
    assert get_payload["configuration_json"]["exclusions"]["urls"] == ["https://portal.example.com/admin"]
    assert get_payload["configuration_json"]["exclusions"]["notes"] == "Avoid billing and admin flows."
    assert get_payload["configuration_json"]["intake"]["preferences"]["boundary_handling"] == "custom-exclusions"
    assert get_payload["configuration_json"]["intake"]["preferences"]["output_style"] == "balanced-technical"


def test_run_configuration_preserves_notes_only_scope_guardrail_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "targets": {"urls": ["https://portal.example.com"]},
                "exclusions": {
                    "notes": "Avoid login and billing flows.",
                },
                "intake": {
                    "mode": "conversational-ai-guided",
                    "preferences": {
                        "primary_goal": "standard-assessment",
                        "output_style": "balanced-technical",
                        "boundary_handling": "notes-only-boundaries",
                    },
                    "confirmation_summary": (
                        "I am going to run a website / web app assessment against https://portal.example.com. "
                        "Scope guardrails: Boundary Notes Recorded. The recorded boundary note stays in force unless you revise the approved scope."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    assert payload["configuration_json"]["exclusions"]["notes"] == "Avoid login and billing flows."
    assert payload["configuration_json"]["intake"]["preferences"]["boundary_handling"] == "notes-only-boundaries"
    assert payload["configuration_json"]["intake"]["preferences"]["output_style"] == "balanced-technical"

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_payload = get_response.json()
    assert get_payload["configuration_json"]["exclusions"]["notes"] == "Avoid login and billing flows."
    assert get_payload["configuration_json"]["intake"]["preferences"]["boundary_handling"] == "notes-only-boundaries"
    assert get_payload["configuration_json"]["intake"]["preferences"]["output_style"] == "balanced-technical"


def test_run_configuration_targets_drive_task_selection_within_cidr_scope(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Internal Follow Up",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-020",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"cidrs": ["10.0.20.0/24"]},
            "denylist_json": {},
        },
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-service-enumeration",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Follow-up Service Enumeration",
                "targets": {"ip_addresses": ["10.0.20.8", "10.0.20.14"]},
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert [task["target_id"] for task in payload["tasks"]] == ["10.0.20.14", "10.0.20.8"]
    assert all(task["tool"] == "nmap" for task in payload["tasks"])


def test_engagement_runs_are_listed_newest_first(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    first = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    assert first.status_code == 201

    second = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-network-discovery"},
    )
    assert second.status_code == 201

    listed = client.get(f"/api/v1/engagements/{engagement_id}/runs")
    assert listed.status_code == 200
    payload = listed.json()
    assert [run["id"] for run in payload[:2]] == [
        second.json()["id"],
        first.json()["id"],
    ]


def test_run_configuration_materializes_secret_references(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [
                        {
                            "label": "Admin",
                            "username": "admin@example.com",
                            "role": "Administrator",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                            "api_key_ref": "vault://prod/customer/api-key",
                            "bearer_token_ref": "Bearer abc.def.ghi",
                            "session_ref": "session-cookie=name=value; Path=/; HttpOnly",
                        }
                    ]
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    account = payload["configuration_json"]["access"]["accounts"][0]
    assert "secret_ref" not in account
    assert "api_key_ref" not in account
    assert "bearer_token_ref" not in account
    assert "session_ref" not in account
    assert set(account["secret_bindings"]) == {"password", "api_key", "bearer_token", "session"}
    assert payload["configuration_json"]["access"]["secret_storage"]["binding_count"] == 4

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert len(rows) == 4
    assert {str(row.engagement_id) for row in rows} == {engagement_id}
    assert {row.storage_backend for row in rows} == {"encrypted_local", "external_pointer"}
    assert any(row.secret_kind == "password" and row.encrypted_value for row in rows)
    assert any(row.secret_kind == "api_key" and row.vault_pointer == "vault://prod/customer/api-key" for row in rows)


def test_run_configuration_keeps_manual_multi_role_access_without_secret_bindings(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [
                        {
                            "label": "Analyst SSO",
                            "username": "analyst@example.com",
                            "role": "Security Analyst",
                            "mfa_notes": "Approve analyst push notification.",
                        },
                        {
                            "label": "Admin SSO",
                            "username": "admin@example.com",
                            "role": "Application Admin",
                            "mfa_notes": "Complete IdP handoff before admin replay.",
                        },
                    ],
                    "manual_auth_steps": "Shared SSO handoff is required before replay.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    accounts = payload["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert accounts[0]["label"] == "Analyst SSO"
    assert accounts[0]["username"] == "analyst@example.com"
    assert accounts[0]["mfa_notes"] == "Approve analyst push notification."
    assert "secret_bindings" not in accounts[0]
    assert accounts[1]["label"] == "Admin SSO"
    assert accounts[1]["username"] == "admin@example.com"
    assert accounts[1]["mfa_notes"] == "Complete IdP handoff before admin replay."
    assert "secret_bindings" not in accounts[1]
    assert payload["configuration_json"]["access"]["manual_auth_steps"] == (
        "Shared SSO handoff is required before replay."
    )
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_run_configuration_keeps_manual_note_only_roles_without_secret_bindings(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [
                        {
                            "label": "Analyst MFA",
                            "role": "Security Analyst",
                            "mfa_notes": "Approve analyst push notification.",
                        },
                        {
                            "label": "Admin SSO",
                            "role": "Application Admin",
                            "mfa_notes": "Complete IdP handoff before admin replay.",
                        },
                    ],
                    "manual_auth_steps": "Shared SSO handoff is required before replay.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    accounts = payload["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert accounts[0]["label"] == "Analyst MFA"
    assert accounts[0]["role"] == "Security Analyst"
    assert accounts[0]["mfa_notes"] == "Approve analyst push notification."
    assert "secret_bindings" not in accounts[0]
    assert accounts[1]["label"] == "Admin SSO"
    assert accounts[1]["role"] == "Application Admin"
    assert accounts[1]["mfa_notes"] == "Complete IdP handoff before admin replay."
    assert "secret_bindings" not in accounts[1]
    assert payload["configuration_json"]["access"]["manual_auth_steps"] == (
        "Shared SSO handoff is required before replay."
    )
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_run_configuration_keeps_shared_manual_auth_notes_without_accounts(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [],
                    "manual_auth_steps": "Operator must complete shared SSO handoff before replay.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["configuration_json"]["access"]["accounts"] == []
    assert payload["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete shared SSO handoff before replay."
    )
    assert "cookie_notes" not in payload["configuration_json"]["access"]
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_run_configuration_keeps_shared_session_notes_without_accounts(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [],
                    "cookie_notes": "Replay imported cookie bundle after operator login.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["configuration_json"]["access"]["accounts"] == []
    assert "manual_auth_steps" not in payload["configuration_json"]["access"]
    assert payload["configuration_json"]["access"]["cookie_notes"] == (
        "Replay imported cookie bundle after operator login."
    )
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_active_run_requires_approval_before_queueing(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-web-safe"},
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["required_approvals"] == 1
    assert created_payload["granted_approvals"] == 0
    assert created_payload["tasks"] == []
    assert created_payload["findings"]["finding_count"] == 0

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["granted_approvals"] == 1
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    assert {task["tool"] for task in approval_payload["tasks"]} == {"zap"}
    assert approval_payload["tasks"][0]["params_json"]["targets"] == ["https://example.com"]
    assert approval_payload["findings"]["finding_count"] == 0


def test_rejected_run_stays_blocked(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-web-safe"},
    )
    run_id = create_response.json()["id"]

    rejection_response = client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "rejected"},
    )

    assert rejection_response.status_code == 200
    rejection_payload = rejection_response.json()
    assert rejection_payload["status"] == "rejected"
    assert rejection_payload["pending_approvals"] == 0
    assert rejection_payload["tasks"] == []


def test_dispatch_is_blocked_when_kill_switch_enabled(tmp_path, monkeypatch) -> None:
    with build_client_with_env(tmp_path, monkeypatch, EXECUTION_KILL_SWITCH="true") as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={"profile_name": "passive-web-baseline"},
        )
        run_id = run_response.json()["id"]

        dispatch_response = client.post(
            f"/api/v1/runs/{run_id}/dispatch",
            headers={"X-Actor": "dispatcher"},
        )

        assert dispatch_response.status_code == 409
        assert dispatch_response.json()["detail"] == "execution kill switch is enabled"


def test_cancel_run_marks_queued_tasks_cancelled(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_id = create_response.json()["id"]

    cancel_response = client.post(
        f"/api/v1/runs/{run_id}/cancel",
        headers={"X-Actor": "operator"},
    )

    assert cancel_response.status_code == 200
    cancel_payload = cancel_response.json()
    assert cancel_payload["status"] == "cancelled"
    assert {task["status"] for task in cancel_payload["tasks"]} == {"cancelled"}
    assert cancel_payload["pending_approvals"] == 0

    dispatch_response = client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 409
