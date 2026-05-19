from __future__ import annotations

from uuid import uuid4

from api.app.config import Settings
from api.app.models import (
    Engagement,
    InventorySnapshot,
    Run,
    RunProfile,
    Scope,
    TargetContextDocument,
)
from api.app.services.ai_action_selector import select_next_best_action_for_run
from api.app.services.roe_policy import compile_roe_policy_decision


def _tenant_headers(tenant_id: str = "default", actor: str = "roe-operator") -> dict[str, str]:
    return {"X-Tenant-ID": tenant_id, "X-Actor": actor}


def _create_policy_run(
    session,
    *,
    profile_name: str | None = None,
    run_class: str = "passive",
    allowlist: dict | None = None,
    denylist: dict | None = None,
    configuration: dict | None = None,
    tenant_id: str | None = None,
) -> tuple[Run, Scope]:
    suffix = uuid4().hex[:8]
    profile = RunProfile(
        name=profile_name or f"roe-policy-{run_class}-{suffix}",
        run_class=run_class,
        limits_json={},
    )
    engagement = Engagement(
        name=f"ROE Policy {suffix}",
        client="Acme Corp",
        tenant_id=tenant_id,
        roe_ref=f"ROE-{suffix}",
        status="active",
    )
    scope = Scope(
        engagement=engagement,
        allowlist_json=allowlist or {"urls": ["https://policy.example.test"]},
        denylist_json=denylist or {},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="roe-operator",
        status="requested",
        configuration_json=configuration or {"targets": {"urls": ["https://policy.example.test"]}},
    )
    session.add_all([engagement, profile, scope, run])
    session.commit()
    session.refresh(run)
    session.refresh(scope)
    return run, scope


def test_roe_policy_allows_in_scope_passive_action_with_reusable_payload(client) -> None:
    with client.app.state.session_factory() as session:
        run, scope = _create_policy_run(session)
        decision = compile_roe_policy_decision(
            run=run,
            scope=scope,
            target="https://policy.example.test",
            runner="httpx",
            requested_risk_tier="passive",
            settings=Settings(execution_kill_switch=False),
        )

    assert decision["decision"] == "allow"
    assert decision["target_normalization"]["allowed_by_allowlist"] is True
    assert decision["target_normalization"]["blocked_by_denylist"] is False
    assert decision["affected_action"]["runner"] == "httpx"
    assert decision["rate_limits"]["run_class"] == "passive"
    assert decision["credential_policy"]["plaintext_credentials_allowed"] is False
    assert decision["execution_contract"]["analysis_only"] is True
    assert decision["provenance"]["dispatches_work"] is False
    assert any(source.startswith("scope:") for source in decision["source_policy_ids"])
    assert "target is in scope" in decision["explanation"]


def test_roe_policy_denies_denylisted_and_out_of_scope_targets(client) -> None:
    with client.app.state.session_factory() as session:
        run, scope = _create_policy_run(
            session,
            allowlist={"domains": ["example.test"]},
            denylist={"domains": ["admin.example.test"]},
            configuration={"targets": {"domains": ["example.test"]}},
        )
        denylisted = compile_roe_policy_decision(
            run=run,
            scope=scope,
            target="https://admin.example.test",
            runner="httpx",
        )
        out_of_scope = compile_roe_policy_decision(
            run=run,
            scope=scope,
            target="https://other.test",
            runner="httpx",
        )

    assert denylisted["decision"] == "deny"
    assert denylisted["blocker_reason_ids"] == ["target_denylisted"]
    assert "denylist" in denylisted["explanation"]
    assert out_of_scope["decision"] == "deny"
    assert out_of_scope["blocker_reason_ids"] == ["target_out_of_scope"]
    assert "outside the current scope allowlist" in out_of_scope["explanation"]


def test_roe_policy_requires_approval_for_higher_tier_without_roe_confirmation(client) -> None:
    with client.app.state.session_factory() as session:
        run, scope = _create_policy_run(session, run_class="passive")
        decision = compile_roe_policy_decision(
            run=run,
            scope=scope,
            target="https://policy.example.test",
            requested_risk_tier="active",
        )

    assert decision["decision"] == "approval_required"
    assert "risk_tier_upgrade:passive->active" in decision["approval_reason_ids"]
    assert decision["target_normalization"]["allowed_by_allowlist"] is True


def test_roe_policy_allows_higher_tier_when_roe_confirms_that_tier(client) -> None:
    with client.app.state.session_factory() as session:
        run, scope = _create_policy_run(
            session,
            run_class="passive",
            configuration={
                "targets": {"urls": ["https://policy.example.test"]},
                "assessment_mode": {
                    "authorization_level": "full",
                    "typed_scope_confirmation": "https://policy.example.test",
                    "controlled_proof_requires_later_approval": False,
                },
            },
        )
        decision = compile_roe_policy_decision(
            run=run,
            scope=scope,
            target="https://policy.example.test",
            requested_risk_tier="active",
        )

    assert decision["decision"] == "allow"
    assert decision["authorization"]["full_authorization_confirmed"] is True
    assert decision["approval_reason_ids"] == []


def test_roe_policy_kill_switch_blocks_planning_and_dispatch_explanations(client) -> None:
    with client.app.state.session_factory() as session:
        run, scope = _create_policy_run(session)
        decision = compile_roe_policy_decision(
            run=run,
            scope=scope,
            target="https://policy.example.test",
            runner="httpx",
            settings=Settings(execution_kill_switch=True),
        )

    assert decision["decision"] == "kill_switch_blocked"
    assert decision["blocker_reason_ids"] == ["kill_switch:execution"]
    assert "kill switch is enabled" in decision["explanation"]
    assert decision["execution_contract"]["dispatches_work"] is False


def test_roe_policy_endpoint_is_tenant_scoped_and_shared_payload(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers=_tenant_headers("tenant-a"),
        json={"name": "Tenant ROE", "client": "Acme Corp", "roe_ref": "ROE-TENANT"},
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers=_tenant_headers("tenant-a"),
        json={
            "allowlist_json": {"urls": ["https://tenant-policy.example.test"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_tenant_headers("tenant-a"),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {"targets": {"urls": ["https://tenant-policy.example.test"]}},
        },
    )
    assert run_response.status_code == 201
    run_id = run_response.json()["id"]

    allowed = client.get(
        f"/api/v1/runs/{run_id}/roe-policy",
        headers=_tenant_headers("tenant-a"),
        params={
            "target": "https://tenant-policy.example.test",
            "runner": "httpx",
            "risk_tier": "passive",
        },
    )
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload["decision"] == "allow"
    assert payload["target_normalization"]["allowed_by_allowlist"] is True
    assert payload["execution_contract"]["analysis_only"] is True

    cross_tenant = client.get(
        f"/api/v1/runs/{run_id}/roe-policy",
        headers=_tenant_headers("tenant-b"),
        params={"target": "https://tenant-policy.example.test", "runner": "httpx"},
    )
    assert cross_tenant.status_code == 404


def test_ai_selector_attaches_roe_policy_payload_without_dispatching(client) -> None:
    with client.app.state.session_factory() as session:
        run, scope = _create_policy_run(
            session,
            configuration={
                "run_mode": "ai_loop",
                "targets": {"urls": ["https://policy.example.test"]},
            },
        )
        snapshot = InventorySnapshot(
            engagement=run.engagement,
            requested_by="roe-selector",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://policy.example.test"],
                "signal_profile": {"signals": [{"key": "web_target_present", "value": True}]},
            },
            summary_json={"url_count": 1},
            confidence_score=0.9,
        )
        run.source_inventory_snapshot = snapshot
        context = TargetContextDocument(
            run=run,
            layer_name="roe_policy_selector_context",
            context_kind="roe_policy_selector_context",
            status="recorded",
            source_targets_json=[{"kind": "url", "value": "https://policy.example.test"}],
            technologies_detected_json=[],
            endpoints_discovered_json=["https://policy.example.test"],
            recommended_tools_json=["httpx"],
            micro_plan_json=[],
            evidence_refs_json=[{"type": "inventory_snapshot", "id": "roe-selector"}],
            context_summary="Stored web target signal for ROE policy selector validation.",
            provenance_json={"live_target_actions_performed": False},
        )
        session.add_all([snapshot, context])
        session.commit()
        report = select_next_best_action_for_run(
            session,
            run=run,
            scope=scope,
            approved_targets=[{"kind": "url", "value": "https://policy.example.test"}],
            tested_action_keys=set(),
        )

    httpx_action = next(action for action in report["actions"] if action["runner"] == "httpx")
    policy_decision = httpx_action["roe_policy_decision"]
    assert policy_decision["decision"] == "allow"
    assert policy_decision["execution_contract"]["dispatches_work"] is False
    assert httpx_action["provenance"]["roe_policy_compiler"] == "roe-policy-compiler-v1"
