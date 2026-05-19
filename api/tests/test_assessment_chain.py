from __future__ import annotations

import copy
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import (
    AgentReasoning,
    AssessmentChain,
    AuditEvent,
    Finding,
    InventorySnapshot,
    Run,
    RunProfile,
    Task,
)
from api.app.services import assessment_chain as assessment_chain_service
from api.app.services.assessment_chain import (
    advance_assessment_chain_for_completed_run,
    auto_continue_recoverable_blocked_assessment_chain,
    load_assessment_chain,
)


def _create_engagement_with_assessment_chain_scope(client) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Assessment Chain Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-CHAIN",
        },
    )
    engagement_id = engagement_response.json()["id"]
    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "cidrs": ["10.0.20.0/24"],
                "hosts": ["10.0.20.25", "dc01.corp.example"],
                "urls": ["https://portal.example.test"],
                "domains": ["corp.example"],
                "ad_domains": ["corp.example"],
                "directory_hosts": ["dc01.corp.example"],
            },
            "denylist_json": {},
        },
    )
    return engagement_id


def _assessment_chain_configuration(*, assessment_type: str = "Internal Range / LAN") -> dict:
    return {
        "assessment_type": assessment_type,
        "test_profile": "Deep",
        "targets": {
            "cidr_ranges": ["10.0.20.0/24"],
            "hosts": ["10.0.20.25", "dc01.corp.example"],
            "urls": ["https://portal.example.test"],
            "domains": ["corp.example"],
            "ad_domains": ["corp.example"],
            "directory_hosts": ["dc01.corp.example"],
        },
        "access": {
            "accounts": [
                {
                    "label": "Domain Admin",
                    "username": "administrator",
                    "domain": "CORP",
                    "secret_ref": "Winter2026!",
                }
            ]
        },
        "credential_attacks": {
            "attempts_per_window": 1,
        },
        "responder": {
            "interface": "eth0",
            "duration_minutes": 5,
        },
        "impacket": {
            "remote_exec_method": "wmiexec",
        },
    }


def _with_chain_authorization(
    configuration: dict,
    *,
    level: str,
    mode: str = "FULL-INTERNAL-LAN",
    confirmation_target: str = "10.0.20.0/24",
    typed_scope_confirmation: str | None = None,
    confirmed_scope: str = "10.0.20.0/24, 10.0.20.25, dc01.corp.example",
    exploit_confirmation_authorized: bool = False,
) -> dict:
    payload = copy.deepcopy(configuration)
    access = dict(payload.get("access") or {})
    prerequisites = dict(access.get("prerequisites") or {})
    prerequisites["intrusive_lan_authorized"] = level == "full"
    prerequisites["exploit_confirmation_authorized"] = bool(exploit_confirmation_authorized)
    access["prerequisites"] = prerequisites
    payload["access"] = access
    payload["assessment_mode"] = {
        "enabled": True,
        "mode": mode,
        "authorization_level": level,
        "confirmation_target": confirmation_target,
        "typed_scope_confirmation": typed_scope_confirmation or "",
        "confirmed_scope": confirmed_scope,
        "intrusive_lan_authorized": prerequisites["intrusive_lan_authorized"],
        "exploit_confirmation_authorized": prerequisites["exploit_confirmation_authorized"],
    }
    return payload


def test_full_lan_iot_chain_definition_matches_required_phase_contract() -> None:
    definition = assessment_chain_service.ASSESSMENT_CHAIN_DEFINITIONS["FULL-LAN-IOT"]

    assert definition.label == "Full LAN + IoT"
    assert definition.phase_preapproval_allowed is False
    assert [(phase.key, phase.profiles) for phase in definition.phases] == [
        (
            "iot-discovery",
            (
                "passive-network-discovery",
                "passive-lan-iot-discovery",
                "passive-lan-network-capture",
            ),
        ),
        (
            "iot-enumeration",
            (
                "passive-network-service-enumeration",
                "passive-lan-nse-full",
                "passive-lan-snmp-enum",
            ),
        ),
        (
            "iot-service-analysis",
            ("passive-lan-smart-home-audit", "active-lan-camera-audit"),
        ),
        (
            "iot-credential-testing",
            ("active-lan-default-creds-audit", "active-lan-ssh-brute", "passive-lan-smb-enum"),
        ),
        (
            "iot-segmentation",
            ("passive-lan-segmentation-check", "passive-lan-ipv6-discovery"),
        ),
        (
            "iot-intrusive",
            (
                "passive-lan-infrastructure-audit",
                "intrusive-lan-arp-spoof",
                "intrusive-lan-credential-capture",
            ),
        ),
    ]
    assert [phase.requires_approval for phase in definition.phases] == [
        False,
        True,
        True,
        True,
        True,
        True,
    ]
    assert definition.phases[-1].never_auto_start is True


def test_full_external_web_chain_includes_crypto_logging_and_oauth_probe() -> None:
    definition = assessment_chain_service.ASSESSMENT_CHAIN_DEFINITIONS["FULL-EXTERNAL-WEB"]

    assert definition.phases[0].key == "passive-surface"
    assert "passive-crypto-audit" in definition.phases[0].profiles
    assert "passive-web-logging-probe" in definition.phases[0].profiles
    assert "passive-web-vuln-components" in definition.phases[0].profiles
    assert "passive-web-headers-security" in definition.phases[0].profiles
    assert "passive-web-nikto-scan" in definition.phases[0].profiles
    assert definition.phases[1].key == "active-web-validation"
    assert "active-web-oauth-probe" in definition.phases[1].profiles
    assert "active-web-rce-nuclei-audit" in definition.phases[1].profiles
    assert "active-web-content-discovery" in definition.phases[1].profiles
    assert "active-web-feroxbuster" in definition.phases[1].profiles


def test_full_external_web_chain_dispatches_new_web_security_profiles() -> None:
    definition = assessment_chain_service.ASSESSMENT_CHAIN_DEFINITIONS["FULL-EXTERNAL-WEB"]
    passive_profiles = set(definition.phases[0].profiles)
    active_profiles = set(definition.phases[1].profiles)

    expected_passive = {
        "passive-web-vuln-components",
        "passive-web-headers-security",
    }
    expected = {
        "active-web-xxe-probe",
        "active-web-jwt-probe",
        "active-web-vuln-components",
        "active-web-xss-extended",
        "active-web-ssrf-probe",
        "active-web-deserialization-probe",
        "active-web-session-security",
        "active-web-auth-flow",
        "active-web-client-state",
        "active-web-headers-security",
        "active-web-graphql-probe",
        "active-web-ssti-probe",
        "active-web-http-smuggling",
        "active-web-idor-bac",
        "active-web-rce-nuclei-audit",
        "active-web-content-discovery",
        "active-web-feroxbuster",
    }

    assert expected_passive.issubset(passive_profiles)
    assert expected.issubset(active_profiles)
    assert expected.issubset(assessment_chain_service.WEB_FOLLOW_UP_PROFILES)
    assert (expected_passive | {"passive-web-nikto-scan"}).issubset(
        assessment_chain_service.WEB_FOLLOW_UP_PROFILES
    )
    for phase in definition.phases:
        assert len(phase.profiles) == len(set(phase.profiles))


def test_full_internal_lan_chain_includes_linux_privilege_escalation_enumeration() -> None:
    definition = assessment_chain_service.ASSESSMENT_CHAIN_DEFINITIONS["FULL-INTERNAL-LAN"]

    assert definition.phases[0].key == "passive-discovery"
    assert "passive-lan-network-capture" in definition.phases[0].profiles
    assert definition.phases[1].key == "active-enrichment"
    assert "active-lan-ssh-brute" in definition.phases[1].profiles
    assert definition.phases[2].key == "intrusive-credential"
    assert "intrusive-credential-priv-esc-linux" in definition.phases[2].profiles
    assert definition.phases[3].key == "intrusive-exploitation"
    assert "intrusive-lan-arp-spoof" in definition.phases[3].profiles
    assert "intrusive-lan-arp-spoof" in assessment_chain_service.HOST_FOLLOW_UP_PROFILES


def test_full_ad_chain_includes_bounded_service_brute_force() -> None:
    definition = assessment_chain_service.ASSESSMENT_CHAIN_DEFINITIONS["FULL-AD-ASSESSMENT"]

    assert definition.phases[1].key == "directory-enumeration"
    assert "active-lan-ssh-brute" in definition.phases[1].profiles


def test_full_internal_lan_assessment_chain_creates_queued_passive_run(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _assessment_chain_configuration(),
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["profile"]["name"] == "passive-network-discovery"
    assert payload["status"] == "queued"
    assert payload["assessment_chain"]["assessment_mode"] == "FULL-INTERNAL-LAN"
    assert payload["assessment_chain"]["status"] == "active"
    assert payload["assessment_chain"]["current_phase_key"] == "passive-discovery"
    assert payload["assessment_chain"]["current_run_id"] == payload["id"]
    assert payload["tasks"][0]["tool"] == "nmap"


def test_assessment_chain_phase_approval_queues_next_phase_once(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-identity-ldap-enum",
            "assessment_mode": "FULL-AD-ASSESSMENT",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _assessment_chain_configuration(),
        },
    )
    created_run = create_response.json()
    chain_id = created_run["assessment_chain"]["id"]

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:ldap-enum",
            settings=get_settings(),
        )
        session.commit()
        assert chain is not None
        assert chain.status == "pending_phase_approval"
        assert chain.current_phase_index == 1

    approval_response = client.post(
        f"/api/v1/assessment-chains/{chain_id}/phases/directory-enumeration/decision",
        headers={"X-Actor": "approver"},
        json={"decision": "approved"},
    )
    assert approval_response.status_code == 200
    approved_chain = approval_response.json()
    assert approved_chain["status"] == "active"
    assert approved_chain["current_phase_key"] == "directory-enumeration"
    assert approved_chain["current_run_id"] is not None
    run_response = client.get(f"/api/v1/runs/{approved_chain['current_run_id']}")
    assert run_response.status_code == 200
    queued_run = run_response.json()
    assert queued_run["profile"]["name"] == "active-ad-bloodhound"
    assert queued_run["status"] == "queued"
    assert queued_run["pending_approvals"] == 0
    assert queued_run["assessment_chain"]["current_run_id"] == queued_run["id"]


def test_full_external_web_chain_skips_missing_credential_step_without_orphan_run(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    configuration = _with_chain_authorization(
        _assessment_chain_configuration(assessment_type="External Web"),
        level="full",
        mode="FULL-EXTERNAL-WEB",
        confirmation_target="https://portal.example.test",
        typed_scope_confirmation="https://portal.example.test",
        confirmed_scope="https://portal.example.test",
        exploit_confirmation_authorized=True,
    )
    configuration["access"] = {"prerequisites": configuration["access"]["prerequisites"]}
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "assessment_mode": "FULL-EXTERNAL-WEB",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": configuration,
        },
    )
    assert create_response.status_code == 201
    chain_id = UUID(create_response.json()["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        phases = copy.deepcopy(chain.phases_json or [])
        phases[0]["status"] = "completed"
        phases[0]["completed_at"] = "2026-05-08T00:00:00+00:00"
        phases[1]["status"] = "active"
        phases[1]["approved_by"] = "operator"
        phases[1]["approved_at"] = "2026-05-08T00:00:00+00:00"
        missing_credential_step = next(
            index
            for index, step in enumerate(phases[1]["steps"])
            if step["profile_name"] == "active-web-session-security"
        )
        chain.current_phase_index = 1
        chain.current_step_index = missing_credential_step
        chain.current_run_id = None
        chain.status = "active"
        chain.phases_json = phases
        session.flush()

        runs_before = session.scalars(
            select(Run).where(Run.assessment_chain_id == chain.id)
        ).all()
        launched = assessment_chain_service._launch_next_chain_run(
            session,
            chain=chain,
            actor="operator",
        )
        session.commit()

        assert launched is not None
        session.refresh(chain)
        runs_after = session.scalars(
            select(Run).where(Run.assessment_chain_id == chain.id)
        ).all()
        updated_phases = chain.phases_json
        skipped_step = updated_phases[1]["steps"][missing_credential_step]
        assert skipped_step["status"] == "skipped"
        assert skipped_step["run_id"] is None
        assert skipped_step["blocker_type"] == "missing_credentials"
        assert len(runs_after) == len(runs_before) + 1
        assert chain.current_run_id == launched.id


def test_assessment_chain_findings_endpoint_aggregates_child_runs(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "assessment_mode": "FULL-EXTERNAL-WEB",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(assessment_type="External Web"),
                level="active",
                mode="FULL-EXTERNAL-WEB",
                confirmation_target="https://portal.example.test",
                confirmed_scope="https://portal.example.test",
            ),
        },
    )
    assert create_response.status_code == 201
    created_run = create_response.json()
    chain_id = UUID(created_run["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "active-web-safe"))
        assert profile is not None
        follow_up_run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="runner:httpx",
            status="completed",
            configuration_json=_assessment_chain_configuration(assessment_type="External Web"),
        )
        session.add(follow_up_run)
        session.flush()
        follow_up_run_id = follow_up_run.id
        session.add_all(
            [
                Task(
                    run_id=follow_up_run.id,
                    tool="active-chain-check",
                    target_id="https://portal.example.test/login",
                    status="completed",
                    params_json={},
                ),
                Finding(
                    run_id=UUID(created_run["id"]),
                    title="Baseline finding",
                    severity="info",
                    target_id="https://portal.example.test",
                    evidence_ref="artifact://baseline",
                    status="open",
                ),
                Finding(
                    run_id=follow_up_run.id,
                    title="Active finding",
                    severity="medium",
                    target_id="https://portal.example.test/login",
                    evidence_ref="artifact://active",
                    status="open",
                ),
            ]
        )
        session.commit()

    response = client.get(f"/api/v1/assessment-chains/{chain_id}/findings")

    assert response.status_code == 200
    titles = {finding["title"] for finding in response.json()}
    assert {"Baseline finding", "Active finding"}.issubset(titles)

    tasks_response = client.get(f"/api/v1/assessment-chains/{chain_id}/tasks")
    assert tasks_response.status_code == 200
    assert any(task["tool"] == "active-chain-check" for task in tasks_response.json())

    reports_response = client.get(f"/api/v1/runs/{follow_up_run_id}/reports")
    assert reports_response.status_code == 200
    catalog = reports_response.json()
    assert catalog[0]["included_findings"]["count"] == 2
    assert catalog[0]["preview_allowed"] is True

    markdown_response = client.get(
        f"/api/v1/runs/{follow_up_run_id}/report?format=markdown&variant=technical"
    )
    assert markdown_response.status_code == 200
    assert "Baseline finding" in markdown_response.text
    assert "Active finding" in markdown_response.text


def test_full_external_web_chain_keeps_active_phase_on_configured_scope_when_httpx_has_no_inventory(
    client,
) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    configuration = _with_chain_authorization(
        _assessment_chain_configuration(assessment_type="External Web"),
        level="active",
        mode="FULL-EXTERNAL-WEB",
        confirmation_target="https://portal.example.test",
        confirmed_scope="https://portal.example.test",
    )
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-easm-discovery",
            "assessment_mode": "FULL-EXTERNAL-WEB",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": configuration,
            "dispatch_after_create": True,
        },
    )

    assert create_response.status_code == 201
    created_run = create_response.json()
    assert created_run["profile"]["name"] == "passive-easm-discovery"
    assert created_run["configuration_json"]["runtime_dispatch"]["last_dispatch_mode"] == "manual"

    with client.app.state.session_factory() as session:
        first_run = session.get(Run, UUID(created_run["id"]))
        assert first_run is not None
        first_run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=first_run.id,
            actor="runner:easm-discover",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        baseline_run = session.get(Run, chain.current_run_id)
        assert baseline_run is not None
        assert baseline_run.profile is not None
        assert baseline_run.profile.name == "passive-web-baseline"
        assert baseline_run.configuration_json["targets"]["urls"] == ["https://portal.example.test"]

        baseline_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=baseline_run.id,
            actor="runner:httpx",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        crypto_run = session.get(Run, chain.current_run_id)
        assert crypto_run is not None
        assert crypto_run.profile is not None
        assert crypto_run.profile.name == "passive-crypto-audit"
        assert crypto_run.configuration_json["targets"]["urls"] == ["https://portal.example.test"]

        crypto_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=crypto_run.id,
            actor="runner:crypto-audit",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        logging_run = session.get(Run, chain.current_run_id)
        assert logging_run is not None
        assert logging_run.profile is not None
        assert logging_run.profile.name == "passive-web-logging-probe"
        assert logging_run.configuration_json["targets"]["urls"] == ["https://portal.example.test"]

        logging_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=logging_run.id,
            actor="runner:logging-probe",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        component_run = session.get(Run, chain.current_run_id)
        assert component_run is not None
        assert component_run.profile is not None
        assert component_run.profile.name == "passive-web-vuln-components"
        assert component_run.configuration_json["targets"]["urls"] == [
            "https://portal.example.test"
        ]

        component_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=component_run.id,
            actor="runner:vuln-components",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        headers_run = session.get(Run, chain.current_run_id)
        assert headers_run is not None
        assert headers_run.profile is not None
        assert headers_run.profile.name == "passive-web-headers-security"
        assert headers_run.configuration_json["targets"]["urls"] == [
            "https://portal.example.test"
        ]

        headers_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=headers_run.id,
            actor="runner:headers-security",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        nikto_run = session.get(Run, chain.current_run_id)
        assert nikto_run is not None
        assert nikto_run.profile is not None
        assert nikto_run.profile.name == "passive-web-nikto-scan"
        assert nikto_run.configuration_json["targets"]["urls"] == ["https://portal.example.test"]

        nikto_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=nikto_run.id,
            actor="runner:nikto",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        nuclei_run = session.get(Run, chain.current_run_id)
        assert nuclei_run is not None
        assert nuclei_run.profile is not None
        assert nuclei_run.profile.name == "passive-web-nuclei-audit"
        assert nuclei_run.configuration_json["targets"]["urls"] == ["https://portal.example.test"]

        nuclei_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=nuclei_run.id,
            actor="runner:nuclei",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        rce_run = session.get(Run, chain.current_run_id)
        assert rce_run is not None
        assert rce_run.profile is not None
        assert rce_run.profile.name == "active-web-rce-nuclei-audit"
        assert rce_run.configuration_json["targets"]["urls"] == ["https://portal.example.test"]

        rce_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=rce_run.id,
            actor="runner:nuclei",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        content_run = session.get(Run, chain.current_run_id)
        assert content_run is not None
        assert content_run.profile is not None
        assert content_run.profile.name == "active-web-content-discovery"
        assert content_run.configuration_json["targets"]["urls"] == [
            "https://portal.example.test"
        ]

        content_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=content_run.id,
            actor="runner:content-discovery",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        ferox_run = session.get(Run, chain.current_run_id)
        assert ferox_run is not None
        assert ferox_run.profile is not None
        assert ferox_run.profile.name == "active-web-feroxbuster"
        assert ferox_run.configuration_json["targets"]["urls"] == [
            "https://portal.example.test"
        ]

        ferox_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=ferox_run.id,
            actor="runner:feroxbuster",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None and chain.current_run_id is not None
        active_run = session.get(Run, chain.current_run_id)
        assert active_run is not None
        assert active_run.profile is not None
        assert active_run.profile.name == "active-web-safe"
        assert active_run.configuration_json["targets"]["urls"] == [
            "https://portal.example.test"
        ]


def test_full_external_web_url_only_website_starts_with_web_baseline_not_easm(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "operator"},
        json={
            "name": "URL-only Website Chain",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-URL-WEB",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "operator"},
        json={
            "allowlist_json": {"urls": ["https://portal.example.test"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    configuration = _with_chain_authorization(
        {
            "assessment_type": "Website / Web App",
            "test_profile": "Standard",
            "execution_profile": "active-web-safe",
            "targets": {"urls": ["https://portal.example.test"]},
        },
        level="active",
        mode="FULL-EXTERNAL-WEB",
        confirmation_target="https://portal.example.test",
        confirmed_scope="https://portal.example.test",
    )

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "assessment_mode": "FULL-EXTERNAL-WEB",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": configuration,
        },
    )

    assert create_response.status_code == 201
    created_run = create_response.json()
    assert created_run["profile"]["name"] == "passive-web-baseline"
    assert created_run["configuration_json"]["targets"]["urls"] == ["https://portal.example.test"]
    assert created_run["status"] == "queued"
    chain = created_run["assessment_chain"]
    phase_one_steps = chain["phases"][0]["steps"]
    assert [step["profile_name"] for step in phase_one_steps][0] == "passive-web-baseline"
    assert "passive-easm-discovery" not in [
        step["profile_name"] for step in phase_one_steps
    ]


def test_full_external_web_domain_scope_keeps_easm_first(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "operator"},
        json={
            "name": "Domain Website Chain",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-DOMAIN-WEB",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "operator"},
        json={
            "allowlist_json": {"domains": ["example.test"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    configuration = _with_chain_authorization(
        {
            "assessment_type": "Website / Web App",
            "test_profile": "External Surface Only",
            "execution_profile": "passive-easm-discovery",
            "targets": {"domains": ["example.test"]},
        },
        level="active",
        mode="FULL-EXTERNAL-WEB",
        confirmation_target="example.test",
        confirmed_scope="example.test",
    )

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-easm-discovery",
            "assessment_mode": "FULL-EXTERNAL-WEB",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": configuration,
        },
    )

    assert create_response.status_code == 201
    created_run = create_response.json()
    assert created_run["profile"]["name"] == "passive-easm-discovery"
    assert created_run["assessment_chain"]["phases"][0]["steps"][0]["profile_name"] == (
        "passive-easm-discovery"
    )


def test_full_authorization_auto_advances_pre_authorized_non_exploitation_phase(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-identity-ldap-enum",
            "assessment_mode": "FULL-AD-ASSESSMENT",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                mode="FULL-AD-ASSESSMENT",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    assert create_response.status_code == 201
    created_run = create_response.json()

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:ldap-enum",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.status == "active"
        assert chain.current_phase_index == 1
        assert chain.current_run_id is not None
        assert chain.phases_json[1]["key"] == "directory-enumeration"
        assert chain.phases_json[1]["status"] == "active"
        assert chain.phases_json[1]["approved_by"] == "operator"
        queued_run = session.get(Run, chain.current_run_id)
        assert queued_run is not None and queued_run.profile is not None
        assert queued_run.profile.name == "active-ad-bloodhound"

        serialized = assessment_chain_service.build_assessment_chain_summary(chain)
        phase_state = serialized["phases"][1]["authorization_state"]
        assert phase_state["status"] == "pre_authorized"
        assert phase_state["pre_authorized"] is True


def test_internal_lan_chain_service_enumeration_uses_discovered_hosts(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    configuration = _assessment_chain_configuration()
    configuration["targets"] = {
        "cidr_ranges": ["10.0.20.0/24"],
        "hosts": [],
        "urls": [],
        "domains": [],
        "ad_domains": [],
        "directory_hosts": [],
    }
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": configuration,
        },
    )
    assert create_response.status_code == 201
    created_run = create_response.json()
    chain_id = created_run["assessment_chain"]["id"]

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="runner:nmap",
            status="completed",
            source_tools_json=["nmap"],
            raw_inputs_json={"run_id": str(run.id)},
            normalized_inventory_json={
                "hosts": [
                    {"host": "10.0.20.8", "source": "nmap", "confidence": 0.88},
                    {"host": "10.0.20.14", "source": "nmap", "confidence": 0.88},
                ],
                "services": [],
                "http_endpoints": [],
                "confidence_score": 0.88,
            },
            summary_json={"host_count": 2},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.88,
        )
        session.add(snapshot)
        run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:nmap",
            settings=get_settings(),
        )
        session.commit()
        assert chain is not None
        assert chain.status == "active"
        assert chain.current_run_id is not None
        iot_run = session.get(Run, chain.current_run_id)
        assert iot_run is not None and iot_run.profile is not None
        assert iot_run.profile.name == "passive-lan-iot-discovery"

        iot_run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=iot_run.id,
            actor="runner:mdns-ssdp",
            settings=get_settings(),
        )
        session.commit()
        assert chain is not None
        assert chain.status == "active"
        capture_run = session.get(Run, chain.current_run_id)
        assert capture_run is not None and capture_run.profile is not None
        assert capture_run.profile.name == "passive-lan-network-capture"

        capture_run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=capture_run.id,
            actor="runner:network-capture",
            settings=get_settings(),
        )
        session.commit()
        assert chain is not None
        assert chain.status == "pending_phase_approval"

    approval_response = client.post(
        f"/api/v1/assessment-chains/{chain_id}/phases/active-enrichment/decision",
        headers={"X-Actor": "approver"},
        json={"decision": "approved"},
    )
    assert approval_response.status_code == 200
    approved_chain = approval_response.json()
    queued_run_id = approved_chain["current_run_id"]
    assert queued_run_id is not None

    run_response = client.get(f"/api/v1/runs/{queued_run_id}")
    assert run_response.status_code == 200
    queued_run = run_response.json()
    assert queued_run["profile"]["name"] == "passive-network-service-enumeration"
    assert queued_run["configuration_json"]["targets"] == {
        "hosts": ["10.0.20.8", "10.0.20.14"],
        "ip_addresses": ["10.0.20.8", "10.0.20.14"],
    }
    assert sorted(task["target_id"] for task in queued_run["tasks"]) == [
        "10.0.20.14",
        "10.0.20.8",
    ]
    assert all(task["params_json"]["target_kind"] == "host" for task in queued_run["tasks"])
    assert all(task["params_json"]["top_ports"] == 10000 for task in queued_run["tasks"])
    assert all(task["params_json"]["version_intensity"] == 5 for task in queued_run["tasks"])
    assert all(task["params_json"]["timeout_seconds"] == 180.0 for task in queued_run["tasks"])

    with client.app.state.session_factory() as session:
        queued_tasks = session.scalars(
            select(Task).where(Task.run_id == UUID(queued_run_id)).order_by(Task.target_id)
        ).all()
        assert [task.target_id for task in queued_tasks] == ["10.0.20.14", "10.0.20.8"]
        assert all(task.params_json["limits"]["discovery_only"] is False for task in queued_tasks)


def test_full_lan_iot_chain_keeps_operator_phase_gate_manual_despite_full_auth() -> None:
    chain = AssessmentChain(
        assessment_mode="FULL-LAN-IOT",
        created_by="operator",
        metadata_json={
            "phase_preapproval_allowed": False,
            "authorization": {
                "level": "full",
                "actor": "operator",
                "confirmed_at": "2026-04-30T00:00:00+00:00",
            },
        },
    )
    phase = {
        "key": "iot-enumeration",
        "tier": "active",
        "requires_approval": True,
        "status": "pending_approval",
        "approved_by": None,
        "approved_at": None,
    }

    assert assessment_chain_service._apply_chain_phase_preapproval(chain, phase) is False
    assert phase["approved_by"] is None
    assert phase["approved_at"] is None
    assert phase["status"] == "pending_approval"


def test_full_lan_iot_follow_up_profiles_use_discovered_hosts() -> None:
    assert {
        "passive-network-service-enumeration",
        "passive-lan-nse-full",
        "passive-lan-snmp-enum",
        "passive-lan-smart-home-audit",
        "active-lan-camera-audit",
        "active-lan-default-creds-audit",
        "active-lan-ssh-brute",
        "passive-lan-segmentation-check",
        "passive-lan-ipv6-discovery",
        "passive-lan-network-capture",
        "passive-lan-infrastructure-audit",
    }.issubset(assessment_chain_service.HOST_FOLLOW_UP_PROFILES)


def test_internal_lan_chain_web_follow_up_aggregates_all_service_inventory_snapshots(
    client,
) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    configuration = _assessment_chain_configuration()
    configuration["targets"] = {
        "cidr_ranges": ["10.0.20.0/24"],
        "hosts": [],
        "urls": [],
        "domains": [],
        "ad_domains": [],
        "directory_hosts": [],
    }
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": configuration,
        },
    )
    created_run = create_response.json()
    chain_id = created_run["assessment_chain"]["id"]

    with client.app.state.session_factory() as session:
        discovery_run = session.get(Run, UUID(created_run["id"]))
        assert discovery_run is not None
        session.add(
            InventorySnapshot(
                engagement_id=UUID(engagement_id),
                requested_by="runner:nmap",
                status="completed",
                source_tools_json=["nmap"],
                raw_inputs_json={"run_id": str(discovery_run.id)},
                normalized_inventory_json={
                    "hosts": [
                        {"host": "10.0.20.8", "source": "nmap", "confidence": 0.88},
                        {"host": "10.0.20.14", "source": "nmap", "confidence": 0.88},
                    ],
                    "services": [],
                    "http_endpoints": [],
                },
                summary_json={"host_count": 2},
                environment_notes_json=[],
                assumptions_json=[],
                confidence_score=0.88,
            )
        )
        discovery_run.status = "completed"
        session.flush()
        advance_assessment_chain_for_completed_run(
            session,
            run_id=discovery_run.id,
            actor="runner:nmap",
            settings=get_settings(),
        )
        chain = load_assessment_chain(session, UUID(chain_id))
        assert chain is not None and chain.current_run_id is not None
        iot_run = session.get(Run, chain.current_run_id)
        assert iot_run is not None and iot_run.profile is not None
        assert iot_run.profile.name == "passive-lan-iot-discovery"
        iot_run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=iot_run.id,
            actor="runner:mdns-ssdp",
            settings=get_settings(),
        )
        assert chain is not None and chain.current_run_id is not None
        capture_run = session.get(Run, chain.current_run_id)
        assert capture_run is not None and capture_run.profile is not None
        assert capture_run.profile.name == "passive-lan-network-capture"
        capture_run.status = "completed"
        advance_assessment_chain_for_completed_run(
            session,
            run_id=capture_run.id,
            actor="runner:network-capture",
            settings=get_settings(),
        )
        session.commit()

    approval_response = client.post(
        f"/api/v1/assessment-chains/{chain_id}/phases/active-enrichment/decision",
        headers={"X-Actor": "approver"},
        json={"decision": "approved"},
    )
    service_run_id = approval_response.json()["current_run_id"]

    with client.app.state.session_factory() as session:
        service_run = session.get(Run, UUID(service_run_id))
        assert service_run is not None
        session.add_all(
            [
                InventorySnapshot(
                    engagement_id=UUID(engagement_id),
                    requested_by="runner:nmap",
                    status="completed",
                    source_tools_json=["nmap"],
                    raw_inputs_json={"run_id": str(service_run.id)},
                    normalized_inventory_json={
                        "hosts": [{"host": "10.0.20.8", "source": "nmap"}],
                        "services": [{"host": "10.0.20.8", "port": 443, "service": "https"}],
                        "http_endpoints": [{"url": "https://10.0.20.8"}],
                    },
                    summary_json={"host_count": 1},
                    environment_notes_json=[],
                    assumptions_json=[],
                    confidence_score=0.9,
                ),
                InventorySnapshot(
                    engagement_id=UUID(engagement_id),
                    requested_by="runner:nmap",
                    status="completed",
                    source_tools_json=["nmap"],
                    raw_inputs_json={"run_id": str(service_run.id)},
                    normalized_inventory_json={
                        "hosts": [{"host": "10.0.20.14", "source": "nmap"}],
                        "services": [{"host": "10.0.20.14", "port": 80, "service": "http"}],
                        "http_endpoints": [{"url": "http://10.0.20.14"}],
                    },
                    summary_json={"host_count": 1},
                    environment_notes_json=[],
                    assumptions_json=[],
                    confidence_score=0.9,
                ),
            ]
        )
        service_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=service_run.id,
            actor="runner:nmap",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.current_run_id is not None
        infra_run = session.get(Run, chain.current_run_id)
        assert infra_run is not None
        assert infra_run.profile is not None
        assert infra_run.profile.name == "passive-lan-infrastructure-audit"
        assert sorted(infra_run.configuration_json["targets"]["hosts"]) == [
            "10.0.20.14",
            "10.0.20.8",
        ]

        infra_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=infra_run.id,
            actor="runner:external-infra",
            settings=get_settings(),
        )
        assert chain is not None and chain.current_run_id is not None
        smb_run = session.get(Run, chain.current_run_id)
        assert smb_run is not None
        assert smb_run.profile is not None
        assert smb_run.profile.name == "passive-lan-smb-enum"

        smb_run.status = "completed"
        session.flush()
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=smb_run.id,
            actor="runner:netexec",
            settings=get_settings(),
        )
        assert chain is not None and chain.current_run_id is not None
        web_run = session.get(Run, chain.current_run_id)
        assert web_run is not None
        assert web_run.profile is not None
        assert web_run.profile.name == "passive-web-baseline"
        assert sorted(web_run.configuration_json["targets"]["urls"]) == [
            "http://10.0.20.14",
            "https://10.0.20.8",
        ]


def test_assessment_chain_exploitation_phase_never_auto_starts(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _assessment_chain_configuration(),
        },
    )
    chain_id = UUID(create_response.json()["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "intrusive-ad-password-spray")
        )
        assert profile is not None

        phases = copy.deepcopy(chain.phases_json or [])
        for index in range(2):
            phases[index]["status"] = "completed"
            phases[index]["completed_at"] = "2026-04-24T00:00:00+00:00"
        for step in phases[2]["steps"][:-1]:
            step["status"] = "completed"
            step["run_id"] = "completed-step"

        run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(run)
        session.flush()

        phases[2]["status"] = "active"
        phases[2]["steps"][-1]["status"] = "running"
        phases[2]["steps"][-1]["run_id"] = str(run.id)
        chain.current_phase_index = 2
        chain.current_step_index = len(phases[2]["steps"]) - 1
        chain.current_run_id = run.id
        chain.phases_json = phases

        advanced_chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:credential-attacks",
            settings=get_settings(),
        )
        session.commit()

        assert advanced_chain is not None
        assert advanced_chain.status == "pending_phase_approval"
        assert advanced_chain.current_phase_index == 3
        assert advanced_chain.current_run_id is None
        assert advanced_chain.phases_json[3]["key"] == "intrusive-exploitation"
        assert advanced_chain.phases_json[3]["status"] == "pending_approval"


def test_assessment_chain_full_authorization_requires_typed_target_confirmation(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.5",
            ),
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "full authorization requires typed target confirmation"


def test_assessment_chain_full_authorization_audits_scope_and_keeps_exploitation_gated(
    client,
) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    assert create_response.status_code == 201
    chain_id = UUID(create_response.json()["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        audit_event = session.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.object_id == str(chain_id),
                AuditEvent.action == "assessment_chain.authorization_confirmed",
            )
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        )
        assert audit_event is not None
        assert audit_event.actor == "operator"
        assert audit_event.metadata_json["authorization_level"] == "full"
        assert (
            audit_event.metadata_json["confirmed_scope"]
            == "10.0.20.0/24, 10.0.20.25, dc01.corp.example"
        )
        assert audit_event.metadata_json["intrusive_lan_authorized"] is True
        assert audit_event.metadata_json["exploit_confirmation_authorized"] is False

        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "intrusive-ad-password-spray")
        )
        assert profile is not None

        phases = copy.deepcopy(chain.phases_json or [])
        for index in range(2):
            phases[index]["status"] = "completed"
            phases[index]["completed_at"] = "2026-04-24T00:00:00+00:00"
        for step in phases[2]["steps"][:-1]:
            step["status"] = "completed"
            step["run_id"] = "completed-step"

        run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(run)
        session.flush()

        phases[2]["status"] = "active"
        phases[2]["approved_by"] = "operator"
        phases[2]["approved_at"] = "2026-04-24T00:00:00+00:00"
        phases[2]["steps"][-1]["status"] = "running"
        phases[2]["steps"][-1]["run_id"] = str(run.id)
        chain.current_phase_index = 2
        chain.current_step_index = len(phases[2]["steps"]) - 1
        chain.current_run_id = run.id
        chain.phases_json = phases

        advanced_chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:credential-attacks",
            settings=get_settings(),
        )
        session.commit()

        assert advanced_chain is not None
        assert advanced_chain.status == "pending_phase_approval"
        assert advanced_chain.current_phase_index == 3
        assert advanced_chain.current_run_id is None
        assert advanced_chain.phases_json[3]["key"] == "intrusive-exploitation"
        assert advanced_chain.phases_json[3]["status"] == "pending_approval"
        serialized = assessment_chain_service.build_assessment_chain_summary(advanced_chain)
        exploitation_state = serialized["phases"][3]["authorization_state"]
        assert exploitation_state["status"] == "manual_approval_required"
        assert "explicit exploit-confirmation" in exploitation_state["gate_reason"]


def test_assessment_chain_full_authorization_with_exploit_unlocker_auto_starts_exploitation(
    client,
) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
                exploit_confirmation_authorized=True,
            ),
        },
    )
    assert create_response.status_code == 201
    chain_id = UUID(create_response.json()["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "intrusive-ad-password-spray")
        )
        assert profile is not None

        phases = copy.deepcopy(chain.phases_json or [])
        for index in range(2):
            phases[index]["status"] = "completed"
            phases[index]["completed_at"] = "2026-04-24T00:00:00+00:00"
        for step in phases[2]["steps"][:-1]:
            step["status"] = "completed"
            step["run_id"] = "completed-step"

        run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(run)
        session.flush()

        phases[2]["status"] = "active"
        phases[2]["approved_by"] = "operator"
        phases[2]["approved_at"] = "2026-04-24T00:00:00+00:00"
        phases[2]["steps"][-1]["status"] = "running"
        phases[2]["steps"][-1]["run_id"] = str(run.id)
        chain.current_phase_index = 2
        chain.current_step_index = len(phases[2]["steps"]) - 1
        chain.current_run_id = run.id
        chain.phases_json = phases

        advanced_chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:credential-attacks",
            settings=get_settings(),
        )
        session.commit()

        assert advanced_chain is not None
        assert advanced_chain.status == "active"
        assert advanced_chain.current_phase_index == 3
        assert advanced_chain.current_run_id is not None
        assert advanced_chain.phases_json[3]["key"] == "intrusive-exploitation"
        assert advanced_chain.phases_json[3]["status"] == "active"
        assert advanced_chain.phases_json[3]["approved_by"] == "operator"
        assert advanced_chain.phases_json[3]["approved_at"] is not None


def test_assessment_chain_reports_completed_with_gaps_when_only_skipped_steps_remain(
    client,
) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    chain_id = UUID(create_response.json()["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "intrusive-impacket-dcsync")
        )
        assert profile is not None
        phases = copy.deepcopy(chain.phases_json or [])
        for index in range(3):
            phases[index]["status"] = "completed"
            phases[index]["completed_at"] = "2026-04-24T00:00:00+00:00"
        phases[3]["status"] = "active"
        phases[3]["approved_by"] = "operator"
        phases[3]["approved_at"] = "2026-04-24T00:00:00+00:00"
        for step in phases[3]["steps"][:-1]:
            step["status"] = "skipped"
            step["skip_reason"] = "Prerequisite evidence was not available."

        run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(run)
        session.flush()
        phases[3]["steps"][-1]["status"] = "running"
        phases[3]["steps"][-1]["run_id"] = str(run.id)
        chain.current_phase_index = 3
        chain.current_step_index = len(phases[3]["steps"]) - 1
        chain.current_run_id = run.id
        chain.phases_json = phases

        advanced_chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:impacket-lateral",
            settings=get_settings(),
        )
        session.commit()

        assert advanced_chain is not None
        assert advanced_chain.status == "completed_with_gaps"
        assert advanced_chain.phases_json[3]["status"] == "completed_with_gaps"


def test_full_lan_chain_auto_detects_responder_interface_for_cidr_targets(
    client, monkeypatch
) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    configuration = _assessment_chain_configuration()
    configuration.pop("responder", None)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                configuration,
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    chain_id = UUID(create_response.json()["assessment_chain"]["id"])
    seen_targets: list[str] = []

    def fake_route_interface(target: str) -> str:
        seen_targets.append(target)
        return "eth-test"

    monkeypatch.setattr(
        assessment_chain_service,
        "_route_interface_for_target",
        fake_route_interface,
    )

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        phases = copy.deepcopy(chain.phases_json or [])
        for index in range(2):
            phases[index]["status"] = "completed"
            phases[index]["completed_at"] = "2026-04-24T00:00:00+00:00"
        phases[2]["status"] = "active"
        phases[2]["approved_by"] = "operator"
        phases[2]["approved_at"] = "2026-04-24T00:00:00+00:00"
        chain.current_phase_index = 2
        chain.current_step_index = 0
        chain.phases_json = phases
        session.flush()

        run_configuration, _ = assessment_chain_service._phase_step_run_configuration(
            session,
            chain,
            phase_key="intrusive-credential",
            step_index=0,
            profile_name="intrusive-lan-credential-capture",
        )

        assert seen_targets == ["10.0.20.0/24"]
        assert run_configuration["responder"]["interface"] == "eth-test"
        assert run_configuration["responder"]["interface_source"] == "route-auto-detected"


def test_assessment_chain_marks_chain_cancelled_when_run_is_cancelled(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _assessment_chain_configuration(),
        },
    )
    created_run = create_response.json()

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        run.status = "cancelled"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:nmap",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.status == "cancelled"
        assert chain.current_run_id is None


def test_assessment_chain_halt_endpoint_stops_at_phase_boundary(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-identity-ldap-enum",
            "assessment_mode": "FULL-AD-ASSESSMENT",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _assessment_chain_configuration(),
        },
    )
    created_run = create_response.json()
    chain_id = created_run["assessment_chain"]["id"]

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:ldap-enum",
            settings=get_settings(),
        )
        session.commit()
        assert chain is not None
        assert chain.status == "pending_phase_approval"

    halt_response = client.post(
        f"/api/v1/assessment-chains/{chain_id}/halt",
        headers={"X-Actor": "operator"},
    )
    assert halt_response.status_code == 200
    halted_chain = halt_response.json()
    assert halted_chain["status"] == "halted"
    assert halted_chain["halt_requested"] is True
    assert halted_chain["current_run_id"] is None


def test_assessment_chain_continue_endpoint_reviews_failed_runner(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    created_run = create_response.json()
    chain_id = UUID(created_run["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "passive-web-baseline")
        )
        assert profile is not None
        failed_run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed_with_errors",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(failed_run)
        session.flush()

        phases = copy.deepcopy(chain.phases_json or [])
        phases[0]["status"] = "completed"
        phases[0]["completed_at"] = "2026-04-24T00:00:00+00:00"
        phases[1]["status"] = "blocked"
        phases[1]["started_at"] = "2026-04-24T00:01:00+00:00"
        phases[1]["steps"][0]["status"] = "completed"
        phases[1]["steps"][0]["run_id"] = "completed-service-enum"
        phases[1]["steps"][1]["status"] = "failed"
        phases[1]["steps"][1]["run_id"] = str(failed_run.id)
        chain.status = "blocked"
        chain.current_phase_index = 1
        chain.current_step_index = 1
        chain.current_run_id = None
        chain.last_completed_run_id = failed_run.id
        chain.phases_json = phases
        session.commit()

    continue_response = client.post(
        f"/api/v1/assessment-chains/{chain_id}/continue",
        headers={"X-Actor": "operator"},
    )

    assert continue_response.status_code == 200, continue_response.text
    continued_chain = continue_response.json()
    assert continued_chain["status"] != "blocked"
    reviewed_step = continued_chain["phases"][1]["steps"][1]
    assert reviewed_step["status"] == "skipped"
    assert reviewed_step["review_decision"] == "continue_after_failure"
    assert reviewed_step["reviewed_by"] == "operator"
    assert "Operator reviewed" in reviewed_step["skip_reason"]


def test_assessment_chain_auto_continues_recoverable_runner_failure(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    created_run = create_response.json()
    chain_id = UUID(created_run["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "passive-web-baseline")
        )
        assert profile is not None
        failed_run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed_with_errors",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(failed_run)
        session.flush()

        phases = copy.deepcopy(chain.phases_json or [])
        phases[0]["status"] = "completed"
        phases[0]["completed_at"] = "2026-04-24T00:00:00+00:00"
        phases[1]["status"] = "active"
        phases[1]["approved_by"] = "operator"
        phases[1]["approved_at"] = "2026-04-24T00:01:00+00:00"
        phases[1]["steps"] = [
            {
                "profile_name": "passive-web-baseline",
                "status": "running",
                "run_id": str(failed_run.id),
                "skip_reason": None,
            }
        ]
        chain.status = "active"
        chain.current_phase_index = 1
        chain.current_step_index = 0
        chain.current_run_id = failed_run.id
        chain.auto_advance_on_phase_complete = False
        chain.phases_json = phases

        advanced_chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=failed_run.id,
            actor="runner:httpx",
            settings=get_settings(),
        )
        session.commit()

        assert advanced_chain is not None
        assert advanced_chain.status == "pending_phase_approval"
        reviewed_step = advanced_chain.phases_json[1]["steps"][0]
        assert reviewed_step["status"] == "skipped"
        assert reviewed_step["review_decision"] == "auto_continue_after_recoverable_failure"
        assert reviewed_step["reviewed_by"] == "system:auto-triage"
        assert "non-blocking chain gap" in reviewed_step["skip_reason"]
        assert reviewed_step["blocker_type"] == "runner_failure"
        assert "remaining safe planned checks" in reviewed_step["safe_next_action"]

        reasoning = session.scalars(
            select(AgentReasoning).where(AgentReasoning.run_id == failed_run.id)
        ).all()
        assert len(reasoning) == 1
        assert reasoning[0].reasoning_type == "chain_runtime_failure_triage"
        assert reasoning[0].provider == "deterministic-runtime-triage"


def test_assessment_chain_still_blocks_when_discovery_baseline_fails(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _assessment_chain_configuration(),
        },
    )
    created_run = create_response.json()

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        run.status = "completed_with_errors"

        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:nmap",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.status == "blocked"
        assert chain.phases_json[0]["steps"][0]["status"] == "failed"
        failed_step = chain.phases_json[0]["steps"][0]
        assert failed_step["blocker_type"] == "runner_failure"
        assert "Review the failed run output" in failed_step["safe_next_action"]


def test_auto_continue_recoverable_blocked_chain_repairs_existing_blocked_state(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": _with_chain_authorization(
                _assessment_chain_configuration(),
                level="full",
                typed_scope_confirmation="10.0.20.0/24",
            ),
        },
    )
    created_run = create_response.json()
    chain_id = UUID(created_run["assessment_chain"]["id"])

    with client.app.state.session_factory() as session:
        chain = load_assessment_chain(session, chain_id)
        assert chain is not None
        profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "passive-web-baseline")
        )
        assert profile is not None
        failed_run = Run(
            engagement_id=chain.engagement_id,
            assessment_chain_id=chain.id,
            profile_id=profile.id,
            requested_by="operator",
            status="completed_with_errors",
            configuration_json=_assessment_chain_configuration(),
        )
        session.add(failed_run)
        session.flush()

        phases = copy.deepcopy(chain.phases_json or [])
        phases[0]["status"] = "completed"
        phases[0]["completed_at"] = "2026-04-24T00:00:00+00:00"
        phases[1]["status"] = "blocked"
        phases[1]["approved_by"] = "operator"
        phases[1]["approved_at"] = "2026-04-24T00:01:00+00:00"
        phases[1]["steps"] = [
            {
                "profile_name": "passive-web-baseline",
                "status": "failed",
                "run_id": str(failed_run.id),
                "skip_reason": None,
            }
        ]
        chain.status = "blocked"
        chain.current_phase_index = 1
        chain.current_step_index = 0
        chain.current_run_id = None
        chain.auto_advance_on_phase_complete = False
        chain.phases_json = phases

        repaired_chain = auto_continue_recoverable_blocked_assessment_chain(
            session,
            chain=chain,
            actor="system:auto-triage",
            settings=get_settings(),
        )
        session.commit()

        assert repaired_chain.status != "blocked"
        repaired_step = repaired_chain.phases_json[1]["steps"][0]
        assert repaired_step["status"] == "skipped"
        assert repaired_step["review_decision"] == "auto_continue_after_recoverable_failure"
        assert repaired_step["reviewed_by"] == "system:auto-triage"
        assert repaired_step["safe_next_action"]


def test_assessment_chain_skips_zero_target_follow_up_steps_without_failing(client) -> None:
    engagement_id = _create_engagement_with_assessment_chain_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-discovery",
            "assessment_mode": "FULL-INTERNAL-LAN",
            "assessment_auto_advance_on_phase_complete": True,
            "configuration_json": {
                **_assessment_chain_configuration(),
                "targets": {
                    "cidr_ranges": ["10.0.20.0/24"],
                    "hosts": [],
                    "urls": [],
                    "domains": [],
                    "ad_domains": [],
                    "directory_hosts": [],
                },
            },
        },
    )
    created_run = create_response.json()

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(created_run["id"]))
        assert run is not None
        run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=run.id,
            actor="runner:nmap",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.status == "active"
        assert chain.current_phase_index == 0
        assert chain.current_run_id is not None
        iot_run = session.get(Run, chain.current_run_id)
        assert iot_run is not None and iot_run.profile is not None
        assert iot_run.profile.name == "passive-lan-iot-discovery"
        passive_phase = chain.phases_json[0]
        assert passive_phase["status"] == "active"
        assert passive_phase["steps"][0]["status"] == "completed"
        assert passive_phase["steps"][1]["status"] == "running"
        assert passive_phase["steps"][2]["profile_name"] == "passive-lan-network-capture"

        iot_run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=iot_run.id,
            actor="runner:mdns-ssdp",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.status == "active"
        assert chain.current_run_id is not None
        capture_run = session.get(Run, chain.current_run_id)
        assert capture_run is not None and capture_run.profile is not None
        assert capture_run.profile.name == "passive-lan-network-capture"
        passive_phase = chain.phases_json[0]
        assert passive_phase["steps"][1]["status"] == "completed"
        assert passive_phase["steps"][2]["status"] == "running"

        capture_run.status = "completed"
        chain = advance_assessment_chain_for_completed_run(
            session,
            run_id=capture_run.id,
            actor="runner:network-capture",
            settings=get_settings(),
        )
        session.commit()

        assert chain is not None
        assert chain.status == "pending_phase_approval"
        assert chain.current_phase_index == 1
        assert chain.current_run_id is None
        passive_phase = chain.phases_json[0]
        assert passive_phase["status"] == "completed"
        skipped_steps = [step for step in passive_phase["steps"] if step["status"] == "skipped"]
        assert skipped_steps == []
