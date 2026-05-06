from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select

from api.app.models import AssessmentChain, Engagement, Finding, Run, RunProfile, Task


def _seed_run(session, *, suffix: str | None = None) -> tuple[Engagement, Run]:
    unique = suffix or str(uuid4())
    engagement = Engagement(
        name=f"Kill Chain {unique}",
        client="Acme Corp",
        roe_ref=f"ROE-KILL-{unique}",
        status="active",
    )
    profile = RunProfile(
        name=f"kill-chain-profile-{unique}",
        run_class="active",
        limits_json={"tools": ["nmap", "zap", "metasploit"], "approval_required": True},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="kill-chain-operator",
        status="completed",
        configuration_json={
            "assessment_type": "Internal Range / LAN",
            "targets": {"hosts": ["10.0.0.5"]},
        },
    )
    session.add_all([engagement, profile, run])
    session.flush()
    return engagement, run


def _stage_by_id(payload: dict) -> dict[str, dict]:
    return {stage["id"]: stage for stage in payload["stages"]}


def _technique_status(stage: dict, technique_id: str) -> str:
    techniques = {technique["technique_id"]: technique for technique in stage["techniques"]}
    return techniques[technique_id]["status"]


def test_kill_chain_progress_maps_findings_tasks_and_run_read_without_mutating_findings(client) -> None:
    with client.app.state.session_factory() as session:
        engagement, run = _seed_run(session)
        tasks = [
            Task(run=run, tool="nmap", target_id="10.0.0.5", params_json={}, status="completed"),
            Task(run=run, tool="zap", target_id="https://app.example.test", params_json={}, status="completed"),
            Task(run=run, tool="metasploit", target_id="10.0.0.5", params_json={}, status="completed"),
        ]
        findings = [
            Finding(
                run=run,
                title="Nmap open SSH service",
                severity="info",
                target_id="10.0.0.5",
                evidence_ref="artifact://kill-chain/nmap",
                status="open",
                summary="The authorized scan found an open service banner.",
                methodology_tags=["nmap", "service discovery"],
            ),
            Finding(
                run=run,
                title="Service vulnerability CVE-2026-0001",
                severity="high",
                target_id="https://app.example.test",
                evidence_ref="artifact://kill-chain/cve",
                status="open",
                summary="A service vulnerability is present on the public-facing application.",
            ),
            Finding(
                run=run,
                title="Remote code execution verified",
                severity="critical",
                target_id="https://app.example.test",
                evidence_ref="artifact://kill-chain/rce",
                status="open",
                summary="Remote code execution evidence was recorded by the authorized runner.",
            ),
            Finding(
                run=run,
                title="SUID privilege escalation path",
                severity="high",
                target_id="10.0.0.5",
                evidence_ref="artifact://kill-chain/suid",
                status="open",
                summary="A SUID binary allows privilege escalation.",
            ),
            Finding(
                run=run,
                title="Default credential accepted",
                severity="high",
                target_id="10.0.0.5",
                evidence_ref="artifact://kill-chain/credential",
                status="open",
                summary="A default password was accepted.",
            ),
            Finding(
                run=run,
                title="psexec lateral movement validated",
                severity="high",
                target_id="10.0.0.8",
                evidence_ref="artifact://kill-chain/lateral",
                status="open",
                summary="Remote Services lateral movement evidence was recorded.",
            ),
        ]
        session.add_all([*tasks, *findings])
        session.flush()
        original = {
            str(finding.id): {
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "summary": finding.summary,
                "evidence_ref": finding.evidence_ref,
            }
            for finding in findings
        }
        engagement_id = str(engagement.id)
        run_id = str(run.id)
        session.commit()

    response = client.get(f"/api/v1/engagements/{engagement_id}/kill-chain-progress")
    assert response.status_code == 200
    payload = response.json()
    stages = _stage_by_id(payload)

    assert payload["progress_percentage"] >= 69
    assert payload["highest_reached_stage_id"] == "lateral_movement"
    assert payload["current_stage_id"] == "collection"
    assert payload["boundary"]["mutates_findings"] is False
    assert stages["reconnaissance"]["status"] == "confirmed"
    assert stages["initial_access"]["status"] == "confirmed"
    assert stages["execution"]["status"] == "confirmed"
    assert stages["privilege_escalation"]["status"] == "confirmed"
    assert stages["credential_access"]["status"] == "confirmed"
    assert stages["lateral_movement"]["status"] == "confirmed"
    assert stages["collection"]["display_state"] == "current"
    assert _technique_status(stages["initial_access"], "T1190") == "confirmed"
    assert _technique_status(stages["lateral_movement"], "T1021") == "confirmed"

    run_response = client.get(f"/api/v1/runs/{run_id}")
    assert run_response.status_code == 200
    run_payload = run_response.json()
    assert run_payload["kill_chain_progress"]["progress_percentage"] == payload["progress_percentage"]
    assert run_payload["kill_chain_progress"]["highest_reached_stage_id"] == "lateral_movement"

    with client.app.state.session_factory() as session:
        stored_findings = session.scalars(
            select(Finding).where(Finding.id.in_([UUID(item) for item in original]))
        ).all()
        assert {
            str(finding.id): {
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "summary": finding.summary,
                "evidence_ref": finding.evidence_ref,
            }
            for finding in stored_findings
        } == original


def test_kill_chain_progress_uses_assessment_phase_completion_as_tested_coverage(client) -> None:
    with client.app.state.session_factory() as session:
        engagement, run = _seed_run(session, suffix="phases")
        chain = AssessmentChain(
            engagement=engagement,
            current_run=run,
            assessment_mode="FULL-EXTERNAL-WEB",
            status="pending_phase_approval",
            current_phase_index=1,
            current_step_index=0,
            auto_advance_on_phase_complete=True,
            phases_json=[
                {
                    "key": "passive-discovery",
                    "label": "Phase 1 Passive Discovery",
                    "status": "completed",
                    "steps": [
                        {
                            "profile_name": "passive-network-discovery",
                            "tool": "nmap",
                            "status": "completed",
                            "run_id": str(run.id),
                        }
                    ],
                },
                {
                    "key": "active-web-validation",
                    "label": "Phase 2 Active Web Validation",
                    "status": "pending_approval",
                    "steps": [
                        {
                            "profile_name": "passive-web-nuclei-audit",
                            "tool": "nuclei",
                            "status": "pending",
                        }
                    ],
                },
            ],
        )
        session.add(chain)
        session.flush()
        engagement_id = str(engagement.id)
        session.commit()

    response = client.get(f"/api/v1/engagements/{engagement_id}/kill-chain-progress")
    assert response.status_code == 200
    payload = response.json()
    stages = _stage_by_id(payload)

    assert payload["progress_percentage"] == 8
    assert payload["highest_reached_stage_id"] == "reconnaissance"
    assert payload["current_stage_id"] == "initial_access"
    assert stages["reconnaissance"]["status"] == "tested"
    assert stages["reconnaissance"]["display_state"] == "complete"
    assert stages["initial_access"]["status"] == "untested"
    assert stages["initial_access"]["display_state"] == "current"
    assert _technique_status(stages["reconnaissance"], "T1595") == "tested"
