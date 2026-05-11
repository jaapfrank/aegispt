from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select

from api.app.models import (
    AgentProposal,
    AgentReasoning,
    AssessmentChain,
    Engagement,
    Run,
    RunProfile,
    Scope,
    Task,
)
from api.app.services.coverage_truth import build_coverage_truth


def _profile(session, name: str = "autonomous-web") -> RunProfile:
    profile = session.scalar(select(RunProfile).where(RunProfile.name == name))
    assert profile is not None
    return profile


def _create_engagement_scope_and_profile(client) -> tuple[str, str]:
    response = client.get("/api/v1/run-profiles")
    assert response.status_code == 200
    with client.app.state.session_factory() as session:
        profile = _profile(session)
        engagement = Engagement(
            name="Coverage Truth Validation",
            client="Acme Corp",
            roe_ref="ROE-COVERAGE-2026",
            status="active",
        )
        Scope(
            engagement=engagement,
            allowlist_json={
                "urls": ["https://coverage.example.test", "https://coverage.example.test/graphql"],
                "hosts": ["10.0.20.25"],
                "cidrs": ["10.0.20.0/24"],
            },
            denylist_json={},
        )
        session.add(engagement)
        session.commit()
        return str(engagement.id), str(profile.id)


def test_coverage_truth_chain_counts_all_runs_and_honest_gaps(client) -> None:
    engagement_id, profile_id = _create_engagement_scope_and_profile(client)

    with client.app.state.session_factory() as session:
        chain = AssessmentChain(
            engagement_id=UUID(engagement_id),
            assessment_mode="FULL-EXTERNAL-WEB",
            status="active",
            created_by="coverage-tester",
            phases_json=[],
            configuration_json={},
            metadata_json={},
        )
        first_run = Run(
            engagement_id=UUID(engagement_id),
            assessment_chain=chain,
            profile_id=UUID(profile_id),
            requested_by="coverage-tester",
            status="completed",
            configuration_json={"targets": {"urls": ["https://coverage.example.test"]}},
        )
        follow_up_run = Run(
            engagement_id=UUID(engagement_id),
            assessment_chain=chain,
            profile_id=UUID(profile_id),
            requested_by="coverage-tester",
            status="completed",
            configuration_json={"targets": {"urls": ["https://coverage.example.test/graphql"]}},
        )
        session.add_all([chain, first_run, follow_up_run])
        session.flush()
        chain_id = str(chain.id)
        session.add_all(
            [
                Task(
                    run=first_run,
                    tool="httpx",
                    target_id="https://coverage.example.test",
                    status="completed",
                    params_json={},
                ),
                Task(
                    run=follow_up_run,
                    tool="graphql-probe",
                    target_id="https://coverage.example.test/graphql",
                    status="failed",
                    params_json={},
                ),
            ]
        )
        session.commit()
        follow_up_run_id = str(follow_up_run.id)

    response = client.get(
        f"/api/v1/runs/{follow_up_run_id}/coverage-truth",
        headers={"X-Actor": "coverage-tester"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["assessment_chain_id"] == chain_id
    assert payload["summary"]["total_task_count"] == 2
    assert payload["summary"]["executed_task_count"] == 2
    assert payload["summary"]["tested_count"] >= 1
    assert payload["summary"]["partially_tested_count"] >= 1
    assert payload["stop_condition"]["state"] == "complete-with-gaps"
    assert payload["stop_condition"]["run_count"] == 2
    api_surface = next(surface for surface in payload["surfaces"] if surface["key"] == "api")
    assert api_surface["status"] == "partially_tested"
    assert any(api_surface["all_task_ids"])


def test_coverage_truth_terminal_blocked_prerequisite_is_complete_with_gaps(client) -> None:
    engagement_id, profile_id = _create_engagement_scope_and_profile(client)

    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=UUID(profile_id),
            requested_by="coverage-tester",
            status="completed",
            configuration_json={"targets": {"urls": ["https://coverage.example.test/graphql"]}},
        )
        session.add(run)
        session.commit()
        run_id = str(run.id)

    response = client.get(
        f"/api/v1/runs/{run_id}/coverage-truth",
        headers={"X-Actor": "coverage-tester"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["stop_condition"]["state"] == "complete-with-gaps"
    api_surface = next(surface for surface in payload["surfaces"] if surface["key"] == "api")
    assert api_surface["status"] == "not_tested"
    assert "No stored task or finding evidence" in api_surface["reason"]
    assert any(blocker.startswith("prerequisite:graphql-probe:") for blocker in api_surface["blocker_ids"])


def test_coverage_truth_reports_and_api_counts_agree(client) -> None:
    engagement_id, profile_id = _create_engagement_scope_and_profile(client)

    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=UUID(profile_id),
            requested_by="coverage-tester",
            status="requested",
            configuration_json={"targets": {"urls": ["https://coverage.example.test"]}},
        )
        reasoning = AgentReasoning(
            run=run,
            reasoning_type="assessment_loop_next_action",
            status="recorded",
            context_snapshot_json={},
            observations_json=[],
            hypotheses_json=[],
            proposals_json=[],
            provider="deterministic",
        )
        proposal = AgentProposal(
            run=run,
            agent_reasoning=reasoning,
            proposed_tool="nuclei",
            proposed_target="https://coverage.example.test",
            proposed_params_json={},
            reasoning_text="Review needed for active template coverage.",
            risk_tier="active",
            status="pending_review",
        )
        session.add_all(
            [
                run,
                reasoning,
                proposal,
                Task(
                    run=run,
                    tool="httpx",
                    target_id="https://coverage.example.test",
                    status="completed",
                    params_json={},
                ),
            ]
        )
        session.commit()
        run_id = str(run.id)

    api_response = client.get(
        f"/api/v1/runs/{run_id}/coverage-truth",
        headers={"X-Actor": "coverage-tester"},
    )
    catalog_response = client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")

    assert api_response.status_code == 200
    assert catalog_response.status_code == 200
    assert markdown_response.status_code == 200
    api_payload = api_response.json()
    technical = next(item for item in catalog_response.json() if item["variant"] == "technical")
    catalog_truth = technical["included_findings"]["coverage_truth"]
    assert catalog_truth["summary"]["total_task_count"] == api_payload["summary"]["total_task_count"]
    assert catalog_truth["summary"]["tested_count"] == api_payload["summary"]["tested_count"]
    assert catalog_truth["stop_condition"]["state"] == api_payload["stop_condition"]["state"]
    assert "Coverage Truth Stop Condition" in markdown_response.text


def test_coverage_truth_builder_is_read_only(client) -> None:
    engagement_id, profile_id = _create_engagement_scope_and_profile(client)

    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=UUID(profile_id),
            requested_by="coverage-tester",
            status="requested",
            configuration_json={"targets": {"urls": ["https://coverage.example.test"]}},
        )
        session.add(run)
        session.commit()
        before = session.scalar(select(func.count()).select_from(Task).where(Task.run_id == run.id))
        build_coverage_truth(session, run=run)
        after = session.scalar(select(func.count()).select_from(Task).where(Task.run_id == run.id))

    assert before == after == 0
