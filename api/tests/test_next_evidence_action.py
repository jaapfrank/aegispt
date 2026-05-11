from __future__ import annotations

from sqlalchemy import func, select

from api.app.models import AgentProposal, Approval, SecretRef, Task
from api.app.services.hypothesis_confidence import score_hypothesis_confidence
from api.app.services.next_evidence_action import (
    build_next_evidence_action_plan,
    plan_next_evidence_actions,
)
from api.tests.test_assessment_graph import _create_graph_fixture


def _node(
    node_id: str,
    node_type: str,
    label: str,
    *,
    data: dict | None = None,
    evidence_refs: list[str] | None = None,
) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "subtype": node_type,
        "source_id": node_id,
        "source_ids": [node_id],
        "label": label,
        "confidence": 0.84,
        "evidence_refs": evidence_refs or [f"evidence://{node_id}"],
        "data": data or {},
    }


def _planning_graph() -> dict:
    return {
        "graph_version": "normalized-evidence-graph-v1",
        "run_id": "run-next-evidence-fixture",
        "nodes": [
            _node(
                "finding:idor",
                "finding",
                "IDOR broken access control object authorization issue",
                data={"summary": "Object reference access control needs review."},
            ),
            _node("api:account", "api", "https://app.example.test/api/v1/accounts/{id}"),
            _node(
                "finding:ssrf",
                "finding",
                "SSRF server-side request metadata exposure",
            ),
            _node("api:metadata", "api", "http://169.254.169.254/latest/meta-data cloud IAM"),
            _node("identity:cloud-role", "identity", "cloud IAM role service account"),
            _node(
                "permission:oauth",
                "permission",
                "files:read:all bulk_export OAuth scope",
            ),
            _node(
                "connector:bulk",
                "saas_connector",
                "OAuth SaaS connector bulk export dataset",
            ),
            _node("identity:svc", "identity", "service account connector owner"),
            _node(
                "finding:auth",
                "finding",
                "Weak auth missing MFA on login session",
            ),
            _node("api:login", "api", "https://app.example.test/login auth session"),
        ],
        "edges": [],
    }


def test_next_evidence_planner_selects_safest_review_and_explains_alternatives() -> None:
    confidence_report = score_hypothesis_confidence(_planning_graph())
    plan = plan_next_evidence_actions(confidence_report)

    assert plan["execution_contract"]["operator_review_only"] is True
    assert plan["execution_contract"]["creates_tasks"] is False
    assert plan["execution_contract"]["dispatches_work_directly"] is False
    assert plan["execution_contract"]["approves_proposals"] is False
    assert plan["execution_contract"]["mutates_scope"] is False
    assert plan["execution_contract"]["materializes_secrets"] is False

    actions = {action["hypothesis_type"]: action for action in plan["actions"]}
    assert {"idor", "oauth_scope", "ssrf_to_cloud", "weak_auth", "saas_connector_exposure"}.issubset(actions)

    idor = actions["idor"]
    assert idor["safest_next_validation"]["action_type"] == "operator_evidence_review"
    assert idor["safest_next_validation"]["operator_review_only"] is True
    assert idor["safest_next_validation"]["dispatches_work"] is False
    assert idor["runner_capability_metadata"]["runner"]
    assert idor["runner_capability_metadata"]["contract_id"]
    assert idor["runner_capability_metadata"]["expected_evidence"]
    assert idor["lower_value_alternatives"]
    assert idor["lower_value_alternatives"][0]["lower_value_reason"]

    ssrf = actions["ssrf_to_cloud"]
    assert ssrf["runner_capability_metadata"]["risk_tier"] in {"passive", "active", "intrusive"}
    assert "metadata_access_boundary" in {
        item["id"] for item in confidence_report["hypotheses"][2]["missing_evidence"]
    }
    assert all(
        alternative["runner_capability_metadata"] is None
        or alternative["runner_capability_metadata"]["runner"] != ssrf["runner_capability_metadata"]["runner"]
        for alternative in ssrf["lower_value_alternatives"]
    )


def test_next_evidence_planner_is_read_only_for_run_evidence(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        before = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Approval, AgentProposal, SecretRef)
        }
        plan = build_next_evidence_action_plan(session, run_id=run_id)
        after = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Approval, AgentProposal, SecretRef)
        }

    assert after == before
    assert plan["execution_contract"]["creates_tasks"] is False
    assert plan["execution_contract"]["approves_proposals"] is False
    assert plan["execution_contract"]["materializes_secrets"] is False
    assert plan["execution_contract"]["uses_credentials"] is False
    assert "encrypted-test-value" not in str(plan)
    for action in plan["actions"]:
        assert action["recommendation_contract"]["operator_review_only"] is True
        assert action["safest_next_validation"]["creates_tasks"] is False
        assert action["safest_next_validation"]["dispatches_work"] is False
