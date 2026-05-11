from __future__ import annotations

from sqlalchemy import func, select

from api.app.models import AgentProposal, Approval, SecretRef, Task
from api.app.services.hypothesis_confidence import (
    build_hypothesis_confidence_report,
    score_hypothesis_confidence,
)
from api.tests.test_assessment_graph import _create_graph_fixture


def _node(
    node_id: str,
    node_type: str,
    label: str,
    *,
    subtype: str | None = None,
    data: dict | None = None,
    evidence_refs: list[str] | None = None,
    confidence: float = 0.82,
) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "subtype": subtype or node_type,
        "source_id": node_id,
        "source_ids": [node_id],
        "label": label,
        "confidence": confidence,
        "evidence_refs": evidence_refs or [f"evidence://{node_id}"],
        "data": data or {},
    }


def _confidence_graph() -> dict:
    return {
        "graph_version": "normalized-evidence-graph-v1",
        "run_id": "run-confidence-fixture",
        "nodes": [
            _node(
                "finding:idor",
                "finding",
                "IDOR object authorization issue on account API",
                data={"summary": "Broken access control allows object reference review."},
            ),
            _node(
                "api:accounts",
                "api",
                "https://app.example.test/api/v1/accounts/{account_id}",
            ),
            _node(
                "evidence:idor-contradiction",
                "evidence_ref",
                "Neighboring endpoint returned authorization enforced 403",
            ),
            _node(
                "permission:oauth",
                "permission",
                "files:read:all bulk_export admin OAuth scope",
                data={"scope": "files:read:all", "permission": "bulk_export"},
            ),
            _node(
                "connector:canva",
                "saas_connector",
                "Canva OAuth bulk export connector",
                data={"name": "Canva connector", "target_dataset": "brand-assets"},
            ),
            _node(
                "identity:svc-export",
                "identity",
                "service account oauth export identity",
            ),
            _node(
                "finding:ssrf",
                "finding",
                "SSRF metadata endpoint exposure",
                data={"summary": "Server-side request metadata IMDS evidence was imported."},
            ),
            _node(
                "api:metadata",
                "api",
                "http://169.254.169.254/latest/meta-data IAM role metadata",
            ),
            _node(
                "identity:iam-role",
                "identity",
                "cloud IAM role service account",
            ),
            _node(
                "finding:weak-auth",
                "finding",
                "Weak auth missing MFA on login",
                data={"summary": "No MFA evidence and session exposure on login route."},
            ),
            _node(
                "api:login",
                "api",
                "https://app.example.test/login auth session endpoint",
            ),
            _node(
                "credential:connector",
                "credential_ref",
                "service account session connector ref",
                data={"raw_secret_material_exposed": False, "vault_pointer": "aegispt://secret-ref/redacted"},
            ),
        ],
        "edges": [],
    }


def test_hypothesis_confidence_scores_required_hypothesis_families() -> None:
    report = score_hypothesis_confidence(_confidence_graph())

    assert report["execution_contract"]["dispatches_work_directly"] is False
    assert report["execution_contract"]["creates_tasks"] is False
    assert report["execution_contract"]["approves_proposals"] is False
    assert report["execution_contract"]["uses_credentials"] is False

    hypotheses = {item["hypothesis_type"]: item for item in report["hypotheses"]}
    assert {
        "idor",
        "oauth_scope",
        "ssrf_to_cloud",
        "weak_auth",
        "saas_connector_exposure",
    }.issubset(hypotheses)

    for hypothesis in hypotheses.values():
        assert 0 < hypothesis["confidence"] <= 1
        assert hypothesis["confidence_label"] in {"low", "medium", "high"}
        assert hypothesis["supporting_evidence"]
        assert hypothesis["missing_evidence"]
        step = hypothesis["next_safe_validation_step"]
        assert step["action_type"] == "operator_review"
        assert step["operator_review_only"] is True
        assert step["creates_tasks"] is False
        assert step["dispatches_work"] is False
        assert step["approves_proposals"] is False
        assert step["mutates_scope"] is False
        assert step["uses_credentials"] is False
        assert step["materializes_secrets"] is False
        assert step["accesses_live_targets"] is False

    assert hypotheses["idor"]["contradicting_evidence"]
    assert any(item["id"] == "authorization_comparison" for item in hypotheses["idor"]["missing_evidence"])
    assert any(item["id"] == "consent_record" for item in hypotheses["oauth_scope"]["missing_evidence"])
    assert any(item["id"] == "metadata_access_boundary" for item in hypotheses["ssrf_to_cloud"]["missing_evidence"])
    assert any(item["id"] == "auth_policy_record" for item in hypotheses["weak_auth"]["missing_evidence"])
    assert any(item["id"] == "export_audit_log" for item in hypotheses["saas_connector_exposure"]["missing_evidence"])


def test_hypothesis_confidence_report_is_read_only_and_redacted(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        before = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Approval, AgentProposal, SecretRef)
        }
        report = build_hypothesis_confidence_report(session, run_id=run_id)
        after = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Approval, AgentProposal, SecretRef)
        }

    assert after == before
    assert report["execution_contract"]["creates_tasks"] is False
    assert report["execution_contract"]["approves_proposals"] is False
    assert report["execution_contract"]["materializes_secrets"] is False
    assert report["execution_contract"]["uses_credentials"] is False
    assert "encrypted-test-value" not in str(report)
    assert all(
        hypothesis["recommendation_contract"]["operator_review_only"] is True
        for hypothesis in report["hypotheses"]
    )
