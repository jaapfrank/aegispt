from __future__ import annotations

from sqlalchemy import func, select

from api.app.models import AgentProposal, Approval, SecretRef, Task
from api.app.services.saas_identity_trust import (
    build_saas_identity_trust_model,
    build_saas_identity_trust_model_from_graph,
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
) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "subtype": subtype or node_type,
        "source_id": node_id,
        "source_ids": [node_id],
        "label": label,
        "confidence": 0.88,
        "evidence_refs": evidence_refs or [f"evidence://{node_id}"],
        "data": data or {},
    }


def test_saas_identity_trust_model_builds_nodes_flags_and_risk_path() -> None:
    model = build_saas_identity_trust_model_from_graph(
        {
            "graph_version": "normalized-evidence-graph-v1",
            "run_id": "run-saas-trust",
            "nodes": [
                _node(
                    "connector:canva",
                    "saas_connector",
                    "Canva OAuth bulk export connector",
                    subtype="oauth_connector",
                    data={
                        "name": "Canva bulk export connector",
                        "provider": "Canva",
                        "client_id": "oauth-client-redacted",
                        "target_dataset": "sensitive customer records export",
                    },
                ),
                _node(
                    "scope:files-read-all",
                    "permission",
                    "files:read:all bulk_export admin",
                    subtype="oauth_scope",
                    data={"scope": "files:read:all", "permission": "bulk_export"},
                ),
                _node(
                    "identity:svc-export",
                    "identity",
                    "service-account:bulk-export",
                    subtype="service_account",
                    data={"subject": "service-account:bulk-export", "type": "service_account"},
                ),
            ],
            "edges": [],
        }
    )

    assert model["execution_contract"]["uses_tokens"] is False
    assert model["execution_contract"]["mutates_saas_api"] is False
    assert model["execution_contract"]["simulates_exfiltration"] is False
    assert model["execution_contract"]["dispatches_work_directly"] is False

    node_types = {node["type"] for node in model["nodes"]}
    assert {
        "saas_app",
        "oauth_client",
        "oauth_scope",
        "service_account",
        "connector",
        "dataset",
    }.issubset(node_types)

    flag_types = {flag["type"] for flag in model["flags"]}
    assert {"excessive_scope", "cross_system_trust"}.issubset(flag_types)
    assert model["risk_paths"]
    path = model["risk_paths"][0]
    assert path["path_type"] == "saas_identity_trust_chain"
    assert path["evidence_refs"]
    assert path["provenance"]["token_use"] is False
    assert path["provenance"]["saas_api_mutation"] is False
    assert path["provenance"]["exfiltration_simulation"] is False

    for edge in model["edges"]:
        assert edge["evidence_refs"]
        assert edge["provenance"]["saas_api_mutation"] is False


def test_saas_identity_trust_model_is_read_only_for_run_evidence(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        before = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Approval, AgentProposal, SecretRef)
        }
        model = build_saas_identity_trust_model(session, run_id=run_id)
        after = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Approval, AgentProposal, SecretRef)
        }

    assert after == before
    assert model["execution_contract"]["uses_credentials"] is False
    assert model["execution_contract"]["materializes_secrets"] is False
    assert model["execution_contract"]["creates_tasks"] is False
    assert model["execution_contract"]["approves_proposals"] is False
    assert "encrypted-test-value" not in str(model)
    assert "saas_app" in model["summary"]["node_types"]
    assert "oauth_scope" in model["summary"]["node_types"]
