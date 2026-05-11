from __future__ import annotations

from api.app.services.runner_contracts import (
    CONTRACT_VERSION,
    normalize_runner_contract,
    runner_contract_for,
    runner_contract_matrix,
    validate_runner_contract,
)
from api.app.services.runner_registry import runner_capability_registry


def test_runner_contract_matrix_covers_every_registered_runner() -> None:
    registry = runner_capability_registry()
    matrix = runner_contract_matrix()

    assert matrix["contract_version"] == CONTRACT_VERSION
    assert matrix["execution_contract"]["dispatches_work"] is False
    assert matrix["execution_contract"]["mutates_scope"] is False
    assert matrix["execution_contract"]["mutates_approvals"] is False
    assert matrix["summary"]["registered_runner_count"] == len(registry["registered_tools"])
    assert matrix["summary"]["valid_contract_count"] == len(registry["registered_tools"])
    assert matrix["summary"]["gap_count"] == 0
    assert matrix["summary"]["complete"] is True
    assert {contract["runner"] for contract in matrix["contracts"]} == set(registry["registered_tools"])


def test_runner_contract_declares_selection_report_and_approval_contract() -> None:
    contract = runner_contract_for("graphql-probe")

    assert contract["runner"] == "graphql-probe"
    assert contract["validation"]["valid"] is True
    assert "graphql_endpoint" in contract["trigger_signals"]["strong"]
    assert "approved_scope" in contract["prerequisites"]
    assert contract["blockers"]
    assert contract["risk_tier"] in {"active", "intrusive"}
    assert contract["cost"] in {"low", "medium", "high"}
    assert contract["expected_evidence"]
    assert contract["approval"]["required"] is True
    assert contract["approval"]["approval_reason_ids"]
    assert contract["report_mapping"]
    assert all(item["evidence_key"] for item in contract["report_mapping"])
    assert contract["provenance"]["approval_gates_bypassed"] is False


def test_contract_validation_reports_missing_required_selection_fields() -> None:
    invalid_contract = {
        "runner": "partial-runner",
        "trigger_signals": {"strong": [], "weak": []},
        "prerequisites": [],
        "blockers": [],
        "risk_tier": "active",
        "cost": "low",
        "expected_evidence": [],
        "approval": {"required": True, "required_approvals": 1, "approval_reason_ids": []},
        "report_mapping": [],
        "follow_up_candidates": [],
    }

    validation = validate_runner_contract(invalid_contract)

    assert validation["valid"] is False
    assert "trigger_signals" in validation["invalid_fields"]
    assert "prerequisites" in validation["invalid_fields"]
    assert "blockers" in validation["invalid_fields"]
    assert "expected_evidence" in validation["invalid_fields"]
    assert "approval.approval_reason_ids" in validation["invalid_fields"]
    assert "report_mapping" in validation["invalid_fields"]


def test_normalized_contract_derives_report_mapping_from_expected_evidence() -> None:
    contract = normalize_runner_contract(
        {
            "name": "sample-runner",
            "category": "sample",
            "risk_tier": "passive",
            "required_approvals": 0,
            "estimated_minutes": 1,
            "triggers": ["web_target_present"],
            "weak_triggers": [],
            "blockers": ["no_target"],
            "prerequisites": ["approved_scope"],
            "expected_evidence": ["finding_id", "inventory_snapshot", "stdout_hash"],
            "follow_up_tools": ["httpx"],
            "cost": "low",
            "false_positive_rate": "low",
            "description": "sample",
        }
    )

    mapping = {item["evidence_key"]: item["report_section"] for item in contract["report_mapping"]}
    assert mapping["finding_id"] == "findings"
    assert mapping["inventory_snapshot"] == "inventory"
    assert mapping["stdout_hash"] == "execution_ledger"
    assert contract["follow_up_candidates"] == ["httpx"]
