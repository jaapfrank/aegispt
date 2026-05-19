from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from api.app.services.runner_registry import runner_capability_registry

CONTRACT_VERSION = "runner-contract-matrix-v1"
RISK_TIERS = {"passive", "active", "intrusive"}
COST_TIERS = {"low", "medium", "high"}
REQUIRED_CONTRACT_FIELDS = {
    "runner",
    "trigger_signals",
    "prerequisites",
    "blockers",
    "risk_tier",
    "cost",
    "expected_evidence",
    "approval",
    "report_mapping",
    "follow_up_candidates",
}


class RunnerContractError(RuntimeError):
    pass


def normalize_runner_contract(capability: dict[str, Any]) -> dict[str, Any]:
    runner = str(capability.get("name") or "").strip()
    if not runner:
        raise RunnerContractError("runner contract is missing runner name")
    required_approvals = _safe_int(capability.get("required_approvals"))
    risk_tier = str(capability.get("risk_tier") or "").strip().lower()
    approval_required = required_approvals > 0 or risk_tier in {"active", "intrusive"}
    contract = {
        "contract_version": CONTRACT_VERSION,
        "contract_id": f"{runner}:adaptive-contract:v1",
        "runner": runner,
        "trigger_signals": {
            "strong": _string_list(capability.get("triggers")),
            "weak": _string_list(capability.get("weak_triggers")),
        },
        "prerequisites": _string_list(capability.get("prerequisites")),
        "blockers": _string_list(capability.get("blockers")),
        "risk_tier": risk_tier,
        "cost": str(capability.get("cost") or "").strip().lower(),
        "estimated_minutes": _safe_int(capability.get("estimated_minutes")),
        "expected_evidence": _string_list(capability.get("expected_evidence")),
        "approval": {
            "required": approval_required,
            "required_approvals": required_approvals,
            "approval_reason_ids": _approval_reason_ids(
                runner=runner,
                risk_tier=risk_tier,
                required_approvals=required_approvals,
            ),
        },
        "report_mapping": _report_mapping(_string_list(capability.get("expected_evidence"))),
        "follow_up_candidates": _string_list(capability.get("follow_up_tools")),
        "metadata_source": capability.get("metadata_source"),
        "provenance": {
            "source": "runner_capability_registry",
            "runtime_mutation": False,
            "approval_gates_bypassed": False,
            "scope_roe_bypassed": False,
        },
    }
    validation = validate_runner_contract(contract)
    contract["validation"] = validation
    if not validation["valid"]:
        missing = ", ".join(validation["missing_fields"] + validation["invalid_fields"])
        raise RunnerContractError(f"runner contract for {runner} is invalid: {missing}")
    return contract


def validate_runner_contract(contract: dict[str, Any]) -> dict[str, Any]:
    missing_fields = sorted(field for field in REQUIRED_CONTRACT_FIELDS if field not in contract)
    invalid_fields: list[str] = []
    trigger_signals = _as_dict(contract.get("trigger_signals"))
    if not _string_list(trigger_signals.get("strong")) and not _string_list(trigger_signals.get("weak")):
        invalid_fields.append("trigger_signals")
    if not _string_list(contract.get("prerequisites")):
        invalid_fields.append("prerequisites")
    if not _string_list(contract.get("blockers")):
        invalid_fields.append("blockers")
    if str(contract.get("risk_tier") or "").strip().lower() not in RISK_TIERS:
        invalid_fields.append("risk_tier")
    if str(contract.get("cost") or "").strip().lower() not in COST_TIERS:
        invalid_fields.append("cost")
    if not _string_list(contract.get("expected_evidence")):
        invalid_fields.append("expected_evidence")
    approval = _as_dict(contract.get("approval"))
    if "required" not in approval or "required_approvals" not in approval:
        invalid_fields.append("approval")
    elif _safe_int(approval.get("required_approvals")) > 0 and not _string_list(
        approval.get("approval_reason_ids")
    ):
        invalid_fields.append("approval.approval_reason_ids")
    if not _as_list(contract.get("report_mapping")):
        invalid_fields.append("report_mapping")
    if not isinstance(contract.get("follow_up_candidates"), list):
        invalid_fields.append("follow_up_candidates")
    return {
        "valid": not missing_fields and not invalid_fields,
        "missing_fields": missing_fields,
        "invalid_fields": sorted(set(invalid_fields)),
    }


def runner_contract_for(runner: str) -> dict[str, Any]:
    normalized_runner = str(runner or "").strip()
    registry = runner_capability_registry()
    for capability in _as_list(registry.get("capabilities")):
        if isinstance(capability, dict) and capability.get("name") == normalized_runner:
            return normalize_runner_contract(capability)
    raise RunnerContractError(f"runner contract for {normalized_runner or '<unknown>'} is missing")


def runner_contract_matrix() -> dict[str, Any]:
    registry = runner_capability_registry()
    contracts: list[dict[str, Any]] = []
    gap_records: list[dict[str, Any]] = []
    for capability in _as_list(registry.get("capabilities")):
        if not isinstance(capability, dict):
            continue
        runner = str(capability.get("name") or "<unknown>")
        try:
            contracts.append(normalize_runner_contract(capability))
        except RunnerContractError as exc:
            gap_records.append(
                {
                    "runner": runner,
                    "gap_type": "invalid_runner_contract",
                    "reason": str(exc),
                    "selection_effect": "adaptive_selection_blocked",
                }
            )
    contract_names = {contract["runner"] for contract in contracts}
    for runner in _string_list(registry.get("registered_tools")):
        if runner not in contract_names:
            gap_records.append(
                {
                    "runner": runner,
                    "gap_type": "missing_runner_contract",
                    "reason": "registered runner has no valid adaptive selection contract",
                    "selection_effect": "adaptive_selection_blocked",
                }
            )
    return {
        "schema_version": 1,
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work": False,
            "mutates_scope": False,
            "mutates_approvals": False,
            "runtime_self_modification": False,
            "approval_gates_bypassed": False,
        },
        "summary": {
            "registered_runner_count": len(_string_list(registry.get("registered_tools"))),
            "valid_contract_count": len(contracts),
            "gap_count": len(gap_records),
            "complete": not gap_records,
        },
        "contracts": sorted(contracts, key=lambda item: item["runner"]),
        "gap_records": sorted(gap_records, key=lambda item: item["runner"]),
    }


def _approval_reason_ids(*, runner: str, risk_tier: str, required_approvals: int) -> list[str]:
    reasons: list[str] = []
    if required_approvals > 0:
        reasons.append(f"{runner}:approval-count:{required_approvals}")
    if risk_tier in {"active", "intrusive"}:
        reasons.append(f"{runner}:risk-tier:{risk_tier}")
    return reasons


def _report_mapping(expected_evidence: list[str]) -> list[dict[str, str]]:
    mapping: list[dict[str, str]] = []
    for evidence_key in expected_evidence:
        lowered = evidence_key.lower()
        if "finding" in lowered:
            section = "findings"
        elif "inventory" in lowered or "asset" in lowered or "service" in lowered:
            section = "inventory"
        elif "coverage" in lowered:
            section = "coverage_truth"
        elif "report" in lowered:
            section = "reports"
        elif "decision" in lowered or "command" in lowered or "stdout" in lowered or "task" in lowered:
            section = "execution_ledger"
        else:
            section = "evidence_appendix"
        mapping.append({"evidence_key": evidence_key, "report_section": section})
    return mapping


def _string_list(value: Any) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in _as_list(value):
        candidate = str(item or "").strip()
        if candidate and candidate not in seen:
            normalized.append(candidate)
            seen.add(candidate)
    return normalized


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]
