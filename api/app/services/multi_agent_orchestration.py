from __future__ import annotations

from typing import Any

from api.app.models import Run

ROLE_PRIMITIVES: list[dict[str, Any]] = [
    {
        "role_id": "mission_lead",
        "label": "Mission Lead Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "maintain scoped objectives",
            "coordinate review-only handoffs",
            "keep mission state aligned with rules of engagement",
        ],
        "allowed_handoff_types": ["mission_to_policy_review", "mission_to_execution_planning"],
        "forbidden_actions": ["scope_expansion", "tool_execution", "approval_granting"],
        "provenance_requirements": ["run_id", "operator_actor", "policy_check_ids"],
    },
    {
        "role_id": "inventory_surface",
        "label": "Inventory and Surface Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "normalize stored discovery outputs",
            "summarize hosts, services, applications, APIs, and assumptions",
        ],
        "allowed_handoff_types": ["inventory_to_relevance"],
        "forbidden_actions": ["network_scanning", "worker_dispatch", "scope_expansion"],
        "provenance_requirements": ["inventory_snapshot_ids", "source_task_ids", "evidence_refs"],
    },
    {
        "role_id": "threat_relevance",
        "label": "Threat and Relevance Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "map stored inventory context to local relevance signals",
            "propose review-only coverage themes",
        ],
        "allowed_handoff_types": ["relevance_to_capability_forge", "relevance_to_policy_review"],
        "forbidden_actions": ["external_feed_fetch_during_run", "finding_mutation", "severity_mutation"],
        "provenance_requirements": ["relevance_decision_ids", "threat_intel_refs", "methodology_tags"],
    },
    {
        "role_id": "capability_forge",
        "label": "Capability Forge Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "prepare pack-refinement proposals",
            "route artifacts into the existing Codex build lane",
        ],
        "allowed_handoff_types": ["forge_to_codex_build_lane", "forge_to_pack_validation"],
        "forbidden_actions": ["pack_approval", "pack_deployment", "runtime_binding"],
        "provenance_requirements": ["pack_id", "pack_version", "codex_task_id", "validation_result_id"],
    },
    {
        "role_id": "execution_planner",
        "label": "Execution Planner Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "prepare operator-reviewable follow-up plans",
            "preserve approved run profiles and staged progression",
        ],
        "allowed_handoff_types": ["plan_to_policy_review", "plan_to_operator_review"],
        "forbidden_actions": ["task_creation", "run_dispatch", "approval_granting"],
        "provenance_requirements": ["run_profile_name", "required_approval_count", "operator_actor"],
    },
    {
        "role_id": "evidence_qa",
        "label": "Evidence and QA Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "check evidence completeness",
            "flag contradictions between stored tasks, findings, and reports",
        ],
        "allowed_handoff_types": ["evidence_to_reporting", "evidence_to_policy_review"],
        "forbidden_actions": ["artifact_content_write", "finding_status_change", "report_fact_mutation"],
        "provenance_requirements": ["evidence_refs", "artifact_ids", "finding_ids"],
    },
    {
        "role_id": "reporting_assurance",
        "label": "Reporting and Assurance Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "prepare review-only report and assurance summaries",
            "preserve source-traceable evidence references",
        ],
        "allowed_handoff_types": ["reporting_to_operator_review"],
        "forbidden_actions": ["unreviewed_customer_claim", "certification_claim", "canonical_report_replacement"],
        "provenance_requirements": ["report_variant", "source_categories", "evidence_refs"],
    },
    {
        "role_id": "safety_policy",
        "label": "Safety and Policy Agent",
        "activation_state": "inactive_planning",
        "responsibilities": [
            "check authorization, scope, approvals, pack gates, and kill-switch readiness",
            "block unsupported or scope-broadening handoffs",
        ],
        "allowed_handoff_types": ["policy_to_operator_review"],
        "forbidden_actions": ["policy_bypass", "silent_approval", "kill_switch_bypass"],
        "provenance_requirements": ["policy_check_ids", "blocking_reasons", "operator_actor"],
    },
]

HANDOFF_PRIMITIVES: list[dict[str, Any]] = [
    {
        "handoff_type": "mission_to_policy_review",
        "source_role_id": "mission_lead",
        "target_role_id": "safety_policy",
        "activation_state": "inactive_planning",
        "allowed_payload": ["mission_objectives", "scope_summary", "requested_follow_up"],
        "forbidden_effects": ["scope_expansion", "run_dispatch", "approval_granting"],
    },
    {
        "handoff_type": "inventory_to_relevance",
        "source_role_id": "inventory_surface",
        "target_role_id": "threat_relevance",
        "activation_state": "inactive_planning",
        "allowed_payload": ["inventory_snapshot_ids", "normalized_assets", "confidence_notes"],
        "forbidden_effects": ["external_lookup", "finding_mutation", "task_creation"],
    },
    {
        "handoff_type": "relevance_to_capability_forge",
        "source_role_id": "threat_relevance",
        "target_role_id": "capability_forge",
        "activation_state": "inactive_planning",
        "allowed_payload": ["relevance_decision_ids", "methodology_tags", "pack_context"],
        "forbidden_effects": ["pack_approval", "pack_deployment", "runtime_binding"],
    },
    {
        "handoff_type": "plan_to_operator_review",
        "source_role_id": "execution_planner",
        "target_role_id": "mission_lead",
        "activation_state": "inactive_planning",
        "allowed_payload": ["profile_name", "approval_requirements", "operator_next_action"],
        "forbidden_effects": ["task_creation", "run_dispatch", "autonomous_tool_execution"],
    },
    {
        "handoff_type": "evidence_to_reporting",
        "source_role_id": "evidence_qa",
        "target_role_id": "reporting_assurance",
        "activation_state": "inactive_planning",
        "allowed_payload": ["finding_ids", "evidence_refs", "quality_notes"],
        "forbidden_effects": ["finding_status_change", "report_fact_mutation", "customer_claim_finalization"],
    },
]

POLICY_CHECKS: list[dict[str, Any]] = [
    {
        "check_id": "scope_authorization",
        "required_before_activation": True,
        "blocking_default": True,
        "description": "Every handoff must remain inside stored engagement scope and denylist boundaries.",
    },
    {
        "check_id": "operator_approval",
        "required_before_activation": True,
        "blocking_default": True,
        "description": "Any state-changing follow-up must route through explicit operator approval.",
    },
    {
        "check_id": "pack_lifecycle_gate",
        "required_before_activation": True,
        "blocking_default": True,
        "description": "Pack validation, approval, deployment, and runtime binding stay on existing lifecycle APIs.",
    },
    {
        "check_id": "worker_identity",
        "required_before_activation": True,
        "blocking_default": True,
        "description": "Future worker execution requires registered worker identity and task provenance.",
    },
    {
        "check_id": "evidence_provenance",
        "required_before_activation": True,
        "blocking_default": True,
        "description": "Every agent output must reference stored run, task, evidence, finding, or pack records.",
    },
    {
        "check_id": "kill_switch_ready",
        "required_before_activation": True,
        "blocking_default": True,
        "description": "Activation requires operator-visible stop controls and degraded-state handling.",
    },
]

PROVENANCE_METADATA_SHAPE: dict[str, Any] = {
    "required_fields": [
        "agent_role_id",
        "handoff_type",
        "source_run_id",
        "source_task_ids",
        "source_evidence_refs",
        "policy_check_ids",
        "operator_actor",
        "worker_identity",
        "created_at",
    ],
    "optional_fields": [
        "tenant_id",
        "pack_id",
        "pack_version",
        "codex_task_id",
        "relevance_decision_id",
        "inventory_snapshot_id",
        "finding_ids",
        "reasoning_record_id",
    ],
    "write_boundary": (
        "Metadata shape is advisory and inactive. No multi-agent records are created by this baseline."
    ),
}

ACTIVATION_REQUIREMENTS: list[str] = [
    "Promote a future task that explicitly activates multi-agent behavior.",
    "Keep roles, handoffs, and policy checks operator-visible before activation.",
    "Require scope, approval, pack lifecycle, runtime binding, worker identity, evidence provenance, and kill-switch checks.",
    "Block hidden agents, hidden workflows, autonomous tool execution, scope-broadening handoffs, and uncontrolled worker coordination.",
    "Record provenance for every future role output before it can influence runtime state.",
]


def build_multi_agent_orchestration_readiness(run: Run) -> dict[str, Any]:
    activation_request = _detect_forbidden_activation_request(dict(run.configuration_json or {}))
    return {
        "status": "inactive_preparation",
        "active": False,
        "runtime_enabled": False,
        "hidden_agents_enabled": False,
        "distributed_offensive_runtime_enabled": False,
        "autonomous_tool_execution_enabled": False,
        "uncontrolled_worker_coordination_enabled": False,
        "scope_broadening_handoffs_allowed": False,
        "operator_activation_required": True,
        "kill_switch_required": True,
        "stricter_than_single_agent_planning": True,
        "run_context": {
            "run_id": str(run.id),
            "engagement_id": str(run.engagement_id),
            "profile_name": run.profile.name if run.profile is not None else None,
            "status": run.status,
        },
        "roles": ROLE_PRIMITIVES,
        "allowed_handoff_types": HANDOFF_PRIMITIVES,
        "policy_checks": POLICY_CHECKS,
        "provenance_metadata_shape": PROVENANCE_METADATA_SHAPE,
        "activation_requirements": ACTIVATION_REQUIREMENTS,
        "forbidden_activation_request": activation_request,
        "boundary": {
            "planning_primitives_only": True,
            "creates_agent_records": False,
            "creates_tasks": False,
            "dispatches_work": False,
            "approves_work": False,
            "validates_or_deploys_packs": False,
            "binds_runtime_packs": False,
            "changes_worker_runtime": False,
            "changes_finding_schema": False,
        },
    }


def _detect_forbidden_activation_request(configuration: dict[str, Any]) -> dict[str, Any]:
    multi_agent_config = configuration.get("multi_agent_orchestration")
    requested_keys: list[str] = []
    if isinstance(multi_agent_config, dict):
        requested_keys = sorted(str(key) for key in multi_agent_config.keys())

    requested = bool(multi_agent_config)
    return {
        "present": requested,
        "blocked": requested,
        "accepted": False,
        "requested_keys": requested_keys,
        "reason": (
            "Multi-agent orchestration activation is not implemented in this baseline; "
            "configuration is treated as non-executable planning input only."
        )
        if requested
        else None,
    }
