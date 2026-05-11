from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import AgentProposal, RationaleLedgerEntry, Run, Scope, Task
from api.app.policy.engine import normalize_profile_limits
from api.app.services.ai_action_selector import select_next_best_action_for_run
from api.app.services.ai_enrichment import store_agent_proposal_record, store_agent_reasoning_record
from api.app.services.ai_planner import (
    RECURSIVE_CONTEXT_KIND,
    ensure_context_document,
    ensure_recursive_surface_context,
    latest_context_document,
    record_rationale,
)
from api.app.services.assessment_planner import build_assessment_plan_for_run
from api.app.services.audit import write_audit_event
from api.app.services.run_credential_vault import (
    clear_run_credential_vault_if_terminal,
    inject_run_credential_vault_into_task,
)
from api.app.services.runs import (
    derive_targets_for_run,
    pending_approvals,
    planned_targets_for_tool,
    target_value_is_allowed,
)
from api.app.services.task_dispatch import supported_execution_tools

LOOP_VERSION = "2026-05-07.1"
LOOP_CONFIG_KEY = "ai_assessment_loop"
GOAL_REASONING_KIND = "assessment_loop_goal_oriented_reasoning"
LOOP_MAX_ITERATIONS = 20
LOOP_STUCK_THRESHOLD = 3
LOOP_ACTIVE_TASK_STATUSES = {"queued", "pending", "running", "dispatching", "in_progress", "started"}
LOOP_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "skipped"}
LOOP_PROPOSAL_KIND = "assessment_loop_next_action"
LOOP_SEED_TOOLS_BY_TARGET_KIND = {
    "url": "httpx",
    "host": "nmap",
    "cidr": "nmap",
    "domain": "easm-discover",
    "target": "httpx",
}
LOOP_LOW_IMPACT_AUTO_TOOLS = {"httpx", "nmap", "easm-discover", "external-osint", "aws-inventory"}


@dataclass(frozen=True)
class LoopCandidate:
    tool: str
    target: str
    params: dict[str, Any]
    tier: str
    reasoning: str
    confidence: float
    follow_up_hints: list[str]
    expected_evidence: list[str]
    required_approvals: int
    decision_source: str
    selector_decision: str | None = None
    selector_rank: int | None = None
    selector_provenance: dict[str, Any] | None = None


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _loop_state(configuration: dict[str, Any]) -> dict[str, Any]:
    state = _as_dict(configuration.get(LOOP_CONFIG_KEY))
    iterations = [dict(item) for item in _as_list(state.get("iterations")) if isinstance(item, dict)]
    goal_reasoning = _as_dict(state.get("goal_oriented_reasoning"))
    return {
        "enabled": bool(state.get("enabled", True)),
        "run_mode": "ai_loop",
        "version": str(state.get("version") or LOOP_VERSION),
        "max_iterations": int(state.get("max_iterations") or LOOP_MAX_ITERATIONS),
        "stuck_threshold": int(state.get("stuck_threshold") or LOOP_STUCK_THRESHOLD),
        "iteration_count": int(state.get("iteration_count") or len(iterations)),
        "no_new_signal_iterations": int(state.get("no_new_signal_iterations") or 0),
        "status": str(state.get("status") or "ready"),
        "stop_reason": state.get("stop_reason"),
        "latest_evidence_fingerprint": str(state.get("latest_evidence_fingerprint") or ""),
        "latest_next_action": _as_dict(state.get("latest_next_action")) or None,
        "goal_oriented_reasoning": goal_reasoning,
        "iterations": iterations,
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
    }


def _store_loop_state(configuration: dict[str, Any], state: dict[str, Any]) -> None:
    configuration[LOOP_CONFIG_KEY] = {
        "enabled": True,
        "run_mode": "ai_loop",
        "version": LOOP_VERSION,
        "max_iterations": int(state.get("max_iterations") or LOOP_MAX_ITERATIONS),
        "stuck_threshold": int(state.get("stuck_threshold") or LOOP_STUCK_THRESHOLD),
        "iteration_count": int(state.get("iteration_count") or 0),
        "no_new_signal_iterations": int(state.get("no_new_signal_iterations") or 0),
        "status": str(state.get("status") or "ready"),
        "stop_reason": state.get("stop_reason"),
        "latest_evidence_fingerprint": str(state.get("latest_evidence_fingerprint") or ""),
        "latest_next_action": state.get("latest_next_action"),
        "goal_oriented_reasoning": _as_dict(state.get("goal_oriented_reasoning")),
        "iterations": list(state.get("iterations") or []),
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
    }


def _run_uses_ai_loop(run: Run) -> bool:
    configuration = _as_dict(run.configuration_json)
    loop_config = _as_dict(configuration.get(LOOP_CONFIG_KEY))
    return configuration.get("run_mode") == "ai_loop" or loop_config.get("run_mode") == "ai_loop"


def _targets_for_loop(scope: Scope, run: Run) -> list[dict[str, str]]:
    targets = derive_targets_for_run(scope, run)
    return [target for target in targets if str(target.get("value") or "").strip()]


def _target_type(targets: list[dict[str, str]]) -> str:
    kinds = {str(target.get("kind") or "") for target in targets}
    if "cidr" in kinds:
        return "cidr"
    if "url" in kinds:
        return "url"
    if "host" in kinds:
        return "ip_or_host"
    if "domain" in kinds:
        return "domain"
    return "unknown"


def _task_key(tool: str, target: str) -> str:
    return f"{str(tool).strip()}::{str(target).strip()}"


def _tested_action_keys(run: Run) -> set[str]:
    keys: set[str] = set()
    for task in list(run.tasks or []):
        keys.add(_task_key(task.tool, task.target_id))
    for proposal in list(run.agent_proposals or []):
        metadata = _as_dict(proposal.metadata_json)
        if metadata.get("proposal_kind") == LOOP_PROPOSAL_KIND:
            keys.add(_task_key(proposal.proposed_tool, proposal.proposed_target))
    configuration = _as_dict(run.configuration_json)
    state = _loop_state(configuration)
    for iteration in state.get("iterations", []):
        action = _as_dict(iteration.get("next_action"))
        tool = str(action.get("tool") or "").strip()
        target = str(action.get("target") or "").strip()
        if tool and target:
            keys.add(_task_key(tool, target))
    return keys


def _active_loop_tasks(run: Run) -> list[dict[str, str]]:
    active: list[dict[str, str]] = []
    for task in list(run.tasks or []):
        status = str(task.status or "").strip().lower()
        params = _as_dict(task.params_json)
        if status in LOOP_ACTIVE_TASK_STATUSES and (
            isinstance(params.get("assessment_loop"), dict)
            or isinstance(params.get("ai_proposal"), dict)
        ):
            active.append({"task_id": str(task.id), "tool": task.tool, "target": task.target_id, "status": status})
    return active


def _evidence_fingerprint(run: Run) -> str:
    task_bits = [
        f"task:{task.id}:{task.tool}:{task.target_id}:{task.status}"
        for task in sorted(list(run.tasks or []), key=lambda item: str(item.id))
        if str(task.status or "").lower() in LOOP_TERMINAL_STATUSES
    ]
    finding_bits = [
        f"finding:{finding.id}:{finding.title}:{finding.target_id}:{finding.evidence_ref}"
        for finding in sorted(list(run.findings or []), key=lambda item: str(item.id))
    ]
    snapshot = run.source_inventory_snapshot
    snapshot_bits: list[str] = []
    if snapshot is not None:
        inventory = _as_dict(snapshot.normalized_inventory_json)
        profile = _as_dict(inventory.get("signal_profile"))
        signal_keys = [
            str(item.get("key") or "")
            for item in _as_list(profile.get("signals"))
            if isinstance(item, dict)
        ]
        snapshot_bits.append(f"snapshot:{snapshot.id}:{','.join(sorted(signal_keys))}")
    return "|".join([*task_bits, *finding_bits, *snapshot_bits]) or "no-evidence"


def _current_state_payload(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    evidence_fingerprint: str,
) -> dict[str, Any]:
    inventory_snapshot = run.source_inventory_snapshot
    inventory = (
        _as_dict(inventory_snapshot.normalized_inventory_json)
        if inventory_snapshot is not None
        else {}
    )
    signal_profile = _as_dict(inventory.get("signal_profile"))
    return {
        "target_type": _target_type(targets),
        "targets": targets,
        "inventory_snapshot_id": str(inventory_snapshot.id) if inventory_snapshot is not None else None,
        "signal_count": len(_as_list(signal_profile.get("signals"))),
        "finding_count": len(list(run.findings or [])),
        "task_count": len(list(run.tasks or [])),
        "tested_paths": [
            {"tool": task.tool, "target": task.target_id, "status": task.status}
            for task in list(run.tasks or [])
        ],
        "open_threads": [
            {
                "proposal_id": str(proposal.id),
                "tool": proposal.proposed_tool,
                "target": proposal.proposed_target,
                "status": proposal.status,
            }
            for proposal in list(run.agent_proposals or [])
            if proposal.status == "pending_review"
        ],
        "evidence_fingerprint": evidence_fingerprint,
        "scope_enforced": True,
        "roe_required": bool(scope.roe_ref if hasattr(scope, "roe_ref") else True),
    }


def _capability_item(plan: dict[str, Any], tool: str) -> dict[str, Any]:
    for item in plan.get("runners", []):
        if isinstance(item, dict) and str(item.get("runner") or "") == tool:
            return item
    return {}


def _tier_from_capability(item: dict[str, Any], tool: str) -> str:
    risk_tier = str(item.get("risk_tier") or "active").strip().lower()
    required_approvals = int(item.get("required_approvals") or 0)
    if risk_tier == "intrusive" or required_approvals >= 2:
        return "intrusive"
    if required_approvals >= 1:
        return "active"
    if tool in LOOP_LOW_IMPACT_AUTO_TOOLS:
        return "passive"
    return "active"


def _scope_target_allowed(scope: Scope, target: str) -> bool:
    if target_value_is_allowed(scope.denylist_json, target):
        return False
    return target_value_is_allowed(scope.allowlist_json, target)


def _objective_type(objective: str) -> str:
    text = objective.lower()
    if "gruyere" in text or (
        "xss" in text
        and any(token in text for token in ("admin", "cookie", "session", "command injection", "controlled proof"))
    ):
        return "gruyere_multi_step_objective"
    if any(token in text for token in ("domain admin", "active directory", "kerberos", "ldap", "bloodhound")):
        return "identity_admin_objective"
    if any(token in text for token in ("billing", "database", "db", "sql", "customer data", "records")):
        return "data_access_objective"
    if any(token in text for token in ("/etc/shadow", "shadow", "file read", "secret file", "config file")):
        return "sensitive_file_objective"
    if any(token in text for token in ("session", "token", "cookie", "admin panel", "authenticated")):
        return "session_exposure_objective"
    return "custom_objective"


def _goal_tool_sequence(objective_type: str, target_type: str) -> list[str]:
    if objective_type == "gruyere_multi_step_objective":
        return ["httpx", "xss-extended", "session-security", "client-state", "ssti-probe"]
    if objective_type == "identity_admin_objective":
        return ["nmap", "ldap-enum", "bloodhound-collect", "netexec", "credential-attacks"]
    if objective_type == "data_access_objective":
        first = "nmap" if target_type in {"cidr", "ip_or_host"} else "httpx"
        return [first, "content-discovery", "api-assessment", "sqlmap", "auth-flow", "session-security", "idor-bac"]
    if objective_type == "sensitive_file_objective":
        first = "nmap" if target_type in {"cidr", "ip_or_host"} else "httpx"
        return [first, "content-discovery", "ssrf-probe", "xxe-probe", "ssti-probe"]
    if objective_type == "session_exposure_objective":
        return ["httpx", "auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"]
    return ["httpx", "content-discovery", "api-assessment", "auth-flow", "session-security"]


def _target_candidates_for_tool(tool: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    candidates = planned_targets_for_tool(tool, targets, derive_url_hosts_for_nmap=True)
    return [
        {"kind": str(item.get("kind") or "target"), "value": str(item.get("value") or "").strip()}
        for item in candidates
        if str(item.get("value") or "").strip()
    ]


def _goal_stage(tool: str, tier: str) -> str:
    if tool in LOOP_LOW_IMPACT_AUTO_TOOLS:
        return "observe_surface"
    if tool == "xss-extended":
        return "validate_initial_browser_execution"
    if tool == "ssti-probe":
        return "approval_gated_controlled_proof"
    if tool in {"auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"}:
        return "validate_session_exposure_risk"
    if tier == "intrusive":
        return "approval_gated_controlled_proof"
    return "controlled_proof_candidate"


def _goal_reason(tool: str, objective: str, objective_type: str) -> str:
    if tool in {"httpx", "nmap", "easm-discover"}:
        return (
            f"Establish approved surface evidence for the operator objective '{objective}' before any "
            "deeper controlled proof step is proposed."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "xss-extended":
        return (
            "Validate the Gruyere browser-execution entry point with the registered XSS runner before "
            "using any reviewed session or admin-surface evidence for follow-up."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "session-security":
        return (
            "Review session exposure risk from the confirmed Gruyere XSS path and keep any cookie or "
            "token material behind redacted evidence and secret-binding controls."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "client-state":
        return (
            "Use reviewed session evidence only through the registered client-state runner to test the "
            "authenticated Gruyere admin surface without bypassing scope or approval gates."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "ssti-probe":
        return (
            "Produce a bounded Gruyere controlled proof with math-expression canary evidence only; "
            "command payloads, file writes, callbacks, and persistence remain prohibited."
        )
    if tool == "sqlmap":
        return (
            "Use sqlmap only after injectable-parameter or SQL-error evidence exists; any data-layer "
            "check remains a controlled proof with canary evidence."
        )
    if tool in {"auth-flow", "session-security", "jwt-probe"}:
        return (
            "Map authentication and session behavior for session exposure risk without handling raw "
            "credential material outside approved secret references."
        )
    if tool in {"ldap-enum", "bloodhound-collect"}:
        return (
            "Collect read-only identity evidence to test whether the objective has an approved path "
            "through directory relationships."
        )
    if tool in {"netexec", "credential-attacks", "metasploit", "impacket-lateral"}:
        return (
            "Hold this as an approval-gated controlled proof candidate; execution requires the existing "
            "ROE tier and operator approval flow."
        )
    if objective_type == "sensitive_file_objective":
        return "Look for bounded file exposure indicators and prefer canary evidence over sensitive content."
    return "Select this registered runner only if current evidence supports the objective path."


def _goal_evidence_links(
    *,
    run: Run,
    scope: Scope,
    context_document,
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = [
        {"type": "approved_scope", "id": str(scope.id)},
        {"type": "target_context_document", "id": str(context_document.id)},
    ]
    for ref in _as_list(context_document.evidence_refs_json):
        if isinstance(ref, dict):
            links.append({"type": "context_evidence", **ref})
    for task in list(run.tasks or []):
        if str(task.status or "").lower() in LOOP_TERMINAL_STATUSES:
            links.append({"type": "runner_output", "id": str(task.id), "tool": task.tool, "status": task.status})
    for finding in list(run.findings or []):
        links.append(
            {
                "type": "finding",
                "id": str(finding.id),
                "title": finding.title,
                "target": finding.target_id,
                "evidence_ref": finding.evidence_ref,
            }
        )
    return links


def _run_signal_keys(run: Run) -> set[str]:
    snapshot = run.source_inventory_snapshot
    if snapshot is None:
        return set()
    inventory = _as_dict(snapshot.normalized_inventory_json)
    profile = _as_dict(inventory.get("signal_profile"))
    return {
        str(item.get("key") or "").strip()
        for item in _as_list(profile.get("signals"))
        if isinstance(item, dict) and str(item.get("key") or "").strip()
    }


def _goal_step_ready(run: Run, step: dict[str, Any]) -> bool:
    tool = str(step.get("tool") or "")
    signal_keys = _run_signal_keys(run)
    finding_titles = " ".join(str(finding.title or "").lower() for finding in list(run.findings or []))
    if tool == "sqlmap":
        return bool({"injectable_parameter", "sql_error_pattern"} & signal_keys) or "sql injection" in finding_titles
    return True


def _build_goal_oriented_reasoning(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    context_document,
    objective: str,
    actor: str,
    operator_note: str | None,
) -> dict[str, Any]:
    objective_type = _objective_type(objective)
    target_type = _target_type(targets)
    supported_tools = supported_execution_tools()
    evidence_links = _goal_evidence_links(run=run, scope=scope, context_document=context_document)
    path: list[dict[str, Any]] = []
    for tool in _goal_tool_sequence(objective_type, target_type):
        if tool not in supported_tools:
            continue
        candidates = [
            item
            for item in _target_candidates_for_tool(tool, targets)
            if _scope_target_allowed(scope, str(item.get("value") or ""))
        ]
        if not candidates:
            continue
        plan_item = _capability_item(plan, tool)
        tier = _tier_from_capability(plan_item, tool)
        required_approvals = int(plan_item.get("required_approvals") or (1 if tier in {"active", "intrusive"} else 0))
        order = len(path) + 1
        path.append(
            {
                "id": f"goal-step-{order}-{tool}",
                "order": order,
                "objective_type": objective_type,
                "stage": _goal_stage(tool, tier),
                "tool": tool,
                "tier": tier,
                "target_candidates": candidates,
                "reason": _goal_reason(tool, objective, objective_type),
                "expected_evidence": list(plan_item.get("expected_evidence") or []),
                "follow_up_hints": list(plan_item.get("follow_up_tools") or []),
                "required_approvals": required_approvals,
                "requires_operator_approval": tier in {"active", "intrusive"} or required_approvals > 0,
                "registered_runner_required": True,
                "scope_enforced": True,
                "roe_enforced": True,
                "kill_switch_still_authoritative": True,
                "controlled_proof_required": tier in {"active", "intrusive"} or tool not in LOOP_LOW_IMPACT_AUTO_TOOLS,
                "canary_evidence_preferred": tool in {"sqlmap", "ssrf-probe", "xxe-probe", "ssti-probe"},
                "session_exposure_risk_review": tool
                in {"auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"},
                "dispatches_work": False,
                "evidence_links": evidence_links,
            }
        )
    return {
        "status": "recorded",
        "objective": objective,
        "objective_type": objective_type,
        "operator_note": operator_note,
        "recorded_by": actor,
        "recorded_at": _now(),
        "run_mode": "ai_loop",
        "hypothesis_path": path,
        "evidence_links": evidence_links,
        "bounded_goal_hypothesis": True,
        "dispatches_work_directly": False,
        "registered_runner_required": True,
        "scope_enforced": True,
        "roe_enforced": True,
        "approval_gates_bypassed": False,
        "kill_switch_still_authoritative": True,
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
        "context_document_id": str(context_document.id),
    }


def _goal_oriented_candidate(
    *,
    run: Run,
    scope: Scope,
    goal_reasoning: dict[str, Any],
    plan: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    if not goal_reasoning or goal_reasoning.get("run_mode") != "ai_loop":
        return None
    if goal_reasoning.get("status") != "recorded":
        return None
    for step in _as_list(goal_reasoning.get("hypothesis_path")):
        if not isinstance(step, dict) or not _goal_step_ready(run, step):
            continue
        tool = str(step.get("tool") or "").strip()
        if not tool or tool not in supported_execution_tools():
            continue
        for target in _as_list(step.get("target_candidates")):
            if not isinstance(target, dict):
                continue
            target_value = str(target.get("value") or "").strip()
            if not target_value:
                continue
            if _task_key(tool, target_value) in tested_keys:
                continue
            if not _scope_target_allowed(scope, target_value):
                continue
            plan_item = _capability_item(plan, tool)
            tier = _tier_from_capability(plan_item, tool)
            required_approvals = int(step.get("required_approvals") or plan_item.get("required_approvals") or 0)
            return LoopCandidate(
                tool=tool,
                target=target_value,
                params={
                    "target_kind": target.get("kind"),
                    "source": "goal_oriented_reasoning",
                    "goal_oriented_reasoning": {
                        "objective": goal_reasoning.get("objective"),
                        "objective_type": goal_reasoning.get("objective_type"),
                        "hypothesis_step_id": step.get("id"),
                        "hypothesis_order": step.get("order"),
                        "stage": step.get("stage"),
                        "evidence_links": list(step.get("evidence_links") or []),
                        "controlled_proof_required": bool(step.get("controlled_proof_required")),
                        "canary_evidence_preferred": bool(step.get("canary_evidence_preferred")),
                        "session_exposure_risk_review": bool(step.get("session_exposure_risk_review")),
                    },
                },
                tier=tier,
                reasoning=str(step.get("reason") or "Select the next registered runner for the objective path."),
                confidence=0.84,
                follow_up_hints=list(step.get("follow_up_hints") or plan_item.get("follow_up_tools") or []),
                expected_evidence=list(step.get("expected_evidence") or plan_item.get("expected_evidence") or []),
                required_approvals=required_approvals,
                decision_source="goal_oriented_reasoning",
            )
    return None


def _seed_candidate(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    tested_keys: set[str],
    recommended_tools: set[str] | None = None,
) -> LoopCandidate | None:
    if tested_keys:
        return None
    for target in targets:
        kind = str(target.get("kind") or "").strip()
        value = str(target.get("value") or "").strip()
        tool = LOOP_SEED_TOOLS_BY_TARGET_KIND.get(kind)
        if not tool or not value:
            continue
        if recommended_tools and tool not in recommended_tools:
            continue
        planned_targets = planned_targets_for_tool(
            tool,
            targets,
            derive_url_hosts_for_nmap=True,
        )
        chosen_target = next((item for item in planned_targets if item.get("value")), target)
        target_value = str(chosen_target.get("value") or value).strip()
        if not _scope_target_allowed(scope, target_value):
            continue
        if _task_key(tool, target_value) in tested_keys:
            continue
        plan_item = _capability_item(plan, tool)
        tier = _tier_from_capability(plan_item, tool)
        return LoopCandidate(
            tool=tool,
            target=target_value,
            params={
                "loop_seed": True,
                "target_kind": chosen_target.get("kind") or kind,
                "source": "assessment_loop_seed",
            },
            tier=tier,
            reasoning=(
                f"Start the AI loop with {tool} against the approved {chosen_target.get('kind') or kind} "
                "to collect the first evidence-backed inventory signals."
            ),
            confidence=0.78,
            follow_up_hints=list(plan_item.get("follow_up_tools") or []),
            expected_evidence=list(plan_item.get("expected_evidence") or []),
            required_approvals=int(plan_item.get("required_approvals") or 0),
            decision_source="seed_target_type",
        )
    return None


def _plan_candidate(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    tested_keys: set[str],
    recommended_tools: set[str] | None = None,
) -> LoopCandidate | None:
    for item in plan.get("runners", []):
        if not isinstance(item, dict):
            continue
        decision = str(item.get("decision") or "").upper()
        if decision not in {"RUN", "NEEDS_APPROVAL"}:
            continue
        tool = str(item.get("runner") or item.get("tool") or "").strip()
        if not tool or tool not in supported_execution_tools():
            continue
        if recommended_tools and tool not in recommended_tools:
            continue
        planned_targets = planned_targets_for_tool(
            tool,
            targets,
            derive_url_hosts_for_nmap=True,
        )
        for target in planned_targets:
            target_value = str(target.get("value") or "").strip()
            if not target_value:
                continue
            if _task_key(tool, target_value) in tested_keys:
                continue
            if not _scope_target_allowed(scope, target_value):
                continue
            tier = _tier_from_capability(item, tool)
            return LoopCandidate(
                tool=tool,
                target=target_value,
                params={
                    "target_kind": target.get("kind"),
                    "matched_triggers": list(item.get("matched_triggers") or []),
                    "matched_weak_triggers": list(item.get("matched_weak_triggers") or []),
                    "source": "assessment_loop_plan",
                },
                tier=tier,
                reasoning=str(item.get("summary") or f"{tool} is the highest value next action."),
                confidence=float(item.get("confidence") or 0.0),
                follow_up_hints=list(item.get("follow_up_tools") or []),
                expected_evidence=list(item.get("expected_evidence") or []),
                required_approvals=int(item.get("required_approvals") or 0),
                decision_source="assessment_plan",
            )
    return None


def _context_targets(context_document) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    if context_document.context_kind != RECURSIVE_CONTEXT_KIND:
        for target in _as_list(context_document.source_targets_json):
            if not isinstance(target, dict):
                continue
            value = str(target.get("value") or "").strip()
            kind = str(target.get("kind") or "target").strip() or "target"
            if value:
                targets.append({"kind": kind, "value": value})
        if targets:
            return targets
    for endpoint in _as_list(context_document.endpoints_discovered_json):
        endpoint_text = str(endpoint or "").strip()
        if endpoint_text:
            targets.append({"kind": "url" if "://" in endpoint_text else "target", "value": endpoint_text})
    if targets:
        return targets
    for target in _as_list(context_document.source_targets_json):
        if not isinstance(target, dict):
            continue
        value = str(target.get("value") or "").strip()
        kind = str(target.get("kind") or "target").strip() or "target"
        if value:
            targets.append({"kind": kind, "value": value})
    return targets


def _context_micro_plan_candidate(
    *,
    scope: Scope,
    context_document,
    plan: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    if context_document.context_kind != RECURSIVE_CONTEXT_KIND:
        return None
    plan_targets = _context_targets(context_document)
    for step in _as_list(context_document.micro_plan_json):
        if not isinstance(step, dict):
            continue
        tool = str(step.get("tool") or "").strip()
        if not tool or tool not in supported_execution_tools():
            continue
        step_targets = [
            {"kind": "url" if "://" in str(target or "") else "target", "value": str(target or "").strip()}
            for target in _as_list(step.get("target_candidates"))
            if str(target or "").strip()
        ] or plan_targets
        for target in step_targets:
            target_value = str(target.get("value") or "").strip()
            if not target_value:
                continue
            if _task_key(tool, target_value) in tested_keys:
                continue
            if not _scope_target_allowed(scope, target_value):
                continue
            plan_item = _capability_item(plan, tool)
            tier = _tier_from_capability(plan_item, tool)
            return LoopCandidate(
                tool=tool,
                target=target_value,
                params={
                    "target_kind": target.get("kind"),
                    "source": "recursive_surface_micro_plan",
                    "context_document_id": str(context_document.id),
                    "context_layer": context_document.layer_name,
                    "micro_plan_step": int(step.get("order") or 0),
                },
                tier=tier,
                reasoning=str(
                    step.get("reason")
                    or f"Run {tool} against the newly discovered {context_document.layer_name} surface."
                ),
                confidence=float(plan_item.get("confidence") or 0.82),
                follow_up_hints=list(plan_item.get("follow_up_tools") or []),
                expected_evidence=list(plan_item.get("expected_evidence") or []),
                required_approvals=int(plan_item.get("required_approvals") or 0),
                decision_source="recursive_surface_micro_plan",
            )
    return None


def _selector_candidate(selector_report: dict[str, Any], plan: dict[str, Any]) -> LoopCandidate | None:
    for action in _as_list(selector_report.get("actions")):
        if not isinstance(action, dict):
            continue
        decision = str(action.get("decision") or "").strip().upper()
        if decision not in {"RUN", "APPROVAL"}:
            continue
        tool = str(action.get("runner") or "").strip()
        target = str(action.get("target") or "").strip()
        if not tool or tool not in supported_execution_tools() or not target:
            continue
        plan_item = _capability_item(plan, tool)
        tier = str(action.get("risk_tier") or _tier_from_capability(plan_item, tool)).strip().lower()
        return LoopCandidate(
            tool=tool,
            target=target,
            params={
                "target_kind": action.get("target_kind"),
                "source": "next_best_action_selector",
                "next_best_action_selector": {
                    "selector_version": selector_report.get("selector_version"),
                    "graph_version": selector_report.get("graph_version"),
                    "rank": action.get("rank"),
                    "decision": decision,
                    "runner_node_id": action.get("runner_node_id"),
                    "source_ids": list(action.get("source_ids") or []),
                    "prerequisite_state": _as_dict(action.get("prerequisite_state")),
                    "expected_proof_value": action.get("expected_proof_value"),
                    "matched_triggers": list(action.get("matched_triggers") or []),
                    "blocker_reasons": list(action.get("blocker_reasons") or []),
                },
            },
            tier=tier,
            reasoning=str(action.get("rationale") or f"{tool} is the next best action from stored evidence."),
            confidence=float(action.get("confidence") or 0.0),
            follow_up_hints=list(plan_item.get("follow_up_tools") or []),
            expected_evidence=list(action.get("expected_evidence") or plan_item.get("expected_evidence") or []),
            required_approvals=int(action.get("required_approvals") or plan_item.get("required_approvals") or 0),
            decision_source="next_best_action_selector",
            selector_decision=decision,
            selector_rank=int(action.get("rank") or 0) or None,
            selector_provenance=_as_dict(action.get("provenance")),
        )
    return None


def _selector_has_finding_sources(selector_report: dict[str, Any]) -> bool:
    for action in _as_list(selector_report.get("actions")):
        if not isinstance(action, dict):
            continue
        if any(str(source_id).startswith("finding:") for source_id in _as_list(action.get("source_ids"))):
            return True
    return False


def _next_action_payload(candidate: LoopCandidate) -> dict[str, Any]:
    payload = {
        "tool": candidate.tool,
        "target": candidate.target,
        "params": dict(candidate.params),
        "tier": candidate.tier,
        "reasoning": candidate.reasoning,
        "confidence": round(float(candidate.confidence), 3),
        "follow_up_hints": list(candidate.follow_up_hints),
        "expected_evidence": list(candidate.expected_evidence),
        "required_approvals": int(candidate.required_approvals),
        "decision_source": candidate.decision_source,
    }
    if candidate.selector_decision:
        payload["selector_decision"] = candidate.selector_decision
        payload["selector_rank"] = candidate.selector_rank
        payload["selector_provenance"] = dict(candidate.selector_provenance or {})
    return payload


def _queue_passive_loop_task(
    *,
    session: Session,
    run: Run,
    candidate: LoopCandidate,
    actor: str,
    iteration_number: int,
    context_document_id: str,
    rationale_ledger_entry_id: str,
) -> Task:
    if candidate.tool not in supported_execution_tools():
        raise ValueError(f"assessment loop selected unsupported runner: {candidate.tool}")
    normalized_limits = normalize_profile_limits(
        candidate.tier,
        {
            **(_as_dict(run.profile.limits_json) if run.profile is not None else {}),
            "tools": [candidate.tool],
        },
    )
    task = Task(
        run=run,
        tool=candidate.tool,
        target_id=candidate.target,
        status="queued",
        params_json={
            **candidate.params,
            "target_kind": candidate.params.get("target_kind"),
            "profile_name": run.profile.name if run.profile is not None else "ai-loop",
            "run_class": candidate.tier,
            "limits": normalized_limits,
            "assessment_loop": {
                "enabled": True,
                "run_mode": "ai_loop",
                "iteration": iteration_number,
                "tool": candidate.tool,
                "target": candidate.target,
                "tier": candidate.tier,
                "reasoning": candidate.reasoning,
                "confidence": round(float(candidate.confidence), 3),
                "approval_effect": "passive_auto_queued",
                "dispatch_mode": "queued_not_dispatched",
                "registered_runner_required": True,
                "context_document_id": context_document_id,
                "rationale_ledger_entry_id": rationale_ledger_entry_id,
                "scope_enforced": True,
                "kill_switch_still_authoritative": True,
            },
        },
    )
    session.add(task)
    session.flush()
    inject_run_credential_vault_into_task(
        session,
        run=run,
        task=task,
        actor=actor,
    )
    if str(run.status or "").lower() not in {"cancelled", "cancelling", "rejected"}:
        run.status = "queued"
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_loop.passive_task_queued",
        object_type="task",
        object_id=str(task.id),
        metadata={
            "run_id": str(run.id),
            "iteration": iteration_number,
            "tool": candidate.tool,
            "target": candidate.target,
            "tier": candidate.tier,
            "dispatch_mode": "queued_not_dispatched",
            "operator_controlled_flow_only": True,
        },
    )
    return task


def _store_next_action_proposal(
    *,
    session: Session,
    run: Run,
    reasoning,
    candidate: LoopCandidate,
    actor: str,
    iteration_number: int,
    context_document_id: str,
    rationale_ledger_entry_id: str,
) -> AgentProposal:
    proposal = store_agent_proposal_record(
        session=session,
        reasoning=reasoning,
        proposed_tool=candidate.tool,
        proposed_target=candidate.target,
        proposed_params={
            **candidate.params,
            "assessment_loop": {
                "enabled": True,
                "run_mode": "ai_loop",
                "iteration": iteration_number,
                "tier": candidate.tier,
                "required_approvals": candidate.required_approvals,
                "approval_required": candidate.tier in {"active", "intrusive"},
                "dispatches_work": False,
                "registered_runner_required": True,
                "context_document_id": context_document_id,
                "rationale_ledger_entry_id": rationale_ledger_entry_id,
                "scope_enforced": True,
                "roe_enforced": True,
                "kill_switch_still_authoritative": True,
            },
            "review_required": True,
        },
        reasoning_text=candidate.reasoning,
        risk_tier=candidate.tier,
        priority=10 if candidate.tier == "active" else 5,
        confidence_score=float(candidate.confidence),
        status="pending_review",
        metadata={
            "proposal_kind": LOOP_PROPOSAL_KIND,
            "run_mode": "ai_loop",
            "iteration": iteration_number,
            "created_by": actor,
            "requires_operator_review": True,
            "dispatches_work": False,
            "operator_controlled_flow_only": True,
            "active_runtime_mutated": False,
            "context_document_id": context_document_id,
            "rationale_ledger_entry_id": rationale_ledger_entry_id,
            "approval_boundary": (
                "per_action_explicit_approval"
                if candidate.tier == "intrusive"
                else "active_wave_approval"
            ),
        },
    )
    return proposal


def build_assessment_loop_state(session: Session, *, run: Run, scope: Scope) -> dict[str, Any]:
    configuration = _as_dict(run.configuration_json)
    loop_state = _loop_state(configuration)
    targets = _targets_for_loop(scope, run)
    evidence_fingerprint = _evidence_fingerprint(run)
    current_state = _current_state_payload(
        run=run,
        scope=scope,
        targets=targets,
        evidence_fingerprint=evidence_fingerprint,
    )
    plan = build_assessment_plan_for_run(session, run)
    context_document = latest_context_document(session, run_id=run.id)
    context_summary = None
    if context_document is not None:
        context_summary = {
            "context_document_id": str(context_document.id),
            "layer_name": context_document.layer_name,
            "context_kind": context_document.context_kind,
            "status": context_document.status,
            "recommended_tools": list(context_document.recommended_tools_json or []),
            "micro_plan_step_count": len(list(context_document.micro_plan_json or [])),
            "evidence_ref_count": len(list(context_document.evidence_refs_json or [])),
        }
    return {
        "available": True,
        "run_id": str(run.id),
        "run_mode": "ai_loop",
        "loop_version": LOOP_VERSION,
        "status": loop_state["status"],
        "stop_reason": loop_state.get("stop_reason"),
        "iteration_count": loop_state["iteration_count"],
        "max_iterations": loop_state["max_iterations"],
        "stuck_threshold": loop_state["stuck_threshold"],
        "no_new_signal_iterations": loop_state["no_new_signal_iterations"],
        "current_state": current_state,
        "target_context": context_summary,
        "latest_next_action": loop_state.get("latest_next_action"),
        "active_tasks": _active_loop_tasks(run),
        "assessment_plan_summary": plan.get("summary", {}),
        "goal_oriented_reasoning": _as_dict(loop_state.get("goal_oriented_reasoning")),
        "rationale_ledger": _rationale_ledger_payloads(session, run=run),
        "iterations": list(loop_state.get("iterations") or []),
        "dispatches_work_directly": False,
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
    }


def _rationale_ledger_payloads(session: Session, *, run: Run) -> list[dict[str, Any]]:
    entries = session.scalars(
        select(RationaleLedgerEntry)
        .where(RationaleLedgerEntry.run_id == run.id)
        .order_by(RationaleLedgerEntry.created_at.asc(), RationaleLedgerEntry.id.asc())
    ).all()
    payloads: list[dict[str, Any]] = []
    for entry in entries:
        payloads.append(
            {
                "id": str(entry.id),
                "context_document_id": str(entry.context_document_id) if entry.context_document_id else None,
                "task_id": str(entry.task_id) if entry.task_id else None,
                "agent_proposal_id": str(entry.agent_proposal_id) if entry.agent_proposal_id else None,
                "action_type": entry.action_type,
                "tool_name": entry.tool_name,
                "target": entry.target,
                "rationale_text": entry.rationale_text,
                "decision_source": _as_dict(entry.decision_source_json),
                "parameters": _as_dict(entry.parameters_json),
                "status": entry.status,
                "provenance": _as_dict(entry.provenance_json),
                "created_at": entry.created_at.isoformat(),
            }
        )
    return payloads


def record_assessment_loop_goal(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    actor: str,
    objective: str,
    operator_note: str | None = None,
) -> dict[str, Any]:
    if not _run_uses_ai_loop(run):
        raise ValueError("goal-oriented reasoning is available only for runs configured with run_mode=ai_loop")
    normalized_objective = " ".join(str(objective or "").split())
    if not normalized_objective:
        raise ValueError("goal-oriented reasoning requires a non-empty operator objective")
    targets = _targets_for_loop(scope, run)
    if not targets:
        raise ValueError("goal-oriented reasoning requires at least one approved target in scope")
    configuration = _as_dict(run.configuration_json)
    loop_state = _loop_state(configuration)
    plan = build_assessment_plan_for_run(session, run)
    context_document = ensure_context_document(
        session,
        run=run,
        scope=scope,
        targets=targets,
        plan=plan,
    )
    goal_reasoning = _build_goal_oriented_reasoning(
        run=run,
        scope=scope,
        targets=targets,
        plan=plan,
        context_document=context_document,
        objective=normalized_objective,
        actor=actor,
        operator_note=operator_note,
    )
    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        reasoning_type=GOAL_REASONING_KIND,
        status="recorded",
        context_snapshot={
            "run_id": str(run.id),
            "run_mode": "ai_loop",
            "objective": normalized_objective,
            "target_context_document_id": str(context_document.id),
            "assessment_plan_summary": plan.get("summary", {}),
            "scope_enforced": True,
            "roe_enforced": True,
            "fixed_phase_chains_replaced_globally": False,
        },
        observations=[
            {
                "summary": "Operator objective recorded for bounded goal-oriented reasoning.",
                "target_type": _target_type(targets),
                "target_count": len(targets),
            }
        ],
        hypotheses=list(goal_reasoning.get("hypothesis_path") or []),
        proposals=[],
        summary_text=f"Recorded objective: {normalized_objective}",
        thought_text=(
            "Reason backward from the operator objective using only evidence-linked, registered-runner "
            "steps inside scope, ROE, approval, and kill-switch controls."
        ),
        action_text="Store the bounded hypothesis path; no work is dispatched by objective registration.",
        provider="deterministic-assessment-loop",
        model=None,
        llm_tokens_used=0,
        confidence_score=0.84 if goal_reasoning.get("hypothesis_path") else 0.4,
        metadata={
            "reasoning_kind": GOAL_REASONING_KIND,
            "run_mode": "ai_loop",
            "dispatches_work": False,
            "direct_dispatch": False,
            "registered_runner_required": True,
            "scope_enforced": True,
            "roe_enforced": True,
            "approval_gates_bypassed": False,
            "kill_switch_still_authoritative": True,
            "manual_chain_alternative_preserved": True,
        },
    )
    goal_reasoning["reasoning_id"] = str(reasoning.id)
    loop_state["goal_oriented_reasoning"] = goal_reasoning
    loop_state["status"] = loop_state.get("status") or "ready"
    _store_loop_state(configuration, loop_state)
    run.configuration_json = configuration
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_loop.goal_recorded",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "reasoning_id": str(reasoning.id),
            "objective_type": goal_reasoning.get("objective_type"),
            "hypothesis_step_count": len(list(goal_reasoning.get("hypothesis_path") or [])),
            "dispatches_work": False,
            "registered_runner_required": True,
            "scope_enforced": True,
            "roe_enforced": True,
            "approval_gates_bypassed": False,
        },
    )
    return build_assessment_loop_state(session, run=run, scope=scope)


def advance_assessment_loop(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    actor: str,
    operator_note: str | None = None,
) -> dict[str, Any]:
    if not _run_uses_ai_loop(run):
        raise ValueError("assessment loop can advance only for runs configured with run_mode=ai_loop")
    if run.profile is not None and pending_approvals(run, run.profile) > 0:
        raise ValueError("assessment loop cannot advance while the selected run still has pending approvals")
    active_tasks = _active_loop_tasks(run)
    configuration = _as_dict(run.configuration_json)
    loop_state = _loop_state(configuration)
    targets = _targets_for_loop(scope, run)
    if not targets:
        raise ValueError("assessment loop requires at least one approved target in scope")

    evidence_fingerprint = _evidence_fingerprint(run)
    previous_fingerprint = str(loop_state.get("latest_evidence_fingerprint") or "")
    no_new_signal_iterations = int(loop_state.get("no_new_signal_iterations") or 0)
    if previous_fingerprint and previous_fingerprint == evidence_fingerprint:
        no_new_signal_iterations += 1
    else:
        no_new_signal_iterations = 0
    loop_state["no_new_signal_iterations"] = no_new_signal_iterations
    loop_state["latest_evidence_fingerprint"] = evidence_fingerprint

    if active_tasks:
        loop_state["status"] = "waiting_for_execution"
        loop_state["stop_reason"] = None
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        return build_assessment_loop_state(session, run=run, scope=scope)

    max_iterations = int(loop_state.get("max_iterations") or LOOP_MAX_ITERATIONS)
    stuck_threshold = int(loop_state.get("stuck_threshold") or LOOP_STUCK_THRESHOLD)
    if int(loop_state.get("iteration_count") or 0) >= max_iterations:
        loop_state["status"] = "stopped"
        loop_state["stop_reason"] = "max_iterations_reached"
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason="assessment_loop_max_iterations_reached",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={"reason": "max_iterations_reached", "max_iterations": max_iterations},
        )
        return build_assessment_loop_state(session, run=run, scope=scope)
    if no_new_signal_iterations >= stuck_threshold:
        loop_state["status"] = "stopped"
        loop_state["stop_reason"] = "stuck_no_new_signals"
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason="assessment_loop_stuck_no_new_signals",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={"reason": "stuck_no_new_signals", "threshold": stuck_threshold},
        )
        return build_assessment_loop_state(session, run=run, scope=scope)

    plan = build_assessment_plan_for_run(session, run)
    parent_context_document = ensure_context_document(
        session,
        run=run,
        scope=scope,
        targets=targets,
        plan=plan,
    )
    context_document = (
        ensure_recursive_surface_context(
            session,
            run=run,
            scope=scope,
            parent_context=parent_context_document,
            plan=plan,
        )
        or parent_context_document
    )
    recommended_tools = {
        str(tool).strip()
        for tool in list(context_document.recommended_tools_json or [])
        if str(tool).strip()
    }
    tested_keys = _tested_action_keys(run)
    selector_targets = _context_targets(context_document) or targets
    selector_report = select_next_best_action_for_run(
        session,
        run=run,
        scope=scope,
        approved_targets=selector_targets,
        tested_action_keys=tested_keys,
    )
    goal_candidate = _goal_oriented_candidate(
        run=run,
        scope=scope,
        goal_reasoning=_as_dict(loop_state.get("goal_oriented_reasoning")),
        plan=plan,
        tested_keys=tested_keys,
    )
    recursive_candidate = _context_micro_plan_candidate(
        scope=scope,
        context_document=context_document,
        plan=plan,
        tested_keys=tested_keys,
    )
    selector_candidate = (
        _selector_candidate(selector_report, plan)
        if not tested_keys or _selector_has_finding_sources(selector_report)
        else None
    )
    candidate = goal_candidate or recursive_candidate or selector_candidate or _seed_candidate(
        run=run,
        scope=scope,
        targets=_context_targets(context_document) or targets,
        plan=plan,
        tested_keys=tested_keys,
        recommended_tools=recommended_tools,
    ) or _plan_candidate(
        run=run,
        scope=scope,
        targets=_context_targets(context_document) or targets,
        plan=plan,
        tested_keys=tested_keys,
        recommended_tools=recommended_tools,
    )
    if candidate is None:
        loop_state["status"] = "stopped"
        loop_state["stop_reason"] = "no_registered_runner_candidate"
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason="assessment_loop_no_registered_runner_candidate",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={"reason": "no_registered_runner_candidate"},
        )
        return build_assessment_loop_state(session, run=run, scope=scope)

    iteration_number = int(loop_state.get("iteration_count") or 0) + 1
    current_state = _current_state_payload(
        run=run,
        scope=scope,
        targets=targets,
        evidence_fingerprint=evidence_fingerprint,
    )
    next_action = _next_action_payload(candidate)
    next_action["context_document_id"] = str(context_document.id)
    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        reasoning_type="assessment_loop_next_action",
        status="recorded",
        context_snapshot={
            "run_id": str(run.id),
            "run_mode": "ai_loop",
            "iteration": iteration_number,
            "assessment_state": current_state,
            "target_context_document_id": str(context_document.id),
            "parent_context_document_id": (
                str(context_document.parent_context_document_id)
                if context_document.parent_context_document_id
                else None
            ),
            "target_context_summary": context_document.context_summary,
            "target_context_evidence_refs": list(context_document.evidence_refs_json or []),
            "target_context_micro_plan": list(context_document.micro_plan_json or []),
            "assessment_plan_summary": plan.get("summary", {}),
            "next_best_action_selector": {
                "selector_version": selector_report.get("selector_version"),
                "enabled": selector_report.get("enabled"),
                "top_actions": [
                    {
                        "rank": action.get("rank"),
                        "decision": action.get("decision"),
                        "runner": action.get("runner"),
                        "target": action.get("target"),
                        "confidence": action.get("confidence"),
                        "expected_proof_value": action.get("expected_proof_value"),
                        "missing_prerequisites": _as_dict(
                            action.get("prerequisite_state")
                        ).get("missing", []),
                    }
                    for action in _as_list(selector_report.get("actions"))[:5]
                    if isinstance(action, dict)
                ],
                "dispatches_work_directly": False,
            },
            "goal_oriented_reasoning": _as_dict(loop_state.get("goal_oriented_reasoning")),
            "scope_enforced": True,
            "fixed_phase_chains_replaced_globally": False,
        },
        observations=[
            {
                "summary": (
                    f"Assessment loop observed {current_state['task_count']} task(s), "
                    f"{current_state['finding_count']} finding(s), and "
                    f"{current_state['signal_count']} signal(s)."
                ),
                "target_type": current_state["target_type"],
                "no_new_signal_iterations": no_new_signal_iterations,
            }
        ],
        hypotheses=[
            {
                "summary": candidate.reasoning,
                "tool": candidate.tool,
                "target": candidate.target,
                "tier": candidate.tier,
                "confidence": round(float(candidate.confidence), 3),
                "decision_source": candidate.decision_source,
                "selector_decision": candidate.selector_decision,
            }
        ],
        proposals=[next_action],
        summary_text=f"Iteration {iteration_number}: selected {candidate.tool} for {candidate.target}.",
        thought_text=candidate.reasoning,
        action_text=(
            "Queue passive action through the registered runner path."
            if candidate.tier == "passive"
            else "Create a reviewable AI proposal; execution waits for existing approval flow."
        ),
        provider="deterministic-assessment-loop",
        model=None,
        llm_tokens_used=0,
        confidence_score=float(candidate.confidence),
        metadata={
            "proposal_kind": LOOP_PROPOSAL_KIND,
            "run_mode": "ai_loop",
            "iteration": iteration_number,
            "operator_note": operator_note,
            "dispatches_work": candidate.tier == "passive",
            "direct_dispatch": False,
            "registered_runner_required": True,
            "scope_enforced": True,
            "roe_enforced": True,
            "kill_switch_still_authoritative": True,
            "manual_chain_alternative_preserved": True,
            "target_context_document_id": str(context_document.id),
            "next_best_action_selector_used": candidate.decision_source == "next_best_action_selector",
            "selector_decision": candidate.selector_decision,
            "selector_rank": candidate.selector_rank,
        },
    )
    rationale_entry = record_rationale(
        session,
        run=run,
        context_document=context_document,
        tool_name=candidate.tool,
        target=candidate.target,
        rationale=candidate.reasoning,
        parameters={
            **candidate.params,
            "tier": candidate.tier,
            "iteration": iteration_number,
            "confidence": round(float(candidate.confidence), 3),
            "required_approvals": candidate.required_approvals,
        },
        action_type=LOOP_PROPOSAL_KIND,
        decision_source={
            "source": candidate.decision_source,
            "context_document_id": str(context_document.id),
            "goal_oriented_reasoning": _as_dict(candidate.params.get("goal_oriented_reasoning")),
            "next_best_action_selector": _as_dict(candidate.params.get("next_best_action_selector")),
            "selector_provenance": dict(candidate.selector_provenance or {}),
            "recommended_tools": list(context_document.recommended_tools_json or []),
            "registered_runner_required": True,
            "approval_gates_bypassed": False,
        },
        status="recorded_before_dispatch",
    )
    next_action["rationale_ledger_entry_id"] = str(rationale_entry.id)
    queued_task: Task | None = None
    proposal: AgentProposal | None = None
    action_status = "pending_review"
    # For ai_loop runs, auto-queue active candidates too (operator already authorized the run)
    # Intrusive-exploitation tier always requires explicit approval regardless of run mode
    auto_queue_active = _run_uses_ai_loop(run) and candidate.tier == "active"
    if candidate.tier == "passive" or auto_queue_active:
        queued_task = _queue_passive_loop_task(
            session=session,
            run=run,
            candidate=candidate,
            actor=actor,
            iteration_number=iteration_number,
            context_document_id=str(context_document.id),
            rationale_ledger_entry_id=str(rationale_entry.id),
        )
        proposal = store_agent_proposal_record(
            session=session,
            reasoning=reasoning,
            proposed_tool=candidate.tool,
            proposed_target=candidate.target,
            proposed_params={
                **candidate.params,
                "assessment_loop": {
                    "enabled": True,
                    "run_mode": "ai_loop",
                    "iteration": iteration_number,
                    "queued_task_id": str(queued_task.id),
                    "dispatch_mode": "queued_not_dispatched",
                    "context_document_id": str(context_document.id),
                    "rationale_ledger_entry_id": str(rationale_entry.id),
                },
            },
            reasoning_text=candidate.reasoning,
            risk_tier=candidate.tier,
            priority=20,
            confidence_score=float(candidate.confidence),
            status="approved",
            metadata={
                "proposal_kind": LOOP_PROPOSAL_KIND,
                "run_mode": "ai_loop",
                "iteration": iteration_number,
                "dispatches_work": True,
                "queued_task_id": str(queued_task.id),
                "approval_boundary": "passive_auto_queued" if candidate.tier == "passive" else "active_auto_queued_ai_loop",
                "operator_controlled_flow_only": True,
                "active_runtime_mutated": False,
                "context_document_id": str(context_document.id),
                "rationale_ledger_entry_id": str(rationale_entry.id),
            },
        )
        proposal.approved_by = actor
        proposal.approved_at = datetime.now(UTC)
        rationale_entry.task_id = queued_task.id
        rationale_entry.agent_proposal_id = proposal.id
        rationale_entry.status = "task_queued"
        action_status = "queued"
    else:
        proposal = _store_next_action_proposal(
            session=session,
            run=run,
            reasoning=reasoning,
            candidate=candidate,
            actor=actor,
            iteration_number=iteration_number,
            context_document_id=str(context_document.id),
            rationale_ledger_entry_id=str(rationale_entry.id),
        )
        rationale_entry.agent_proposal_id = proposal.id
        rationale_entry.status = "pending_approval"

    iteration = {
        "iteration": iteration_number,
        "status": action_status,
        "created_at": _now(),
        "reasoning_id": str(reasoning.id),
        "proposal_id": str(proposal.id) if proposal is not None else None,
        "queued_task_id": str(queued_task.id) if queued_task is not None else None,
        "context_document_id": str(context_document.id),
        "rationale_ledger_entry_id": str(rationale_entry.id),
        "next_action": next_action,
        "evidence_fingerprint": evidence_fingerprint,
    }
    loop_state["iteration_count"] = iteration_number
    loop_state["status"] = "waiting_for_execution" if queued_task is not None else "waiting_for_approval"
    loop_state["stop_reason"] = None
    loop_state["latest_next_action"] = next_action
    loop_state["iterations"] = [*list(loop_state.get("iterations") or []), iteration]
    _store_loop_state(configuration, loop_state)
    run.configuration_json = configuration

    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_loop.iteration_created",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "iteration": iteration_number,
            "tool": candidate.tool,
            "target": candidate.target,
            "tier": candidate.tier,
            "queued_task_id": str(queued_task.id) if queued_task is not None else None,
            "proposal_id": str(proposal.id) if proposal is not None else None,
            "context_document_id": str(context_document.id),
            "rationale_ledger_entry_id": str(rationale_entry.id),
            "dispatch_mode": "queued_not_dispatched" if queued_task is not None else "review_only",
        },
    )

    return {
        **build_assessment_loop_state(session, run=run, scope=scope),
        "next_action": next_action,
        "queued_task_id": str(queued_task.id) if queued_task is not None else None,
        "proposal_id": str(proposal.id) if proposal is not None else None,
        "reasoning_id": str(reasoning.id),
        "context_document_id": str(context_document.id),
        "rationale_ledger_entry_id": str(rationale_entry.id),
    }
