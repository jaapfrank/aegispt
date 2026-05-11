from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from api.app.models import AgentProposal, Run, Scope, Task
from api.app.services.runner_registry import runner_capability_registry
from api.app.services.runs import derive_targets_for_run, pending_approvals

COVERAGE_TRUTH_VERSION = "coverage-truth-v1"
TERMINAL_RUN_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "rejected"}
ACTIVE_TASK_STATUSES = {"queued", "pending", "running", "dispatching", "in_progress", "started"}
EXECUTED_TASK_STATUSES = {"running", "completed", "completed_with_errors", "failed"}
TERMINAL_TASK_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "skipped"}

SURFACE_RULES: tuple[dict[str, Any], ...] = (
    {
        "key": "web_application",
        "label": "Web applications",
        "target_kinds": {"url", "target"},
        "keywords": {"web", "httpx", "nuclei", "zap", "burp", "playwright", "headers", "xss", "sqlmap"},
        "representative_tools": {"httpx", "headers-security", "nuclei", "zap", "burp", "playwright-web"},
    },
    {
        "key": "api",
        "label": "APIs",
        "target_kinds": {"url", "target"},
        "keywords": {"api", "graphql", "rest", "business-logic", "biz-logic"},
        "representative_tools": {"api-assessment", "graphql-probe", "biz-logic-probe"},
    },
    {
        "key": "internal_network",
        "label": "Internal network / LAN",
        "target_kinds": {"host", "cidr", "domain"},
        "keywords": {"lan", "network", "nmap", "smb", "ldap", "bloodhound", "netexec", "impacket"},
        "representative_tools": {"nmap", "ldap-enum", "bloodhound-collect", "netexec", "impacket-lateral"},
    },
    {
        "key": "cloud",
        "label": "Cloud infrastructure",
        "target_kinds": {"aws-account", "cloud-account"},
        "keywords": {"cloud", "aws", "azure", "gcp", "iam"},
        "representative_tools": {"aws-inventory", "cloud-native"},
    },
    {
        "key": "iot_lan",
        "label": "Smart home / IoT LAN",
        "target_kinds": {"host", "cidr"},
        "keywords": {"iot", "smart-home", "mdns", "ssdp", "upnp", "snmp", "mqtt", "camera", "onvif", "rtsp"},
        "representative_tools": {"mdns-ssdp", "smart-home", "snmp-enum", "camera-test", "iot-default-creds"},
    },
    {
        "key": "wifi_wireless",
        "label": "WiFi / Wireless",
        "target_kinds": {"wireless-site", "ssid", "bssid"},
        "keywords": {"wifi", "wireless", "ssid", "bssid", "wifi-survey"},
        "representative_tools": {"wifi-survey"},
    },
    {
        "key": "intrusive_validation",
        "label": "Intrusive validation",
        "target_kinds": set(),
        "keywords": {"intrusive", "metasploit", "exploit", "secretsdump", "dcsync", "priv-esc"},
        "representative_tools": {"metasploit", "impacket-lateral", "priv-esc-linux", "responder"},
        "requires_explicit_signal": True,
    },
)


def build_coverage_truth(
    session: Session | None,
    *,
    run: Run,
    scope: Scope | None = None,
) -> dict[str, Any]:
    effective_session = session or object_session(run)
    runs = _coverage_runs(effective_session, run)
    primary_scope = scope or _latest_scope(effective_session, run)
    targets = derive_targets_for_run(primary_scope, run) if primary_scope is not None else []
    tasks = sorted(
        [task for coverage_run in runs for task in list(coverage_run.tasks or [])],
        key=lambda task: (task.created_at, task.id),
    )
    proposals = sorted(
        [proposal for coverage_run in runs for proposal in list(coverage_run.agent_proposals or [])],
        key=lambda proposal: (proposal.created_at, proposal.id),
    )
    inventory_text = _inventory_text(runs)
    run_signal = _run_signal_text(runs, targets, inventory_text)
    surfaces = [
        _surface_truth(rule, run_signal=run_signal, targets=targets, tasks=tasks, proposals=proposals)
        for rule in SURFACE_RULES
    ]
    summary = _summary(surfaces, tasks)
    stop_condition = _stop_condition(
        run=run,
        runs=runs,
        scope=primary_scope,
        surfaces=surfaces,
        tasks=tasks,
        proposals=proposals,
    )
    return {
        "coverage_truth_version": COVERAGE_TRUTH_VERSION,
        "run_id": str(run.id),
        "assessment_chain_id": str(run.assessment_chain_id) if run.assessment_chain_id else None,
        "generated_at": datetime.now(UTC).isoformat(),
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "mutates_scope": False,
            "mutates_approvals": False,
            "runtime_self_modification": False,
            "claims_unsupported_coverage": False,
        },
        "summary": summary,
        "stop_condition": stop_condition,
        "surfaces": surfaces,
        "task_rollup": _task_rollup(tasks),
        "policy_state": {
            "scope_present": primary_scope is not None,
            "approved_target_count": len(targets),
            "pending_approval_count": _pending_approval_count(run, proposals),
            "pending_proposal_count": len(_pending_proposals(proposals)),
        },
    }


def coverage_truth_for_run_id(session: Session, *, run_id: UUID | str) -> dict[str, Any]:
    run = session.get(Run, UUID(str(run_id)))
    if run is None:
        raise ValueError(f"run not found: {run_id}")
    return build_coverage_truth(session, run=run)


def _coverage_runs(session: Session | None, run: Run) -> list[Run]:
    if run.assessment_chain_id is None or session is None:
        return [run]
    runs = session.scalars(
        select(Run)
        .where(Run.assessment_chain_id == run.assessment_chain_id)
        .where(Run.deleted_at.is_(None))
        .order_by(Run.created_at.asc(), Run.id.asc())
    ).all()
    return list(runs) or [run]


def _latest_scope(session: Session | None, run: Run) -> Scope | None:
    if run.engagement is not None and run.engagement.scopes:
        return sorted(run.engagement.scopes, key=lambda scope: (scope.created_at, scope.id))[-1]
    if session is None:
        return None
    return session.scalar(
        select(Scope)
        .where(Scope.engagement_id == run.engagement_id)
        .order_by(Scope.created_at.desc(), Scope.id.desc())
    )


def _surface_truth(
    rule: dict[str, Any],
    *,
    run_signal: str,
    targets: list[dict[str, str]],
    tasks: list[Task],
    proposals: list[AgentProposal],
) -> dict[str, Any]:
    applicable = _surface_applicable(rule, run_signal=run_signal, targets=targets)
    matching_tasks = [task for task in tasks if _task_matches_surface(task, rule)]
    matching_proposals = [proposal for proposal in proposals if _proposal_matches_surface(proposal, rule)]
    status = _surface_status(applicable=applicable, tasks=matching_tasks, proposals=matching_proposals)
    blocker_ids = _surface_blocker_ids(status=status, rule=rule, proposals=matching_proposals)
    return {
        "key": rule["key"],
        "label": rule["label"],
        "status": status,
        "applicable": applicable,
        "tested_task_ids": [str(task.id) for task in matching_tasks if task.status in EXECUTED_TASK_STATUSES],
        "all_task_ids": [str(task.id) for task in matching_tasks],
        "task_count": len(matching_tasks),
        "tools": sorted({task.tool for task in matching_tasks}),
        "pending_proposal_ids": [str(proposal.id) for proposal in matching_proposals if proposal.status == "pending_review"],
        "blocker_ids": blocker_ids,
        "reason": _surface_reason(status=status, rule=rule, tasks=matching_tasks, proposals=matching_proposals),
    }


def _surface_applicable(
    rule: dict[str, Any],
    *,
    run_signal: str,
    targets: list[dict[str, str]],
) -> bool:
    if rule.get("requires_explicit_signal") and not _text_matches(run_signal, set(rule["keywords"])):
        return False
    if _text_matches(run_signal, set(rule["keywords"])):
        return True
    target_kinds = set(rule.get("target_kinds") or set())
    return bool(target_kinds and any(target.get("kind") in target_kinds for target in targets))


def _surface_status(
    *,
    applicable: bool,
    tasks: list[Task],
    proposals: list[AgentProposal],
) -> str:
    if not applicable:
        return "not_applicable"
    if any(proposal.status == "pending_review" for proposal in proposals):
        return "blocked"
    if not tasks:
        return "not_tested"
    statuses = {str(task.status or "").lower() for task in tasks}
    if statuses <= {"skipped"}:
        return "skipped"
    if statuses & ACTIVE_TASK_STATUSES:
        return "partially_tested"
    if statuses & {"failed", "completed_with_errors"}:
        return "partially_tested"
    if statuses & {"completed", "running"}:
        return "tested"
    if statuses & {"skipped", "cancelled"}:
        return "skipped"
    return "not_tested"


def _surface_blocker_ids(
    *,
    status: str,
    rule: dict[str, Any],
    proposals: list[AgentProposal],
) -> list[str]:
    blocker_ids: list[str] = []
    if status == "blocked":
        blocker_ids.extend(f"proposal:{proposal.id}" for proposal in proposals if proposal.status == "pending_review")
    if status in {"not_tested", "partially_tested"}:
        for tool in sorted(set(rule.get("representative_tools") or set())):
            for prerequisite in _runner_prerequisites(tool):
                blocker_ids.append(f"prerequisite:{tool}:{prerequisite}")
    return sorted(set(blocker_ids))


def _surface_reason(
    *,
    status: str,
    rule: dict[str, Any],
    tasks: list[Task],
    proposals: list[AgentProposal],
) -> str:
    if status == "tested":
        return "Stored task evidence shows this surface was exercised."
    if status == "partially_tested":
        return "Stored tasks exist, but at least one is active, failed, or completed with errors."
    if status == "blocked":
        return "A pending proposal or approval gate blocks additional checks."
    if status == "skipped":
        return "Stored tasks for this surface were skipped or cancelled."
    if status == "not_applicable":
        return "The run scope, inventory, and profile do not indicate this surface."
    if tasks or proposals:
        return "Only non-executed evidence exists for this surface."
    return "No stored task or finding evidence proves this surface was tested."


def _stop_condition(
    *,
    run: Run,
    runs: list[Run],
    scope: Scope | None,
    surfaces: list[dict[str, Any]],
    tasks: list[Task],
    proposals: list[AgentProposal],
) -> dict[str, Any]:
    pending_proposals = _pending_proposals(proposals)
    active_tasks = [task for task in tasks if str(task.status or "").lower() in ACTIVE_TASK_STATUSES]
    status_counts = Counter(surface["status"] for surface in surfaces)
    blocker_ids = sorted({blocker for surface in surfaces for blocker in surface.get("blocker_ids", [])})
    if scope is None:
        state = "wait"
        reason = "No scope record is available, so coverage cannot be honestly completed."
    elif pending_proposals or _pending_approval_count(run, proposals) > 0:
        state = "approval-needed"
        reason = "Existing approval or proposal gates must be resolved before claiming completion."
    elif active_tasks:
        state = "wait"
        reason = "At least one stored task is still queued or running."
    elif any(run_item.status not in TERMINAL_RUN_STATUSES for run_item in runs):
        state = "continue"
        reason = "The run is not terminal and untested or partially tested surfaces remain."
    elif status_counts.get("blocked", 0) or status_counts.get("not_tested", 0) or status_counts.get("partially_tested", 0):
        state = "complete-with-gaps"
        reason = "The run is terminal, but stored evidence still shows coverage gaps or blockers."
    else:
        state = "complete"
        reason = "All applicable packaged surfaces have stored tested evidence and no blockers."
    return {
        "state": state,
        "reason": reason,
        "blocker_ids": blocker_ids,
        "active_task_ids": [str(task.id) for task in active_tasks],
        "pending_proposal_ids": [str(proposal.id) for proposal in pending_proposals],
        "terminal_run_count": sum(1 for run_item in runs if run_item.status in TERMINAL_RUN_STATUSES),
        "run_count": len(runs),
    }


def _summary(surfaces: list[dict[str, Any]], tasks: list[Task]) -> dict[str, Any]:
    status_counts = Counter(surface["status"] for surface in surfaces)
    applicable = [surface for surface in surfaces if surface["applicable"]]
    return {
        "surface_count": len(surfaces),
        "applicable_surface_count": len(applicable),
        "tested_count": status_counts.get("tested", 0),
        "partially_tested_count": status_counts.get("partially_tested", 0),
        "blocked_count": status_counts.get("blocked", 0),
        "skipped_count": status_counts.get("skipped", 0),
        "not_applicable_count": status_counts.get("not_applicable", 0),
        "not_tested_count": status_counts.get("not_tested", 0),
        "total_task_count": len(tasks),
        "executed_task_count": sum(1 for task in tasks if task.status in EXECUTED_TASK_STATUSES),
    }


def _task_rollup(tasks: list[Task]) -> dict[str, Any]:
    by_status = Counter(str(task.status or "unknown") for task in tasks)
    return {
        "by_status": dict(sorted(by_status.items())),
        "tools": sorted({task.tool for task in tasks}),
        "task_ids": [str(task.id) for task in tasks],
    }


def _pending_proposals(proposals: list[AgentProposal]) -> list[AgentProposal]:
    return [proposal for proposal in proposals if proposal.status == "pending_review"]


def _pending_approval_count(run: Run, proposals: list[AgentProposal]) -> int:
    count = len(_pending_proposals(proposals))
    if run.profile is not None:
        count += pending_approvals(run, run.profile)
    return count


def _task_matches_surface(task: Task, rule: dict[str, Any]) -> bool:
    return _text_matches(_task_text(task), set(rule["keywords"])) or task.tool in set(rule.get("representative_tools") or set())


def _proposal_matches_surface(proposal: AgentProposal, rule: dict[str, Any]) -> bool:
    return _text_matches(_proposal_text(proposal), set(rule["keywords"])) or proposal.proposed_tool in set(rule.get("representative_tools") or set())


def _task_text(task: Task) -> str:
    return " ".join(
        [
            str(task.tool or ""),
            str(task.target_id or ""),
            json.dumps(task.params_json if isinstance(task.params_json, dict) else {}, sort_keys=True, default=str),
        ]
    ).lower()


def _proposal_text(proposal: AgentProposal) -> str:
    return " ".join(
        [
            str(proposal.proposed_tool or ""),
            str(proposal.proposed_target or ""),
            json.dumps(
                proposal.proposed_params_json if isinstance(proposal.proposed_params_json, dict) else {},
                sort_keys=True,
                default=str,
            ),
        ]
    ).lower()


def _run_signal_text(runs: list[Run], targets: list[dict[str, str]], inventory_text: str) -> str:
    return " ".join(
        [
            inventory_text,
            json.dumps(targets, sort_keys=True, default=str),
            *[
                " ".join(
                    [
                        str(run.profile.name if run.profile is not None else ""),
                        str(run.profile.run_class if run.profile is not None else ""),
                        json.dumps(
                            run.configuration_json if isinstance(run.configuration_json, dict) else {},
                            sort_keys=True,
                            default=str,
                        ),
                    ]
                )
                for run in runs
            ],
        ]
    ).lower()


def _inventory_text(runs: list[Run]) -> str:
    payloads: list[str] = []
    for run in runs:
        snapshot = run.source_inventory_snapshot
        if snapshot is None:
            continue
        payloads.append(
            json.dumps(
                {
                    "normalized_inventory": snapshot.normalized_inventory_json,
                    "summary": snapshot.summary_json,
                    "source_tools": snapshot.source_tools_json,
                },
                sort_keys=True,
                default=str,
            )
        )
    return " ".join(payloads).lower()


def _runner_prerequisites(tool: str) -> list[str]:
    registry = runner_capability_registry()
    for capability in registry.get("capabilities", []):
        if isinstance(capability, dict) and capability.get("name") == tool:
            return [str(item) for item in capability.get("prerequisites", []) if str(item).strip()]
    return []


def _text_matches(text: str, keywords: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(str(keyword).lower() in lowered for keyword in keywords)
