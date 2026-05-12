from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import AgentProposal, FindingChain, InventorySnapshot, Run, Scope, Task
from api.app.services.ai_enrichment import store_agent_proposal_record, store_agent_reasoning_record
from api.app.services.audit import write_audit_event
from api.app.services.finding_chains import refresh_finding_chains_for_run
from api.app.services.fingerprinting import build_signal_profile
from api.app.services.runner_registry import runner_capability_registry
from api.app.services.runs import granted_approvals, pending_approvals, queue_run_tasks

PLANNER_VERSION = "2026-05-07.1"
ADAPTIVE_WAVE_VERSION = "2026-05-07.1"
ADAPTIVE_WAVE_MAX = 5
RUN_CONFIDENCE_THRESHOLD = 0.7
INTRUSIVE_TIERS = {"intrusive"}
WEB_SIGNALS = {
    "web_target_present",
    "http_service",
    "html_response",
    "form_with_post_action",
    "login_form_found",
    "graphql_endpoint",
    "api_endpoint_present",
}
ACTIVE_TASK_STATUSES = {"queued", "pending", "running", "dispatching", "in_progress", "started"}
TERMINAL_TASK_STATUSES = {"completed", "failed", "cancelled", "skipped"}
SQLMAP_EVIDENCE = {"injectable_parameter", "sql_error_pattern"}
SQLMAP_WEAK_EVIDENCE = {
    "php_language",
    "mysql_database",
    "php_mysql_stack",
    "wordpress_cms",
    "login_form_found",
}
JWT_EVIDENCE = {"jwt_in_response", "authorization_bearer_header"}
DESERIALIZATION_EVIDENCE = {
    "java_indicators",
    "java_present",
    "java_spring_indicator",
    "serialized_cookie",
    "jsessionid_cookie",
}


@dataclass(frozen=True)
class PlannerSignals:
    snapshot: InventorySnapshot | None
    signals: set[str]
    signal_records: list[dict[str, Any]]
    stack: dict[str, Any]


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _plan_decisions(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    decisions: dict[str, dict[str, Any]] = {}
    for item in plan.get("runners", []):
        if not isinstance(item, dict):
            continue
        runner = str(item.get("runner") or "").strip()
        if not runner:
            continue
        decisions[runner] = {
            "decision": str(item.get("decision") or "").upper(),
            "confidence": item.get("confidence"),
            "matched_triggers": list(item.get("matched_triggers") or []),
            "matched_weak_triggers": list(item.get("matched_weak_triggers") or []),
            "missing_triggers": list(item.get("missing_triggers") or []),
            "risk_tier": item.get("risk_tier"),
            "required_approvals": item.get("required_approvals"),
            "summary": item.get("summary"),
        }
    return decisions


def _adaptive_wave_state(configuration: dict[str, Any]) -> dict[str, Any]:
    state = _as_dict(configuration.get("adaptive_execution_waves"))
    waves = state.get("waves") if isinstance(state.get("waves"), list) else []
    return {
        "enabled": True,
        "version": str(state.get("version") or ADAPTIVE_WAVE_VERSION),
        "max_waves": int(state.get("max_waves") or ADAPTIVE_WAVE_MAX),
        "operator_approval_required": True,
        "dispatches_work": False,
        "waves": [dict(wave) for wave in waves if isinstance(wave, dict)],
        "pending_wave": _as_dict(state.get("pending_wave")) or None,
        "last_plan_decisions": _as_dict(state.get("last_plan_decisions")),
        "latest_plan_summary": _as_dict(state.get("latest_plan_summary")),
    }


def _store_adaptive_wave_state(configuration: dict[str, Any], state: dict[str, Any]) -> None:
    configuration["adaptive_execution_waves"] = {
        "enabled": True,
        "version": ADAPTIVE_WAVE_VERSION,
        "max_waves": int(state.get("max_waves") or ADAPTIVE_WAVE_MAX),
        "operator_approval_required": True,
        "dispatches_work": False,
        "waves": list(state.get("waves") or []),
        "pending_wave": state.get("pending_wave"),
        "last_plan_decisions": _as_dict(state.get("last_plan_decisions")),
        "latest_plan_summary": _as_dict(state.get("latest_plan_summary")),
    }


def _boolish(value: object) -> bool:
    if isinstance(value, (list, tuple, set)):
        return any(_boolish(item) for item in value) or bool(value)
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "present", "detected"}
    return False


def _load_source_inventory_snapshot(session: Session, run: Run) -> InventorySnapshot | None:
    if run.source_inventory_snapshot is not None:
        return run.source_inventory_snapshot
    if run.source_inventory_snapshot_id is not None:
        return session.get(InventorySnapshot, run.source_inventory_snapshot_id)
    return session.scalar(
        select(InventorySnapshot)
        .where(InventorySnapshot.engagement_id == run.engagement_id)
        .order_by(InventorySnapshot.created_at.desc())
    )


def _add_signal(signals: set[str], key: str, value: object = True) -> None:
    if _boolish(value):
        signals.add(key)


def _extract_planner_signals(session: Session, run: Run) -> PlannerSignals:
    snapshot = _load_source_inventory_snapshot(session, run)
    inventory = snapshot.normalized_inventory_json if snapshot is not None else {}
    if not isinstance(inventory, dict):
        inventory = {}
    profile = inventory.get("signal_profile")
    profile = profile if isinstance(profile, dict) else {}
    stack = inventory.get("tech_stack_profile") or profile.get("tech_stack_profile") or {}
    stack = stack if isinstance(stack, dict) else {}
    signal_records = profile.get("signals")
    signal_records = signal_records if isinstance(signal_records, list) else []
    signals: set[str] = set()

    for record in signal_records:
        if not isinstance(record, dict):
            continue
        key = str(record.get("key") or "").strip()
        if key:
            signals.add(key)
            value = record.get("value")
            if isinstance(value, str) and value.strip():
                signals.add(value.strip().lower().replace(" ", "_").replace("/", "_"))

    for language in _as_list(stack.get("language")):
        normalized = str(language or "").strip().lower()
        if normalized:
            signals.add(f"{normalized}_language")
    for cms in _as_list(stack.get("cms")):
        normalized = str(cms or "").strip().lower()
        if normalized:
            signals.add(f"{normalized}_cms")
    for server in _as_list(stack.get("server")):
        normalized = str(server or "").strip().lower()
        if normalized:
            signals.add(f"{normalized}_server")

    _add_signal(signals, "jwt_in_response", stack.get("jwt_present"))
    _add_signal(signals, "graphql_endpoint", stack.get("graphql_present"))
    _add_signal(signals, "java_present", stack.get("java_present"))
    _add_signal(signals, "java_indicators", stack.get("java_indicators"))
    _add_signal(signals, "login_form_found", stack.get("login_forms"))
    _add_signal(signals, "form_with_post_action", stack.get("login_forms"))
    _add_signal(signals, "file_upload_endpoint", stack.get("file_upload_endpoints"))
    _add_signal(signals, "injectable_parameter", stack.get("injectable_parameters"))
    _add_signal(signals, "sql_error_pattern", stack.get("sql_error_patterns"))
    _add_signal(signals, "serialized_cookie", stack.get("serialized_cookie_hints"))
    if stack.get("graphql_endpoints"):
        signals.update({"graphql_endpoint", "api_endpoint_present"})
    if stack.get("api_endpoints") or stack.get("api_base_urls"):
        signals.add("api_endpoint_present")

    summary = snapshot.summary_json if snapshot is not None else {}
    summary = summary if isinstance(summary, dict) else {}
    normalized_targets = inventory.get("targets") or inventory.get("urls") or inventory.get("hosts")
    if _boolish(normalized_targets) or any(
        int(summary.get(key) or 0) > 0
        for key in ("url_count", "host_count", "service_count", "target_count")
    ):
        signals.update({"web_target_present", "http_service"})

    return PlannerSignals(
        snapshot=snapshot,
        signals=signals,
        signal_records=[record for record in signal_records if isinstance(record, dict)],
        stack=stack,
    )


def _matched(items: object, signals: set[str]) -> list[str]:
    return sorted({item for item in _as_list(items) if isinstance(item, str) and item in signals})


def _missing(items: object, signals: set[str]) -> list[str]:
    return sorted({item for item in _as_list(items) if isinstance(item, str) and item not in signals})


def _decision_sentence(
    runner: str,
    decision: str,
    matched_triggers: list[str],
    missing_triggers: list[str],
    matched_weak_triggers: list[str],
    blockers: list[str],
) -> str:
    if runner == "sqlmap" and decision == "WAIT":
        return (
            "SQL injection validation is waiting because PHP/MySQL-style hints are not enough "
            "without injectable parameter or SQL error evidence."
        )
    if runner == "jwt-probe" and decision == "SKIP":
        return "JWT validation is skipped because no JWT response or Bearer authorization signal was found."
    if runner == "deserialization-probe" and decision == "SKIP":
        return "Deserialization validation is skipped because no Java, JSESSIONID, or serialized cookie signal was found."
    if decision == "NEEDS_APPROVAL":
        return "Controlled proof work needs the explicit approval gate before any runner task can be queued."
    if decision == "RUN":
        evidence = ", ".join(matched_triggers[:3]) or ", ".join(matched_weak_triggers[:3])
        return f"{runner} is recommended because the current inventory contains {evidence}."
    if decision == "WAIT":
        evidence = ", ".join(matched_weak_triggers[:3]) or ", ".join(missing_triggers[:3])
        return f"{runner} should wait for stronger recon evidence; current signal gap is {evidence}."
    if blockers:
        return f"{runner} is skipped because {', '.join(blockers[:3])} blocks a safe run."
    return f"{runner} is skipped because required evidence is absent in the current SignalProfile."


def _score_capability(capability: dict[str, Any], signals: set[str]) -> dict[str, Any]:
    runner = str(capability.get("name") or "").strip()
    risk_tier = str(capability.get("risk_tier") or "active").strip().lower()
    required_approval_count = int(capability.get("required_approvals") or 0)
    triggers = capability.get("triggers") or []
    weak_triggers = capability.get("weak_triggers") or []
    blockers = capability.get("blockers") or []
    matched_triggers = _matched(triggers, signals)
    matched_weak_triggers = _matched(weak_triggers, signals)
    matched_blockers = _matched(blockers, signals)
    missing_triggers = _missing(triggers, signals)

    if risk_tier in INTRUSIVE_TIERS:
        decision = "NEEDS_APPROVAL"
        confidence = 0.95
    elif runner == "sqlmap":
        if matched_blockers:
            decision = "SKIP"
            confidence = 0.9
        elif SQLMAP_EVIDENCE.intersection(signals):
            decision = "RUN"
            confidence = 0.88
            matched_triggers = sorted(set(matched_triggers) | SQLMAP_EVIDENCE.intersection(signals))
        elif SQLMAP_WEAK_EVIDENCE.intersection(signals):
            decision = "WAIT"
            confidence = 0.35
            matched_weak_triggers = sorted(
                set(matched_weak_triggers) | SQLMAP_WEAK_EVIDENCE.intersection(signals)
            )
        else:
            decision = "WAIT"
            confidence = 0.25
    elif runner == "jwt-probe":
        if JWT_EVIDENCE.intersection(signals):
            decision = "RUN"
            confidence = 0.9
            matched_triggers = sorted(set(matched_triggers) | JWT_EVIDENCE.intersection(signals))
        else:
            decision = "SKIP"
            confidence = 0.05
    elif runner == "deserialization-probe":
        if DESERIALIZATION_EVIDENCE.intersection(signals):
            decision = "RUN"
            confidence = 0.86
            matched_triggers = sorted(
                set(matched_triggers) | DESERIALIZATION_EVIDENCE.intersection(signals)
            )
        else:
            decision = "SKIP"
            confidence = 0.08
    elif matched_blockers or any(
        b.startswith("no_") and (b[3:] not in signals) and (f"{b[3:]}_present" not in signals)
        for b in blockers
    ):
        decision = "SKIP"
        confidence = 0.88
    elif matched_triggers:
        ratio = len(matched_triggers) / max(len(_as_list(triggers)), 1)
        confidence = min(0.95, 0.62 + ratio * 0.28)
        decision = "RUN" if confidence >= RUN_CONFIDENCE_THRESHOLD else "WAIT"
    elif matched_weak_triggers:
        decision = "WAIT"
        confidence = 0.45
    elif WEB_SIGNALS.intersection(signals) and risk_tier == "passive":
        decision = "RUN"
        confidence = 0.72
    else:
        decision = "SKIP"
        confidence = 0.1

    reasons = [
        _decision_sentence(
            runner,
            decision,
            matched_triggers,
            missing_triggers,
            matched_weak_triggers,
            matched_blockers,
        )
    ]
    if decision == "NEEDS_APPROVAL" and required_approval_count:
        reasons.append(f"Runner metadata requires {required_approval_count} approval gate(s).")

    return {
        "runner": runner,
        "tool": runner,
        "decision": decision,
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "summary": reasons[0],
        "matched_triggers": matched_triggers,
        "matched_weak_triggers": matched_weak_triggers,
        "missing_triggers": missing_triggers,
        "blockers": matched_blockers,
        "risk_tier": risk_tier,
        "required_approvals": required_approval_count,
        "estimated_minutes": int(capability.get("estimated_minutes") or 0),
        "cost": capability.get("cost"),
        "false_positive_rate": capability.get("false_positive_rate"),
        "expected_evidence": list(capability.get("expected_evidence") or []),
        "follow_up_tools": list(capability.get("follow_up_tools") or []),
        "category": capability.get("category"),
        "description": capability.get("description"),
    }


def build_assessment_plan_for_run(session: Session, run: Run) -> dict[str, Any]:
    planner_signals = _extract_planner_signals(session, run)
    registry = runner_capability_registry()
    runners = [
        _score_capability(capability, planner_signals.signals)
        for capability in registry.get("capabilities", [])
        if isinstance(capability, dict)
    ]
    runners.sort(
        key=lambda item: (
            {"RUN": 0, "NEEDS_APPROVAL": 1, "WAIT": 2, "SKIP": 3}.get(item["decision"], 9),
            -float(item["confidence"]),
            item["runner"],
        )
    )
    counts = Counter(item["decision"] for item in runners)
    source_snapshot_id = planner_signals.snapshot.id if planner_signals.snapshot is not None else None
    return {
        "available": True,
        "planner_version": PLANNER_VERSION,
        "metadata_version": registry.get("metadata_version"),
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": str(run.id),
        "source_inventory_snapshot_id": str(source_snapshot_id) if source_snapshot_id else None,
        "signal_count": len(planner_signals.signals),
        "signals": sorted(planner_signals.signals),
        "dispatches_work": False,
        "operator_review_required": True,
        "summary": {
            "run_count": counts.get("RUN", 0),
            "wait_count": counts.get("WAIT", 0),
            "skip_count": counts.get("SKIP", 0),
            "needs_approval_count": counts.get("NEEDS_APPROVAL", 0),
            "selected_by_default": [
                item["runner"] for item in runners if item.get("decision") == "RUN"
            ],
        },
        "runners": runners,
    }


def _active_wave_task_statuses(run: Run) -> list[dict[str, str]]:
    active: list[dict[str, str]] = []
    for task in list(run.tasks or []):
        status = str(task.status or "").strip().lower()
        if status in ACTIVE_TASK_STATUSES:
            active.append({"task_id": str(task.id), "tool": task.tool, "status": status})
    return active


def _completed_wave_tasks(run: Run, wave_number: int) -> list[Task]:
    scoped: list[Task] = []
    fallback: list[Task] = []
    for task in list(run.tasks or []):
        status = str(task.status or "").strip().lower()
        if status not in TERMINAL_TASK_STATUSES:
            continue
        fallback.append(task)
        params = task.params_json if isinstance(task.params_json, dict) else {}
        wave = params.get("adaptive_execution_wave")
        if isinstance(wave, dict) and int(wave.get("wave_number") or 0) == wave_number:
            scoped.append(task)
    return scoped or fallback


def _append_signal(signals: list[dict[str, Any]], seen: set[tuple[str, str, str]], signal: dict[str, Any]) -> None:
    key = str(signal.get("key") or "").strip()
    source = str(signal.get("source") or "adaptive_wave").strip()
    value = signal.get("value")
    if not key or value in (None, ""):
        return
    marker = (key, str(value), source)
    if marker in seen:
        return
    seen.add(marker)
    confidence = signal.get("confidence")
    try:
        normalized_confidence = round(max(0.0, min(float(confidence), 1.0)), 3)
    except (TypeError, ValueError):
        normalized_confidence = 0.7
    signals.append({"key": key, "value": value, "confidence": normalized_confidence, "source": source})


def _signals_from_text(*, text: str, source: str, target: str) -> list[dict[str, Any]]:
    lowered = text.lower()
    signals: list[dict[str, Any]] = []
    if "reflected" in lowered and any(token in lowered for token in ("parameter", "input", "field", "query")):
        signals.append(
            {
                "key": "injectable_parameter",
                "value": target or "reflected-input",
                "confidence": 0.72,
                "source": source,
            }
        )
        signals.append(
            {
                "key": "reflected_parameter",
                "value": target or "reflected-input",
                "confidence": 0.72,
                "source": source,
            }
        )
    if "form" in lowered or "input field" in lowered or "text field" in lowered:
        signals.append(
            {
                "key": "form_inputs_present",
                "value": target or True,
                "confidence": 0.7,
                "source": source,
            }
        )
    if "post action" in lowered or ("form" in lowered and "post" in lowered):
        signals.append(
            {
                "key": "form_with_post_action",
                "value": target or True,
                "confidence": 0.72,
                "source": source,
            }
        )
    if "login" in lowered or "auth flow" in lowered or "authentication flow" in lowered:
        signals.append(
            {
                "key": "login_form_found",
                "value": target or True,
                "confidence": 0.74,
                "source": source,
            }
        )
        signals.append(
            {
                "key": "auth_flow_present",
                "value": target or True,
                "confidence": 0.68,
                "source": source,
            }
        )
    if "session cookie" in lowered or "set-cookie" in lowered:
        signals.append(
            {
                "key": "session_cookie_present",
                "value": target or True,
                "confidence": 0.76,
                "source": source,
            }
        )
    if "file upload" in lowered or "upload endpoint" in lowered:
        signals.append(
            {
                "key": "file_upload_endpoint",
                "value": target or True,
                "confidence": 0.82,
                "source": source,
            }
        )
    return signals


def _wave_evidence_signals(run: Run, tasks: list[Task]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    task_ids = {task.id for task in tasks}
    for finding in list(run.findings or []):
        text = " ".join(
            [
                str(finding.title or ""),
                str(finding.summary or ""),
                " ".join(str(tag) for tag in list(finding.methodology_tags or [])),
                str(finding.evidence_ref or ""),
            ]
        )
        signals.extend(
            _signals_from_text(
                text=text,
                source=f"finding:{finding.id}",
                target=str(finding.target_id or ""),
            )
        )
    for task in tasks:
        for execution in list(task.executions or []):
            text = " ".join([str(execution.stdout_text or ""), str(execution.stderr_text or "")])
            signals.extend(
                _signals_from_text(
                    text=text,
                    source=f"tool_execution:{execution.id}",
                    target=str(task.target_id or ""),
                )
            )
    if not task_ids:
        return signals
    return signals


def _create_wave_signal_snapshot(
    *,
    session: Session,
    run: Run,
    actor: str,
    wave_number: int,
    tasks: list[Task],
) -> InventorySnapshot:
    base_snapshot = _load_source_inventory_snapshot(session, run)
    base_inventory = (
        deepcopy(base_snapshot.normalized_inventory_json)
        if base_snapshot is not None and isinstance(base_snapshot.normalized_inventory_json, dict)
        else {}
    )
    base_summary = (
        deepcopy(base_snapshot.summary_json)
        if base_snapshot is not None and isinstance(base_snapshot.summary_json, dict)
        else {}
    )
    profile = base_inventory.get("signal_profile")
    profile = profile if isinstance(profile, dict) else {}
    existing_signals = [dict(item) for item in _as_list(profile.get("signals")) if isinstance(item, dict)]
    merged_signals: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for signal in existing_signals + _wave_evidence_signals(run, tasks):
        _append_signal(merged_signals, seen, signal)

    rebuilt_profile = build_signal_profile(
        observations=[
            {
                "tool": "adaptive-wave-evidence",
                "kind": "signal_profile",
                "data": {"signal_profile": {"signals": merged_signals}},
            }
        ],
        normalized_inventory=base_inventory,
    )
    base_inventory["signal_profile"] = rebuilt_profile
    base_inventory["tech_stack_profile"] = rebuilt_profile.get("tech_stack_profile", {})
    base_inventory["adaptive_execution_wave"] = {
        "wave_number": wave_number,
        "source_run_id": str(run.id),
        "source_inventory_snapshot_id": str(base_snapshot.id) if base_snapshot is not None else None,
        "completed_task_ids": [str(task.id) for task in tasks],
        "derived_signal_count": max(0, len(merged_signals) - len(existing_signals)),
        "operator_controlled_replan": True,
    }
    base_summary = {
        **base_summary,
        "signal_count": len(rebuilt_profile.get("signals") or []),
        "adaptive_wave_number": wave_number,
        "adaptive_wave_completed_task_count": len(tasks),
    }
    snapshot = InventorySnapshot(
        engagement_id=run.engagement_id,
        requested_by=actor,
        status="completed",
        source_tools_json=sorted(
            set(
                [
                    *(
                        list(base_snapshot.source_tools_json or [])
                        if base_snapshot is not None and isinstance(base_snapshot.source_tools_json, list)
                        else []
                    ),
                    "adaptive-wave-evidence",
                ]
            )
        ),
        raw_inputs_json={
            "adaptive_wave": {
                "wave_number": wave_number,
                "run_id": str(run.id),
                "source_inventory_snapshot_id": str(base_snapshot.id) if base_snapshot is not None else None,
                "completed_task_ids": [str(task.id) for task in tasks],
            }
        },
        normalized_inventory_json=base_inventory,
        summary_json=base_summary,
        environment_notes_json=list(base_snapshot.environment_notes_json or []) if base_snapshot is not None else [],
        assumptions_json=list(base_snapshot.assumptions_json or []) if base_snapshot is not None else [],
        confidence_score=float(base_snapshot.confidence_score if base_snapshot is not None else 0.72),
    )
    session.add(snapshot)
    session.flush()
    run.source_inventory_snapshot_id = snapshot.id
    run.source_inventory_snapshot = snapshot
    return snapshot


def _proposal_target_for_run(run: Run, fallback: str | None = None) -> str:
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    targets = configuration.get("targets") if isinstance(configuration.get("targets"), dict) else {}
    for key in ("urls", "hosts", "ip_addresses", "domains", "cidr_ranges"):
        values = targets.get(key)
        if isinstance(values, list):
            for value in values:
                text = str(value or "").strip()
                if text:
                    return text
    return str(fallback or run.id)


def _existing_adaptive_proposal(
    *,
    session: Session,
    run: Run,
    proposal_kind: str,
    wave_number: int,
    runner: str | None = None,
    finding_chain_id: str | None = None,
) -> AgentProposal | None:
    proposals = session.scalars(
        select(AgentProposal).where(
            AgentProposal.run_id == run.id,
            AgentProposal.status == "pending_review",
        )
    ).all()
    for proposal in proposals:
        metadata = proposal.metadata_json if isinstance(proposal.metadata_json, dict) else {}
        if metadata.get("proposal_kind") != proposal_kind:
            continue
        if int(metadata.get("source_wave_number") or 0) != wave_number:
            continue
        if runner and proposal.proposed_tool != runner:
            continue
        if finding_chain_id and str(metadata.get("finding_chain_id") or "") != finding_chain_id:
            continue
        return proposal
    return None


def _store_promoted_runner_proposals(
    *,
    session: Session,
    run: Run,
    reasoning,
    wave_number: int,
    snapshot: InventorySnapshot,
    promoted_items: list[dict[str, Any]],
) -> list[AgentProposal]:
    proposals: list[AgentProposal] = []
    target = _proposal_target_for_run(run)
    for item in promoted_items:
        runner = str(item.get("runner") or "").strip()
        if not runner:
            continue
        if _existing_adaptive_proposal(
            session=session,
            run=run,
            proposal_kind="adaptive_execution_wave",
            wave_number=wave_number,
            runner=runner,
        ):
            continue
        proposals.append(
            store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool=runner,
                proposed_target=target,
                proposed_params={
                    "source_inventory_snapshot_id": str(snapshot.id),
                    "adaptive_execution_wave": {
                        "source_wave_number": wave_number,
                        "proposed_wave_number": wave_number + 1,
                        "previous_decision": "WAIT",
                        "current_decision": "RUN",
                        "matched_triggers": list(item.get("matched_triggers") or []),
                        "operator_approval_required": True,
                        "dispatches_work": False,
                    },
                    "review_required": True,
                },
                reasoning_text=(
                    f"{runner} moved from WAIT to RUN after wave {wave_number} updated the "
                    "SignalProfile with evidence-backed signals. Queueing still requires explicit operator review."
                ),
                risk_tier=str(item.get("risk_tier") or "active"),
                priority=20,
                confidence_score=float(item.get("confidence") or 0.0),
                metadata={
                    "proposal_kind": "adaptive_execution_wave",
                    "source_wave_number": wave_number,
                    "proposed_wave_number": wave_number + 1,
                    "source_inventory_snapshot_id": str(snapshot.id),
                    "dispatches_work": False,
                    "requires_operator_review": True,
                    "operator_controlled_flow_only": True,
                    "autonomous_wave_dispatch_allowed": False,
                },
            )
        )
    return proposals


def _chain_target(chain: FindingChain, run: Run) -> str:
    for finding in list(run.findings or []):
        if str(finding.id) in {str(item) for item in list(chain.component_finding_ids_json or [])}:
            target = str(finding.target_id or "").strip()
            if target:
                return target
    return _proposal_target_for_run(run)


def _store_compound_chain_wave_proposals(
    *,
    session: Session,
    run: Run,
    reasoning,
    wave_number: int,
    snapshot: InventorySnapshot,
    chains: list[FindingChain],
) -> list[AgentProposal]:
    proposals: list[AgentProposal] = []
    for chain in chains:
        if chain.pattern_id != "web-file-upload-plus-stored-xss":
            continue
        if _existing_adaptive_proposal(
            session=session,
            run=run,
            proposal_kind="adaptive_execution_wave_compound_chain",
            wave_number=wave_number,
            finding_chain_id=str(chain.id),
        ):
            continue
        proposals.append(
            store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool="auth-flow",
                proposed_target=_chain_target(chain, run),
                proposed_params={
                    "source_inventory_snapshot_id": str(snapshot.id),
                    "adaptive_execution_wave": {
                        "source_wave_number": wave_number,
                        "proposed_wave_number": wave_number + 1,
                        "finding_chain_id": str(chain.id),
                        "pattern_id": chain.pattern_id,
                        "component_finding_ids": list(chain.component_finding_ids_json or []),
                        "operator_approval_required": True,
                        "dispatches_work": False,
                        "safe_boundaries": {
                            "controlled_proof_only": True,
                            "canary_evidence_only": True,
                            "credential_collection": False,
                            "session_exposure_claim_requires_evidence": True,
                        },
                    },
                    "review_required": True,
                },
                reasoning_text=(
                    "Wave evidence links file-upload and stored-XSS findings. Review auth-flow as a "
                    "controlled proof proposal for session exposure risk; no task is queued until approved."
                ),
                risk_tier="active",
                priority=25,
                confidence_score=float(chain.confidence_score or 0.0),
                metadata={
                    "proposal_kind": "adaptive_execution_wave_compound_chain",
                    "source_wave_number": wave_number,
                    "proposed_wave_number": wave_number + 1,
                    "finding_chain_id": str(chain.id),
                    "pattern_id": chain.pattern_id,
                    "source_inventory_snapshot_id": str(snapshot.id),
                    "dispatches_work": False,
                    "requires_operator_review": True,
                    "operator_controlled_flow_only": True,
                    "autonomous_wave_dispatch_allowed": False,
                },
            )
        )
    return proposals


def complete_adaptive_execution_wave(
    session: Session,
    *,
    run: Run,
    actor: str,
    operator_note: str | None = None,
) -> dict[str, Any]:
    active_tasks = _active_wave_task_statuses(run)
    if active_tasks:
        raise ValueError("adaptive wave completion requires all queued or running tasks to finish first")

    configuration = dict(run.configuration_json or {})
    wave_state = _adaptive_wave_state(configuration)
    waves = list(wave_state.get("waves") or [])
    max_waves = int(wave_state.get("max_waves") or ADAPTIVE_WAVE_MAX)
    if len(waves) >= max_waves:
        raise ValueError(f"adaptive execution waves are capped at {max_waves} per engagement")

    pending_wave = wave_state.get("pending_wave") if isinstance(wave_state.get("pending_wave"), dict) else {}
    wave_number = int(pending_wave.get("wave_number") or (len(waves) + 1))
    previous_decisions = _as_dict(wave_state.get("last_plan_decisions"))
    if not previous_decisions:
        previous_decisions = _plan_decisions(build_assessment_plan_for_run(session, run))

    completed_tasks = _completed_wave_tasks(run, wave_number)
    snapshot = _create_wave_signal_snapshot(
        session=session,
        run=run,
        actor=actor,
        wave_number=wave_number,
        tasks=completed_tasks,
    )
    current_plan = build_assessment_plan_for_run(session, run)
    current_decisions = _plan_decisions(current_plan)
    promoted_items = [
        item
        for item in current_plan.get("runners", [])
        if isinstance(item, dict)
        and str(item.get("decision") or "").upper() == "RUN"
        and _as_dict(previous_decisions.get(str(item.get("runner") or ""))).get("decision") == "WAIT"
    ]
    persisted_skip_count = sum(
        1
        for runner, previous in previous_decisions.items()
        if _as_dict(previous).get("decision") == "SKIP"
        and _as_dict(current_decisions.get(runner)).get("decision") == "SKIP"
    )
    skip_contradicted = [
        runner
        for runner, previous in previous_decisions.items()
        if _as_dict(previous).get("decision") == "SKIP"
        and _as_dict(current_decisions.get(runner)).get("decision") != "SKIP"
    ]
    chains = refresh_finding_chains_for_run(session=session, run_id=run.id)
    promoted_runners = [str(item.get("runner")) for item in promoted_items]
    observations = [
        {
            "summary": (
                f"Wave {wave_number} complete: {len(completed_tasks)} runner task(s) finished; "
                f"{len(promoted_runners)} runner(s) moved from WAIT to RUN."
            ),
            "evidence_ref": "inventory_snapshot.signal_profile",
            "source_inventory_snapshot_id": str(snapshot.id),
        }
    ]
    hypotheses = [
        {
            "summary": "WAIT runners were re-scored against the updated SignalProfile; promoted runners remain proposals until operator approval.",
            "confidence": 0.82,
        }
    ]
    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        reasoning_type="adaptive_execution_wave",
        status="succeeded",
        context_snapshot={
            "run_id": str(run.id),
            "wave_number": wave_number,
            "previous_plan_decisions": previous_decisions,
            "current_plan_summary": current_plan.get("summary", {}),
            "source_inventory_snapshot_id": str(snapshot.id),
            "completed_task_ids": [str(task.id) for task in completed_tasks],
            "finding_chain_ids": [str(chain.id) for chain in chains],
            "boundary": {
                "dispatches_work": False,
                "creates_tasks": False,
                "operator_approval_required": True,
                "max_waves": max_waves,
            },
        },
        observations=observations,
        hypotheses=hypotheses,
        proposals=[
            {"tool": item.get("runner"), "target": _proposal_target_for_run(run), "summary": item.get("summary")}
            for item in promoted_items
        ],
        summary_text=observations[0]["summary"],
        thought_text=hypotheses[0]["summary"],
        action_text=(
            "Review promoted runner proposals before queueing the next evidence wave."
            if promoted_items or chains
            else "No WAIT runner was unblocked; the operator can stop or wait for new evidence."
        ),
        provider="deterministic-adaptive-wave",
        model="none",
        llm_tokens_used=0,
        confidence_score=0.82,
        metadata={
            "provider_mode": "deterministic",
            "dispatches_work": False,
            "operator_controlled_flow_only": True,
            "wave_number": wave_number,
            "source_inventory_snapshot_id": str(snapshot.id),
        },
    )
    runner_proposals = _store_promoted_runner_proposals(
        session=session,
        run=run,
        reasoning=reasoning,
        wave_number=wave_number,
        snapshot=snapshot,
        promoted_items=promoted_items,
    )
    chain_proposals = _store_compound_chain_wave_proposals(
        session=session,
        run=run,
        reasoning=reasoning,
        wave_number=wave_number,
        snapshot=snapshot,
        chains=chains,
    )
    proposal_ids = [str(proposal.id) for proposal in [*runner_proposals, *chain_proposals]]
    wave_record = {
        "wave_number": wave_number,
        "status": "completed",
        "completed_at": datetime.now(UTC).isoformat(),
        "completed_task_ids": [str(task.id) for task in completed_tasks],
        "completed_runner_count": len({task.tool for task in completed_tasks}),
        "source_inventory_snapshot_id": str(snapshot.id),
        "signal_count": current_plan.get("signal_count"),
        "promoted_runners": promoted_runners,
        "promoted_count": len(promoted_runners),
        "proposal_ids": proposal_ids,
        "wait_count": int(_as_dict(current_plan.get("summary")).get("wait_count") or 0),
        "skip_count": int(_as_dict(current_plan.get("summary")).get("skip_count") or 0),
        "persisted_skip_count": persisted_skip_count,
        "skip_contradicted_runners": skip_contradicted,
        "compound_chain_count": len(chains),
        "operator_approval_required": True,
        "dispatches_work": False,
        "operator_note": (operator_note or "").strip() or None,
    }
    waves.append(wave_record)
    wave_state["waves"] = waves
    wave_state["pending_wave"] = None
    wave_state["last_plan_decisions"] = current_decisions
    wave_state["latest_plan_summary"] = dict(current_plan.get("summary") or {})
    _store_adaptive_wave_state(configuration, wave_state)
    run.configuration_json = configuration
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_plan.adaptive_wave_completed",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "wave_number": wave_number,
            "source_inventory_snapshot_id": str(snapshot.id),
            "promoted_runners": promoted_runners,
            "proposal_ids": proposal_ids,
            "dispatches_work": False,
            "operator_controlled_flow_only": True,
        },
    )
    return {
        "run": run,
        "assessment_plan": current_plan,
        "adaptive_execution_waves": configuration["adaptive_execution_waves"],
        "proposal_ids": proposal_ids,
        "reasoning_id": str(reasoning.id),
    }


def _selected_plan_items(plan: dict[str, Any], approved_runners: list[str]) -> list[dict[str, Any]]:
    requested = {str(runner or "").strip() for runner in approved_runners if str(runner or "").strip()}
    return [
        item
        for item in plan.get("runners", [])
        if isinstance(item, dict) and str(item.get("runner") or "").strip() in requested
    ]


def queue_assessment_plan_tasks(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    approved_runners: list[str],
    actor: str,
    allow_wait_overrides: bool = False,
) -> dict[str, Any]:
    if run.profile is None:
        raise ValueError("run profile relationship not loaded")
    existing_tasks = session.scalars(select(Task).where(Task.run_id == run.id)).first()
    if existing_tasks is not None:
        raise ValueError("assessment plan can only queue before runner tasks exist")
    if pending_approvals(run, run.profile) > 0:
        raise ValueError("run approval gate is still pending")
    plan = build_assessment_plan_for_run(session, run)
    selected_items = _selected_plan_items(plan, approved_runners)
    selected_runners = [str(item["runner"]) for item in selected_items]
    invalid = sorted(
        {
            str(runner or "").strip()
            for runner in approved_runners
            if str(runner or "").strip() and str(runner or "").strip() not in selected_runners
        }
    )
    blocked: list[dict[str, Any]] = []
    launchable: list[str] = []
    granted = granted_approvals(run, profile=run.profile)

    for item in selected_items:
        decision = str(item.get("decision") or "")
        required = int(item.get("required_approvals") or 0)
        if decision == "RUN":
            pass
        elif decision == "WAIT" and allow_wait_overrides:
            pass
        else:
            blocked.append({"runner": item.get("runner"), "reason": f"decision is {decision}"})
            continue
        if str(item.get("risk_tier") or "").lower() in INTRUSIVE_TIERS:
            blocked.append({"runner": item.get("runner"), "reason": "explicit approval gate required"})
            continue
        if required > granted:
            blocked.append(
                {
                    "runner": item.get("runner"),
                    "reason": f"requires {required} approval gate(s); {granted} granted on this run",
                }
            )
            continue
        launchable.append(str(item["runner"]))

    if invalid:
        blocked.extend({"runner": runner, "reason": "not present in assessment plan"} for runner in invalid)
    if not launchable:
        return {"run": run, "plan": plan, "queued_tasks": [], "blocked": blocked}

    limits_json = dict(run.profile.limits_json or {})
    limits_json["tools"] = launchable
    planner_profile = SimpleNamespace(
        name=f"{run.profile.name}-assessment-plan",
        run_class=run.profile.run_class,
        limits_json=limits_json,
    )
    queued_tasks: list[Task] = queue_run_tasks(session, run, scope, planner_profile)  # type: ignore[arg-type]
    queued_runner_names = sorted({task.tool for task in queued_tasks})
    configuration = dict(run.configuration_json or {})
    wave_state = _adaptive_wave_state(configuration)
    waves = list(wave_state.get("waves") or [])
    next_wave_number = min(len(waves) + 1, int(wave_state.get("max_waves") or ADAPTIVE_WAVE_MAX))
    wave_state["pending_wave"] = {
        "wave_number": next_wave_number,
        "status": "queued",
        "queued_at": datetime.now(UTC).isoformat(),
        "approved_by": actor,
        "approved_runners": launchable,
        "queued_runners": queued_runner_names,
        "source_inventory_snapshot_id": plan.get("source_inventory_snapshot_id"),
        "operator_approval_required": True,
        "dispatches_work": False,
    }
    wave_state["last_plan_decisions"] = _plan_decisions(plan)
    wave_state["latest_plan_summary"] = dict(plan.get("summary") or {})
    _store_adaptive_wave_state(configuration, wave_state)
    for task in queued_tasks:
        params = dict(task.params_json or {})
        params["adaptive_execution_wave"] = {
            "wave_number": next_wave_number,
            "approved_by": actor,
            "approved_at": wave_state["pending_wave"]["queued_at"],
            "source_inventory_snapshot_id": plan.get("source_inventory_snapshot_id"),
            "operator_approval_required": True,
            "dispatch_mode": "queued_not_dispatched",
        }
        task.params_json = params
    configuration["assessment_plan"] = {
        "planner_version": plan["planner_version"],
        "source_inventory_snapshot_id": plan.get("source_inventory_snapshot_id"),
        "approved_runners": launchable,
        "queued_runners": queued_runner_names,
        "blocked": blocked,
        "approved_by": actor,
        "approved_at": datetime.now(UTC).isoformat(),
    }
    run.configuration_json = configuration
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_plan.queued",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "approved_runners": launchable,
            "queued_runners": queued_runner_names,
            "blocked": blocked,
            "decision_summary": plan.get("summary", {}),
        },
    )
    return {"run": run, "plan": plan, "queued_tasks": queued_tasks, "blocked": blocked}
