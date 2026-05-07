from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import InventorySnapshot, Run, Scope, Task
from api.app.services.audit import write_audit_event
from api.app.services.runner_registry import runner_capability_registry
from api.app.services.runs import granted_approvals, pending_approvals, queue_run_tasks


PLANNER_VERSION = "2026-05-07.1"
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
    elif matched_blockers:
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
