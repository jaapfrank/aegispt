from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    Engagement,
    InternalValidationApproval,
    InternalValidationSession,
    InternalValidationStep,
    Run,
    RunProfile,
)
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.services.audit import write_audit_event
from api.app.services.runs import latest_scope_query, queue_run_tasks, required_approvals
from api.app.services.task_dispatch import dispatch_task_batch


FINAL_RUN_FAILURE_STATUSES = {"failed", "completed_with_errors", "rejected", "cancelled", "cancelling"}
SUCCESSFUL_STEP_STATUSES = {"completed"}
FINAL_STEP_STATUSES = {"completed", "failed", "rejected"}
WEB_SCOPE_KEYS = ("urls", "domains", "hosts", "targets")
CODE_SCOPE_KEYS = ("paths",)


@dataclass(slots=True, frozen=True)
class InternalValidationScenarioStepDefinition:
    step_id: str
    title: str
    description: str
    profile_name: str
    required_approvals: int
    required_scope_keys: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class InternalValidationScenarioDefinition:
    scenario_id: str
    name: str
    description: str
    steps: tuple[InternalValidationScenarioStepDefinition, ...]


CURATED_INTERNAL_VALIDATION_SCENARIOS: tuple[InternalValidationScenarioDefinition, ...] = (
    InternalValidationScenarioDefinition(
        scenario_id="curated-web-validation",
        name="Curated Web Validation",
        description="Human-in-the-loop web validation from passive baseline to controlled active ZAP.",
        steps=(
            InternalValidationScenarioStepDefinition(
                step_id="baseline-httpx",
                title="Passive Web Baseline",
                description="Collect passive HTTP fingerprints for the allowlisted web targets.",
                profile_name="passive-web-baseline",
                required_approvals=1,
                required_scope_keys=WEB_SCOPE_KEYS,
            ),
            InternalValidationScenarioStepDefinition(
                step_id="zap-passive-review",
                title="Approval-Gated ZAP Passive Validation",
                description="Run the approval-gated ZAP spider plus passive alert collection step.",
                profile_name="active-web-safe",
                required_approvals=1,
                required_scope_keys=WEB_SCOPE_KEYS,
            ),
            InternalValidationScenarioStepDefinition(
                step_id="zap-active-validation",
                title="Controlled Active ZAP Validation",
                description="Run the approval-gated ZAP active validation step with explicit reviewer sign-off.",
                profile_name="active-web-zap-active",
                required_approvals=2,
                required_scope_keys=WEB_SCOPE_KEYS,
            ),
        ),
    ),
    InternalValidationScenarioDefinition(
        scenario_id="curated-code-validation",
        name="Curated Code Validation",
        description="Human-reviewed Semgrep validation over allowlisted repository paths.",
        steps=(
            InternalValidationScenarioStepDefinition(
                step_id="semgrep-baseline",
                title="Semgrep Baseline",
                description="Run the curated Semgrep profile over allowlisted code paths.",
                profile_name="passive-code-semgrep-audit",
                required_approvals=1,
                required_scope_keys=CODE_SCOPE_KEYS,
            ),
        ),
    ),
)


def list_internal_validation_scenarios() -> tuple[InternalValidationScenarioDefinition, ...]:
    return CURATED_INTERNAL_VALIDATION_SCENARIOS


def get_internal_validation_scenario(scenario_id: str) -> InternalValidationScenarioDefinition | None:
    normalized = scenario_id.strip().lower()
    for scenario in CURATED_INTERNAL_VALIDATION_SCENARIOS:
        if scenario.scenario_id == normalized:
            return scenario
    return None


def granted_step_approvals(step: InternalValidationStep) -> int:
    return sum(1 for approval in step.approvals if approval.decision == "approved")


def pending_step_approvals(step: InternalValidationStep) -> int:
    return max(step.approval_count_required - granted_step_approvals(step), 0)


def sorted_internal_validation_steps(validation_session: InternalValidationSession) -> list[InternalValidationStep]:
    return sorted(
        validation_session.steps,
        key=lambda step: (step.sequence, step.created_at or datetime.min.replace(tzinfo=timezone.utc), str(step.id or "")),
    )


def sorted_step_approvals(step: InternalValidationStep) -> list[InternalValidationApproval]:
    return sorted(
        step.approvals,
        key=lambda approval: (
            approval.created_at or datetime.min.replace(tzinfo=timezone.utc),
            str(approval.id or ""),
        ),
    )


def load_internal_validation_session(session: Session, session_id: UUID) -> InternalValidationSession | None:
    return session.scalar(
        select(InternalValidationSession)
        .options(
            selectinload(InternalValidationSession.engagement),
            selectinload(InternalValidationSession.steps)
            .selectinload(InternalValidationStep.approvals),
            selectinload(InternalValidationSession.steps)
            .selectinload(InternalValidationStep.launched_run),
        )
        .where(InternalValidationSession.id == session_id)
    )


def list_engagement_internal_validation_sessions(
    session: Session,
    engagement_id: UUID,
) -> list[InternalValidationSession]:
    return list(
        session.scalars(
            select(InternalValidationSession)
            .where(InternalValidationSession.engagement_id == engagement_id)
            .order_by(InternalValidationSession.created_at, InternalValidationSession.id)
        ).all()
    )


def _scope_has_required_keys(scope, required_scope_keys: tuple[str, ...]) -> bool:
    allowlist_json = getattr(scope, "allowlist_json", {})
    for key in required_scope_keys:
        values = allowlist_json.get(key, [])
        if isinstance(values, list) and any(isinstance(value, str) and value.strip() for value in values):
            return True
    return False


def build_preflight_checks(
    *,
    session: Session,
    engagement: Engagement,
    scenario: InternalValidationScenarioDefinition | None,
    settings: Settings,
) -> tuple[str, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    scope = session.scalar(latest_scope_query(engagement.id))

    if scope is None:
        checks.append(
            {
                "check_id": "engagement.scope_present",
                "step_id": None,
                "status": "failed",
                "detail": "Engagement scope ontbreekt; internal validation kan niet starten.",
            }
        )
        return "failed", checks

    checks.append(
        {
            "check_id": "engagement.scope_present",
            "step_id": None,
            "status": "passed",
            "detail": "De engagement heeft een actieve scope.",
        }
    )

    kill_switch_enabled = execution_kill_switch_enabled(settings)
    checks.append(
        {
            "check_id": "execution.kill_switch_disabled",
            "step_id": None,
            "status": "warning" if kill_switch_enabled else "passed",
            "detail": (
                "De globale execution kill switch staat aan; nieuwe step-executies worden geblokkeerd totdat die weer uit staat."
                if kill_switch_enabled
                else "De globale execution kill switch staat uit."
            ),
        }
    )

    if scenario is None:
        checks.append(
            {
                "check_id": "scenario.exists",
                "step_id": None,
                "status": "failed",
                "detail": "Het gevraagde curated scenario bestaat niet.",
            }
        )
        return "failed", checks

    checks.append(
        {
            "check_id": "scenario.exists",
            "step_id": None,
            "status": "passed",
            "detail": f"Curated scenario '{scenario.scenario_id}' is beschikbaar.",
        }
    )

    failed = False

    for step in scenario.steps:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == step.profile_name))
        profile_present = profile is not None
        checks.append(
            {
                "check_id": f"profile.{step.profile_name}.available",
                "step_id": step.step_id,
                "status": "passed" if profile_present else "failed",
                "detail": (
                    f"Run-profiel '{step.profile_name}' is beschikbaar."
                    if profile_present
                    else f"Run-profiel '{step.profile_name}' ontbreekt."
                ),
            }
        )
        failed = failed or not profile_present

        scope_supported = _scope_has_required_keys(scope, step.required_scope_keys)
        checks.append(
            {
                "check_id": f"step.{step.step_id}.scope_requirements",
                "step_id": step.step_id,
                "status": "passed" if scope_supported else "failed",
                "detail": (
                    f"Scope ondersteunt stap '{step.step_id}'."
                    if scope_supported
                    else f"Scope mist een van de vereiste sleutels: {', '.join(step.required_scope_keys)}."
                ),
            }
        )
        failed = failed or not scope_supported

    return ("failed" if failed else "passed"), checks


def ensure_internal_validation_steps(
    *,
    validation_session: InternalValidationSession,
    scenario: InternalValidationScenarioDefinition,
) -> None:
    if validation_session.steps:
        return

    for index, step in enumerate(scenario.steps, start=1):
        validation_session.steps.append(
            InternalValidationStep(
                sequence=index,
                step_id=step.step_id,
                title=step.title,
                description=step.description,
                profile_name=step.profile_name,
                status="pending_preflight",
                approval_count_required=step.required_approvals,
                params_json={"required_scope_keys": list(step.required_scope_keys)},
            )
        )


def _map_launched_run_status(run_status: str) -> str:
    if run_status == "completed":
        return "completed"
    if run_status in FINAL_RUN_FAILURE_STATUSES:
        return "failed"
    if run_status in {"queued", "requested", "pending_approval"}:
        return "queued"
    return "running"


def refresh_internal_validation_session_state(
    *,
    session: Session,
    validation_session: InternalValidationSession,
    settings: Settings,
) -> InternalValidationScenarioDefinition | None:
    scenario = get_internal_validation_scenario(validation_session.scenario_id)
    engagement = validation_session.engagement
    if engagement is None:
        engagement = session.get(Engagement, validation_session.engagement_id)
        validation_session.engagement = engagement

    if engagement is None:
        validation_session.preflight_state = "failed"
        validation_session.preflight_json = {
            "checks": [
                {
                    "check_id": "engagement.exists",
                    "step_id": None,
                    "status": "failed",
                    "detail": "De gekoppelde engagement bestaat niet meer.",
                }
            ]
        }
        validation_session.status = "blocked_preflight"
        return scenario

    preflight_state, checks = build_preflight_checks(
        session=session,
        engagement=engagement,
        scenario=scenario,
        settings=settings,
    )
    validation_session.preflight_state = preflight_state
    validation_session.preflight_json = {"checks": checks}

    if scenario is None:
        validation_session.status = "blocked_preflight"
        return None

    ensure_internal_validation_steps(validation_session=validation_session, scenario=scenario)

    steps = sorted_internal_validation_steps(validation_session)
    prior_steps_satisfied = True
    any_running = False
    any_queued = False
    any_ready = False
    any_pending_approval = False

    if preflight_state != "passed":
        for step in steps:
            if step.status not in FINAL_STEP_STATUSES:
                step.status = "blocked_preflight"
        validation_session.status = "blocked_preflight"
        return scenario

    for step in steps:
        has_rejection = any(approval.decision == "rejected" for approval in step.approvals)
        if has_rejection:
            step.status = "rejected"
            step.completed_at = datetime.now(timezone.utc)
            prior_steps_satisfied = False
            continue

        if step.launched_run is not None:
            mapped_status = _map_launched_run_status(step.launched_run.status)
            step.status = mapped_status
            if mapped_status == "completed":
                if step.completed_at is None:
                    step.completed_at = datetime.now(timezone.utc)
            else:
                prior_steps_satisfied = False
                any_running = any_running or mapped_status == "running"
                any_queued = any_queued or mapped_status == "queued"
            continue

        if not prior_steps_satisfied:
            step.status = "pending_prerequisite"
            continue

        if pending_step_approvals(step) > 0:
            step.status = "pending_approval"
            any_pending_approval = True
            prior_steps_satisfied = False
        else:
            step.status = "ready"
            any_ready = True
            prior_steps_satisfied = False

    if any(step.status == "rejected" for step in steps):
        validation_session.status = "rejected"
    elif any(step.status == "failed" for step in steps):
        validation_session.status = "failed"
    elif all(step.status == "completed" for step in steps):
        validation_session.status = "completed"
    elif any_running:
        validation_session.status = "running"
    elif any_queued:
        validation_session.status = "queued"
    elif any_ready:
        validation_session.status = "ready"
    elif any_pending_approval:
        validation_session.status = "pending_approval"
    else:
        validation_session.status = "pending_prerequisite"

    first_started_step = next(
        (step for step in steps if step.status in {"queued", "running", "completed"} or step.launched_run_id is not None),
        None,
    )
    if first_started_step is not None and validation_session.started_at is None:
        validation_session.started_at = first_started_step.created_at

    if validation_session.status in {"completed", "failed", "rejected"}:
        validation_session.completed_at = validation_session.completed_at or datetime.now(timezone.utc)

    return scenario


def create_internal_validation_session(
    *,
    session: Session,
    engagement: Engagement,
    scenario_id: str,
    actor: str,
    settings: Settings,
) -> InternalValidationSession:
    scenario = get_internal_validation_scenario(scenario_id)
    validation_session = InternalValidationSession(
        engagement_id=engagement.id,
        scenario_id=scenario_id.strip().lower(),
        requested_by=actor,
        status="draft",
        preflight_state="pending",
        preflight_json={"checks": []},
    )
    session.add(validation_session)
    session.flush()

    if scenario is not None:
        ensure_internal_validation_steps(validation_session=validation_session, scenario=scenario)

    write_audit_event(
        session=session,
        actor=actor,
        action="internal_validation.requested",
        object_type="internal_validation_session",
        object_id=str(validation_session.id),
        metadata={"engagement_id": str(engagement.id), "scenario_id": validation_session.scenario_id},
    )

    refresh_internal_validation_session_state(
        session=session,
        validation_session=validation_session,
        settings=settings,
    )
    session.flush()
    return validation_session


def record_internal_validation_step_approval(
    *,
    session: Session,
    validation_session: InternalValidationSession,
    step: InternalValidationStep,
    actor: str,
    decision: str,
    settings: Settings,
) -> None:
    existing_approval = session.scalar(
        select(InternalValidationApproval).where(
            InternalValidationApproval.step_id == step.id,
            InternalValidationApproval.approver_id == actor,
        )
    )
    if existing_approval is not None:
        raise ValueError("actor already decided this internal validation step")

    approval = InternalValidationApproval(
        session_id=validation_session.id,
        step_id=step.id,
        approver_id=actor,
        decision=decision,
    )
    session.add(approval)
    step.approvals.append(approval)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="internal_validation.step.approval_recorded",
        object_type="internal_validation_step",
        object_id=str(step.id),
        metadata={"session_id": str(validation_session.id), "step_id": step.step_id, "decision": decision},
    )

    refresh_internal_validation_session_state(
        session=session,
        validation_session=validation_session,
        settings=settings,
    )


def execute_internal_validation_step(
    *,
    session: Session,
    validation_session: InternalValidationSession,
    step: InternalValidationStep,
    actor: str,
    settings: Settings,
) -> str:
    refresh_internal_validation_session_state(
        session=session,
        validation_session=validation_session,
        settings=settings,
    )

    if validation_session.preflight_state != "passed":
        raise ValueError("internal validation preflight has not passed")
    if step.status != "ready":
        raise ValueError(f"step is not ready for execution: {step.status}")
    if execution_kill_switch_enabled(settings):
        raise ValueError("execution kill switch is enabled")

    scope = session.scalar(latest_scope_query(validation_session.engagement_id))
    if scope is None:
        raise ValueError("engagement scope missing during internal validation execution")

    profile = session.scalar(select(RunProfile).where(RunProfile.name == step.profile_name))
    if profile is None:
        raise ValueError("run profile missing during internal validation execution")

    planned_dispatch_mode = settings.task_dispatch_mode.strip().lower()
    run = Run(
        engagement_id=validation_session.engagement_id,
        profile_id=profile.id,
        requested_by=actor,
        status="requested",
    )
    session.add(run)
    session.flush()
    validation_session_id = validation_session.id

    write_audit_event(
        session=session,
        actor=actor,
        action="run.requested",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "engagement_id": str(validation_session.engagement_id),
            "profile_name": profile.name,
            "internal_validation_session_id": str(validation_session.id),
            "internal_validation_step_id": step.step_id,
        },
    )

    queue_run_tasks(session, run, scope, profile)
    session.flush()
    task_ids = [task.id for task in run.tasks]
    write_audit_event(
        session=session,
        actor=actor,
        action="run.queued",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "engagement_id": str(validation_session.engagement_id),
            "profile_name": profile.name,
            "internal_validation_session_id": str(validation_session.id),
            "internal_validation_step_id": step.step_id,
            "run_required_approvals": required_approvals(profile),
        },
    )

    step.launched_run_id = run.id
    step.launched_run = run
    validation_session.started_at = validation_session.started_at or datetime.now(timezone.utc)

    write_audit_event(
        session=session,
        actor=actor,
        action="internal_validation.step.executed",
        object_type="internal_validation_step",
        object_id=str(step.id),
        metadata={
            "session_id": str(validation_session.id),
            "step_id": step.step_id,
            "launched_run_id": str(run.id),
            "dispatch_mode": planned_dispatch_mode,
        },
    )

    session.flush()
    session.commit()

    dispatch_mode = dispatch_task_batch(task_ids, settings)

    write_audit_event(
        session=session,
        actor=actor,
        action="run.dispatched",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "dispatch_mode": dispatch_mode,
            "task_count": len(task_ids),
            "internal_validation_session_id": str(validation_session_id),
            "internal_validation_step_id": step.step_id,
        },
    )

    session.expire_all()
    reloaded_validation_session = load_internal_validation_session(session, validation_session_id)
    if reloaded_validation_session is not None:
        refresh_internal_validation_session_state(
            session=session,
            validation_session=reloaded_validation_session,
            settings=settings,
        )
        session.flush()

    return dispatch_mode
