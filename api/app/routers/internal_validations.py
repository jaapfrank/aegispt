from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import Engagement, InternalValidationStep
from api.app.schemas.internal_validations import (
    InternalValidationApprovalRead,
    InternalValidationCreate,
    InternalValidationPreflightCheckRead,
    InternalValidationScenarioRead,
    InternalValidationScenarioStepRead,
    InternalValidationSessionRead,
    InternalValidationStepApprovalCreate,
    InternalValidationStepExecuteRead,
    InternalValidationStepRead,
)
from api.app.services.internal_validations import (
    create_internal_validation_session,
    execute_internal_validation_step,
    get_internal_validation_scenario,
    granted_step_approvals,
    list_engagement_internal_validation_sessions,
    list_internal_validation_scenarios,
    load_internal_validation_session,
    pending_step_approvals,
    record_internal_validation_step_approval,
    refresh_internal_validation_session_state,
    sorted_internal_validation_steps,
    sorted_step_approvals,
)
from api.app.services.run_profiles import ensure_default_run_profiles

router = APIRouter(prefix="/api/v1", tags=["internal-validations"])


def serialize_scenario(scenario) -> InternalValidationScenarioRead:
    return InternalValidationScenarioRead(
        scenario_id=scenario.scenario_id,
        name=scenario.name,
        description=scenario.description,
        steps=[
            InternalValidationScenarioStepRead(
                step_id=step.step_id,
                title=step.title,
                description=step.description,
                profile_name=step.profile_name,
                required_approvals=step.required_approvals,
                required_scope_keys=list(step.required_scope_keys),
            )
            for step in scenario.steps
        ],
    )


def serialize_internal_validation_session(
    validation_session,
    *,
    settings: Settings,
    db_session: Session,
) -> InternalValidationSessionRead:
    scenario = refresh_internal_validation_session_state(
        session=db_session,
        validation_session=validation_session,
        settings=settings,
    )
    checks = validation_session.preflight_json.get("checks", [])
    steps = sorted_internal_validation_steps(validation_session)
    return InternalValidationSessionRead(
        id=validation_session.id,
        engagement_id=validation_session.engagement_id,
        scenario_id=validation_session.scenario_id,
        scenario_name=scenario.name if scenario is not None else validation_session.scenario_id,
        requested_by=validation_session.requested_by,
        status=validation_session.status,
        preflight_state=validation_session.preflight_state,
        preflight_checks=[
            InternalValidationPreflightCheckRead(
                check_id=str(check.get("check_id", "")),
                step_id=str(check["step_id"]) if check.get("step_id") is not None else None,
                status=str(check.get("status", "unknown")),
                detail=str(check.get("detail", "")),
            )
            for check in checks
            if isinstance(check, dict)
        ],
        steps=[
            InternalValidationStepRead(
                id=step.id,
                step_id=step.step_id,
                sequence=step.sequence,
                title=step.title,
                description=step.description,
                profile_name=step.profile_name,
                status=step.status,
                required_approvals=step.approval_count_required,
                granted_approvals=granted_step_approvals(step),
                pending_approvals=pending_step_approvals(step),
                approvals=[
                    InternalValidationApprovalRead(
                        id=approval.id,
                        approver_id=approval.approver_id,
                        decision=approval.decision,
                        created_at=approval.created_at,
                    )
                    for approval in sorted_step_approvals(step)
                ],
                launched_run_id=step.launched_run_id,
                launched_run_status=step.launched_run.status if step.launched_run is not None else None,
                completed_at=step.completed_at,
            )
            for step in steps
        ],
        created_at=validation_session.created_at,
        started_at=validation_session.started_at,
        completed_at=validation_session.completed_at,
    )


def _load_step_or_404(validation_session, step_id: str) -> InternalValidationStep:
    for step in validation_session.steps:
        if step.step_id == step_id:
            return step
    raise HTTPException(status_code=404, detail="internal validation step not found")


@router.get("/internal-validations/scenarios", response_model=list[InternalValidationScenarioRead])
def list_scenarios() -> list[InternalValidationScenarioRead]:
    return [serialize_scenario(scenario) for scenario in list_internal_validation_scenarios()]


@router.get(
    "/engagements/{engagement_id}/internal-validations",
    response_model=list[InternalValidationSessionRead],
)
def list_sessions_for_engagement(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[InternalValidationSessionRead]:
    if ensure_default_run_profiles(session):
        session.commit()
    sessions = [
        load_internal_validation_session(session, validation_session.id)
        for validation_session in list_engagement_internal_validation_sessions(session, engagement_id)
    ]
    return [
        serialize_internal_validation_session(validation_session, settings=settings, db_session=session)
        for validation_session in sessions
        if validation_session is not None
    ]


@router.post(
    "/engagements/{engagement_id}/internal-validations",
    response_model=InternalValidationSessionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_session(
    engagement_id: UUID,
    payload: InternalValidationCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> InternalValidationSessionRead:
    if ensure_default_run_profiles(session):
        session.commit()
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if get_internal_validation_scenario(payload.scenario_id) is None:
        raise HTTPException(status_code=404, detail="internal validation scenario not found")

    validation_session = create_internal_validation_session(
        session=session,
        engagement=engagement,
        scenario_id=payload.scenario_id,
        actor=actor,
        settings=settings,
    )
    session.commit()

    hydrated_session = load_internal_validation_session(session, validation_session.id)
    if hydrated_session is None:
        raise HTTPException(status_code=500, detail="internal validation session could not be reloaded")
    return serialize_internal_validation_session(hydrated_session, settings=settings, db_session=session)


@router.get(
    "/internal-validations/{session_id}",
    response_model=InternalValidationSessionRead,
)
def get_session_detail(
    session_id: UUID,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> InternalValidationSessionRead:
    if ensure_default_run_profiles(session):
        session.commit()
    validation_session = load_internal_validation_session(session, session_id)
    if validation_session is None:
        raise HTTPException(status_code=404, detail="internal validation session not found")
    return serialize_internal_validation_session(validation_session, settings=settings, db_session=session)


@router.post(
    "/internal-validations/{session_id}/steps/{step_id}/approvals",
    response_model=InternalValidationSessionRead,
)
def approve_step(
    session_id: UUID,
    step_id: str,
    payload: InternalValidationStepApprovalCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> InternalValidationSessionRead:
    if ensure_default_run_profiles(session):
        session.commit()
    validation_session = load_internal_validation_session(session, session_id)
    if validation_session is None:
        raise HTTPException(status_code=404, detail="internal validation session not found")

    step = _load_step_or_404(validation_session, step_id)
    if step.status in {"completed", "failed", "rejected"}:
        raise HTTPException(status_code=409, detail="internal validation step is already finalized")

    try:
        record_internal_validation_step_approval(
            session=session,
            validation_session=validation_session,
            step=step,
            actor=actor,
            decision=payload.decision,
            settings=settings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    hydrated_session = load_internal_validation_session(session, validation_session.id)
    if hydrated_session is None:
        raise HTTPException(status_code=500, detail="internal validation session could not be reloaded")
    return serialize_internal_validation_session(hydrated_session, settings=settings, db_session=session)


@router.post(
    "/internal-validations/{session_id}/steps/{step_id}/execute",
    response_model=InternalValidationStepExecuteRead,
)
def execute_step(
    session_id: UUID,
    step_id: str,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> InternalValidationStepExecuteRead:
    if ensure_default_run_profiles(session):
        session.commit()
    validation_session = load_internal_validation_session(session, session_id)
    if validation_session is None:
        raise HTTPException(status_code=404, detail="internal validation session not found")

    step = _load_step_or_404(validation_session, step_id)

    try:
        dispatch_mode = execute_internal_validation_step(
            session=session,
            validation_session=validation_session,
            step=step,
            actor=actor,
            settings=settings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    hydrated_session = load_internal_validation_session(session, validation_session.id)
    if hydrated_session is None:
        raise HTTPException(status_code=500, detail="internal validation session could not be reloaded")

    hydrated_step = _load_step_or_404(hydrated_session, step_id)
    if hydrated_step.launched_run_id is None:
        raise HTTPException(status_code=500, detail="internal validation step did not launch a run")

    return InternalValidationStepExecuteRead(
        session=serialize_internal_validation_session(hydrated_session, settings=settings, db_session=session),
        dispatch_mode=dispatch_mode,
        launched_run_id=hydrated_step.launched_run_id,
    )
