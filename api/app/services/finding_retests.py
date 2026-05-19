from __future__ import annotations

import copy
import ipaddress
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import Engagement, Finding, FindingRemediation, Run
from api.app.schemas.remediation import FindingRetestRead
from api.app.services.audit import write_audit_event
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    latest_scope_query,
    load_run,
    queue_run_tasks,
    required_approvals,
)
from api.app.services.secrets import materialize_run_configuration_secrets


class FindingRetestRequestError(ValueError):
    pass


def _target_map_for_finding_retest(target_id: str) -> dict[str, list[str]]:
    normalized = target_id.strip()
    if normalized.startswith(("http://", "https://")):
        return {"urls": [normalized]}

    try:
        ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        pass
    else:
        if "/" in normalized:
            return {"cidr_ranges": [normalized]}
        return {"ip_addresses": [normalized]}

    if "." in normalized and "/" not in normalized:
        return {"hosts": [normalized]}
    return {"targets": [normalized]}


def _retest_metadata(
    *,
    finding: Finding,
    source_run: Run,
    remediation: FindingRemediation | None,
    notes: str | None,
) -> dict[str, object]:
    return {
        "mode": "single_finding",
        "source_finding_id": str(finding.id),
        "source_run_id": str(source_run.id),
        "source_finding_title": finding.title,
        "source_finding_severity": finding.severity,
        "source_finding_status": finding.status,
        "source_finding_target": finding.target_id,
        "source_evidence_ref": finding.evidence_ref,
        "source_finding_summary": finding.summary,
        "source_summary": finding.summary,
        "remediation_id": str(remediation.id) if remediation is not None else None,
        "remediation_state": remediation.state if remediation is not None else None,
        "remediation_notes": remediation.notes if remediation is not None else None,
        "operator_notes": notes,
        "verification_state": "requested",
    }


def _build_retest_configuration(
    *,
    finding: Finding,
    source_run: Run,
    remediation: FindingRemediation | None,
    notes: str | None,
) -> dict[str, object]:
    configuration = copy.deepcopy(source_run.configuration_json or {})
    if not isinstance(configuration, dict):
        configuration = {}

    configuration["assessment_type"] = configuration.get("assessment_type") or "Single-Finding Retest"
    configuration["test_profile"] = "Single-Finding Retest"
    configuration["execution_profile"] = source_run.profile.name if source_run.profile is not None else None
    configuration["targets"] = _target_map_for_finding_retest(finding.target_id)

    modules = configuration.get("modules")
    if not isinstance(modules, dict):
        modules = {}
    modules = dict(modules)
    modules["single_finding_retest"] = True
    configuration["modules"] = modules

    configuration.pop("follow_up", None)
    configuration["retest"] = _retest_metadata(
        finding=finding,
        source_run=source_run,
        remediation=remediation,
        notes=notes,
    )
    return configuration


def request_single_finding_retest(
    *,
    session: Session,
    finding: Finding,
    notes: str | None,
    actor: str,
    settings: Settings,
) -> FindingRetestRead:
    ensure_default_run_profiles(session)

    if finding.run_id is None:
        raise FindingRetestRequestError("finding has no source run to retest")

    source_run = load_run(session, finding.run_id)
    if source_run is None:
        raise FindingRetestRequestError("source run not found for finding")
    if source_run.profile is None:
        raise FindingRetestRequestError("source run profile not found")

    engagement = session.scalar(select(Engagement).where(Engagement.id == source_run.engagement_id))
    if engagement is None:
        raise FindingRetestRequestError("source engagement not found")

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise FindingRetestRequestError("engagement scope required before requesting retests")

    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))
    retest_configuration = _build_retest_configuration(
        finding=finding,
        source_run=source_run,
        remediation=remediation,
        notes=notes,
    )
    aligned_configuration = align_run_configuration_with_engagement(retest_configuration, engagement=engagement)
    try:
        stored_configuration, created_secret_refs = materialize_run_configuration_secrets(
            session,
            engagement_id=engagement.id,
            configuration=aligned_configuration,
            settings=settings,
        )
    except ValueError as exc:
        raise FindingRetestRequestError(str(exc)) from exc

    timestamp = datetime.now(tz=UTC)
    retest_run = Run(
        engagement_id=engagement.id,
        profile_id=source_run.profile.id,
        profile=source_run.profile,
        source_inventory_snapshot_id=source_run.source_inventory_snapshot_id or finding.source_inventory_snapshot_id,
        requested_by=actor,
        status="requested",
        configuration_json=stored_configuration,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(retest_run)
    session.flush()

    deployment = latest_pack_deployment(session, engagement_id=engagement.id, run_profile_name=source_run.profile.name)
    if deployment is not None and deployment.pack is not None:
        bind_pack_to_run(session, run=retest_run, pack=deployment.pack)

    retest_metadata = dict(stored_configuration.get("retest", {}))
    write_audit_event(
        session=session,
        actor=actor,
        action="run.requested",
        object_type="run",
        object_id=str(retest_run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": source_run.profile.name,
            "single_finding_retest": True,
            "source_finding_id": str(finding.id),
            "source_run_id": str(source_run.id),
            "bound_pack_id": str(retest_run.bound_pack_id) if retest_run.bound_pack_id else None,
            "bound_pack_version": retest_run.bound_pack_version,
            "secret_binding_count": len(created_secret_refs),
        },
    )

    queued_tasks = []
    if required_approvals(source_run.profile) == 0:
        queued_tasks = queue_run_tasks(session, retest_run, scope, source_run.profile)
        for task in queued_tasks:
            task_params = dict(task.params_json or {})
            task_params["retest"] = retest_metadata
            task.params_json = task_params
        write_audit_event(
            session=session,
            actor=actor,
            action="run.queued",
            object_type="run",
            object_id=str(retest_run.id),
            metadata={
                "engagement_id": str(engagement.id),
                "profile_name": source_run.profile.name,
                "single_finding_retest": True,
                "source_finding_id": str(finding.id),
            },
        )
    else:
        retest_run.status = "pending_approval"

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.retest_requested",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "source_run_id": str(source_run.id),
            "retest_run_id": str(retest_run.id),
            "profile_name": source_run.profile.name,
            "retest_status": retest_run.status,
        },
    )
    session.flush()
    session.refresh(retest_run)

    return FindingRetestRead(
        retest_run_id=retest_run.id,
        source_finding_id=finding.id,
        source_run_id=source_run.id,
        status=retest_run.status,
        profile_name=source_run.profile.name,
        queued_task_ids=[task.id for task in queued_tasks],
        configuration_json=dict(retest_run.configuration_json or {}),
    )
