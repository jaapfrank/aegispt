from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    Engagement,
    Finding,
    FindingRemediation,
    FindingValidationRecord,
    Run,
    RunProfile,
)
from api.app.schemas.remediation import FindingMicroScanRead
from api.app.services.audit import write_audit_event
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    latest_scope_query,
    load_run,
    queue_run_tasks,
    required_approvals,
    target_is_allowed,
)
from api.app.services.secrets import materialize_run_configuration_secrets


class ProofOfResolutionRequestError(ValueError):
    pass


PROFILE_BY_TOOL = {
    "auth-flow": "active-web-auth-flow",
    "client-state": "active-web-client-state",
    "content-discovery": "active-web-content-discovery",
    "deserialization-probe": "active-web-deserialization-probe",
    "graphql-probe": "active-web-graphql-probe",
    "headers-security": "passive-web-headers-security",
    "idor-bac": "active-web-idor-bac",
    "jwt-probe": "active-web-jwt-probe",
    "ldap-enum": "passive-identity-ldap-enum",
    "llm-probe": "active-llm-application-probe",
    "nuclei": "passive-web-nuclei-audit",
    "semgrep": "passive-code-semgrep-audit",
    "session-security": "active-web-session-security",
    "sqlmap": "active-web-sqlmap-confirmation",
    "ssrf-probe": "active-web-ssrf-probe",
    "vuln-components": "passive-web-vuln-components",
    "xss-extended": "active-web-xss-extended",
    "xxe-probe": "active-web-xxe-probe",
    "zap": "active-web-safe",
}


@dataclass(slots=True)
class _ReplayRecipe:
    tool: str
    target: str
    params_json: dict[str, Any]
    expected_match_pattern: str | None
    artifact: dict[str, Any]
    raw: dict[str, Any]
    digest: str


def request_proof_of_resolution_micro_scan(
    *,
    session: Session,
    finding: Finding,
    actor: str,
    settings: Settings,
    notes: str | None,
) -> FindingMicroScanRead:
    ensure_default_run_profiles(session)

    source_run = _source_run(session, finding)
    engagement = _source_engagement(session, source_run)
    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise ProofOfResolutionRequestError("engagement scope required before requesting proof of resolution")

    recipe = _replay_recipe_for_finding(finding)
    profile_name = _profile_name_for_recipe(recipe)
    profile = session.scalar(select(RunProfile).where(RunProfile.name == profile_name))
    if profile is None:
        raise ProofOfResolutionRequestError(f"micro-scan profile {profile_name} is unavailable")
    if not target_is_allowed(scope, recipe.target):
        raise ProofOfResolutionRequestError(
            f"micro-scan target {recipe.target} is outside the current approved scope"
        )

    remediation = _ensure_ready_for_retest(
        session=session,
        finding=finding,
        actor=actor,
        notes=notes,
    )
    validation_record = FindingValidationRecord(
        finding_id=finding.id,
        status="validation_queued",
        validation_profile_name=profile.name,
        validator_tool=recipe.tool,
        validator_target_id=recipe.target,
        note=f"Queued proof-of-resolution micro-scan for {finding.target_id}.",
        metadata_json={
            "mode": "proof_of_resolution_micro_scan",
            "replay_recipe_sha256": recipe.digest,
            "source_evidence_ref": finding.evidence_ref,
            "artifact_ref": recipe.artifact,
            "operator_notes": notes,
        },
    )
    session.add(validation_record)
    session.flush()

    configuration = _micro_scan_configuration(
        finding=finding,
        source_run=source_run,
        remediation=remediation,
        recipe=recipe,
        validation_record=validation_record,
        profile=profile,
        notes=notes,
    )
    aligned_configuration = align_run_configuration_with_engagement(configuration, engagement=engagement)
    try:
        stored_configuration, created_secret_refs = materialize_run_configuration_secrets(
            session,
            engagement_id=engagement.id,
            configuration=aligned_configuration,
            settings=settings,
        )
    except ValueError as exc:
        raise ProofOfResolutionRequestError(str(exc)) from exc

    micro_scan_run = Run(
        engagement_id=engagement.id,
        profile_id=profile.id,
        profile=profile,
        source_inventory_snapshot_id=source_run.source_inventory_snapshot_id or finding.source_inventory_snapshot_id,
        requested_by=actor,
        status="requested",
        configuration_json=stored_configuration,
    )
    session.add(micro_scan_run)
    session.flush()
    validation_record.run_id = micro_scan_run.id

    deployment = latest_pack_deployment(session, engagement_id=engagement.id, run_profile_name=profile.name)
    if deployment is not None and deployment.pack is not None:
        bind_pack_to_run(session, run=micro_scan_run, pack=deployment.pack)

    write_audit_event(
        session=session,
        actor=actor,
        action="run.requested",
        object_type="run",
        object_id=str(micro_scan_run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": profile.name,
            "proof_of_resolution_micro_scan": True,
            "source_finding_id": str(finding.id),
            "replay_recipe_sha256": recipe.digest,
            "secret_binding_count": len(created_secret_refs),
        },
    )

    queued_tasks = []
    if required_approvals(profile) == 0:
        queued_tasks = queue_run_tasks(session, micro_scan_run, scope, profile)
        write_audit_event(
            session=session,
            actor=actor,
            action="run.queued",
            object_type="run",
            object_id=str(micro_scan_run.id),
            metadata={
                "engagement_id": str(engagement.id),
                "profile_name": profile.name,
                "proof_of_resolution_micro_scan": True,
                "source_finding_id": str(finding.id),
                "queued_task_count": len(queued_tasks),
            },
        )
    else:
        micro_scan_run.status = "pending_approval"
        validation_record.note = (
            f"Proof-of-resolution micro-scan queued for {finding.target_id}; approval is required before it can run."
        )

    finding.validation_status = "validation_queued"
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.proof_of_resolution_micro_scan.queued",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "validation_record_id": str(validation_record.id),
            "micro_scan_run_id": str(micro_scan_run.id),
            "profile_name": profile.name,
            "validator_tool": recipe.tool,
            "target_id": recipe.target,
            "approval_required_count": required_approvals(profile),
            "replay_recipe_sha256": recipe.digest,
        },
    )
    session.flush()
    session.refresh(micro_scan_run)
    session.refresh(validation_record)

    return FindingMicroScanRead(
        micro_scan_run_id=micro_scan_run.id,
        source_finding_id=finding.id,
        source_run_id=source_run.id,
        validation_record_id=validation_record.id,
        status=micro_scan_run.status,
        profile_name=profile.name,
        validator_tool=recipe.tool,
        validator_target_id=recipe.target,
        replay_recipe_sha256=recipe.digest,
        queued_task_ids=[task.id for task in queued_tasks],
        configuration_json=dict(micro_scan_run.configuration_json or {}),
    )


def _source_run(session: Session, finding: Finding) -> Run:
    if finding.run_id is None:
        raise ProofOfResolutionRequestError("finding has no source run to verify")
    source_run = load_run(session, finding.run_id)
    if source_run is None:
        raise ProofOfResolutionRequestError("source run not found for finding")
    if source_run.profile is None:
        raise ProofOfResolutionRequestError("source run profile not found")
    return source_run


def _source_engagement(session: Session, source_run: Run) -> Engagement:
    engagement = session.scalar(
        select(Engagement)
        .options(selectinload(Engagement.scopes))
        .where(Engagement.id == source_run.engagement_id)
    )
    if engagement is None:
        raise ProofOfResolutionRequestError("source engagement not found")
    return engagement


def _replay_recipe_for_finding(finding: Finding) -> _ReplayRecipe:
    if not isinstance(finding.replay_recipe_json, dict) or not finding.replay_recipe_json:
        raise ProofOfResolutionRequestError("finding has no replay recipe for an exact micro-scan")
    raw_recipe = copy.deepcopy(finding.replay_recipe_json)
    tool = str(raw_recipe.get("tool") or raw_recipe.get("runner") or "").strip()
    if not tool:
        raise ProofOfResolutionRequestError("finding replay recipe is missing a registered tool")
    target = str(raw_recipe.get("target") or finding.target_id or "").strip()
    if not target:
        raise ProofOfResolutionRequestError("finding replay recipe is missing a target")
    params_json = raw_recipe.get("params_json")
    if not isinstance(params_json, dict):
        params_json = {}
    expected_match_pattern = str(raw_recipe.get("expected_match_pattern") or "").strip() or None
    artifact = raw_recipe.get("artifact") if isinstance(raw_recipe.get("artifact"), dict) else {}
    digest = hashlib.sha256(json.dumps(raw_recipe, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return _ReplayRecipe(
        tool=tool,
        target=target,
        params_json=copy.deepcopy(params_json),
        expected_match_pattern=expected_match_pattern,
        artifact=dict(artifact),
        raw=raw_recipe,
        digest=digest,
    )


def _profile_name_for_recipe(recipe: _ReplayRecipe) -> str:
    if recipe.tool == "zap":
        limits = recipe.params_json.get("limits") if isinstance(recipe.params_json.get("limits"), dict) else {}
        scan_mode = str(limits.get("scan_mode") or "").strip().lower()
        return "active-web-zap-active" if scan_mode == "spider-active-passive" else "active-web-safe"
    if recipe.tool == "headers-security":
        limits = recipe.params_json.get("limits") if isinstance(recipe.params_json.get("limits"), dict) else {}
        if bool(limits.get("active_origin_reflection_probes")):
            return "active-web-headers-security"
    profile_name = PROFILE_BY_TOOL.get(recipe.tool)
    if profile_name is None:
        raise ProofOfResolutionRequestError(f"{recipe.tool} does not have a registered micro-scan profile")
    return profile_name


def _ensure_ready_for_retest(
    *,
    session: Session,
    finding: Finding,
    actor: str,
    notes: str | None,
) -> FindingRemediation:
    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))
    previous_state = remediation.state if remediation is not None else None
    if remediation is None:
        remediation = FindingRemediation(
            finding_id=finding.id,
            state="ready_for_retest",
            notes=notes,
            created_by=actor,
            updated_by=actor,
        )
        session.add(remediation)
    elif remediation.state != "verified":
        remediation.state = "ready_for_retest"
        if notes is not None:
            remediation.notes = notes
        remediation.updated_by = actor
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.remediation.ready_for_retest",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "previous_state": previous_state,
            "state": remediation.state,
            "proof_of_resolution_micro_scan": True,
        },
    )
    return remediation


def _micro_scan_configuration(
    *,
    finding: Finding,
    source_run: Run,
    remediation: FindingRemediation,
    recipe: _ReplayRecipe,
    validation_record: FindingValidationRecord,
    profile: RunProfile,
    notes: str | None,
) -> dict[str, Any]:
    validation_payload = {
        "mode": "finding_reprobe",
        "source_finding_id": str(finding.id),
        "source_run_id": str(source_run.id),
        "source_task_id": _safe_str(recipe.params_json.get("task_id")),
        "source_execution_id": _safe_str(recipe.params_json.get("tool_execution_id")),
        "validation_record_id": str(validation_record.id),
        "original_finding_title": finding.title,
        "original_finding_target": finding.target_id,
        "original_evidence_ref": finding.evidence_ref,
        "comparison_pattern": recipe.expected_match_pattern,
        "proof_of_resolution": {
            "mode": "micro_scan",
            "source_finding_id": str(finding.id),
            "remediation_id": str(remediation.id) if remediation.id else None,
            "replay_recipe_sha256": recipe.digest,
            "success_condition": "expected evidence pattern is no longer reproduced",
        },
    }
    return {
        "assessment_type": "Proof of Resolution Micro-Scan",
        "test_profile": "Proof of Resolution Micro-Scan",
        "execution_profile": profile.name,
        "targets": _target_map(recipe.target),
        "modules": {
            "proof_of_resolution_micro_scan": True,
            "finding_validation": True,
        },
        "safety": {
            "max_validation_depth": "micro",
            "note": "Hyper-targeted controlled proof only, using the original replay recipe.",
        },
        "validation": validation_payload,
        "proof_of_resolution": {
            "mode": "micro_scan",
            "source_finding_id": str(finding.id),
            "source_run_id": str(source_run.id),
            "source_evidence_ref": finding.evidence_ref,
            "source_finding_title": finding.title,
            "source_finding_target": finding.target_id,
            "remediation_id": str(remediation.id) if remediation.id else None,
            "remediation_state": remediation.state,
            "operator_notes": notes,
            "replay_tool": recipe.tool,
            "replay_target": recipe.target,
            "replay_recipe_sha256": recipe.digest,
            "replay_recipe_artifact": recipe.artifact,
            "replay_task_params": recipe.params_json,
            "expected_match_pattern": recipe.expected_match_pattern,
            "success_condition": "expected evidence pattern is no longer reproduced",
            "approval_gates_bypassed": False,
        },
    }


def _target_map(target: str) -> dict[str, list[str]]:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return {"urls": [target]}
    if "/" in target:
        return {"cidr_ranges": [target]}
    if "." in target:
        return {"hosts": [target]}
    return {"targets": [target]}


def _safe_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
