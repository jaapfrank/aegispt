from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import (
    CapabilityPack,
    CapabilityPackApproval,
    CapabilityPackArtifact,
    CapabilityPackDeployment,
    CapabilityPackValidationResult,
    RelevanceDecision,
    Run,
    ThreatIntelRecord,
)

PACK_RUNTIME_STATES = {
    "proposed",
    "generated",
    "validation_failed",
    "validated",
    "approved",
    "deployed",
    "retired",
    "superseded",
}


def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return normalized.strip("-") or "generated-capability"


def _sha256_for_artifact(*, content_text: str | None, content_json: dict[str, Any] | None) -> str:
    if content_text is not None:
        payload = content_text.encode("utf-8")
    else:
        payload = json.dumps(content_json or {}, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _json_copy(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    return json.loads(json.dumps(value, sort_keys=True))


def load_pack(session: Session, pack_id: UUID | str) -> CapabilityPack | None:
    return session.scalar(
        select(CapabilityPack)
        .options(
            selectinload(CapabilityPack.artifacts),
            selectinload(CapabilityPack.validation_results),
            selectinload(CapabilityPack.approvals),
            selectinload(CapabilityPack.deployments),
        )
        .where(CapabilityPack.id == pack_id)
    )


def latest_pack_deployment(
    session: Session,
    *,
    engagement_id: UUID,
    run_profile_name: str | None = None,
) -> CapabilityPackDeployment | None:
    deployments = session.scalars(
        select(CapabilityPackDeployment)
        .options(selectinload(CapabilityPackDeployment.pack))
        .where(
            CapabilityPackDeployment.engagement_id == engagement_id,
            CapabilityPackDeployment.status == "deployed",
        )
        .order_by(CapabilityPackDeployment.created_at.desc(), CapabilityPackDeployment.id.desc())
    ).all()
    if run_profile_name:
        for deployment in deployments:
            if deployment.run_profile_name == run_profile_name:
                return deployment
    return deployments[0] if deployments else None


def artifact_refs_for_tool(pack: CapabilityPack, tool: str) -> list[dict[str, Any]]:
    relevant_types = {
        "nuclei": {"nuclei_template", "scanner_profile", "metadata", "workflow"},
        "zap": {"zap_job", "scanner_profile", "metadata", "workflow"},
        "playwright": {"playwright_flow", "metadata", "workflow"},
        "semgrep": {"semgrep_rule", "metadata", "workflow"},
        "httpx": {"scanner_profile", "metadata", "workflow"},
    }.get(tool, {"metadata", "workflow"})

    return [
        {
            "artifact_id": str(artifact.id),
            "artifact_type": artifact.artifact_type,
            "logical_name": artifact.logical_name,
            "status": artifact.status,
        }
        for artifact in pack.artifacts
        if artifact.artifact_type in relevant_types
    ]


def validation_checks_for_artifact_type(artifact_type: str) -> list[str]:
    if artifact_type == "nuclei_template":
        return ["contains template id", "contains info block"]
    if artifact_type == "semgrep_rule":
        return ["contains rules block", "contains rule id"]
    if artifact_type == "playwright_flow":
        return ["has steps array"]
    if artifact_type in {"scanner_profile", "zap_job"}:
        return ["has tool", "has targets or note"]
    if artifact_type in {"workflow", "metadata"}:
        return ["has content json"]
    return []


def _next_pack_version(session: Session, *, engagement_id: UUID, name: str) -> str:
    existing = session.scalars(
        select(CapabilityPack)
        .where(
            CapabilityPack.engagement_id == engagement_id,
            CapabilityPack.name == name,
        )
        .order_by(CapabilityPack.created_at.asc(), CapabilityPack.id.asc())
    ).all()
    return f"v{len(existing) + 1}"


def _inventory_targets(recommendations: dict[str, Any]) -> list[str]:
    evidence_basis = recommendations.get("evidence_basis", [])
    for entry in evidence_basis:
        if not isinstance(entry, dict) or entry.get("type") != "inventory_snapshot":
            continue
        signals = entry.get("signals")
        if isinstance(signals, list):
            return [str(signal) for signal in signals if isinstance(signal, str)]
    return []


def _artifact_blueprint_for_capability(
    capability: dict[str, Any],
    *,
    targets: list[str],
) -> dict[str, Any]:
    capability_type = str(capability.get("capability_type") or "scanner_profile")
    logical_base = _slugify(f"{capability.get('source', 'generated')}-{capability.get('advisory_id', 'advisory')}-{capability.get('title', 'capability')}")
    methodology_tags = list(capability.get("methodology_tags") or [])
    rationale = str(capability.get("rationale") or "")
    evidence_basis = list(capability.get("evidence_basis") or [])

    if capability_type == "nuclei_template":
        content_text = (
            f"id: {logical_base}\n"
            "info:\n"
            f"  name: {capability.get('title')}\n"
            "  severity: medium\n"
            f"  tags: {','.join(methodology_tags) or 'aegispt'}\n"
            "http:\n"
            "  - method: GET\n"
            "    path:\n"
            "      - \"{{BaseURL}}/\"\n"
            "    matchers:\n"
            "      - type: word\n"
            "        words:\n"
            f"          - \"{capability.get('advisory_id')}\"\n"
        )
        return {
            "artifact_type": capability_type,
            "logical_name": f"{logical_base}.yaml",
            "methodology_tags": methodology_tags,
            "content_text": content_text,
            "content_json": None,
            "provenance_json": {
                "title": capability.get("title"),
                "tool": capability.get("tool"),
                "evidence_basis": evidence_basis,
                "rationale": rationale,
            },
        }

    if capability_type == "semgrep_rule":
        content_text = (
            "rules:\n"
            f"  - id: {logical_base}\n"
            f"    message: {capability.get('title')}\n"
            "    severity: WARNING\n"
            "    languages: [python, javascript]\n"
            "    patterns:\n"
            "      - pattern-regex: \"TODO_SUPERVISED_PATTERN\"\n"
        )
        return {
            "artifact_type": capability_type,
            "logical_name": f"{logical_base}.yaml",
            "methodology_tags": methodology_tags,
            "content_text": content_text,
            "content_json": None,
            "provenance_json": {
                "title": capability.get("title"),
                "tool": capability.get("tool"),
                "evidence_basis": evidence_basis,
                "rationale": rationale,
            },
        }

    if capability_type == "playwright_flow":
        return {
            "artifact_type": capability_type,
            "logical_name": f"{logical_base}.json",
            "methodology_tags": methodology_tags,
            "content_text": None,
            "content_json": {
                "name": capability.get("title"),
                "steps": [
                    {"action": "navigate", "target": targets[0] if targets else "https://example.invalid"},
                    {"action": "capture", "label": "landing-page"},
                    {"action": "assert", "type": "response_or_dom", "description": rationale},
                ],
            },
            "provenance_json": {
                "title": capability.get("title"),
                "tool": capability.get("tool"),
                "evidence_basis": evidence_basis,
                "rationale": rationale,
            },
        }

    if capability_type == "zap_job":
        return {
            "artifact_type": capability_type,
            "logical_name": f"{logical_base}.json",
            "methodology_tags": methodology_tags,
            "content_text": None,
            "content_json": {
                "job_name": capability.get("title"),
                "tool": "zap",
                "scan_mode": "spider-passive",
                "targets": targets,
                "notes": rationale,
            },
            "provenance_json": {
                "title": capability.get("title"),
                "tool": "zap",
                "evidence_basis": evidence_basis,
                "rationale": rationale,
            },
        }

    return {
        "artifact_type": "scanner_profile",
        "logical_name": f"{logical_base}.json",
        "methodology_tags": methodology_tags,
        "content_text": None,
        "content_json": {
            "name": capability.get("title"),
            "tool": capability.get("tool"),
            "targets": targets,
            "notes": rationale,
            "confidence": capability.get("confidence"),
        },
        "provenance_json": {
            "title": capability.get("title"),
            "tool": capability.get("tool"),
            "evidence_basis": evidence_basis,
            "rationale": rationale,
        },
    }


def generate_pack_from_relevance(
    session: Session,
    *,
    requested_by: str,
    decision: RelevanceDecision,
    name: str | None = None,
    description: str | None = None,
    generation_mode: str = "codex-supervised",
    parent_pack_id: UUID | None = None,
) -> CapabilityPack:
    recommendations = decision.recommendations_json
    proposed_capabilities = list(recommendations.get("proposed_capabilities") or [])
    pack_name = (name or f"adaptive-{decision.engagement_id}").strip()
    version = _next_pack_version(session, engagement_id=decision.engagement_id, name=pack_name)
    targets = _inventory_targets(recommendations)

    pack = CapabilityPack(
        engagement_id=decision.engagement_id,
        relevance_decision_id=decision.id,
        source_inventory_snapshot_id=decision.inventory_snapshot_id,
        parent_pack_id=parent_pack_id,
        name=pack_name,
        version=version,
        status="generated",
        generated_by=requested_by,
        generation_mode=generation_mode,
        description=description or decision.justification_text,
        source_threat_intel_refs_json=list(decision.threat_intel_refs_json),
        methodology_tags=list(dict.fromkeys(recommendations.get("proposed_methodology_tags") or [])),
        manifest_json={
            "inventory_snapshot_id": str(decision.inventory_snapshot_id),
            "relevance_decision_id": str(decision.id),
            "threat_intel_refs": list(decision.threat_intel_refs_json),
            "generation_reason": decision.justification_text,
            "adaptive_coverage": {
                "proposed_capability_count": len(proposed_capabilities),
                "methodology_tags": list(dict.fromkeys(recommendations.get("proposed_methodology_tags") or [])),
            },
            "validation_policy": "syntax-check, dry-run where possible, approval before deployment",
            "runtime_policy": "closed runtime, no live self-modification during active assessment",
        },
        provenance_json={
            "requested_by": requested_by,
            "generation_mode": generation_mode,
            "decision_confidence": decision.confidence_score,
            "evidence_basis": decision.evidence_basis_json,
        },
    )
    session.add(pack)
    session.flush()

    artifacts: list[CapabilityPackArtifact] = []
    for capability in proposed_capabilities:
        blueprint = _artifact_blueprint_for_capability(capability, targets=targets)
        artifact = CapabilityPackArtifact(
            pack_id=pack.id,
            artifact_type=blueprint["artifact_type"],
            logical_name=blueprint["logical_name"],
            status="generated",
            checksum_sha256=_sha256_for_artifact(
                content_text=blueprint["content_text"],
                content_json=blueprint["content_json"],
            ),
            methodology_tags=list(blueprint["methodology_tags"]),
            content_text=blueprint["content_text"],
            content_json=blueprint["content_json"],
            provenance_json=dict(blueprint["provenance_json"]),
        )
        session.add(artifact)
        artifacts.append(artifact)

    for artifact_type, logical_name, content_json in (
        (
            "workflow",
            "validation-promotion-workflow.json",
            {
                "steps": [
                    "inventory",
                    "relevance",
                    "codex-build",
                    "validation",
                    "approval",
                    "deployment",
                    "runtime-binding",
                ]
            },
        ),
        (
            "metadata",
            "reporting-metadata.json",
            {
                "inventory_snapshot_id": str(decision.inventory_snapshot_id),
                "relevance_decision_id": str(decision.id),
                "threat_intel_refs": list(decision.threat_intel_refs_json),
                "methodology_tags": list(pack.methodology_tags),
            },
        ),
    ):
        artifact = CapabilityPackArtifact(
            pack_id=pack.id,
            artifact_type=artifact_type,
            logical_name=logical_name,
            status="generated",
            checksum_sha256=_sha256_for_artifact(content_text=None, content_json=content_json),
            methodology_tags=list(pack.methodology_tags),
            content_text=None,
            content_json=content_json,
            provenance_json={"generated_by": requested_by, "generation_mode": generation_mode},
        )
        session.add(artifact)
        artifacts.append(artifact)

    session.flush()
    return pack


def stage_generated_nuclei_template_pack(
    session: Session,
    *,
    engagement_id: UUID,
    requested_by: str,
    record: ThreatIntelRecord,
    template_yaml: str,
    validation_summary: dict[str, Any],
    model: str,
    prompt_digest: str,
    generation_metadata: dict[str, Any] | None = None,
) -> tuple[CapabilityPack, CapabilityPackArtifact]:
    generation_metadata = generation_metadata or {}
    pack_name = _slugify(f"cve-template-{record.advisory_id}")
    version = _next_pack_version(session, engagement_id=engagement_id, name=pack_name)
    generated_at = datetime.now(UTC).isoformat()
    manifest = {
        "cve_template_generation": {
            "threat_intel_record_id": str(record.id),
            "advisory_id": record.advisory_id,
            "source": record.source,
            "provider": "chatgpt_oauth",
            "model": model,
            "prompt_digest_sha256": prompt_digest,
            "validated_before_storage": True,
            "detection_only": True,
            "auto_deploy": False,
            "operator_review_required": True,
            "generated_at": generated_at,
        },
        "validation_policy": "schema-check-before-storage, pack validation required before approval",
        "runtime_policy": "staged only; validate, approve, deploy, and bind through the existing pack lifecycle",
    }
    provenance = {
        "requested_by": requested_by,
        "generation_mode": "ai-cve-nuclei-template",
        "threat_intel_record_id": str(record.id),
        "advisory_id": record.advisory_id,
        "provider": "chatgpt_oauth",
        "model": model,
        "token_exposed": False,
        "generation_metadata": _json_copy(generation_metadata, {}),
    }
    pack = CapabilityPack(
        engagement_id=engagement_id,
        relevance_decision_id=None,
        source_inventory_snapshot_id=None,
        parent_pack_id=None,
        name=pack_name,
        version=version,
        status="generated",
        generated_by=requested_by,
        generation_mode="ai-cve-nuclei-template",
        description=f"Detection-only Nuclei template generated for {record.advisory_id}; pending pack lifecycle review.",
        source_threat_intel_refs_json=[record.advisory_id, str(record.id)],
        methodology_tags=["cve", "nuclei", "detection-only"],
        manifest_json=manifest,
        provenance_json=provenance,
    )
    session.add(pack)
    session.flush()

    logical_name = f"{_slugify(record.advisory_id)}-detection.yaml"
    template_artifact = CapabilityPackArtifact(
        pack_id=pack.id,
        artifact_type="nuclei_template",
        logical_name=logical_name,
        status="generated",
        checksum_sha256=_sha256_for_artifact(content_text=template_yaml, content_json=None),
        methodology_tags=["cve", "nuclei", "detection-only"],
        content_text=template_yaml,
        content_json=None,
        provenance_json={
            "generated_by": requested_by,
            "generation_mode": "ai-cve-nuclei-template",
            "threat_intel_record_id": str(record.id),
            "advisory_id": record.advisory_id,
            "validation_summary": _json_copy(validation_summary, {}),
            "detection_only": True,
            "auto_deploy": False,
        },
    )
    session.add(template_artifact)
    session.flush()

    review_metadata = {
        "threat_intel_record_id": str(record.id),
        "advisory_id": record.advisory_id,
        "title": record.title,
        "affected_products": list(record.affected_products_json or []),
        "affected_versions": list(record.affected_versions_json or []),
        "validation": _json_copy(validation_summary, {}),
        "generation": _json_copy(generation_metadata, {}),
        "review_gate": "pack validation, approval, deployment, runtime binding",
    }
    for artifact_type, logical_name, content_json in (
        ("metadata", "generated-template-review.json", review_metadata),
        (
            "workflow",
            "validation-promotion-workflow.json",
            {
                "steps": [
                    "threat-intel-record",
                    "ai-template-generation",
                    "schema-validation",
                    "pack-review",
                    "pack-validation",
                    "approval",
                    "deployment",
                    "runtime-binding",
                ],
                "auto_deploy": False,
            },
        ),
    ):
        artifact = CapabilityPackArtifact(
            pack_id=pack.id,
            artifact_type=artifact_type,
            logical_name=logical_name,
            status="generated",
            checksum_sha256=_sha256_for_artifact(content_text=None, content_json=content_json),
            methodology_tags=["cve", "nuclei", "detection-only"],
            content_text=None,
            content_json=content_json,
            provenance_json={
                "generated_by": requested_by,
                "generation_mode": "ai-cve-nuclei-template",
                "source_artifact_id": str(template_artifact.id),
            },
        )
        session.add(artifact)

    metadata = _json_copy(record.metadata_json, {})
    metadata["generated_nuclei_template"] = {
        "status": "pending_review",
        "engagement_id": str(engagement_id),
        "pack_id": str(pack.id),
        "pack_version": pack.version,
        "artifact_id": str(template_artifact.id),
        "review_url": f"/app/?screen=pack-forge&pack_id={pack.id}",
        "generated_at": generated_at,
        "provider": "chatgpt_oauth",
        "model": model,
        "validation": _json_copy(validation_summary, {}),
        "yaml_diff": generation_metadata.get("yaml_diff"),
        "auto_deploy": False,
        "operator_review_required": True,
    }
    record.metadata_json = metadata
    session.flush()
    return pack, template_artifact


def stage_codex_reimport(
    session: Session,
    *,
    source_pack: CapabilityPack,
    requested_by: str,
    validation_result: dict[str, Any],
    artifact_payloads: list[dict[str, Any]],
    codex_task_id: str | None = None,
    pack_version: str | None = None,
    change_summary: str | None = None,
    operator_notes: str | None = None,
) -> CapabilityPack:
    if not isinstance(validation_result, dict) or not validation_result:
        raise ValueError("validation-result payload is required before reimport can be staged")

    validation_status = str(validation_result.get("status") or "").lower()
    if validation_status != "passed":
        raise ValueError("validation-result status must be passed before reimport can be staged")

    validation_pack_id = validation_result.get("pack_id")
    if validation_pack_id is not None and str(validation_pack_id) != str(source_pack.id):
        raise ValueError("validation-result pack_id does not match the source pack")

    if pack_version is not None and str(pack_version) != str(source_pack.version):
        raise ValueError("reimport pack_version does not match the source pack version")

    if validation_result.get("blocking_issues_json"):
        raise ValueError("validation-result contains blocking issues and cannot be reimported")

    if not artifact_payloads:
        raise ValueError("at least one artifact payload is required for reimport")

    source_artifacts = {
        (artifact.artifact_type, artifact.logical_name): artifact
        for artifact in source_pack.artifacts
    }
    staged_payloads: dict[tuple[str, str], dict[str, Any]] = {}
    for payload in artifact_payloads:
        artifact_type = str(payload.get("artifact_type") or "")
        logical_name = str(payload.get("logical_name") or "")
        key = (artifact_type, logical_name)
        if key not in source_artifacts:
            raise ValueError(f"artifact {artifact_type}/{logical_name} is not part of the source pack")
        if key in staged_payloads:
            raise ValueError(f"artifact {artifact_type}/{logical_name} was supplied more than once")

        content_text = payload.get("content_text")
        content_json = payload.get("content_json")
        if content_text is not None and content_json is not None:
            raise ValueError(f"artifact {artifact_type}/{logical_name} must provide text or json content, not both")
        if content_text is None and content_json is None:
            raise ValueError(f"artifact {artifact_type}/{logical_name} must provide content for reimport")

        expected_checksum = payload.get("checksum_sha256")
        checksum = _sha256_for_artifact(content_text=content_text, content_json=content_json)
        if expected_checksum is not None and str(expected_checksum) != checksum:
            raise ValueError(f"artifact {artifact_type}/{logical_name} checksum does not match supplied content")

        staged_payloads[key] = payload

    manifest_json = _json_copy(source_pack.manifest_json, {})
    manifest_json["codex_reimport"] = {
        "source_pack_id": str(source_pack.id),
        "source_pack_version": source_pack.version,
        "codex_task_id": codex_task_id,
        "validation_result_id": str(validation_result.get("id") or ""),
        "validation_result_status": validation_status,
        "imported_artifact_count": len(staged_payloads),
        "change_summary": change_summary,
        "runtime_policy": "staged only; validate, approve, deploy, and bind through the existing pack lifecycle",
    }

    provenance_json = _json_copy(source_pack.provenance_json, {})
    provenance_json["codex_reimport"] = {
        "requested_by": requested_by,
        "source_pack_id": str(source_pack.id),
        "source_pack_version": source_pack.version,
        "codex_task_id": codex_task_id,
        "validation_result_id": str(validation_result.get("id") or ""),
        "operator_notes_recorded": bool(operator_notes),
    }

    staged_pack = CapabilityPack(
        engagement_id=source_pack.engagement_id,
        relevance_decision_id=source_pack.relevance_decision_id,
        source_inventory_snapshot_id=source_pack.source_inventory_snapshot_id,
        parent_pack_id=source_pack.id,
        name=source_pack.name,
        version=_next_pack_version(session, engagement_id=source_pack.engagement_id, name=source_pack.name),
        status="generated",
        generated_by=requested_by,
        generation_mode="codex-reimport",
        description=source_pack.description,
        source_threat_intel_refs_json=list(source_pack.source_threat_intel_refs_json),
        methodology_tags=list(source_pack.methodology_tags),
        manifest_json=manifest_json,
        provenance_json=provenance_json,
    )
    session.add(staged_pack)
    session.flush()

    for source_artifact in sorted(source_pack.artifacts, key=lambda item: (item.artifact_type, item.logical_name)):
        key = (source_artifact.artifact_type, source_artifact.logical_name)
        payload = staged_payloads.get(key)
        content_text = source_artifact.content_text
        content_json = _json_copy(source_artifact.content_json, None)
        methodology_tags = list(source_artifact.methodology_tags)
        provenance = _json_copy(source_artifact.provenance_json, {})

        if payload is not None:
            content_text = payload.get("content_text")
            content_json = _json_copy(payload.get("content_json"), None)
            methodology_tags = list(payload.get("methodology_tags") or source_artifact.methodology_tags)
            provenance.update(_json_copy(payload.get("provenance_json"), {}))
            provenance["codex_reimport"] = {
                "source_pack_id": str(source_pack.id),
                "source_pack_version": source_pack.version,
                "source_artifact_id": str(source_artifact.id),
                "codex_task_id": codex_task_id,
                "validation_result_id": str(validation_result.get("id") or ""),
                "change_summary": change_summary,
                "operator_notes": operator_notes,
            }
        else:
            provenance["copied_from_artifact_id"] = str(source_artifact.id)

        artifact = CapabilityPackArtifact(
            pack_id=staged_pack.id,
            artifact_type=source_artifact.artifact_type,
            logical_name=source_artifact.logical_name,
            status="generated",
            checksum_sha256=_sha256_for_artifact(content_text=content_text, content_json=content_json),
            methodology_tags=methodology_tags,
            content_text=content_text,
            content_json=content_json,
            provenance_json=provenance,
        )
        session.add(artifact)

    session.flush()
    return staged_pack


def validate_pack(session: Session, *, pack: CapabilityPack, executed_by: str) -> CapabilityPackValidationResult:
    if pack.status not in PACK_RUNTIME_STATES:
        raise ValueError("unknown pack status")

    artifact_results: list[dict[str, Any]] = []
    blocking_issues: list[str] = []

    for artifact in pack.artifacts:
        checks = validation_checks_for_artifact_type(artifact.artifact_type)
        passed = True

        if artifact.artifact_type == "nuclei_template":
            passed = bool(artifact.content_text and "id:" in artifact.content_text and "info:" in artifact.content_text)
        elif artifact.artifact_type == "semgrep_rule":
            passed = bool(artifact.content_text and "rules:" in artifact.content_text and "id:" in artifact.content_text)
        elif artifact.artifact_type == "playwright_flow":
            passed = (
                isinstance(artifact.content_json, dict)
                and isinstance(artifact.content_json.get("steps"), list)
                and bool(artifact.content_json.get("steps"))
            )
        elif artifact.artifact_type in {"scanner_profile", "zap_job"}:
            passed = isinstance(artifact.content_json, dict) and bool(artifact.content_json.get("tool")) and bool(
                artifact.content_json.get("targets") or artifact.content_json.get("target") or artifact.content_json.get("notes")
            )
        elif artifact.artifact_type in {"workflow", "metadata"}:
            passed = isinstance(artifact.content_json, dict) and bool(artifact.content_json)

        artifact.status = "validated" if passed else "validation_failed"
        if not passed:
            blocking_issues.append(f"{artifact.logical_name} failed validation")

        artifact_results.append(
            {
                "artifact_id": str(artifact.id),
                "artifact_type": artifact.artifact_type,
                "logical_name": artifact.logical_name,
                "status": "passed" if passed else "failed",
                "checks": checks,
            }
        )

    status = "passed" if not blocking_issues else "failed"
    validation = CapabilityPackValidationResult(
        pack_id=pack.id,
        validator="capability-pack-validation",
        executed_by=executed_by,
        status=status,
        summary=f"Validated {len(pack.artifacts)} artifacts; {len(blocking_issues)} blocking issues.",
        artifact_results_json=artifact_results,
        validation_artifacts_json=[
            {
                "artifact_type": "validation-summary",
                "summary": "simple syntax and structure checks completed",
            }
        ],
        blocking_issues_json=blocking_issues,
    )
    session.add(validation)
    pack.status = "validated" if status == "passed" else "validation_failed"
    session.flush()
    return validation


def latest_validation_for_pack(pack: CapabilityPack) -> CapabilityPackValidationResult | None:
    ordered = sorted(pack.validation_results, key=lambda item: (item.created_at, item.id.hex), reverse=True)
    return ordered[0] if ordered else None


def approve_pack(
    session: Session,
    *,
    pack: CapabilityPack,
    approver_id: str,
    notes: str | None = None,
) -> CapabilityPackApproval:
    latest_validation = latest_validation_for_pack(pack)
    if latest_validation is None or latest_validation.status != "passed":
        raise ValueError("pack requires a successful validation before approval")

    approval = CapabilityPackApproval(
        pack_id=pack.id,
        approval_step="pack.promotion",
        approver_id=approver_id,
        decision="approved",
        notes=notes,
    )
    session.add(approval)
    pack.status = "approved"
    _update_generated_template_link(session, pack=pack, status="approved_reviewed")
    session.flush()
    return approval


def deploy_pack(
    session: Session,
    *,
    pack: CapabilityPack,
    deployed_by: str,
    engagement_id: UUID,
    deployment_target: str = "engagement-runtime",
    run_profile_name: str | None = None,
    notes: str | None = None,
) -> CapabilityPackDeployment:
    if pack.status not in {"approved", "deployed"}:
        raise ValueError("pack must be approved before deployment")

    previous = latest_pack_deployment(session, engagement_id=engagement_id, run_profile_name=run_profile_name)
    if previous is not None and previous.pack_id != pack.id:
        previous.status = "superseded"
        previous.pack.status = "superseded"

    deployment = CapabilityPackDeployment(
        pack_id=pack.id,
        engagement_id=engagement_id,
        deployed_by=deployed_by,
        deployment_target=deployment_target,
        run_profile_name=run_profile_name,
        status="deployed",
        notes=notes,
        runtime_binding_json={
            "pack_version": pack.version,
            "pack_name": pack.name,
            "methodology_tags": list(pack.methodology_tags),
            "source_inventory_snapshot_id": str(pack.source_inventory_snapshot_id) if pack.source_inventory_snapshot_id else None,
            "relevance_decision_id": str(pack.relevance_decision_id) if pack.relevance_decision_id else None,
        },
    )
    session.add(deployment)
    pack.status = "deployed"
    session.flush()
    _update_generated_template_link(
        session,
        pack=pack,
        status="deployed",
        deployment_id=deployment.id,
    )
    session.flush()
    return deployment


def rollback_pack(
    session: Session,
    *,
    current_pack: CapabilityPack,
    deployed_by: str,
    engagement_id: UUID,
    run_profile_name: str | None = None,
    notes: str | None = None,
) -> CapabilityPackDeployment:
    deployments = session.scalars(
        select(CapabilityPackDeployment)
        .options(selectinload(CapabilityPackDeployment.pack))
        .where(
            CapabilityPackDeployment.engagement_id == engagement_id,
            CapabilityPackDeployment.status.in_(["deployed", "superseded"]),
        )
        .order_by(CapabilityPackDeployment.created_at.desc(), CapabilityPackDeployment.id.desc())
    ).all()

    candidate: CapabilityPackDeployment | None = None
    current_deployment: CapabilityPackDeployment | None = None
    for deployment in deployments:
        if run_profile_name and deployment.run_profile_name != run_profile_name:
            continue
        if deployment.pack_id == current_pack.id and current_deployment is None:
            current_deployment = deployment
            continue
        if deployment.pack_id != current_pack.id:
            candidate = deployment
            break

    if candidate is None:
        raise ValueError("no previous deployment available for rollback")

    if current_deployment is not None:
        current_deployment.status = "rolled_back"
    current_pack.status = "superseded"
    candidate.pack.status = "deployed"

    deployment = CapabilityPackDeployment(
        pack_id=candidate.pack_id,
        engagement_id=engagement_id,
        deployed_by=deployed_by,
        deployment_target=candidate.deployment_target,
        run_profile_name=run_profile_name or candidate.run_profile_name,
        status="deployed",
        rollback_from_pack_id=current_pack.id,
        notes=notes,
        runtime_binding_json={
            **candidate.runtime_binding_json,
            "rollback_from_pack_id": str(current_pack.id),
            "rollback_note": notes,
        },
    )
    session.add(deployment)
    session.flush()
    return deployment


def bind_pack_to_run(session: Session, *, run: Run, pack: CapabilityPack) -> Run:
    deployment = latest_pack_deployment(
        session,
        engagement_id=run.engagement_id,
        run_profile_name=run.profile.name if run.profile is not None else None,
    )
    if deployment is None or deployment.pack_id != pack.id:
        raise ValueError("pack must be deployed for this engagement before runtime binding")

    run.bound_pack_id = pack.id
    run.bound_pack_version = pack.version
    run.bound_pack_deployment_id = deployment.id
    if pack.source_inventory_snapshot_id is not None:
        run.source_inventory_snapshot_id = pack.source_inventory_snapshot_id
    session.flush()
    return run


def _update_generated_template_link(
    session: Session,
    *,
    pack: CapabilityPack,
    status: str,
    deployment_id: UUID | None = None,
) -> None:
    generation = (pack.manifest_json or {}).get("cve_template_generation")
    if not isinstance(generation, dict):
        return
    record_id = generation.get("threat_intel_record_id")
    try:
        parsed_record_id = UUID(str(record_id))
    except (TypeError, ValueError):
        return
    record = session.get(ThreatIntelRecord, parsed_record_id)
    if record is None:
        return
    metadata = _json_copy(record.metadata_json, {})
    link = _json_copy(metadata.get("generated_nuclei_template"), {})
    if str(link.get("pack_id") or "") != str(pack.id):
        return
    link["status"] = status
    link["pack_status"] = pack.status
    link["updated_at"] = datetime.now(UTC).isoformat()
    if deployment_id is not None:
        link["deployment_id"] = str(deployment_id)
        link["tested_via_generated_template"] = True
    metadata["generated_nuclei_template"] = link
    record.metadata_json = metadata
