from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import CapabilityPack, ThreatIntelRecord
from api.app.services.chatgpt_oauth import (
    ChatGPTOAuthError,
    send_chatgpt_backend_streaming_json_request,
)
from api.app.services.cve_template_generator import (
    ALLOWED_HTTP_METHODS,
    CveTemplateUnavailable,
    NucleiTemplateValidationError,
    UnsafeNucleiTemplateError,
    extract_template_yaml,
    is_cve_record,
    unified_yaml_diff,
    validate_detection_only_nuclei_template,
)
from api.app.services.packs import stage_generated_research_template_pack
from api.app.services.threat_intel import upsert_threat_intel_record


def generate_research_detection_template(
    *,
    session: Session,
    engagement_id: UUID,
    description: str,
    output_kind: str,
    actor: str,
    settings: Settings,
) -> dict[str, Any]:
    clean_description = " ".join(str(description or "").split())
    if output_kind == "python_detection":
        return blocked_python_detection_payload(clean_description)
    if output_kind != "nuclei_yaml":
        raise NucleiTemplateValidationError("unsupported research output kind")

    instructions, input_items = build_research_prompt(clean_description)
    try:
        response_payload = send_chatgpt_backend_streaming_json_request(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
            model=settings.chatgpt_oauth_model,
            instructions=instructions,
            input_items=input_items,
        )
    except ChatGPTOAuthError as exc:
        raise CveTemplateUnavailable(str(exc)) from exc

    template_yaml = extract_template_yaml(response_payload)
    validation = validate_detection_only_nuclei_template(template_yaml)
    yaml_diff = unified_yaml_diff(template_yaml)
    prompt_digest = hashlib.sha256(
        json.dumps(
            {
                "description": clean_description,
                "engagement_id": str(engagement_id),
                "instructions": instructions,
                "input_items": input_items,
                "output_kind": output_kind,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    record = upsert_research_threat_intel_record(
        session=session,
        description=clean_description,
        output_kind=output_kind,
        prompt_digest=prompt_digest,
        actor=actor,
    )
    generation_metadata = {
        "provider": "chatgpt_oauth",
        "token_exposed": False,
        "model_response_keys": sorted(str(key) for key in response_payload.keys()),
        "rationale": str(response_payload.get("rationale") or ""),
        "detection_strategy": str(response_payload.get("detection_strategy") or ""),
        "safety_notes": _string_list(response_payload.get("safety_notes")),
        "yaml_diff": yaml_diff,
        "operator_description": clean_description,
        "output_kind": output_kind,
    }
    pack, artifact = stage_generated_research_template_pack(
        session,
        engagement_id=engagement_id,
        requested_by=actor,
        record=record,
        description=clean_description,
        output_kind=output_kind,
        template_yaml=template_yaml,
        validation_summary=validation,
        model=settings.chatgpt_oauth_model,
        prompt_digest=prompt_digest,
        generation_metadata=generation_metadata,
    )
    return generation_response_payload(
        record=record,
        status="generated",
        message="Detection-only research template staged as a generated capability pack.",
        pack=pack,
        artifact_id=artifact.id,
        template_yaml=template_yaml,
        yaml_diff=yaml_diff,
        validation=validation,
    )


def list_research_proposals(session: Session, *, engagement_id: UUID) -> list[dict[str, Any]]:
    modes = ("ai-cve-nuclei-template", "ai-research-nuclei-template")
    packs = session.scalars(
        select(CapabilityPack)
        .options(selectinload(CapabilityPack.artifacts))
        .where(CapabilityPack.engagement_id == engagement_id, CapabilityPack.generation_mode.in_(modes))
        .order_by(CapabilityPack.created_at.desc(), CapabilityPack.id.desc())
    ).all()
    return [_proposal_for_pack(pack) for pack in packs]


def cve_records_for_research(session: Session) -> list[ThreatIntelRecord]:
    records = session.scalars(select(ThreatIntelRecord).order_by(ThreatIntelRecord.created_at.desc())).all()
    return [record for record in records if is_cve_record(record)]


def build_research_prompt(description: str) -> tuple[str, list[dict[str, Any]]]:
    instructions = (
        "You generate review-only security detection ideas for AegisPT. "
        "Return one JSON object with keys template_yaml, detection_strategy, rationale, and safety_notes. "
        "Generate only a detection-only Nuclei HTTP YAML template: use GET or HEAD requests against {{BaseURL}}, "
        "include id, info.name, info.severity, and at least one matcher. "
        "Do not generate exploit payloads, command execution, credentials, raw requests, interactsh callbacks, "
        "destructive actions, static external targets, or runtime code. "
        "If the operator idea cannot be safely represented, return a conservative GET matcher that requires review."
    )
    payload = {
        "task": "generate_detection_only_research_nuclei_template",
        "operator_description": description,
        "nuclei_schema_expectations": {
            "required_top_level": ["id", "info", "http"],
            "required_info": ["name", "severity"],
            "http_request_methods_allowed": sorted(ALLOWED_HTTP_METHODS),
            "review_gate": "Generated pack must be validated, approved, deployed, and runtime-bound through the existing lifecycle.",
        },
        "safety_boundary": {
            "detection_only": True,
            "auto_deploy": False,
            "external_template_downloads": False,
            "runtime_self_modification": False,
        },
    }
    return instructions, [{"role": "user", "content": [{"type": "input_text", "text": json.dumps(payload, sort_keys=True)}]}]


def upsert_research_threat_intel_record(
    *,
    session: Session,
    description: str,
    output_kind: str,
    prompt_digest: str,
    actor: str,
) -> ThreatIntelRecord:
    advisory_id = f"RESEARCH-{prompt_digest[:12].upper()}"
    title = _title_from_description(description)
    return upsert_threat_intel_record(
        session,
        {
            "source": "ai-research",
            "advisory_id": advisory_id,
            "title": title,
            "summary": description,
            "affected_products": [],
            "affected_versions": [],
            "product_match_hints": _keywords_for_description(description),
            "architecture_hints": [],
            "attack_surface_type": "operator-described",
            "suggested_test_patterns": ["ai-research", "detection-only", output_kind],
            "confidence": 0.5,
            "severity": "medium",
            "references": [],
            "normalization_status": "research-draft",
            "metadata": {
                "ai_research": True,
                "operator_description": description,
                "output_kind": output_kind,
                "prompt_digest_sha256": prompt_digest,
                "requested_by": actor,
                "badge_types": ["source"],
                "external_lookup_performed": False,
            },
        },
    )


def generation_response_payload(
    *,
    record: ThreatIntelRecord | None,
    status: str,
    message: str,
    pack: CapabilityPack | None = None,
    artifact_id: UUID | str | None = None,
    template_yaml: str | None = None,
    yaml_diff: str | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    generated_template = dict((record.metadata_json or {}).get("generated_nuclei_template") or {}) if record else {}
    return {
        "record_id": record.id if record is not None else None,
        "status": status,
        "message": message,
        "pack_id": pack.id if pack is not None else generated_template.get("pack_id"),
        "artifact_id": artifact_id if artifact_id is not None else generated_template.get("artifact_id"),
        "pack_status": pack.status if pack is not None else generated_template.get("status"),
        "review_url": _review_url(str(pack.id)) if pack is not None else generated_template.get("review_url"),
        "template_yaml": template_yaml,
        "yaml_diff": yaml_diff,
        "validation": validation or {},
        "generated_template": generated_template,
        "lifecycle_note": lifecycle_note(),
    }


def unavailable_generation_payload(message: str) -> dict[str, Any]:
    return generation_response_payload(
        record=None,
        status="unavailable",
        message=message,
        validation={
            "provider": "chatgpt_oauth",
            "connected": False,
            "token_exposed": False,
            "generated_at": datetime.now(UTC).isoformat(),
        },
    )


def blocked_python_detection_payload(description: str) -> dict[str, Any]:
    return generation_response_payload(
        record=None,
        status="blocked",
        message=(
            "Python detection script generation is blocked until a repository-backed safety validator exists. "
            "Use Nuclei YAML for review-gated detection ideas in this release."
        ),
        validation={
            "output_kind": "python_detection",
            "operator_description": description,
            "blocked": True,
            "reason": "no_existing_python_detection_script_validator",
            "detection_only": True,
            "auto_deploy": False,
            "operator_review_required": True,
            "validated_at": datetime.now(UTC).isoformat(),
        },
    )


def lifecycle_note() -> str:
    return (
        "Generated research output is staged only. Operators must use the existing pack validation, approval, "
        "deployment, and runtime-binding lifecycle before any run can use it."
    )


def _proposal_for_pack(pack: CapabilityPack) -> dict[str, Any]:
    manifest = dict(pack.manifest_json or {})
    research = manifest.get("ai_research_generation") if isinstance(manifest.get("ai_research_generation"), dict) else {}
    cve = manifest.get("cve_template_generation") if isinstance(manifest.get("cve_template_generation"), dict) else {}
    generation = research or cve
    provenance = dict(pack.provenance_json or {})
    generation_metadata = dict(provenance.get("generation_metadata") or {})
    artifact = next((item for item in pack.artifacts if item.artifact_type == "nuclei_template"), None)
    validation = {}
    yaml_diff = None
    if artifact is not None:
        artifact_provenance = dict(artifact.provenance_json or {})
        validation = dict(artifact_provenance.get("validation_summary") or {})
    if isinstance(generation_metadata, dict):
        yaml_diff = generation_metadata.get("yaml_diff")
    source = "custom_idea" if research else "cve_template"
    title = (
        research.get("title")
        or research.get("operator_description")
        or cve.get("advisory_id")
        or pack.description
        or pack.name
    )
    return {
        "id": str(pack.id),
        "pack_id": str(pack.id),
        "artifact_id": str(artifact.id) if artifact is not None else None,
        "record_id": generation.get("threat_intel_record_id"),
        "source": source,
        "title": str(title or pack.name),
        "description": pack.description,
        "status": _proposal_status(pack.status),
        "pack_status": pack.status,
        "review_url": _review_url(str(pack.id)),
        "generation_mode": pack.generation_mode,
        "output_kind": research.get("output_kind") or "nuclei_yaml",
        "provider": generation.get("provider") or provenance.get("provider"),
        "model": generation.get("model") or provenance.get("model"),
        "advisory_id": generation.get("advisory_id"),
        "validation": validation,
        "yaml_diff": yaml_diff,
        "reasoning": generation_metadata.get("rationale") if isinstance(generation_metadata, dict) else None,
        "detection_strategy": generation_metadata.get("detection_strategy") if isinstance(generation_metadata, dict) else None,
        "safety_notes": _string_list(generation_metadata.get("safety_notes")) if isinstance(generation_metadata, dict) else [],
        "created_at": pack.created_at,
        "updated_at": pack.updated_at,
    }


def _proposal_status(pack_status: str) -> str:
    return {
        "generated": "staged",
        "validated": "validated",
        "approved": "approved",
        "deployed": "deployed",
        "validation_failed": "rejected",
        "retired": "rejected",
    }.get(str(pack_status or "").lower(), str(pack_status or "draft"))


def _title_from_description(description: str) -> str:
    text = description.strip()
    if len(text) <= 72:
        return text or "AI research detection idea"
    return f"{text[:69].rstrip()}..."


def _keywords_for_description(description: str) -> list[str]:
    words = []
    for token in description.replace("/", " ").replace(":", " ").split():
        clean = "".join(ch for ch in token if ch.isalnum() or ch in {"-", "_"}).strip()
        if len(clean) >= 4:
            words.append(clean)
    return list(dict.fromkeys(words))[:12]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item or "").strip()]


def _review_url(pack_id: Any) -> str | None:
    if not pack_id:
        return None
    return f"/app/?screen=pack-forge&pack_id={pack_id}"


__all__ = [
    "CveTemplateUnavailable",
    "NucleiTemplateValidationError",
    "UnsafeNucleiTemplateError",
    "blocked_python_detection_payload",
    "cve_records_for_research",
    "generate_research_detection_template",
    "lifecycle_note",
    "list_research_proposals",
    "unavailable_generation_payload",
]
