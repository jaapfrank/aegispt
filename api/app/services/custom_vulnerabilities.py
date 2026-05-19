from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import (
    CapabilityPackArtifact,
    CustomVulnerability,
    CustomVulnerabilityEngagementSetting,
)
from api.app.services.chatgpt_oauth import (
    ChatGPTOAuthError,
    send_chatgpt_backend_streaming_json_request,
)

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
ALLOWED_STATUSES = {"draft", "active", "deprecated"}
CUSTOM_ID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{2,99}$")
KNOWN_ID_PATTERN = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|AEGIS-\d{4}-\d{3,}|ORG-\d{4}-\d{3,})\b", re.I)
CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.I)
CVSS_PATTERN = re.compile(r"\b(?:CVSS|score)\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b", re.I)


class CustomVulnerabilityError(ValueError):
    pass


def tenant_key(tenant_id: str | None) -> str:
    return (tenant_id or "default").strip() or "default"


def list_custom_vulnerabilities(
    session: Session,
    *,
    tenant_id: str | None,
    query: str | None = None,
    product: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    include_deleted: bool = False,
    engagement_id: UUID | None = None,
) -> list[CustomVulnerability]:
    statement = select(CustomVulnerability).where(CustomVulnerability.tenant_id == tenant_key(tenant_id))
    if not include_deleted:
        statement = statement.where(CustomVulnerability.deleted_at.is_(None))
    if severity:
        statement = statement.where(CustomVulnerability.severity == _normalize_severity(severity))
    if status:
        statement = statement.where(CustomVulnerability.status == _normalize_status(status))
    statement = statement.order_by(CustomVulnerability.created_at.desc(), CustomVulnerability.id.desc())
    records = session.scalars(statement).all()
    normalized_query = _clean_text(query).lower()
    normalized_product = _clean_text(product).lower()
    filtered: list[CustomVulnerability] = []
    for record in records:
        haystack = " ".join(
            [
                record.custom_id,
                record.title,
                record.description,
                record.severity,
                record.status,
                " ".join(record.affected_products_json or []),
                " ".join(record.cwe_ids_json or []),
            ]
        ).lower()
        product_haystack = " ".join(record.affected_products_json or []).lower()
        if normalized_query and normalized_query not in haystack:
            continue
        if normalized_product and normalized_product not in product_haystack:
            continue
        filtered.append(record)
    if engagement_id is None:
        return filtered
    # Touch engagement settings in one deterministic query so later serialization does not need N+1 logic.
    settings = session.scalars(
        select(CustomVulnerabilityEngagementSetting).where(
            CustomVulnerabilityEngagementSetting.engagement_id == engagement_id,
            CustomVulnerabilityEngagementSetting.custom_vulnerability_id.in_([item.id for item in filtered]),
        )
    ).all()
    settings_by_id = {setting.custom_vulnerability_id: setting for setting in settings}
    for record in filtered:
        record._aegispt_engagement_setting = settings_by_id.get(record.id)  # type: ignore[attr-defined]
    return filtered


def load_custom_vulnerability(
    session: Session,
    *,
    vulnerability_id: UUID,
    tenant_id: str | None,
    include_deleted: bool = False,
) -> CustomVulnerability | None:
    statement = select(CustomVulnerability).where(
        CustomVulnerability.id == vulnerability_id,
        CustomVulnerability.tenant_id == tenant_key(tenant_id),
    )
    if not include_deleted:
        statement = statement.where(CustomVulnerability.deleted_at.is_(None))
    return session.scalar(statement)


def create_custom_vulnerability(
    session: Session,
    *,
    tenant_id: str | None,
    payload: dict[str, Any],
    actor: str,
) -> CustomVulnerability:
    normalized = normalize_custom_vulnerability_payload(
        session,
        tenant_id=tenant_id,
        payload=payload,
        default_status=str(payload.get("status") or "draft"),
    )
    if _find_by_custom_id(session, tenant_id=tenant_id, custom_id=normalized["custom_id"]) is not None:
        raise CustomVulnerabilityError("custom_id already exists for this tenant")
    now = datetime.now(UTC)
    record = CustomVulnerability(
        tenant_id=tenant_key(tenant_id),
        custom_id=normalized["custom_id"],
        title=normalized["title"],
        description=normalized["description"],
        severity=normalized["severity"],
        cvss_score=normalized["cvss_score"],
        affected_products_json=normalized["affected_products"],
        cwe_ids_json=normalized["cwe_ids"],
        discovery_date=normalized["discovery_date"],
        reporter=normalized["reporter"] or actor,
        status=normalized["status"],
        linked_nuclei_template_ref=normalized["linked_nuclei_template_ref"],
        linked_threat_intel_record_id=normalized["linked_threat_intel_record_id"],
        metadata_json={
            **normalized["metadata"],
            "source": normalized["metadata"].get("source") or "operator",
            "pack_gate_bypassed": False,
            "auto_deploy": False,
        },
        created_at=now,
        updated_at=now,
    )
    session.add(record)
    session.flush()
    return record


def update_custom_vulnerability(
    session: Session,
    *,
    record: CustomVulnerability,
    patch: dict[str, Any],
    fields_set: set[str],
) -> CustomVulnerability:
    if "custom_id" in fields_set and patch.get("custom_id") is not None:
        next_custom_id = _normalize_custom_id(str(patch.get("custom_id") or ""))
        existing = _find_by_custom_id(session, tenant_id=record.tenant_id, custom_id=next_custom_id)
        if existing is not None and existing.id != record.id:
            raise CustomVulnerabilityError("custom_id already exists for this tenant")
        record.custom_id = next_custom_id
    if "title" in fields_set and patch.get("title") is not None:
        record.title = _required_text(patch.get("title"), "title")
    if "description" in fields_set and patch.get("description") is not None:
        record.description = _required_text(patch.get("description"), "description")
    if "severity" in fields_set and patch.get("severity") is not None:
        record.severity = _normalize_severity(str(patch.get("severity") or ""))
    if "cvss_score" in fields_set:
        record.cvss_score = _normalize_cvss(patch.get("cvss_score"))
    if "affected_products" in fields_set and patch.get("affected_products") is not None:
        record.affected_products_json = _string_list(patch.get("affected_products"))
    if "cwe_ids" in fields_set and patch.get("cwe_ids") is not None:
        record.cwe_ids_json = _normalize_cwe_ids(patch.get("cwe_ids"))
    if "discovery_date" in fields_set:
        record.discovery_date = patch.get("discovery_date")
    if "reporter" in fields_set:
        record.reporter = _clean_text(patch.get("reporter")) or None
    if "status" in fields_set and patch.get("status") is not None:
        record.status = _normalize_status(str(patch.get("status") or ""))
    if "linked_nuclei_template_ref" in fields_set:
        record.linked_nuclei_template_ref = _clean_text(patch.get("linked_nuclei_template_ref")) or None
    if "linked_threat_intel_record_id" in fields_set:
        record.linked_threat_intel_record_id = patch.get("linked_threat_intel_record_id")
    if "metadata" in fields_set and isinstance(patch.get("metadata"), dict):
        record.metadata_json = {
            **dict(record.metadata_json or {}),
            **dict(patch.get("metadata") or {}),
            "pack_gate_bypassed": False,
            "auto_deploy": False,
        }
    session.flush()
    return record


def soft_delete_custom_vulnerability(session: Session, *, record: CustomVulnerability) -> CustomVulnerability:
    record.deleted_at = datetime.now(UTC)
    for setting in list(record.engagement_settings or []):
        setting.enabled = False
        setting.metadata_json = {
            **dict(setting.metadata_json or {}),
            "disabled_reason": "custom vulnerability soft-deleted",
        }
    session.flush()
    return record


def import_custom_vulnerabilities(
    session: Session,
    *,
    tenant_id: str | None,
    import_format: str,
    payload: dict[str, Any] | list[dict[str, Any]] | str,
    default_status: str,
    actor: str,
    settings: Settings,
    engagement_id: UUID | None = None,
    use_ai: bool = False,
) -> dict[str, Any]:
    ai_assistance = {
        "requested": bool(use_ai),
        "status": "not_requested",
        "provider": "chatgpt_oauth",
        "token_exposed": False,
    }
    if import_format == "plain_text":
        parsed_payloads = []
        if use_ai:
            ai_payload = _ai_structure_plain_text(
                session=session,
                engagement_id=engagement_id,
                settings=settings,
                text=str(payload or ""),
            )
            ai_assistance.update(ai_payload["ai_assistance"])
            parsed_payloads = ai_payload["records"]
        if not parsed_payloads:
            parsed_payloads = [_parse_plain_text_payload(str(payload or ""))]
    elif import_format == "nvd_json":
        parsed_payloads = _parse_nvd_payload(payload)
    elif import_format == "csaf":
        parsed_payloads = _parse_csaf_payload(payload)
    elif import_format == "aegispt_export":
        parsed_payloads = _parse_aegispt_export_payload(payload)
    else:
        raise CustomVulnerabilityError(f"unsupported import format: {import_format}")

    imported: list[CustomVulnerability] = []
    imported_count = 0
    updated_count = 0
    skipped_count = 0
    for raw in parsed_payloads:
        try:
            normalized = normalize_custom_vulnerability_payload(
                session,
                tenant_id=tenant_id,
                payload={**raw, "status": raw.get("status") or default_status},
                default_status=default_status,
            )
        except CustomVulnerabilityError:
            skipped_count += 1
            continue
        existing = _find_by_custom_id(session, tenant_id=tenant_id, custom_id=normalized["custom_id"])
        if existing is None:
            record = create_custom_vulnerability(
                session,
                tenant_id=tenant_id,
                payload=normalized,
                actor=actor,
            )
            imported_count += 1
        else:
            record = update_custom_vulnerability(
                session,
                record=existing,
                patch=normalized,
                fields_set=set(normalized),
            )
            updated_count += 1
        imported.append(record)
    session.flush()
    return {
        "imported_count": imported_count,
        "updated_count": updated_count,
        "skipped_count": skipped_count,
        "ai_assistance": ai_assistance,
        "items": imported,
    }


def export_custom_vulnerabilities(
    session: Session,
    *,
    tenant_id: str | None,
    include_deleted: bool = False,
) -> dict[str, Any]:
    records = list_custom_vulnerabilities(
        session,
        tenant_id=tenant_id,
        include_deleted=include_deleted,
    )
    return {
        "exported_at": datetime.now(UTC),
        "tenant_id": tenant_key(tenant_id),
        "format": "aegispt_custom_vulnerabilities.v1",
        "items": [_export_item(record) for record in records],
    }


def set_custom_vulnerability_engagement_enabled(
    session: Session,
    *,
    record: CustomVulnerability,
    engagement_id: UUID,
    enabled: bool,
    actor: str,
) -> CustomVulnerabilityEngagementSetting:
    setting = session.scalar(
        select(CustomVulnerabilityEngagementSetting).where(
            CustomVulnerabilityEngagementSetting.custom_vulnerability_id == record.id,
            CustomVulnerabilityEngagementSetting.engagement_id == engagement_id,
        )
    )
    if setting is None:
        now = datetime.now(UTC)
        setting = CustomVulnerabilityEngagementSetting(
            custom_vulnerability_id=record.id,
            engagement_id=engagement_id,
            enabled=False,
            metadata_json={},
            created_at=now,
            updated_at=now,
        )
        session.add(setting)
    setting.enabled = bool(enabled)
    setting.enabled_by = actor if enabled else setting.enabled_by
    setting.enabled_at = datetime.now(UTC) if enabled else setting.enabled_at
    coverage = build_test_coverage(session, record)
    setting.metadata_json = {
        **dict(setting.metadata_json or {}),
        "linked_nuclei_template_ref": record.linked_nuclei_template_ref,
        "coverage_status": coverage["status"],
        "ready_to_run": bool(coverage["deployed"] and enabled),
        "pack_gate_bypassed": False,
        "runtime_binding_required": True,
    }
    record._aegispt_engagement_setting = setting  # type: ignore[attr-defined]
    session.flush()
    return setting


def build_scan_options(
    session: Session,
    *,
    tenant_id: str | None,
    engagement_id: UUID,
) -> list[dict[str, Any]]:
    records = list_custom_vulnerabilities(
        session,
        tenant_id=tenant_id,
        status="active",
        engagement_id=engagement_id,
    )
    options: list[dict[str, Any]] = []
    for record in records:
        coverage = build_test_coverage(session, record)
        if not record.linked_nuclei_template_ref:
            continue
        engagement_state = build_engagement_state(record, engagement_id)
        enabled = bool(engagement_state and engagement_state["enabled"])
        options.append(
            {
                "id": record.id,
                "custom_id": record.custom_id,
                "title": record.title,
                "severity": record.severity,
                "affected_products": list(record.affected_products_json or []),
                "enabled": enabled,
                "has_linked_template": True,
                "test_coverage": coverage,
                "profile_option": {
                    "profile_name": "passive-web-nuclei-audit",
                    "additional_check": True,
                    "check_id": record.custom_id,
                    "tool": "nuclei",
                    "pack_artifact_ref": record.linked_nuclei_template_ref,
                    "ready_to_run": bool(enabled and coverage["deployed"]),
                    "pack_lifecycle_required": True,
                    "auto_deploy": False,
                },
            }
        )
    return options


def build_read_payload(
    session: Session,
    record: CustomVulnerability,
    *,
    engagement_id: UUID | None = None,
) -> dict[str, Any]:
    return {
        "id": record.id,
        "tenant_id": record.tenant_id,
        "custom_id": record.custom_id,
        "title": record.title,
        "description": record.description,
        "severity": record.severity,
        "cvss_score": record.cvss_score,
        "affected_products_json": list(record.affected_products_json or []),
        "cwe_ids_json": list(record.cwe_ids_json or []),
        "discovery_date": record.discovery_date,
        "reporter": record.reporter,
        "status": record.status,
        "linked_nuclei_template_ref": record.linked_nuclei_template_ref,
        "linked_threat_intel_record_id": record.linked_threat_intel_record_id,
        "metadata_json": dict(record.metadata_json or {}),
        "deleted_at": record.deleted_at,
        "test_coverage": build_test_coverage(session, record),
        "engagement_state": build_engagement_state(record, engagement_id) if engagement_id else None,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def build_engagement_state(
    record: CustomVulnerability,
    engagement_id: UUID | None,
) -> dict[str, Any] | None:
    if engagement_id is None:
        return None
    setting = getattr(record, "_aegispt_engagement_setting", None)
    if setting is None:
        setting = next(
            (
                candidate
                for candidate in list(record.engagement_settings or [])
                if candidate.engagement_id == engagement_id
            ),
            None,
        )
    return {
        "engagement_id": engagement_id,
        "enabled": bool(setting.enabled) if setting is not None else False,
        "enabled_by": setting.enabled_by if setting is not None else None,
        "enabled_at": setting.enabled_at if setting is not None else None,
    }


def build_test_coverage(session: Session, record: CustomVulnerability) -> dict[str, Any]:
    ref = _clean_text(record.linked_nuclei_template_ref)
    if not ref:
        return {
            "status": "missing_template",
            "message": "No pack-lane Nuclei template is linked yet.",
            "linked_nuclei_template_ref": None,
            "artifact_id": None,
            "pack_id": None,
            "pack_status": None,
            "validation_status": None,
            "deployed": False,
            "deployment_id": None,
            "runtime_binding_required": True,
        }
    artifact_id = _extract_uuid(ref)
    artifact = session.get(CapabilityPackArtifact, artifact_id) if artifact_id is not None else None
    if artifact is None:
        return {
            "status": "linked_ref_unresolved",
            "message": "Linked template reference is recorded but no local pack artifact was found.",
            "linked_nuclei_template_ref": ref,
            "artifact_id": artifact_id,
            "pack_id": None,
            "pack_status": None,
            "validation_status": None,
            "deployed": False,
            "deployment_id": None,
            "runtime_binding_required": True,
        }
    pack = artifact.pack
    validations = sorted(pack.validation_results or [], key=lambda item: item.created_at, reverse=True)
    deployments = sorted(pack.deployments or [], key=lambda item: item.created_at, reverse=True)
    latest_validation = validations[0] if validations else None
    latest_deployment = next((deployment for deployment in deployments if deployment.status == "deployed"), None)
    if latest_deployment is not None:
        status = "deployed"
        message = "Template is deployed through the existing pack lifecycle and can be selected for scans."
    elif pack.status == "approved":
        status = "approved_not_deployed"
        message = "Template is approved but not deployed or runtime-bound yet."
    elif latest_validation is not None:
        status = f"validation_{latest_validation.status}"
        message = "Template has validation evidence but still needs approval/deployment before runtime use."
    else:
        status = "pending_pack_review"
        message = "Template exists as a pack artifact and still needs validation, approval, and deployment."
    return {
        "status": status,
        "message": message,
        "linked_nuclei_template_ref": ref,
        "artifact_id": artifact.id,
        "pack_id": artifact.pack_id,
        "pack_status": pack.status,
        "validation_status": latest_validation.status if latest_validation is not None else None,
        "deployed": latest_deployment is not None,
        "deployment_id": latest_deployment.id if latest_deployment is not None else None,
        "runtime_binding_required": True,
    }


def normalize_custom_vulnerability_payload(
    session: Session,
    *,
    tenant_id: str | None,
    payload: dict[str, Any],
    default_status: str,
) -> dict[str, Any]:
    custom_id = _clean_text(payload.get("custom_id")) or _generate_custom_id(session, tenant_id=tenant_id)
    return {
        "custom_id": _normalize_custom_id(custom_id),
        "title": _required_text(payload.get("title"), "title"),
        "description": _required_text(payload.get("description"), "description"),
        "severity": _normalize_severity(str(payload.get("severity") or "medium")),
        "cvss_score": _normalize_cvss(payload.get("cvss_score")),
        "affected_products": _string_list(payload.get("affected_products") or payload.get("affected_products_json")),
        "cwe_ids": _normalize_cwe_ids(payload.get("cwe_ids") or payload.get("cwe_ids_json")),
        "discovery_date": _normalize_datetime(payload.get("discovery_date")),
        "reporter": _clean_text(payload.get("reporter")) or None,
        "status": _normalize_status(str(payload.get("status") or default_status)),
        "linked_nuclei_template_ref": _clean_text(payload.get("linked_nuclei_template_ref")) or None,
        "linked_threat_intel_record_id": _normalize_uuid(payload.get("linked_threat_intel_record_id")),
        "metadata": dict(payload.get("metadata") or payload.get("metadata_json") or {}),
    }


def _find_by_custom_id(
    session: Session,
    *,
    tenant_id: str | None,
    custom_id: str,
) -> CustomVulnerability | None:
    return session.scalar(
        select(CustomVulnerability).where(
            CustomVulnerability.tenant_id == tenant_key(tenant_id),
            CustomVulnerability.custom_id == _normalize_custom_id(custom_id),
        )
    )


def _ai_structure_plain_text(
    *,
    session: Session,
    engagement_id: UUID | None,
    settings: Settings,
    text: str,
) -> dict[str, Any]:
    if engagement_id is None:
        return {
            "records": [],
            "ai_assistance": {
                "requested": True,
                "status": "unavailable",
                "provider": "chatgpt_oauth",
                "message": "Engagement id is required for ChatGPT OAuth structuring.",
                "token_exposed": False,
            },
        }
    instructions = (
        "Structure one operator-supplied vulnerability description for AegisPT's custom vulnerability library. "
        "Return JSON with a records array. Each record must have custom_id, title, description, severity, "
        "cvss_score, affected_products, cwe_ids, and status. Do not create exploit steps, payloads, credentials, "
        "runtime actions, or scan dispatch instructions. Keep it metadata-only."
    )
    try:
        response = send_chatgpt_backend_streaming_json_request(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
            model=settings.chatgpt_oauth_model,
            instructions=instructions,
            input_items=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": text[:12000],
                        }
                    ],
                }
            ],
        )
    except ChatGPTOAuthError as exc:
        return {
            "records": [],
            "ai_assistance": {
                "requested": True,
                "status": "unavailable",
                "provider": "chatgpt_oauth",
                "message": str(exc),
                "token_exposed": False,
            },
        }
    records = response.get("records") if isinstance(response.get("records"), list) else [response]
    return {
        "records": [item for item in records if isinstance(item, dict)],
        "ai_assistance": {
            "requested": True,
            "status": "structured",
            "provider": "chatgpt_oauth",
            "model": settings.chatgpt_oauth_model,
            "record_count": len(records),
            "token_exposed": False,
        },
    }


def _parse_nvd_payload(payload: dict[str, Any] | list[dict[str, Any]] | str) -> list[dict[str, Any]]:
    data = _jsonish_payload(payload)
    raw_items: list[dict[str, Any]]
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        raw_items = [item.get("cve") if isinstance(item, dict) and isinstance(item.get("cve"), dict) else item for item in data["vulnerabilities"]]
    elif isinstance(data, dict) and isinstance(data.get("cve"), dict):
        raw_items = [data["cve"]]
    elif isinstance(data, list):
        raw_items = [item.get("cve") if isinstance(item, dict) and isinstance(item.get("cve"), dict) else item for item in data]
    elif isinstance(data, dict):
        raw_items = [data]
    else:
        return []
    return [_normalize_nvd_item(item) for item in raw_items if isinstance(item, dict)]


def _normalize_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    custom_id = _clean_text(item.get("id") or item.get("cve_id") or item.get("custom_id"))
    description = _localized_description(item.get("descriptions")) or _clean_text(item.get("description") or item.get("summary"))
    score, severity = _nvd_score_and_severity(item)
    products = _nvd_products(item)
    cwes = _nvd_cwes(item)
    references = _nvd_references(item)
    return {
        "custom_id": custom_id,
        "title": _clean_text(item.get("title")) or custom_id or "Imported CVE",
        "description": description or _clean_text(item.get("title")) or custom_id or "Imported vulnerability definition.",
        "severity": severity or _severity_from_score(score),
        "cvss_score": score,
        "affected_products": products,
        "cwe_ids": cwes,
        "status": "draft",
        "metadata": {
            "import_format": "nvd_json",
            "references": references,
            "source": "nvd-import",
            "raw_id": custom_id,
        },
    }


def _parse_csaf_payload(payload: dict[str, Any] | list[dict[str, Any]] | str) -> list[dict[str, Any]]:
    data = _jsonish_payload(payload)
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        vulnerabilities = data["vulnerabilities"]
        document = data.get("document") if isinstance(data.get("document"), dict) else {}
    elif isinstance(data, list):
        vulnerabilities = data
        document = {}
    elif isinstance(data, dict):
        vulnerabilities = [data]
        document = {}
    else:
        return []
    doc_title = _clean_text(document.get("title"))
    return [_normalize_csaf_item(item, doc_title=doc_title) for item in vulnerabilities if isinstance(item, dict)]


def _normalize_csaf_item(item: dict[str, Any], *, doc_title: str) -> dict[str, Any]:
    custom_id = _clean_text(item.get("cve") or item.get("cve_id") or item.get("id") or item.get("custom_id"))
    notes = item.get("notes") if isinstance(item.get("notes"), list) else []
    description = _clean_text(item.get("description")) or " ".join(
        _clean_text(note.get("text")) for note in notes if isinstance(note, dict)
    ).strip()
    score, severity = _csaf_score_and_severity(item)
    products = _string_list((item.get("product_status") or {}).get("known_affected") if isinstance(item.get("product_status"), dict) else [])
    cwes = _normalize_cwe_ids([item.get("cwe", {}).get("id") if isinstance(item.get("cwe"), dict) else item.get("cwe")])
    return {
        "custom_id": custom_id,
        "title": _clean_text(item.get("title")) or custom_id or doc_title or "Imported CSAF vulnerability",
        "description": description or _clean_text(item.get("title")) or "Imported CSAF vulnerability definition.",
        "severity": severity or _severity_from_score(score),
        "cvss_score": score,
        "affected_products": products,
        "cwe_ids": cwes,
        "status": "draft",
        "metadata": {
            "import_format": "csaf",
            "source": "csaf-import",
            "document_title": doc_title,
        },
    }


def _parse_plain_text_payload(text: str) -> dict[str, Any]:
    normalized = str(text or "").strip()
    first_line = next((line.strip() for line in normalized.splitlines() if line.strip()), "")
    custom_id_match = KNOWN_ID_PATTERN.search(normalized)
    cwes = sorted({match.group(0).upper() for match in CWE_PATTERN.finditer(normalized)})
    score_match = CVSS_PATTERN.search(normalized)
    score = _normalize_cvss(score_match.group(1)) if score_match else None
    severity = _severity_from_text(normalized) or _severity_from_score(score)
    products = _extract_products_from_text(normalized)
    return {
        "custom_id": custom_id_match.group(0).upper() if custom_id_match else "",
        "title": first_line[:180] or "Custom vulnerability",
        "description": normalized or "Operator-supplied custom vulnerability.",
        "severity": severity,
        "cvss_score": score,
        "affected_products": products,
        "cwe_ids": cwes,
        "status": "draft",
        "metadata": {"import_format": "plain_text", "source": "operator-text"},
    }


def _parse_aegispt_export_payload(payload: dict[str, Any] | list[dict[str, Any]] | str) -> list[dict[str, Any]]:
    data = _jsonish_payload(payload)
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [item for item in data["items"] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _export_item(record: CustomVulnerability) -> dict[str, Any]:
    return {
        "custom_id": record.custom_id,
        "title": record.title,
        "description": record.description,
        "severity": record.severity,
        "cvss_score": record.cvss_score,
        "affected_products": list(record.affected_products_json or []),
        "cwe_ids": list(record.cwe_ids_json or []),
        "discovery_date": record.discovery_date.isoformat() if record.discovery_date else None,
        "reporter": record.reporter,
        "status": record.status,
        "linked_nuclei_template_ref": record.linked_nuclei_template_ref,
        "linked_threat_intel_record_id": str(record.linked_threat_intel_record_id) if record.linked_threat_intel_record_id else None,
        "metadata": dict(record.metadata_json or {}),
    }


def _generate_custom_id(session: Session, *, tenant_id: str | None) -> str:
    year = datetime.now(UTC).year
    prefix = f"AEGIS-{year}-"
    count = session.scalar(
        select(func.count(CustomVulnerability.id)).where(
            CustomVulnerability.tenant_id == tenant_key(tenant_id),
            CustomVulnerability.custom_id.like(f"{prefix}%"),
        )
    ) or 0
    return f"{prefix}{int(count) + 1:03d}"


def _normalize_custom_id(value: str) -> str:
    normalized = _clean_text(value).upper().replace(" ", "-")
    if not CUSTOM_ID_PATTERN.fullmatch(normalized):
        raise CustomVulnerabilityError("custom_id must be 3-100 chars using letters, numbers, dot, colon, underscore, or dash")
    return normalized


def _normalize_severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ALLOWED_SEVERITIES:
        raise CustomVulnerabilityError("severity must be critical, high, medium, or low")
    return normalized


def _normalize_status(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ALLOWED_STATUSES:
        raise CustomVulnerabilityError("status must be draft, active, or deprecated")
    return normalized


def _normalize_cvss(value: Any) -> float | None:
    if value is None or value == "":
        return None
    score = float(value)
    if score < 0 or score > 10:
        raise CustomVulnerabilityError("cvss_score must be between 0 and 10")
    return score


def _required_text(value: Any, field: str) -> str:
    normalized = _clean_text(value)
    if not normalized:
        raise CustomVulnerabilityError(f"{field} is required")
    return normalized


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        items = re.split(r"[,;\n]", value)
    elif isinstance(value, list | tuple | set):
        items = value
    else:
        items = []
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = _clean_text(item)
        if not normalized or normalized.lower() in seen:
            continue
        seen.add(normalized.lower())
        result.append(normalized)
    return result


def _normalize_cwe_ids(value: Any) -> list[str]:
    cwes = []
    for item in _string_list(value):
        match = CWE_PATTERN.search(item)
        if match:
            cwes.append(match.group(0).upper())
    return sorted(set(cwes))


def _extract_uuid(value: str) -> UUID | None:
    match = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value)
    if not match:
        return None
    try:
        return UUID(match.group(0))
    except ValueError:
        return None


def _normalize_uuid(value: Any) -> UUID | None:
    if value is None or value == "":
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        raise CustomVulnerabilityError("linked_threat_intel_record_id must be a valid UUID") from None


def _normalize_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise CustomVulnerabilityError("discovery_date must be an ISO datetime") from None


def _jsonish_payload(payload: Any) -> Any:
    if isinstance(payload, str):
        import json

        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload
    return payload


def _localized_description(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            if str(item.get("lang") or "").lower() in {"en", "eng", ""}:
                return _clean_text(item.get("value"))
    return ""


def _nvd_score_and_severity(item: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        metric = entries[0] if isinstance(entries[0], dict) else {}
        cvss_data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
        score = _normalize_cvss(cvss_data.get("baseScore"))
        severity = _clean_text(metric.get("baseSeverity") or cvss_data.get("baseSeverity")).lower()
        return score, severity if severity in ALLOWED_SEVERITIES else None
    return _normalize_cvss(item.get("cvss_score")), _clean_text(item.get("severity")).lower() or None


def _nvd_products(item: dict[str, Any]) -> list[str]:
    products = _string_list(item.get("affected_products"))
    configurations = item.get("configurations") if isinstance(item.get("configurations"), list) else []
    for configuration in configurations:
        nodes = configuration.get("nodes") if isinstance(configuration, dict) else []
        for node in nodes or []:
            matches = node.get("cpeMatch") if isinstance(node, dict) else []
            for cpe_match in matches or []:
                criteria = _clean_text(cpe_match.get("criteria") if isinstance(cpe_match, dict) else "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    products.extend(_string_list([f"{vendor} {product}".strip(), product]))
    return _string_list(products)


def _nvd_cwes(item: dict[str, Any]) -> list[str]:
    cwes = _normalize_cwe_ids(item.get("cwe_ids"))
    weaknesses = item.get("weaknesses") if isinstance(item.get("weaknesses"), list) else []
    for weakness in weaknesses:
        descriptions = weakness.get("description") if isinstance(weakness, dict) else []
        for description in descriptions or []:
            if isinstance(description, dict):
                cwes.extend(_normalize_cwe_ids([description.get("value")]))
    return sorted(set(cwes))


def _nvd_references(item: dict[str, Any]) -> list[str]:
    references = item.get("references")
    if isinstance(references, dict):
        references = references.get("referenceData") or references.get("references")
    if isinstance(references, list):
        return _string_list([entry.get("url") if isinstance(entry, dict) else entry for entry in references])
    return []


def _csaf_score_and_severity(item: dict[str, Any]) -> tuple[float | None, str | None]:
    scores = item.get("scores") if isinstance(item.get("scores"), list) else []
    for score_entry in scores:
        cvss = score_entry.get("cvss_v3") if isinstance(score_entry, dict) else {}
        if isinstance(cvss, dict):
            score = _normalize_cvss(cvss.get("baseScore") or cvss.get("base_score"))
            severity = _clean_text(cvss.get("baseSeverity") or cvss.get("base_severity")).lower()
            return score, severity if severity in ALLOWED_SEVERITIES else None
    return None, None


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _severity_from_text(text: str) -> str | None:
    normalized = text.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"\b{severity}\b", normalized):
            return severity
    return None


def _extract_products_from_text(text: str) -> list[str]:
    patterns = [
        r"affected products?\s*[:=]\s*([^\n]+)",
        r"product\s*[:=]\s*([^\n]+)",
        r"component\s*[:=]\s*([^\n]+)",
    ]
    products: list[str] = []
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            products.extend(_string_list(match.group(1)))
    return _string_list(products)
