from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Engagement, EngagementCasebookEntry, Run

CASEBOOK_VERSION = "engagement-casebook-v1"
DEFAULT_TENANT_ID = "default"
CASEBOOK_ENTRY_TYPES = {
    "architecture_note",
    "blocked_path",
    "accepted_gap",
    "resolved_finding",
    "operator_constraint",
    "target_context",
}
SECRET_KEYWORDS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "jwt",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
}
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


class EngagementCasebookError(ValueError):
    pass


class CasebookSecretRejectedError(EngagementCasebookError):
    pass


def create_casebook_entry(
    session: Session,
    *,
    engagement: Engagement,
    entry_type: str,
    title: str,
    summary: str,
    source_refs: list[dict[str, Any]],
    created_by: str,
    data: dict[str, Any] | None = None,
    tenant_id: str | None = None,
    status: str = "recorded",
) -> EngagementCasebookEntry:
    normalized_tenant = _tenant_key(tenant_id if tenant_id is not None else engagement.tenant_id)
    _assert_engagement_tenant(engagement, normalized_tenant)
    normalized_type = _normalize_entry_type(entry_type)
    normalized_title = _clean_text(title, field="title", limit=255)
    normalized_summary = _clean_text(summary, field="summary", limit=2000)
    normalized_sources = _normalize_source_refs(source_refs)
    normalized_data = _sanitize_json(data or {}, field_path="data")
    entry = EngagementCasebookEntry(
        engagement_id=engagement.id,
        tenant_id=normalized_tenant,
        entry_type=normalized_type,
        title=normalized_title,
        summary=normalized_summary,
        source_refs_json=normalized_sources,
        data_json=normalized_data,
        status=str(status or "recorded").strip() or "recorded",
        created_by=_clean_text(created_by or "system", field="created_by", limit=255),
        provenance_json={
            "version": CASEBOOK_VERSION,
            "source": "engagement_casebook_service",
            "planning_input_only": True,
            "evidence_linked": True,
            "source_ref_count": len(normalized_sources),
            "secrets_stored": False,
            "scope_expansion_allowed": False,
            "runtime_self_modification": False,
        },
    )
    session.add(entry)
    session.flush()
    return entry


def build_casebook_from_engagement(
    session: Session,
    *,
    engagement: Engagement,
    actor: str = "system",
    tenant_id: str | None = None,
) -> list[EngagementCasebookEntry]:
    created: list[EngagementCasebookEntry] = []
    normalized_tenant = _tenant_key(tenant_id if tenant_id is not None else engagement.tenant_id)
    _assert_engagement_tenant(engagement, normalized_tenant)
    existing_keys = {
        _entry_dedupe_key(entry)
        for entry in list_casebook_entries(
            session,
            engagement_id=engagement.id,
            tenant_id=normalized_tenant,
        )
    }

    for snapshot in list(engagement.inventory_snapshots or []):
        summary = _inventory_summary(snapshot.normalized_inventory_json)
        if summary:
            created.extend(
                _create_if_missing(
                    session,
                    existing_keys=existing_keys,
                    engagement=engagement,
                    tenant_id=normalized_tenant,
                    entry_type="architecture_note",
                    title="Observed architecture from inventory",
                    summary=summary,
                    source_refs=[{"type": "inventory_snapshot", "id": str(snapshot.id)}],
                    created_by=actor,
                    data={"confidence_score": snapshot.confidence_score},
                )
            )

    for run in list(engagement.runs or []):
        for context in list(run.context_documents or []):
            created.extend(
                _create_if_missing(
                    session,
                    existing_keys=existing_keys,
                    engagement=engagement,
                    tenant_id=normalized_tenant,
                    entry_type="target_context",
                    title=f"Target context: {context.layer_name}",
                    summary=context.context_summary,
                    source_refs=[{"type": "target_context_document", "id": str(context.id)}],
                    created_by=actor,
                    data={
                        "context_kind": context.context_kind,
                        "recommended_tools": list(context.recommended_tools_json or []),
                    },
                )
            )
        for finding in list(run.findings or []):
            if str(finding.status or "").lower() in {"accepted_risk", "risk_accepted"}:
                created.extend(
                    _create_if_missing(
                        session,
                        existing_keys=existing_keys,
                        engagement=engagement,
                        tenant_id=normalized_tenant,
                        entry_type="accepted_gap",
                        title=f"Accepted gap: {finding.title}",
                        summary=finding.summary or finding.false_positive_reason or finding.title,
                        source_refs=[{"type": "finding", "id": str(finding.id)}],
                        created_by=actor,
                        data={"severity": finding.severity, "target_id": finding.target_id},
                    )
                )
            if str(finding.status or "").lower() in {"resolved", "verified"}:
                created.extend(
                    _create_if_missing(
                        session,
                        existing_keys=existing_keys,
                        engagement=engagement,
                        tenant_id=normalized_tenant,
                        entry_type="resolved_finding",
                        title=f"Resolved finding: {finding.title}",
                        summary=finding.summary or finding.title,
                        source_refs=[{"type": "finding", "id": str(finding.id)}],
                        created_by=actor,
                        data={"severity": finding.severity, "target_id": finding.target_id},
                    )
                )
    return created


def list_casebook_entries(
    session: Session,
    *,
    engagement_id: UUID,
    tenant_id: str | None,
    entry_types: list[str] | None = None,
    limit: int = 25,
) -> list[EngagementCasebookEntry]:
    normalized_tenant = _tenant_key(tenant_id)
    statement = (
        select(EngagementCasebookEntry)
        .where(
            EngagementCasebookEntry.engagement_id == engagement_id,
            EngagementCasebookEntry.tenant_id == normalized_tenant,
            EngagementCasebookEntry.status == "recorded",
        )
        .order_by(
            EngagementCasebookEntry.updated_at.desc(),
            EngagementCasebookEntry.created_at.desc(),
            EngagementCasebookEntry.id.desc(),
        )
        .limit(max(1, min(int(limit or 25), 100)))
    )
    if entry_types:
        statement = statement.where(
            EngagementCasebookEntry.entry_type.in_([_normalize_entry_type(item) for item in entry_types])
        )
    return list(session.scalars(statement).all())


def casebook_context_for_run(
    session: Session,
    *,
    run: Run,
    limit: int = 10,
) -> dict[str, Any]:
    engagement = run.engagement
    if engagement is None:
        engagement = session.get(Engagement, run.engagement_id)
    if engagement is None:
        return _empty_context(str(run.engagement_id), None)
    entries = list_casebook_entries(
        session,
        engagement_id=engagement.id,
        tenant_id=engagement.tenant_id,
        limit=limit,
    )
    return {
        "casebook_version": CASEBOOK_VERSION,
        "engagement_id": str(engagement.id),
        "tenant_id": _tenant_key(engagement.tenant_id),
        "planning_input_only": True,
        "not_evidence": True,
        "scope_expansion_allowed": False,
        "secret_material_stored": False,
        "entries": [_entry_context(entry) for entry in entries],
    }


def _create_if_missing(
    session: Session,
    *,
    existing_keys: set[tuple[str, str]],
    engagement: Engagement,
    tenant_id: str,
    entry_type: str,
    title: str,
    summary: str,
    source_refs: list[dict[str, Any]],
    created_by: str,
    data: dict[str, Any] | None = None,
) -> list[EngagementCasebookEntry]:
    normalized_sources = _normalize_source_refs(source_refs)
    key = (entry_type, "|".join(f"{item['type']}:{item['id']}" for item in normalized_sources))
    if key in existing_keys:
        return []
    entry = create_casebook_entry(
        session,
        engagement=engagement,
        tenant_id=tenant_id,
        entry_type=entry_type,
        title=title,
        summary=summary,
        source_refs=normalized_sources,
        created_by=created_by,
        data=data,
    )
    existing_keys.add(key)
    return [entry]


def _entry_context(entry: EngagementCasebookEntry) -> dict[str, Any]:
    return {
        "id": str(entry.id),
        "entry_type": entry.entry_type,
        "title": entry.title,
        "summary": entry.summary,
        "source_refs": list(entry.source_refs_json or []),
        "data": dict(entry.data_json or {}),
        "planning_input_only": True,
        "not_evidence": True,
    }


def _empty_context(engagement_id: str, tenant_id: str | None) -> dict[str, Any]:
    return {
        "casebook_version": CASEBOOK_VERSION,
        "engagement_id": engagement_id,
        "tenant_id": _tenant_key(tenant_id),
        "planning_input_only": True,
        "not_evidence": True,
        "scope_expansion_allowed": False,
        "secret_material_stored": False,
        "entries": [],
    }


def _entry_dedupe_key(entry: EngagementCasebookEntry) -> tuple[str, str]:
    refs = _normalize_source_refs(entry.source_refs_json or [])
    return (entry.entry_type, "|".join(f"{item['type']}:{item['id']}" for item in refs))


def _inventory_summary(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    targets = _string_list(payload.get("targets"))[:5]
    stack = payload.get("tech_stack_profile") if isinstance(payload.get("tech_stack_profile"), dict) else {}
    technologies = []
    for value in stack.values():
        technologies.extend(_string_list(value))
    bits = []
    if targets:
        bits.append(f"Observed targets: {', '.join(targets)}")
    if technologies:
        bits.append(f"Observed technologies: {', '.join(sorted(set(technologies))[:8])}")
    return ". ".join(bits)


def _normalize_entry_type(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    if normalized not in CASEBOOK_ENTRY_TYPES:
        raise EngagementCasebookError(f"unsupported casebook entry_type: {value}")
    return normalized


def _normalize_source_refs(source_refs: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not source_refs:
        raise EngagementCasebookError("casebook entries require at least one source_ref")
    normalized: list[dict[str, str]] = []
    for ref in source_refs:
        if not isinstance(ref, dict):
            raise EngagementCasebookError("casebook source_ref must be an object")
        ref_type = str(ref.get("type") or "").strip()
        ref_id = str(ref.get("id") or "").strip()
        if not ref_type or not ref_id:
            raise EngagementCasebookError("casebook source_ref requires type and id")
        _reject_if_secret(ref_type, field_path="source_refs.type")
        _reject_if_secret(ref_id, field_path="source_refs.id")
        normalized.append({"type": ref_type, "id": ref_id})
    return normalized


def _assert_engagement_tenant(engagement: Engagement, tenant_id: str) -> None:
    expected = _tenant_key(engagement.tenant_id)
    if expected != tenant_id:
        raise EngagementCasebookError("casebook tenant does not match engagement tenant")


def _tenant_key(value: str | None) -> str:
    return str(value or DEFAULT_TENANT_ID).strip() or DEFAULT_TENANT_ID


def _sanitize_json(value: Any, *, field_path: str) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize_json(raw, field_path=f"{field_path}.{key}")
            for key, raw in value.items()
            if _key_allowed(str(key), field_path=f"{field_path}.{key}")
        }
    if isinstance(value, list):
        return [
            _sanitize_json(item, field_path=f"{field_path}[]")
            for item in value[:50]
        ]
    if isinstance(value, str):
        return _clean_text(value, field=field_path, limit=1000)
    if isinstance(value, int | float | bool) or value is None:
        return value
    return _clean_text(str(value), field=field_path, limit=1000)


def _key_allowed(key: str, *, field_path: str) -> bool:
    _reject_if_secret(key, field_path=field_path)
    return True


def _clean_text(value: Any, *, field: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise EngagementCasebookError(f"casebook {field} is required")
    _reject_if_secret(text, field_path=field)
    return text[:limit]


def _reject_if_secret(value: str, *, field_path: str) -> None:
    lowered = value.lower()
    if any(keyword in lowered for keyword in SECRET_KEYWORDS):
        raise CasebookSecretRejectedError(f"casebook {field_path} contains secret-like material")
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        raise CasebookSecretRejectedError(f"casebook {field_path} contains secret-like material")


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple | set):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    return [text] if text else []
