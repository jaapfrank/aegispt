from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import ThreatIntelRecord


def upsert_threat_intel_record(session: Session, payload: dict[str, Any]) -> ThreatIntelRecord:
    source = str(payload.get("source") or "").strip()
    advisory_id = str(payload.get("advisory_id") or "").strip()
    if not source or not advisory_id:
        raise ValueError("source and advisory_id are required")

    record = session.scalar(
        select(ThreatIntelRecord).where(
            ThreatIntelRecord.source == source,
            ThreatIntelRecord.advisory_id == advisory_id,
        )
    )
    if record is None:
        record = ThreatIntelRecord(source=source, advisory_id=advisory_id, title=str(payload.get("title") or "").strip())
        session.add(record)

    record.title = str(payload.get("title") or record.title).strip()
    record.summary = str(payload.get("summary") or "").strip() or None
    record.affected_products_json = list(payload.get("affected_products") or [])
    record.affected_versions_json = list(payload.get("affected_versions") or [])
    record.product_match_hints_json = list(payload.get("product_match_hints") or [])
    record.architecture_hints_json = list(payload.get("architecture_hints") or [])
    record.attack_surface_type = str(payload.get("attack_surface_type") or "").strip() or None
    record.suggested_test_patterns_json = list(payload.get("suggested_test_patterns") or [])
    record.confidence_score = float(payload.get("confidence") or 0.0)
    record.severity = str(payload.get("severity") or "").strip() or None
    record.references_json = list(payload.get("references") or [])
    record.published_at = payload.get("published_at")
    record.updated_at = payload.get("updated_at")
    record.normalization_status = str(payload.get("normalization_status") or "normalized")
    record.metadata_json = {
        "affected_product_count": len(record.affected_products_json),
        "pattern_count": len(record.suggested_test_patterns_json),
        "source": record.source,
    }
    session.flush()
    return record


def search_threat_intel_records(
    session: Session,
    *,
    query: str | None = None,
    product: str | None = None,
    attack_surface_type: str | None = None,
) -> list[ThreatIntelRecord]:
    records = session.scalars(select(ThreatIntelRecord).order_by(ThreatIntelRecord.created_at.desc())).all()

    normalized_query = (query or "").strip().lower()
    normalized_product = (product or "").strip().lower()
    normalized_surface = (attack_surface_type or "").strip().lower()

    filtered: list[ThreatIntelRecord] = []
    for record in records:
        haystack = " ".join(
            [
                record.source.lower(),
                record.advisory_id.lower(),
                record.title.lower(),
                (record.summary or "").lower(),
                " ".join(item.lower() for item in record.affected_products_json),
                " ".join(item.lower() for item in record.product_match_hints_json),
            ]
        )
        if normalized_query and normalized_query not in haystack:
            continue
        if normalized_product:
            product_haystack = {
                item.lower()
                for item in [
                    *record.affected_products_json,
                    *record.product_match_hints_json,
                ]
            }
            if normalized_product not in product_haystack:
                continue
        if normalized_surface and normalized_surface != (record.attack_surface_type or "").strip().lower():
            continue
        filtered.append(record)

    return filtered


def load_threat_intel_record(session: Session, record_id: UUID) -> ThreatIntelRecord | None:
    return session.scalar(select(ThreatIntelRecord).where(ThreatIntelRecord.id == record_id))

