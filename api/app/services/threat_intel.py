from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import ThreatIntelRecord

APPROVED_FEED_TYPES = {"cisa_kev", "mitre_attack", "cve_cvss"}
FEED_SOURCE_BY_TYPE = {
    "cisa_kev": "cisa-kev",
    "mitre_attack": "mitre-attack",
    "cve_cvss": "cve-cvss",
}

THREAT_INTEL_BOUNDARY = {
    "mode": "local-cache-only",
    "external_lookup_performed": False,
    "downloads_exploits": False,
    "claims_actor_attribution": False,
    "changes_finding_severity": False,
    "message": (
        "Threat-intel badges are matched only against locally stored approved-feed records. "
        "They do not call external feeds during finding analysis, download exploits, claim actor attribution, "
        "or change finding severity."
    ),
}


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
    record.advisory_updated_at = payload.get("updated_at")
    record.normalization_status = str(payload.get("normalization_status") or "normalized")
    metadata = dict(payload.get("metadata") or {})
    record.metadata_json = {
        **metadata,
        "affected_product_count": len(record.affected_products_json),
        "pattern_count": len(record.suggested_test_patterns_json),
        "source": record.source,
        "external_lookup_performed": False,
    }
    session.flush()
    return record


def import_threat_intel_feed(
    session: Session,
    *,
    feed_type: str,
    feed_name: str,
    feed_cached_at: datetime,
    stale_after_days: int,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized_feed_type = feed_type.strip().lower()
    if normalized_feed_type not in APPROVED_FEED_TYPES:
        raise ValueError(f"unsupported threat-intel feed type: {feed_type}")

    source = FEED_SOURCE_BY_TYPE[normalized_feed_type]
    imported: list[ThreatIntelRecord] = []
    updated_count = 0
    for raw_record in records:
        payload = _normalize_feed_record(
            feed_type=normalized_feed_type,
            source=source,
            feed_name=feed_name,
            feed_cached_at=feed_cached_at,
            stale_after_days=stale_after_days,
            raw_record=raw_record,
        )
        if payload is None:
            continue
        existing = session.scalar(
            select(ThreatIntelRecord).where(
                ThreatIntelRecord.source == payload["source"],
                ThreatIntelRecord.advisory_id == payload["advisory_id"],
            )
        )
        if existing is not None:
            updated_count += 1
        imported.append(upsert_threat_intel_record(session, payload))

    session.flush()
    return {
        "imported_count": len(imported),
        "updated_count": updated_count,
        "feed_type": normalized_feed_type,
        "feed_name": feed_name,
        "feed_cached_at": feed_cached_at,
        "stale_after_days": stale_after_days,
        "external_lookup_performed": False,
        "records": imported,
    }


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


def build_finding_threat_intel_badges(session: Session, finding: Any) -> dict[str, Any]:
    records = session.scalars(select(ThreatIntelRecord).order_by(ThreatIntelRecord.source, ThreatIntelRecord.advisory_id)).all()
    badges = []
    for record in records:
        matched_terms = _matched_terms_for_finding(record=record, finding=finding)
        if not matched_terms:
            continue
        badges.append(_badge_for_record(record=record, matched_terms=matched_terms))

    badges.sort(key=lambda item: (item["badge_rank"], item["source"], item["advisory_id"]))
    for badge in badges:
        badge.pop("badge_rank", None)

    if not badges:
        return {
            "available": False,
            "badges": [],
            "no_badge_reason": "No locally cached approved-feed threat-intel record matched this finding.",
            "stale_record_count": 0,
            "boundary": dict(THREAT_INTEL_BOUNDARY),
        }

    return {
        "available": True,
        "badges": badges,
        "no_badge_reason": None,
        "stale_record_count": sum(1 for badge in badges if badge["cache_status"] == "stale"),
        "boundary": dict(THREAT_INTEL_BOUNDARY),
    }


def _normalize_feed_record(
    *,
    feed_type: str,
    source: str,
    feed_name: str,
    feed_cached_at: datetime,
    stale_after_days: int,
    raw_record: dict[str, Any],
) -> dict[str, Any] | None:
    if feed_type == "cisa_kev":
        return _normalize_cisa_kev_record(
            source=source,
            feed_name=feed_name,
            feed_cached_at=feed_cached_at,
            stale_after_days=stale_after_days,
            raw_record=raw_record,
        )
    if feed_type == "mitre_attack":
        return _normalize_mitre_attack_record(
            source=source,
            feed_name=feed_name,
            feed_cached_at=feed_cached_at,
            stale_after_days=stale_after_days,
            raw_record=raw_record,
        )
    if feed_type == "cve_cvss":
        return _normalize_cve_cvss_record(
            source=source,
            feed_name=feed_name,
            feed_cached_at=feed_cached_at,
            stale_after_days=stale_after_days,
            raw_record=raw_record,
        )
    return None


def _normalize_cisa_kev_record(
    *,
    source: str,
    feed_name: str,
    feed_cached_at: datetime,
    stale_after_days: int,
    raw_record: dict[str, Any],
) -> dict[str, Any] | None:
    advisory_id = _first_text(raw_record, "cveID", "cve_id", "id", "advisory_id")
    if not advisory_id:
        return None
    vendor = _first_text(raw_record, "vendorProject", "vendor")
    product = _first_text(raw_record, "product")
    title = _first_text(raw_record, "vulnerabilityName", "title", "name") or advisory_id
    references = list(raw_record.get("references") or [])
    if not references:
        references = ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
    metadata = _base_feed_metadata(
        feed_type="cisa_kev",
        feed_name=feed_name,
        feed_cached_at=feed_cached_at,
        stale_after_days=stale_after_days,
        badge_types=["kev"],
    )
    metadata.update(
        {
            "kev": True,
            "known_ransomware_campaign_use": _first_text(raw_record, "knownRansomwareCampaignUse"),
            "required_action": _first_text(raw_record, "requiredAction"),
            "due_date": _iso_or_none(raw_record.get("dueDate")),
        }
    )
    products = [item for item in [vendor, product, f"{vendor} {product}".strip()] if item]
    return {
        "source": source,
        "advisory_id": advisory_id,
        "title": title,
        "summary": _first_text(raw_record, "summary", "notes", "description"),
        "affected_products": products,
        "product_match_hints": [advisory_id, *products],
        "suggested_test_patterns": ["local-cache-kev-review"],
        "confidence": 0.9,
        "severity": "known_exploited",
        "references": references,
        "published_at": raw_record.get("dateAdded") or raw_record.get("published_at"),
        "updated_at": raw_record.get("updated_at") or feed_cached_at,
        "normalization_status": "normalized",
        "metadata": metadata,
    }


def _normalize_mitre_attack_record(
    *,
    source: str,
    feed_name: str,
    feed_cached_at: datetime,
    stale_after_days: int,
    raw_record: dict[str, Any],
) -> dict[str, Any] | None:
    technique_id = _first_text(raw_record, "technique_id", "id", "advisory_id")
    if not technique_id:
        return None
    title = _first_text(raw_record, "name", "title") or technique_id
    tactics = list(raw_record.get("tactics") or [])
    tactic = _first_text(raw_record, "tactic")
    if tactic:
        tactics.append(tactic)
    platforms = list(raw_record.get("platforms") or [])
    metadata = _base_feed_metadata(
        feed_type="mitre_attack",
        feed_name=feed_name,
        feed_cached_at=feed_cached_at,
        stale_after_days=stale_after_days,
        badge_types=["attack"],
    )
    metadata.update(
        {
            "attack_technique_id": technique_id,
            "tactics": list(dict.fromkeys(tactics)),
            "platforms": platforms,
            "claims_actor_attribution": False,
        }
    )
    return {
        "source": source,
        "advisory_id": technique_id,
        "title": title,
        "summary": _first_text(raw_record, "description", "summary", "notes"),
        "affected_products": platforms,
        "product_match_hints": [technique_id, title, *tactics, *platforms],
        "attack_surface_type": "technique",
        "suggested_test_patterns": [f"attack:{technique_id}"],
        "confidence": 0.75,
        "severity": "context",
        "references": list(raw_record.get("references") or ["https://attack.mitre.org/"]),
        "published_at": raw_record.get("published_at"),
        "updated_at": raw_record.get("updated_at") or feed_cached_at,
        "normalization_status": "normalized",
        "metadata": metadata,
    }


def _normalize_cve_cvss_record(
    *,
    source: str,
    feed_name: str,
    feed_cached_at: datetime,
    stale_after_days: int,
    raw_record: dict[str, Any],
) -> dict[str, Any] | None:
    cve_id = _first_text(raw_record, "cve_id", "cveID", "id", "advisory_id")
    if not cve_id:
        return None
    cvss_score = raw_record.get("cvss_score")
    cvss_severity = _first_text(raw_record, "cvss_severity", "severity")
    cwe_ids = list(raw_record.get("cwe_ids") or [])
    affected_products = list(raw_record.get("affected_products") or [])
    metadata = _base_feed_metadata(
        feed_type="cve_cvss",
        feed_name=feed_name,
        feed_cached_at=feed_cached_at,
        stale_after_days=stale_after_days,
        badge_types=["cvss"],
    )
    metadata.update(
        {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cwe_ids": cwe_ids,
        }
    )
    return {
        "source": source,
        "advisory_id": cve_id,
        "title": _first_text(raw_record, "title", "name") or cve_id,
        "summary": _first_text(raw_record, "description", "summary", "notes"),
        "affected_products": affected_products,
        "product_match_hints": [cve_id, *affected_products, *cwe_ids],
        "suggested_test_patterns": [f"cve:{cve_id}", *cwe_ids],
        "confidence": 0.8,
        "severity": cvss_severity,
        "references": list(raw_record.get("references") or []),
        "published_at": raw_record.get("published_at"),
        "updated_at": raw_record.get("updated_at") or feed_cached_at,
        "normalization_status": "normalized",
        "metadata": metadata,
    }


def _base_feed_metadata(
    *,
    feed_type: str,
    feed_name: str,
    feed_cached_at: datetime,
    stale_after_days: int,
    badge_types: list[str],
) -> dict[str, Any]:
    return {
        "feed_type": feed_type,
        "feed_name": feed_name,
        "feed_cached_at": _iso_or_none(feed_cached_at),
        "stale_after_days": stale_after_days,
        "badge_types": badge_types,
        "approved_feed": True,
        "external_lookup_performed": False,
        "downloads_exploits": False,
        "claims_actor_attribution": False,
    }


def _matched_terms_for_finding(*, record: ThreatIntelRecord, finding: Any) -> list[str]:
    haystack = _finding_haystack(finding)
    candidate_terms = [
        record.advisory_id,
        record.title,
        *(record.product_match_hints_json or []),
        *(record.affected_products_json or []),
        *(record.suggested_test_patterns_json or []),
    ]
    metadata = dict(record.metadata_json or {})
    candidate_terms.extend(
        str(item)
        for item in [
            metadata.get("cve_id"),
            metadata.get("attack_technique_id"),
            metadata.get("cvss_severity"),
            *(metadata.get("cwe_ids") or []),
            *(metadata.get("tactics") or []),
        ]
        if item
    )
    matches: list[str] = []
    for term in candidate_terms:
        normalized = str(term or "").strip().lower()
        if len(normalized) < 4:
            continue
        if normalized in haystack:
            matches.append(str(term))
    return list(dict.fromkeys(matches))


def _finding_haystack(finding: Any) -> str:
    values = [
        getattr(finding, "title", None),
        getattr(finding, "summary", None),
        getattr(finding, "target_id", None),
        getattr(finding, "evidence_ref", None),
        getattr(finding, "control_family", None),
        getattr(finding, "wstg_id", None),
        getattr(finding, "asvs_reference", None),
        " ".join(getattr(finding, "methodology_tags", None) or []),
    ]
    return " ".join(str(value or "") for value in values).lower()


def _badge_for_record(*, record: ThreatIntelRecord, matched_terms: list[str]) -> dict[str, Any]:
    metadata = dict(record.metadata_json or {})
    badge_types = list(metadata.get("badge_types") or [_badge_type_for_source(record.source)])
    primary_type = str(badge_types[0] if badge_types else "source").lower()
    cache_status, cache_detail = _cache_status(metadata)
    return {
        "record_id": str(record.id),
        "type": primary_type,
        "label": _badge_label(record=record, metadata=metadata, badge_type=primary_type),
        "source": record.source,
        "advisory_id": record.advisory_id,
        "title": record.title,
        "severity": record.severity,
        "confidence_score": record.confidence_score,
        "cache_status": cache_status,
        "cache_detail": cache_detail,
        "references": list(record.references_json or []),
        "matched_terms": matched_terms,
        "external_lookup_performed": False,
        "downloads_exploits": False,
        "claims_actor_attribution": False,
        "changes_finding_severity": False,
        "generated_template": _generated_template_badge(metadata),
        "metadata": {
            key: value
            for key, value in metadata.items()
            if key
            in {
                "feed_type",
                "feed_name",
                "feed_cached_at",
                "stale_after_days",
                "kev",
                "cvss_score",
                "cvss_severity",
                "attack_technique_id",
                "tactics",
                "cwe_ids",
                "known_ransomware_campaign_use",
            }
        },
        "badge_rank": {"kev": 0, "cvss": 1, "attack": 2, "source": 3}.get(primary_type, 4),
    }


def _generated_template_badge(metadata: dict[str, Any]) -> dict[str, Any] | None:
    template = metadata.get("generated_nuclei_template")
    if not isinstance(template, dict) or not template.get("pack_id"):
        return None
    status = str(template.get("status") or "pending_review")
    return {
        "status": status,
        "pack_id": template.get("pack_id"),
        "artifact_id": template.get("artifact_id"),
        "deployment_id": template.get("deployment_id"),
        "review_url": template.get("review_url"),
        "tested_via_generated_template": bool(template.get("tested_via_generated_template")) or status == "deployed",
        "operator_review_required": bool(template.get("operator_review_required", True)),
        "auto_deploy": bool(template.get("auto_deploy", False)),
    }


def _badge_label(*, record: ThreatIntelRecord, metadata: dict[str, Any], badge_type: str) -> str:
    if badge_type == "kev":
        return f"KEV {record.advisory_id}"
    if badge_type == "cvss":
        score = metadata.get("cvss_score")
        severity = metadata.get("cvss_severity") or record.severity
        if score is not None:
            return f"CVSS {score} {severity or ''}".strip()
        return f"CVSS {severity or record.advisory_id}"
    if badge_type == "attack":
        return f"ATT&CK {metadata.get('attack_technique_id') or record.advisory_id}"
    return f"{record.source} {record.advisory_id}"


def _badge_type_for_source(source: str) -> str:
    if source == "cisa-kev":
        return "kev"
    if source == "cve-cvss":
        return "cvss"
    if source == "mitre-attack":
        return "attack"
    return "source"


def _cache_status(metadata: dict[str, Any]) -> tuple[str, str]:
    cached_at = _parse_datetime(metadata.get("feed_cached_at"))
    stale_after_days = int(metadata.get("stale_after_days") or 30)
    if cached_at is None:
        return "unknown", "No feed cache timestamp was recorded."
    age_seconds = (datetime.now(UTC) - cached_at).total_seconds()
    age_days = max(0, int(age_seconds // 86400))
    if age_days > stale_after_days:
        return "stale", f"Cached {age_days} days ago; stale threshold is {stale_after_days} days."
    return "fresh", f"Cached {age_days} days ago; stale threshold is {stale_after_days} days."


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_or_none(value: Any) -> str | None:
    parsed = _parse_datetime(value)
    return parsed.isoformat() if parsed is not None else None


def _first_text(raw_record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = raw_record.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None
