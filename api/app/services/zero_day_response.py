from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Engagement, InventorySnapshot, Run, RunProfile, ThreatIntelRecord
from api.app.services.audit import write_audit_event
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    latest_scope_query,
    queue_run_tasks,
    required_approvals,
    validate_configured_targets_within_scope,
)

ZERO_DAY_SCAN_PROFILE = "active-web-rce-nuclei-audit"
ZERO_DAY_BOUNDARY = {
    "mode": "stored-inventory-correlation",
    "external_lookup_performed": False,
    "automatic_tests_started": False,
    "automatic_approval_created": False,
    "exploitation_enabled": False,
    "credential_materialization": False,
    "scope_enforced": True,
    "operator_approval_required_for_runtime": True,
}


def build_zero_day_rapid_response(
    session: Session,
    *,
    engagements: list[Engagement],
    limit: int = 12,
) -> dict[str, Any]:
    generated_at = datetime.now(UTC)
    engagement_ids = [engagement.id for engagement in engagements]
    if not engagement_ids:
        return _empty_response(generated_at)

    snapshots = list(
        session.scalars(
            select(InventorySnapshot)
            .where(InventorySnapshot.engagement_id.in_(engagement_ids))
            .order_by(InventorySnapshot.created_at.desc(), InventorySnapshot.id.desc())
        ).all()
    )
    records = [
        record
        for record in session.scalars(
            select(ThreatIntelRecord).order_by(
                ThreatIntelRecord.updated_at.desc(),
                ThreatIntelRecord.created_at.desc(),
                ThreatIntelRecord.id.desc(),
            )
        ).all()
        if _record_is_rapid_response_candidate(record)
    ]
    engagement_names = {engagement.id: engagement.name for engagement in engagements}
    alerts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for snapshot in snapshots:
        inventory = (
            snapshot.normalized_inventory_json
            if isinstance(snapshot.normalized_inventory_json, dict)
            else {}
        )
        for product in _products_from_inventory(inventory):
            for record in records:
                matched_terms = _record_product_match_terms(record, product)
                if not matched_terms:
                    continue
                version_status, version_detail = _version_status(
                    product.get("version"),
                    record.affected_versions_json or [],
                )
                if version_status == "not_affected":
                    continue
                target = _product_target(product, inventory)
                if not target:
                    continue
                key = (str(record.id), str(snapshot.id), target.lower())
                if key in seen:
                    continue
                seen.add(key)
                alerts.append(
                    _alert_payload(
                        record=record,
                        snapshot=snapshot,
                        engagement_name=engagement_names.get(snapshot.engagement_id, "Engagement"),
                        product=product,
                        target=target,
                        matched_terms=matched_terms,
                        version_status=version_status,
                        version_detail=version_detail,
                    )
                )
    alerts.sort(key=_alert_sort_key)
    limited = alerts[: max(1, limit)]
    return {
        "generated_at": generated_at.isoformat(),
        "status": "alerts" if limited else "clear",
        "alert_count": len(alerts),
        "exposed_asset_count": len({str(alert.get("target") or "") for alert in alerts}),
        "alerts": limited,
        "boundary": dict(ZERO_DAY_BOUNDARY),
    }


def launch_zero_day_rapid_response_scan(
    session: Session,
    *,
    engagement: Engagement,
    record_id: UUID,
    actor: str,
    target: str | None = None,
) -> dict[str, Any]:
    ensure_default_run_profiles(session)
    response = build_zero_day_rapid_response(session, engagements=[engagement], limit=100)
    selected = _select_alert(response.get("alerts", []), record_id=record_id, target=target)
    if selected is None:
        raise ValueError("No affected in-scope inventory asset matched this zero-day record")

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise ValueError("engagement scope required before requesting rapid response scans")
    profile = session.scalar(select(RunProfile).where(RunProfile.name == ZERO_DAY_SCAN_PROFILE))
    if profile is None:
        raise ValueError(f"run profile not found: {ZERO_DAY_SCAN_PROFILE}")

    target_value = str(selected["target"]).strip()
    targets = _target_map_for_value(target_value)
    configuration = {
        "assessment_type": "Zero-Day Rapid Response",
        "targets": targets,
        "nuclei": {
            "rce_template_selection": True,
            "requested_template_ids": [str(selected["advisory_id"]).lower()],
            "oob_enabled": False,
        },
        "runtime_launch": {"dispatch_after_approval": True},
        "zero_day_rapid_response": {
            "record_id": str(selected["record_id"]),
            "advisory_id": selected["advisory_id"],
            "title": selected["title"],
            "source_inventory_snapshot_id": selected["source_inventory_snapshot_id"],
            "matched_product": selected["matched_product"],
            "target": target_value,
            "operator_approval_required": True,
            "automatic_approval_created": False,
            "automatic_tests_started": False,
            "scope_enforced": True,
            "exploitation_enabled": False,
        },
    }
    validate_configured_targets_within_scope(scope, configuration)

    timestamp = datetime.now(UTC)
    run = Run(
        engagement_id=engagement.id,
        profile_id=profile.id,
        profile=profile,
        source_inventory_snapshot_id=UUID(str(selected["source_inventory_snapshot_id"])),
        requested_by=actor,
        status="requested",
        configuration_json=configuration,
        autonomous_mode=False,
        autonomous_intrusive_allowed=False,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(run)
    session.flush()
    approval_count = required_approvals(profile)
    if approval_count > 0:
        run.status = "pending_approval"
    else:
        queue_run_tasks(session, run, scope, profile)

    write_audit_event(
        session=session,
        actor=actor,
        action="zero_day_rapid_response.scan_requested",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": profile.name,
            "record_id": str(selected["record_id"]),
            "advisory_id": selected["advisory_id"],
            "target": target_value,
            "required_approvals": approval_count,
            "automatic_approval_created": False,
            "automatic_tests_started": False,
            "scope_enforced": True,
        },
    )
    session.flush()
    return {
        "accepted": True,
        "run_id": str(run.id),
        "run_status": run.status,
        "profile_name": profile.name,
        "required_approvals": approval_count,
        "granted_approvals": 0,
        "target": target_value,
        "record_id": selected["record_id"],
        "advisory_id": selected["advisory_id"],
        "operator_approval_required": approval_count > 0,
        "automatic_approval_created": False,
        "automatic_tests_started": False,
        "scope_enforced": True,
        "detail": (
            "Zero-day rapid response scan was staged through the normal run profile and "
            "approval gate. No runtime task starts until the configured approval is granted."
        ),
    }


def _empty_response(generated_at: datetime) -> dict[str, Any]:
    return {
        "generated_at": generated_at.isoformat(),
        "status": "clear",
        "alert_count": 0,
        "exposed_asset_count": 0,
        "alerts": [],
        "boundary": dict(ZERO_DAY_BOUNDARY),
    }


def _record_is_rapid_response_candidate(record: ThreatIntelRecord) -> bool:
    metadata = record.metadata_json if isinstance(record.metadata_json, dict) else {}
    if bool(metadata.get("kev")) or str(record.source or "").lower() in {"cisa-kev", "cisa_kev"}:
        return True
    score = metadata.get("cvss_score")
    if isinstance(score, (int, float)) and float(score) >= 7.0:
        return True
    severity = str(record.severity or metadata.get("cvss_severity") or "").strip().lower()
    return severity in {"critical", "high", "known_exploited"}


def _products_from_inventory(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    for source_key in ("vendor_product_fingerprints", "technologies", "services"):
        for entry in inventory.get(source_key, []) if isinstance(inventory.get(source_key), list) else []:
            if not isinstance(entry, dict):
                continue
            product = _clean(entry.get("product") or entry.get("name") or entry.get("service"))
            if not product:
                continue
            products.append(
                {
                    "vendor": _clean(entry.get("vendor")),
                    "product": product,
                    "version": _clean(entry.get("version")),
                    "source": _clean(entry.get("source")) or source_key,
                    "host": _clean(entry.get("host")),
                    "port": entry.get("port") if isinstance(entry.get("port"), int) else None,
                    "confidence": _bounded_float(entry.get("confidence"), default=0.6),
                    "evidence_source": source_key,
                }
            )
    profile = inventory.get("tech_stack_profile")
    if isinstance(profile, dict):
        products.extend(_products_from_tech_stack_profile(profile))
    unique: dict[tuple[str, str | None, str | None], dict[str, Any]] = {}
    for product in products:
        key = (
            _norm(product.get("product")),
            _norm(product.get("version")) or None,
            _norm(product.get("host")) or None,
        )
        if key[0] in {"", "http", "https", "unknown", "unknown-service"}:
            continue
        existing = unique.get(key)
        if existing is None or product.get("evidence_source") == "tech_stack_profile":
            unique[key] = product
    return list(unique.values())


def _products_from_tech_stack_profile(profile: dict[str, Any]) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    for key, values in profile.items():
        if key not in {"server", "language", "cms", "java_indicators"}:
            continue
        if not isinstance(values, list):
            values = [values]
        for raw in values:
            parsed = _parse_product_value(raw)
            if parsed is None:
                continue
            products.append(
                {
                    **parsed,
                    "source": f"tech_stack_profile.{key}",
                    "confidence": 0.82,
                    "evidence_source": "tech_stack_profile",
                }
            )
    return products


def _parse_product_value(value: Any) -> dict[str, Any] | None:
    text = str(value or "").strip()
    if not text or text.lower() in {"true", "false"}:
        return None
    match = re.search(r"([A-Za-z][A-Za-z0-9_.+-]*)(?:/|\s)(\d+(?:[._-]\d+){0,4})", text)
    if match:
        return {"vendor": None, "product": match.group(1), "version": match.group(2).replace("_", ".")}
    cleaned = re.sub(r"[^A-Za-z0-9 ._+-]", " ", text).strip()
    if not cleaned:
        return None
    return {"vendor": None, "product": cleaned.split()[0], "version": None}


def _record_product_match_terms(record: ThreatIntelRecord, product: dict[str, Any]) -> list[str]:
    metadata = record.metadata_json if isinstance(record.metadata_json, dict) else {}
    values = [
        record.advisory_id,
        record.title,
        record.summary,
        *(record.affected_products_json or []),
        *(record.product_match_hints_json or []),
        *(str(item) for item in metadata.get("affected_products", []) if isinstance(metadata.get("affected_products"), list)),
        *(str(item) for item in metadata.get("products", []) if isinstance(metadata.get("products"), list)),
    ]
    haystack = _norm(" ".join(str(value or "") for value in values))
    candidates = [
        product.get("product"),
        " ".join(str(item or "").strip() for item in (product.get("vendor"), product.get("product")) if str(item or "").strip()),
    ]
    matches = []
    for candidate in candidates:
        normalized = _norm(candidate)
        if len(normalized) < 3:
            continue
        if normalized in haystack:
            matches.append(str(candidate))
    return list(dict.fromkeys(matches))


def _version_status(version: str | None, affected_ranges: list[str]) -> tuple[str, str]:
    ranges = [str(item).strip() for item in affected_ranges if str(item or "").strip()]
    if not ranges:
        return "affected", "No affected-version range was supplied by the advisory record."
    if not version:
        return "unknown", "Advisory has affected-version ranges, but inventory did not capture a product version."
    parsed = _version_tuple(version)
    if parsed is None:
        return "unknown", f"Inventory version `{version}` could not be compared safely."
    for item in ranges:
        if _version_range_matches(parsed, item):
            return "affected", f"Inventory version `{version}` matches advisory range `{item}`."
    return "not_affected", f"Inventory version `{version}` did not match advisory ranges."


def _version_range_matches(version: tuple[int, ...], expression: str) -> bool:
    text = expression.strip().lower()
    if text in {"*", "all", "any", "affected"}:
        return True
    between = re.match(r"^(.+?)\s*(?:-|to|through)\s*(.+)$", text)
    if between:
        lower = _version_tuple(between.group(1))
        upper = _version_tuple(between.group(2))
        return (lower is None or _compare_versions(version, lower) >= 0) and (
            upper is None or _compare_versions(version, upper) <= 0
        )
    before = re.match(r"^(?:before|prior to|<)\s*v?([0-9][0-9a-zA-Z._-]*)$", text)
    if before:
        target = _version_tuple(before.group(1))
        return target is not None and _compare_versions(version, target) < 0
    op_match = re.match(r"^(<=|>=|<|>|=|==)\s*v?([0-9][0-9a-zA-Z._*-]*)$", text)
    if op_match:
        op = op_match.group(1)
        raw_target = op_match.group(2)
        if "*" in raw_target:
            return _wildcard_version_matches(version, raw_target)
        target = _version_tuple(raw_target)
        if target is None:
            return False
        comparison = _compare_versions(version, target)
        return {
            "<": comparison < 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
            "=": comparison == 0,
            "==": comparison == 0,
        }[op]
    if "*" in text:
        return _wildcard_version_matches(version, text)
    exact = _version_tuple(text)
    return exact is not None and _compare_versions(version, exact) == 0


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+(?:[._-]\d+){0,6})", str(value or ""))
    if not match:
        return None
    return tuple(int(part) for part in re.split(r"[._-]", match.group(1)) if part.isdigit())


def _wildcard_version_matches(version: tuple[int, ...], expression: str) -> bool:
    prefix = tuple(
        int(part)
        for part in re.split(r"[._-]", expression.replace("*", ""))
        if part.strip().isdigit()
    )
    return bool(prefix) and version[: len(prefix)] == prefix


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _product_target(product: dict[str, Any], inventory: dict[str, Any]) -> str | None:
    host = _clean(product.get("host"))
    if host:
        return host
    for endpoint in inventory.get("http_endpoints", []) if isinstance(inventory.get("http_endpoints"), list) else []:
        if isinstance(endpoint, dict) and _clean(endpoint.get("url")):
            return _clean(endpoint.get("url"))
    for host_entry in inventory.get("hosts", []) if isinstance(inventory.get("hosts"), list) else []:
        if isinstance(host_entry, dict) and _clean(host_entry.get("host")):
            return _clean(host_entry.get("host"))
    return None


def _target_map_for_value(value: str) -> dict[str, list[str]]:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return {"urls": [value]}
    return {"hosts": [value]}


def _alert_payload(
    *,
    record: ThreatIntelRecord,
    snapshot: InventorySnapshot,
    engagement_name: str,
    product: dict[str, Any],
    target: str,
    matched_terms: list[str],
    version_status: str,
    version_detail: str,
) -> dict[str, Any]:
    metadata = record.metadata_json if isinstance(record.metadata_json, dict) else {}
    cvss_score = metadata.get("cvss_score")
    severity = str(record.severity or metadata.get("cvss_severity") or "high").lower()
    confidence = min(
        1.0,
        round(
            (_bounded_float(product.get("confidence"), default=0.6) * 0.45)
            + (max(float(record.confidence_score or 0.0), 0.65) * 0.35)
            + (0.2 if version_status == "affected" else 0.08),
            3,
        ),
    )
    return {
        "id": f"{record.id}:{snapshot.id}:{abs(hash(target))}",
        "record_id": str(record.id),
        "advisory_id": record.advisory_id,
        "title": record.title,
        "severity": "known_exploited" if bool(metadata.get("kev")) else severity,
        "cvss_score": cvss_score if isinstance(cvss_score, (int, float)) else None,
        "kev": bool(metadata.get("kev")) or str(record.source).lower() in {"cisa-kev", "cisa_kev"},
        "engagement_id": str(snapshot.engagement_id),
        "engagement_name": engagement_name,
        "source_inventory_snapshot_id": str(snapshot.id),
        "target": target,
        "matched_product": {
            "vendor": product.get("vendor"),
            "product": product.get("product"),
            "version": product.get("version"),
            "source": product.get("source"),
            "evidence_source": product.get("evidence_source"),
            "confidence": _bounded_float(product.get("confidence"), default=0.6),
        },
        "matched_terms": matched_terms,
        "affected_versions": list(record.affected_versions_json or []),
        "version_status": version_status,
        "version_detail": version_detail,
        "confidence": confidence,
        "scan_now": {
            "available": True,
            "profile_name": ZERO_DAY_SCAN_PROFILE,
            "requires_operator_approval": True,
            "automatic_tests_started": False,
        },
        "references": list(record.references_json or []),
        "boundary": dict(ZERO_DAY_BOUNDARY),
    }


def _alert_sort_key(alert: dict[str, Any]) -> tuple[int, float, float, str]:
    severity = str(alert.get("severity") or "").lower()
    severity_rank = {"known_exploited": 0, "critical": 1, "high": 2}.get(severity, 3)
    return (
        severity_rank,
        -float(alert.get("cvss_score") or 0.0),
        -float(alert.get("confidence") or 0.0),
        str(alert.get("advisory_id") or ""),
    )


def _select_alert(alerts: list[Any], *, record_id: UUID, target: str | None) -> dict[str, Any] | None:
    normalized_target = str(target or "").strip().lower()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        if str(alert.get("record_id") or "") != str(record_id):
            continue
        if normalized_target and str(alert.get("target") or "").strip().lower() != normalized_target:
            continue
        return alert
    return None


def _bounded_float(value: Any, *, default: float) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    return default


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())
