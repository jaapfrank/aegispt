from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

BUSINESS_IMPACT_MODEL_VERSION = "predefined-business-impact-v1"

BUSINESS_CATEGORIES: dict[str, dict[str, Any]] = {
    "revenue": {"label": "Revenue operations", "weight": 1.0},
    "customer_data": {"label": "Customer data", "weight": 0.92},
    "identity_access": {"label": "Identity and access", "weight": 0.88},
    "operations": {"label": "Core operations", "weight": 0.78},
    "compliance": {"label": "Compliance records", "weight": 0.72},
    "public_presence": {"label": "Public presence", "weight": 0.46},
    "general": {"label": "General business service", "weight": 0.35},
}

CRITICALITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.78,
    "medium": 0.52,
    "low": 0.28,
    "unknown": 0.18,
}

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.78,
    "medium": 0.52,
    "low": 0.28,
    "info": 0.12,
    "unknown": 0.08,
}


def normalize_business_tags(normalized_inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tags: dict[str, dict[str, Any]] = {}

    for process in _dict_list(normalized_inventory.get("business_processes")):
        tag = _business_tag_from_payload(process)
        refs = _string_list(process.get("asset_refs") or process.get("assets") or process.get("targets"))
        for ref in refs:
            for key in _asset_ref_keys(ref):
                tags[key] = tag

    for collection_name in (
        "hosts",
        "services",
        "http_endpoints",
        "cloud_resources",
        "identity_subjects",
        "identity_groups",
        "saas_apps",
        "datasets",
    ):
        for payload in _dict_list(normalized_inventory.get(collection_name)):
            tag = _business_tag_from_payload(payload)
            for key in _payload_asset_keys(collection_name, payload):
                tags.setdefault(key, tag)

    return tags


def business_impact_for_path(
    path: dict[str, Any],
    *,
    nodes_by_id: dict[str, dict[str, Any]],
    normalized_inventory: dict[str, Any],
) -> dict[str, Any]:
    tags = normalize_business_tags(normalized_inventory)
    matched_tags: list[dict[str, Any]] = []
    matched_asset_refs: list[str] = []

    for node_id in [str(value) for value in path.get("node_ids", []) if str(value)]:
        node = nodes_by_id.get(node_id)
        if not node:
            continue
        for key in _node_asset_keys(node):
            tag = tags.get(key)
            if tag is not None:
                matched_tags.append(tag)
                matched_asset_refs.append(key)

    if not matched_tags:
        matched_tags.append(_default_tag_for_path(path))

    deduped_processes = _dedupe_tags(matched_tags)
    highest = max(deduped_processes, key=lambda tag: tag["score"])
    severity_weight = SEVERITY_WEIGHTS.get(_normalized_label(path.get("severity")), SEVERITY_WEIGHTS["unknown"])
    confidence = _bounded_float(path.get("confidence"), default=0.5)
    score = round(min(100.0, ((highest["score"] * 72.0) + (severity_weight * 22.0) + (confidence * 6.0))), 1)
    tier = _score_tier(score)

    return {
        "model": BUSINESS_IMPACT_MODEL_VERSION,
        "score": score,
        "tier": tier,
        "business_processes": deduped_processes,
        "primary_process": highest,
        "matched_asset_refs": sorted(set(matched_asset_refs)),
        "evidence_refs": _string_list(path.get("evidence_refs")),
        "financial_exposure": _financial_label(highest, tier),
        "operational_impact": _operational_label(highest, tier),
        "confidence": round(confidence, 3),
        "review_only": True,
        "runtime_actions_performed": False,
        "formula_editor_used": False,
    }


def annotate_paths_with_business_impact(
    candidate_paths: list[dict[str, Any]],
    *,
    nodes_by_id: dict[str, dict[str, Any]],
    normalized_inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    for path in candidate_paths:
        path["business_impact"] = business_impact_for_path(
            path,
            nodes_by_id=nodes_by_id,
            normalized_inventory=normalized_inventory,
        )
    return candidate_paths


def summarize_blast_radius(candidate_paths: list[dict[str, Any]]) -> dict[str, Any]:
    impacts = [
        impact
        for impact in (path.get("business_impact") for path in candidate_paths)
        if isinstance(impact, dict)
    ]
    if not impacts:
        return {
            "model": BUSINESS_IMPACT_MODEL_VERSION,
            "score": 0.0,
            "tier": "none",
            "critical_path_count": 0,
            "affected_business_processes": [],
            "highest_impact_path_id": None,
            "review_only": True,
        }

    highest = max(impacts, key=lambda impact: float(impact.get("score") or 0.0))
    process_map: dict[str, dict[str, Any]] = {}
    critical_path_count = 0
    for path in candidate_paths:
        impact = path.get("business_impact") if isinstance(path.get("business_impact"), dict) else {}
        if str(impact.get("tier") or "") in {"critical", "high"}:
            critical_path_count += 1
        for process in impact.get("business_processes", []) if isinstance(impact.get("business_processes"), list) else []:
            if isinstance(process, dict):
                key = str(process.get("id") or process.get("label") or "").strip()
                if key:
                    process_map.setdefault(key, process)

    score = round(max(float(impact.get("score") or 0.0) for impact in impacts), 1)
    highest_path = next(
        (
            path
            for path in candidate_paths
            if isinstance(path.get("business_impact"), dict)
            and float(path["business_impact"].get("score") or 0.0) == float(highest.get("score") or 0.0)
        ),
        None,
    )
    return {
        "model": BUSINESS_IMPACT_MODEL_VERSION,
        "score": score,
        "tier": _score_tier(score),
        "critical_path_count": critical_path_count,
        "affected_business_processes": sorted(
            process_map.values(),
            key=lambda item: (float(item.get("score") or 0.0), str(item.get("label") or "")),
            reverse=True,
        ),
        "highest_impact_path_id": highest_path.get("id") if isinstance(highest_path, dict) else None,
        "financial_exposure": highest.get("financial_exposure"),
        "operational_impact": highest.get("operational_impact"),
        "review_only": True,
        "runtime_actions_performed": False,
    }


def _business_tag_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    category = _normalized_category(
        payload.get("business_category")
        or payload.get("category")
        or payload.get("process_category")
        or payload.get("business_process")
    )
    criticality = _normalized_criticality(
        payload.get("business_criticality")
        or payload.get("criticality")
        or payload.get("asset_criticality")
        or payload.get("impact")
    )
    label = _clean_string(
        payload.get("business_process")
        or payload.get("process")
        or payload.get("label")
        or payload.get("name")
        or BUSINESS_CATEGORIES[category]["label"]
    )
    process_id = _clean_string(payload.get("id") or payload.get("process_id") or label).lower().replace(" ", "-")
    score = round(BUSINESS_CATEGORIES[category]["weight"] * CRITICALITY_WEIGHTS[criticality], 3)
    return {
        "id": process_id,
        "label": label,
        "category": category,
        "category_label": BUSINESS_CATEGORIES[category]["label"],
        "criticality": criticality,
        "score": score,
        "predefined": True,
    }


def _default_tag_for_path(path: dict[str, Any]) -> dict[str, Any]:
    target = _clean_string(path.get("target_id")).lower()
    title = _clean_string(path.get("finding_title")).lower()
    if any(token in target or token in title for token in ("login", "sso", "oauth", "admin", "identity")):
        return _business_tag_from_payload(
            {"business_process": "Identity and access", "business_category": "identity_access", "criticality": "high"}
        )
    if any(token in target or token in title for token in ("payment", "checkout", "invoice", "billing")):
        return _business_tag_from_payload(
            {"business_process": "Revenue operations", "business_category": "revenue", "criticality": "critical"}
        )
    return _business_tag_from_payload(
        {"business_process": "Public presence", "business_category": "public_presence", "criticality": "medium"}
    )


def _payload_asset_keys(collection_name: str, payload: dict[str, Any]) -> list[str]:
    values = [
        payload.get("asset_ref"),
        payload.get("asset_id"),
        payload.get("host"),
        payload.get("hostname"),
        payload.get("url"),
        payload.get("endpoint"),
        payload.get("resource_id"),
        payload.get("arn"),
        payload.get("principal_id"),
        payload.get("name"),
    ]
    if collection_name == "services" and payload.get("host") and payload.get("port"):
        values.append(f"{payload.get('host')}:{payload.get('port')}")
    keys: list[str] = []
    for value in values:
        keys.extend(_asset_ref_keys(value))
    return sorted(set(keys))


def _node_asset_keys(node: dict[str, Any]) -> list[str]:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    values = [
        node.get("id"),
        node.get("label"),
        metadata.get("host"),
        metadata.get("url"),
        metadata.get("resource_id"),
        metadata.get("arn"),
        metadata.get("principal_id"),
    ]
    keys: list[str] = []
    for value in values:
        keys.extend(_asset_ref_keys(value))
    return sorted(set(keys))


def _asset_ref_keys(value: Any) -> list[str]:
    text = _clean_string(value)
    if not text:
        return []
    keys = {text.lower()}
    parsed = urlparse(text)
    if parsed.netloc:
        url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path}".rstrip("/")
        keys.add(url.lower())
        keys.add(parsed.netloc.lower())
        keys.add(f"host:{parsed.netloc.lower()}")
    if text.startswith("host:"):
        keys.add(text[5:].lower())
    elif "." in text and "/" not in text:
        keys.add(f"host:{text.lower()}")
    return sorted(keys)


def _dedupe_tags(tags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for tag in tags:
        key = str(tag.get("id") or tag.get("label") or "").strip()
        if not key:
            continue
        if key not in result or float(tag.get("score") or 0.0) > float(result[key].get("score") or 0.0):
            result[key] = tag
    return sorted(result.values(), key=lambda item: (float(item.get("score") or 0.0), str(item.get("label") or "")), reverse=True)


def _normalized_category(value: Any) -> str:
    raw = _normalized_label(value).replace("-", "_")
    aliases = {
        "payments": "revenue",
        "payment": "revenue",
        "billing": "revenue",
        "sales": "revenue",
        "pii": "customer_data",
        "customer": "customer_data",
        "data": "customer_data",
        "auth": "identity_access",
        "identity": "identity_access",
        "iam": "identity_access",
        "admin": "identity_access",
        "operations": "operations",
        "ops": "operations",
        "production": "operations",
        "compliance": "compliance",
        "regulatory": "compliance",
        "public": "public_presence",
        "marketing": "public_presence",
    }
    return aliases.get(raw, raw if raw in BUSINESS_CATEGORIES else "general")


def _normalized_criticality(value: Any) -> str:
    raw = _normalized_label(value)
    if raw in {"critical", "high", "medium", "low"}:
        return raw
    if raw in {"mission_critical", "tier_0", "tier0"}:
        return "critical"
    if raw in {"important", "tier_1", "tier1"}:
        return "high"
    return "unknown"


def _score_tier(score: float) -> str:
    if score >= 82:
        return "critical"
    if score >= 64:
        return "high"
    if score >= 38:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _financial_label(tag: dict[str, Any], tier: str) -> str:
    if tag.get("category") == "revenue" and tier in {"critical", "high"}:
        return "direct revenue exposure"
    if tag.get("category") == "customer_data" and tier in {"critical", "high"}:
        return "customer trust and regulatory exposure"
    if tier in {"critical", "high"}:
        return "material business exposure"
    return "limited modeled financial exposure"


def _operational_label(tag: dict[str, Any], tier: str) -> str:
    if tag.get("category") == "identity_access" and tier in {"critical", "high"}:
        return "identity control-plane disruption risk"
    if tag.get("category") == "operations" and tier in {"critical", "high"}:
        return "core operations disruption risk"
    if tier in {"critical", "high"}:
        return "elevated operational risk"
    return "localized operational risk"


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        if isinstance(value, str):
            return [value] if value.strip() else []
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _clean_string(value: Any) -> str:
    return str(value or "").strip()


def _normalized_label(value: Any) -> str:
    return _clean_string(value).lower().replace(" ", "_")


def _bounded_float(value: Any, *, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0.0, min(1.0, parsed))

