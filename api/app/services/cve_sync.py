from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Callable
from uuid import UUID
from xml.etree import ElementTree

import httpx
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.models import CveFeedSyncLog, CveProductWatchlistEntry, Engagement, InstanceSetting, InventorySnapshot, ThreatIntelRecord
from api.app.services.secrets import decrypt_secret_value
from api.app.services.settings import DEFAULT_TENANT_SCOPE, tenant_scope_key
from api.app.services.threat_intel import upsert_threat_intel_record

SOURCE_ORDER = ("cisa_kev", "ncsc_nl", "nvd", "opencve")
SOURCE_LABELS = {
    "cisa_kev": "CISA KEV",
    "ncsc_nl": "NCSC NL",
    "nvd": "NVD",
    "opencve": "OpenCVE",
}
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GENERIC_PRODUCT_TERMS = {
    "http",
    "https",
    "unknown-service",
    "application/json",
    "text/html",
    "open port",
}


@dataclass(frozen=True)
class FeedFetchResult:
    status_code: int
    text: str = ""
    json_data: Any | None = None
    headers: dict[str, str] = field(default_factory=dict)


FeedFetcher = Callable[..., FeedFetchResult | dict[str, Any] | tuple[Any, ...] | httpx.Response]


def list_product_watchlist_entries(
    session: Session,
    *,
    tenant_id: str | None,
    include_suggested: bool = True,
) -> list[CveProductWatchlistEntry]:
    tenant_key = tenant_scope_key(tenant_id)
    statement = select(CveProductWatchlistEntry).where(CveProductWatchlistEntry.tenant_id == tenant_key)
    if not include_suggested:
        statement = statement.where(CveProductWatchlistEntry.status == "approved")
    return list(
        session.scalars(
            statement.order_by(CveProductWatchlistEntry.status, CveProductWatchlistEntry.query)
        ).all()
    )


def upsert_product_watchlist_entry(
    session: Session,
    *,
    tenant_id: str | None,
    query: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    status: str = "approved",
    source: str = "operator",
    actor: str = "system",
    source_inventory_snapshot_id: UUID | None = None,
    metadata: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> CveProductWatchlistEntry:
    timestamp = now or datetime.now(UTC)
    clean_vendor = _clean_optional(vendor)
    clean_product = _clean_optional(product)
    clean_query = _clean_required(query or " ".join(item for item in [clean_vendor, clean_product] if item))
    normalized_query = normalize_watchlist_query(clean_query)
    if not normalized_query:
        raise ValueError("product watchlist query is required")

    normalized_status = status if status in {"approved", "suggested"} else "approved"
    entry = session.scalar(
        select(CveProductWatchlistEntry).where(
            CveProductWatchlistEntry.tenant_id == tenant_scope_key(tenant_id),
            CveProductWatchlistEntry.normalized_query == normalized_query,
        )
    )
    if entry is None:
        entry = CveProductWatchlistEntry(
            tenant_id=tenant_scope_key(tenant_id),
            query=clean_query,
            normalized_query=normalized_query,
            status=normalized_status,
            source=source,
        )
        session.add(entry)

    entry.vendor = clean_vendor
    entry.product = clean_product
    entry.query = clean_query
    entry.status = "approved" if entry.status == "approved" or normalized_status == "approved" else "suggested"
    entry.source = source if entry.source != "operator" else entry.source
    entry.source_inventory_snapshot_id = source_inventory_snapshot_id or entry.source_inventory_snapshot_id
    entry.last_seen_at = timestamp
    if entry.status == "approved" and entry.approved_at is None:
        entry.approved_at = timestamp
        entry.approved_by = actor
    entry.metadata_json = {
        **(entry.metadata_json or {}),
        **(metadata or {}),
        "relevance_first": True,
        "full_cve_mirror": False,
    }
    session.flush()
    return entry


def approve_product_watchlist_entry(
    session: Session,
    *,
    entry_id: UUID,
    tenant_id: str | None,
    actor: str,
) -> CveProductWatchlistEntry | None:
    entry = _load_watchlist_entry(session, entry_id=entry_id, tenant_id=tenant_id)
    if entry is None:
        return None
    entry.status = "approved"
    entry.approved_at = datetime.now(UTC)
    entry.approved_by = actor
    session.flush()
    return entry


def delete_product_watchlist_entry(session: Session, *, entry_id: UUID, tenant_id: str | None) -> bool:
    entry = _load_watchlist_entry(session, entry_id=entry_id, tenant_id=tenant_id)
    if entry is None:
        return False
    session.delete(entry)
    session.flush()
    return True


def suggest_watchlist_from_inventory_snapshot(
    session: Session,
    *,
    inventory_snapshot_id: UUID,
    tenant_id: str | None,
    actor: str = "system",
    limit: int = 25,
) -> list[CveProductWatchlistEntry]:
    snapshot = session.scalar(select(InventorySnapshot).where(InventorySnapshot.id == inventory_snapshot_id))
    if snapshot is None:
        raise ValueError("inventory snapshot not found")
    snapshot_tenant = _tenant_for_inventory_snapshot(session, snapshot)
    if tenant_id is not None and snapshot_tenant != tenant_id:
        raise ValueError("inventory snapshot not found")

    suggestions = extract_product_suggestions(snapshot.normalized_inventory_json, limit=limit)
    entries = []
    for suggestion in suggestions:
        entries.append(
            upsert_product_watchlist_entry(
                session,
                tenant_id=snapshot_tenant,
                query=suggestion["query"],
                vendor=suggestion.get("vendor"),
                product=suggestion.get("product"),
                status="suggested",
                source="inventory",
                actor=actor,
                source_inventory_snapshot_id=snapshot.id,
                metadata={"inventory_source": suggestion.get("source"), "confidence": suggestion.get("confidence")},
            )
        )
    session.flush()
    return entries


def extract_product_suggestions(normalized_inventory: dict[str, Any] | None, *, limit: int = 25) -> list[dict[str, Any]]:
    inventory = normalized_inventory if isinstance(normalized_inventory, dict) else {}
    candidates: list[dict[str, Any]] = []
    for entry in inventory.get("vendor_product_fingerprints", []) or []:
        if isinstance(entry, dict):
            candidates.append(
                {
                    "vendor": _clean_optional(entry.get("vendor")),
                    "product": _clean_optional(entry.get("product")),
                    "source": entry.get("source") or "inventory",
                    "confidence": entry.get("confidence"),
                }
            )
    for entry in inventory.get("technologies", []) or []:
        if isinstance(entry, dict):
            candidates.append(
                {
                    "vendor": _clean_optional(entry.get("vendor")),
                    "product": _clean_optional(entry.get("name") or entry.get("product")),
                    "source": entry.get("source") or "inventory",
                    "confidence": entry.get("confidence"),
                }
            )
        elif isinstance(entry, str):
            candidates.append({"vendor": None, "product": _clean_optional(entry), "source": "inventory"})
    for entry in inventory.get("services", []) or []:
        if isinstance(entry, dict):
            candidates.append(
                {
                    "vendor": None,
                    "product": _clean_optional(entry.get("product") or entry.get("service")),
                    "source": entry.get("source") or "inventory",
                    "confidence": entry.get("confidence"),
                }
            )

    unique: dict[str, dict[str, Any]] = {}
    for item in candidates:
        query = " ".join(part for part in [item.get("vendor"), item.get("product")] if part).strip()
        normalized = normalize_watchlist_query(query)
        if not normalized or normalized in GENERIC_PRODUCT_TERMS:
            continue
        unique.setdefault(
            normalized,
            {
                **item,
                "query": query,
            },
        )
    return list(unique.values())[:limit]


def latest_feed_sync_status(session: Session, *, tenant_id: str | None) -> dict[str, Any]:
    tenant_key = tenant_scope_key(tenant_id)
    logs = session.scalars(
        select(CveFeedSyncLog)
        .where(CveFeedSyncLog.tenant_id == tenant_key)
        .order_by(desc(CveFeedSyncLog.started_at), desc(CveFeedSyncLog.created_at))
    ).all()
    latest_by_source: dict[str, CveFeedSyncLog] = {}
    for log in logs:
        latest_by_source.setdefault(log.source, log)
    entries = list_product_watchlist_entries(session, tenant_id=tenant_key)
    approved_count = sum(1 for entry in entries if entry.status == "approved")
    suggested_count = sum(1 for entry in entries if entry.status == "suggested")
    return {
        "tenant_id": tenant_key,
        "sources": [_source_status(source, latest_by_source.get(source)) for source in SOURCE_ORDER],
        "watchlist": {
            "approved_count": approved_count,
            "suggested_count": suggested_count,
            "total_count": len(entries),
        },
        "policy": {
            "mode": "relevance-first-local-cache",
            "full_cve_mirror": False,
            "cisa_kev_full_sync": True,
            "ncsc_nl_full_sync": True,
            "nvd_watchlist_only": True,
            "opencve_watchlist_only": True,
            "finding_time_external_lookup": False,
        },
    }


def sync_cve_feeds(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings | None = None,
    fetcher: FeedFetcher | None = None,
    source_names: list[str] | None = None,
    force: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    runtime_settings = settings or get_settings()
    timestamp = now or datetime.now(UTC)
    tenant_key = tenant_scope_key(tenant_id)
    selected_sources = [source for source in (source_names or list(SOURCE_ORDER)) if source in SOURCE_ORDER]
    if not selected_sources:
        selected_sources = list(SOURCE_ORDER)
    if not force and not runtime_settings.cve_feed_sync_enabled:
        return {
            "tenant_id": tenant_key,
            "status": "disabled",
            "sources": [],
            "imported_count": 0,
            "updated_count": 0,
            "skipped_count": 0,
            "policy": latest_feed_sync_status(session, tenant_id=tenant_key)["policy"],
        }

    approved_entries = list_product_watchlist_entries(session, tenant_id=tenant_key, include_suggested=False)
    nvd_key = resolve_feed_credential(
        session,
        tenant_id=tenant_key,
        setting_key="threat_intel.nvd_api_key",
        env_value=runtime_settings.cve_feed_nvd_api_key,
        settings=runtime_settings,
    )
    opencve_token = resolve_feed_credential(
        session,
        tenant_id=tenant_key,
        setting_key="threat_intel.opencve_api_token",
        env_value=runtime_settings.cve_feed_opencve_api_token,
        settings=runtime_settings,
    )

    results: list[dict[str, Any]] = []
    for source in selected_sources:
        try:
            if source == "cisa_kev":
                result = _sync_cisa_kev(session, settings=runtime_settings, fetcher=fetcher, tenant_key=tenant_key, now=timestamp)
            elif source == "ncsc_nl":
                result = _sync_ncsc_nl(session, settings=runtime_settings, fetcher=fetcher, tenant_key=tenant_key, now=timestamp)
            elif source == "nvd":
                result = _sync_nvd(
                    session,
                    settings=runtime_settings,
                    fetcher=fetcher,
                    tenant_key=tenant_key,
                    watchlist=approved_entries,
                    api_key=nvd_key,
                    now=timestamp,
                )
            else:
                result = _sync_opencve(
                    session,
                    settings=runtime_settings,
                    fetcher=fetcher,
                    tenant_key=tenant_key,
                    watchlist=approved_entries,
                    api_token=opencve_token,
                    now=timestamp,
                )
        except Exception as exc:  # noqa: BLE001 - sync failures are non-blocking by design.
            result = _write_sync_log(
                session,
                tenant_key=tenant_key,
                source=source,
                status="failed",
                started_at=timestamp,
                imported_count=0,
                updated_count=0,
                skipped_count=0,
                error=str(exc),
                metadata=_sync_failure_metadata(source, exc),
            )
        results.append(result)

    session.flush()
    return {
        "tenant_id": tenant_key,
        "status": "completed",
        "sources": results,
        "imported_count": sum(item["imported_count"] for item in results),
        "updated_count": sum(item["updated_count"] for item in results),
        "skipped_count": sum(item["skipped_count"] for item in results),
        "policy": latest_feed_sync_status(session, tenant_id=tenant_key)["policy"],
    }


def resolve_feed_credential(
    session: Session,
    *,
    tenant_id: str | None,
    setting_key: str,
    env_value: str | None,
    settings: Settings,
) -> str | None:
    if env_value:
        return env_value
    row = session.scalar(
        select(InstanceSetting).where(
            InstanceSetting.tenant_id == tenant_scope_key(tenant_id),
            InstanceSetting.setting_key == setting_key,
            InstanceSetting.sensitive.is_(True),
        )
    )
    if row is None or not row.encrypted_value or not row.storage_backend:
        return None
    try:
        return decrypt_secret_value(row.encrypted_value, settings, storage_backend=row.storage_backend)
    except Exception:
        return None


def normalize_watchlist_query(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _sync_cisa_kev(
    session: Session,
    *,
    settings: Settings,
    fetcher: FeedFetcher | None,
    tenant_key: str,
    now: datetime,
) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    response = _fetch(settings.cve_feed_cisa_kev_url, fetcher=fetcher, timeout=settings.cve_feed_timeout_seconds)
    data = response.json_data if isinstance(response.json_data, dict) else {}
    records = data.get("vulnerabilities", []) if isinstance(data.get("vulnerabilities"), list) else []
    imported, updated, skipped = _upsert_payloads(session, [_cisa_kev_payload(record, now=now) for record in records])
    return _write_sync_log(
        session,
        tenant_key=tenant_key,
        source="cisa_kev",
        status="completed",
        started_at=started_at,
        imported_count=imported,
        updated_count=updated,
        skipped_count=skipped,
        metadata={"feed_url": settings.cve_feed_cisa_kev_url, "full_sync": True},
    )


def _sync_ncsc_nl(
    session: Session,
    *,
    settings: Settings,
    fetcher: FeedFetcher | None,
    tenant_key: str,
    now: datetime,
) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    response = _fetch(settings.cve_feed_ncsc_nl_rss_url, fetcher=fetcher, timeout=settings.cve_feed_timeout_seconds)
    payloads = _ncsc_payloads(response.text, now=now)
    imported, updated, skipped = _upsert_payloads(session, payloads)
    return _write_sync_log(
        session,
        tenant_key=tenant_key,
        source="ncsc_nl",
        status="completed",
        started_at=started_at,
        imported_count=imported,
        updated_count=updated,
        skipped_count=skipped,
        metadata={"feed_url": settings.cve_feed_ncsc_nl_rss_url, "full_sync": True},
    )


def _sync_nvd(
    session: Session,
    *,
    settings: Settings,
    fetcher: FeedFetcher | None,
    tenant_key: str,
    watchlist: list[CveProductWatchlistEntry],
    api_key: str | None,
    now: datetime,
) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    if not watchlist:
        return _write_sync_log(
            session,
            tenant_key=tenant_key,
            source="nvd",
            status="skipped",
            started_at=started_at,
            skipped_count=1,
            metadata={"reason": "empty_watchlist", "watchlist_only": True},
        )
    headers = {"apiKey": api_key} if api_key else {}
    payloads: list[dict[str, Any] | None] = []
    seen: set[str] = set()
    for entry in watchlist:
        params = {
            "keywordSearch": entry.query,
            "resultsPerPage": min(settings.cve_feed_max_records_per_source, 2000),
        }
        response = _fetch(settings.cve_feed_nvd_api_url, fetcher=fetcher, headers=headers, params=params, timeout=settings.cve_feed_timeout_seconds)
        for raw in _nvd_records(response.json_data):
            payload = _nvd_payload(raw, watchlist_entry=entry, settings=settings, now=now)
            if payload is None or payload["advisory_id"] in seen:
                continue
            seen.add(payload["advisory_id"])
            payloads.append(payload)
    imported, updated, skipped = _upsert_payloads(session, payloads)
    return _write_sync_log(
        session,
        tenant_key=tenant_key,
        source="nvd",
        status="completed",
        started_at=started_at,
        imported_count=imported,
        updated_count=updated,
        skipped_count=skipped,
        metadata={"watchlist_only": True, "watchlist_count": len(watchlist), "credential_configured": bool(api_key)},
    )


def _sync_opencve(
    session: Session,
    *,
    settings: Settings,
    fetcher: FeedFetcher | None,
    tenant_key: str,
    watchlist: list[CveProductWatchlistEntry],
    api_token: str | None,
    now: datetime,
) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    if not watchlist:
        return _write_sync_log(
            session,
            tenant_key=tenant_key,
            source="opencve",
            status="skipped",
            started_at=started_at,
            skipped_count=1,
            metadata={"reason": "empty_watchlist", "watchlist_only": True},
        )
    if not api_token:
        return _write_sync_log(
            session,
            tenant_key=tenant_key,
            source="opencve",
            status="skipped",
            started_at=started_at,
            skipped_count=1,
            metadata={"reason": "missing_optional_token", "watchlist_only": True},
        )
    payloads: list[dict[str, Any] | None] = []
    seen: set[str] = set()
    headers = {"Authorization": f"Bearer {api_token}"}
    for entry in watchlist:
        response = _fetch(
            settings.cve_feed_opencve_api_url,
            fetcher=fetcher,
            headers=headers,
            params={"search": entry.query, "page_size": settings.cve_feed_max_records_per_source},
            timeout=settings.cve_feed_timeout_seconds,
        )
        for raw in _opencve_records(response.json_data):
            payload = _opencve_payload(raw, watchlist_entry=entry, settings=settings, now=now)
            if payload is None or payload["advisory_id"] in seen:
                continue
            seen.add(payload["advisory_id"])
            payloads.append(payload)
    imported, updated, skipped = _upsert_payloads(session, payloads)
    return _write_sync_log(
        session,
        tenant_key=tenant_key,
        source="opencve",
        status="completed",
        started_at=started_at,
        imported_count=imported,
        updated_count=updated,
        skipped_count=skipped,
        metadata={"watchlist_only": True, "watchlist_count": len(watchlist), "credential_configured": True},
    )


def _upsert_payloads(session: Session, payloads: list[dict[str, Any] | None]) -> tuple[int, int, int]:
    imported = 0
    updated = 0
    skipped = 0
    for payload in payloads:
        if payload is None:
            skipped += 1
            continue
        existing = session.scalar(
            select(ThreatIntelRecord).where(
                ThreatIntelRecord.source == payload["source"],
                ThreatIntelRecord.advisory_id == payload["advisory_id"],
            )
        )
        if existing is not None:
            updated += 1
        upsert_threat_intel_record(session, payload)
        imported += 1
    return imported, updated, skipped


def _cisa_kev_payload(raw: Any, *, now: datetime) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    cve_id = _first_text(raw, "cveID", "cve_id", "id")
    if not cve_id:
        return None
    vendor = _first_text(raw, "vendorProject", "vendor")
    product = _first_text(raw, "product")
    products = [item for item in [vendor, product, f"{vendor or ''} {product or ''}".strip()] if item]
    return {
        "source": "cisa-kev",
        "advisory_id": cve_id.upper(),
        "title": _first_text(raw, "vulnerabilityName", "title") or cve_id.upper(),
        "summary": _first_text(raw, "shortDescription", "notes", "requiredAction"),
        "affected_products": products,
        "product_match_hints": [cve_id.upper(), *products],
        "suggested_test_patterns": ["local-cache-kev-review"],
        "confidence": 0.9,
        "severity": "known_exploited",
        "references": _list_or_default(raw.get("references"), ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]),
        "published_at": _parse_datetime(raw.get("dateAdded")),
        "updated_at": now,
        "normalization_status": "normalized",
        "metadata": {
            "feed_type": "cisa_kev",
            "feed_name": "CISA Known Exploited Vulnerabilities",
            "feed_cached_at": now.isoformat(),
            "stale_after_days": 14,
            "badge_types": ["kev"],
            "kev": True,
            "approved_feed": True,
            "external_lookup_performed": False,
            "downloads_exploits": False,
            "claims_actor_attribution": False,
            "known_ransomware_campaign_use": _first_text(raw, "knownRansomwareCampaignUse"),
            "required_action": _first_text(raw, "requiredAction"),
            "due_date": _iso_or_none(raw.get("dueDate")),
        },
    }


def _ncsc_payloads(xml_text: str, *, now: datetime) -> list[dict[str, Any] | None]:
    if not xml_text.strip():
        return []
    root = ElementTree.fromstring(xml_text)
    payloads: list[dict[str, Any] | None] = []
    for item in root.findall(".//item"):
        title = _xml_text(item, "title") or "NCSC NL advisory"
        summary = _xml_text(item, "description")
        link = _xml_text(item, "link")
        published_at = _parse_datetime(_xml_text(item, "pubDate"))
        cves = CVE_PATTERN.findall(" ".join(part for part in [title, summary, link] if part))
        for cve_id in list(dict.fromkeys(cve.upper() for cve in cves)):
            payloads.append(
                {
                    "source": "ncsc-nl",
                    "advisory_id": cve_id,
                    "title": title,
                    "summary": summary,
                    "affected_products": [title],
                    "product_match_hints": [cve_id, title],
                    "suggested_test_patterns": [f"cve:{cve_id}", "local-cache-ncsc-review"],
                    "confidence": 0.75,
                    "severity": "advisory",
                    "references": [link] if link else [],
                    "published_at": published_at,
                    "updated_at": now,
                    "normalization_status": "normalized",
                    "metadata": {
                        "feed_type": "ncsc_nl",
                        "feed_name": "NCSC NL RSS Advisories",
                        "feed_cached_at": now.isoformat(),
                        "stale_after_days": 14,
                        "badge_types": ["source"],
                        "approved_feed": True,
                        "external_lookup_performed": False,
                        "downloads_exploits": False,
                        "claims_actor_attribution": False,
                    },
                }
            )
    return payloads


def _nvd_records(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    values = data.get("vulnerabilities", [])
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def _nvd_payload(
    raw: dict[str, Any],
    *,
    watchlist_entry: CveProductWatchlistEntry,
    settings: Settings,
    now: datetime,
) -> dict[str, Any] | None:
    cve = raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
    cve_id = _first_text(cve, "id", "cve_id", "cveID")
    if not cve_id:
        return None
    score, severity = _nvd_cvss(cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {})
    if score is not None and score < settings.cve_feed_min_cvss_score:
        return None
    affected_products = _nvd_products(cve)
    description = _description_from_list(cve.get("descriptions"))
    haystack = " ".join([description or "", " ".join(affected_products), cve_id]).lower()
    watch_terms = [
        watchlist_entry.normalized_query,
        normalize_watchlist_query(watchlist_entry.vendor),
        normalize_watchlist_query(watchlist_entry.product),
    ]
    if not any(term and term in haystack for term in watch_terms):
        return None
    references = _nvd_references(cve.get("references"))
    return {
        "source": "nvd",
        "advisory_id": cve_id.upper(),
        "title": cve_id.upper(),
        "summary": description,
        "affected_products": affected_products,
        "product_match_hints": [cve_id.upper(), watchlist_entry.query, *affected_products],
        "suggested_test_patterns": [f"cve:{cve_id.upper()}"],
        "confidence": 0.8,
        "severity": severity,
        "references": references,
        "published_at": _parse_datetime(cve.get("published")),
        "updated_at": _parse_datetime(cve.get("lastModified")) or now,
        "normalization_status": "normalized",
        "metadata": {
            "feed_type": "nvd",
            "feed_name": "NVD CVE API",
            "feed_cached_at": now.isoformat(),
            "stale_after_days": 14,
            "badge_types": ["cvss"],
            "approved_feed": True,
            "external_lookup_performed": False,
            "downloads_exploits": False,
            "claims_actor_attribution": False,
            "watchlist_query": watchlist_entry.query,
            "cvss_score": score,
            "cvss_severity": severity,
        },
    }


def _opencve_records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("results", "data", "items", "cves"):
            values = data.get(key)
            if isinstance(values, list):
                return [item for item in values if isinstance(item, dict)]
    return []


def _opencve_payload(
    raw: dict[str, Any],
    *,
    watchlist_entry: CveProductWatchlistEntry,
    settings: Settings,
    now: datetime,
) -> dict[str, Any] | None:
    cve_id = _first_text(raw, "cve_id", "id", "cveID")
    if not cve_id:
        return None
    score = _float_or_none(raw.get("cvss") or raw.get("cvss_score") or raw.get("cvss3"))
    severity = _first_text(raw, "severity", "cvss_severity")
    if score is not None and score < settings.cve_feed_min_cvss_score:
        return None
    affected_products = _extract_flat_products(raw)
    summary = _first_text(raw, "summary", "description")
    haystack = " ".join([summary or "", " ".join(affected_products), cve_id]).lower()
    watch_terms = [
        watchlist_entry.normalized_query,
        normalize_watchlist_query(watchlist_entry.vendor),
        normalize_watchlist_query(watchlist_entry.product),
    ]
    if not any(term and term in haystack for term in watch_terms):
        return None
    return {
        "source": "opencve",
        "advisory_id": cve_id.upper(),
        "title": _first_text(raw, "title") or cve_id.upper(),
        "summary": summary,
        "affected_products": affected_products,
        "product_match_hints": [cve_id.upper(), watchlist_entry.query, *affected_products],
        "suggested_test_patterns": [f"cve:{cve_id.upper()}"],
        "confidence": 0.75,
        "severity": severity,
        "references": _list_or_default(raw.get("references"), []),
        "published_at": _parse_datetime(raw.get("published_at") or raw.get("created_at")),
        "updated_at": _parse_datetime(raw.get("updated_at")) or now,
        "normalization_status": "normalized",
        "metadata": {
            "feed_type": "opencve",
            "feed_name": "OpenCVE API",
            "feed_cached_at": now.isoformat(),
            "stale_after_days": 14,
            "badge_types": ["cvss"],
            "approved_feed": True,
            "external_lookup_performed": False,
            "downloads_exploits": False,
            "claims_actor_attribution": False,
            "watchlist_query": watchlist_entry.query,
            "cvss_score": score,
            "cvss_severity": severity,
        },
    }


def _write_sync_log(
    session: Session,
    *,
    tenant_key: str,
    source: str,
    status: str,
    started_at: datetime,
    imported_count: int = 0,
    updated_count: int = 0,
    skipped_count: int = 0,
    error: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    completed_at = datetime.now(UTC)
    log = CveFeedSyncLog(
        tenant_id=tenant_key,
        source=source,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        imported_count=imported_count,
        updated_count=updated_count,
        skipped_count=skipped_count,
        error_text=error,
        metadata_json={
            "source_label": SOURCE_LABELS.get(source, source),
            "non_blocking": status == "failed",
            **(metadata or {}),
        },
    )
    session.add(log)
    session.flush()
    return _source_status(source, log)


def _sync_failure_metadata(source: str, exc: Exception) -> dict[str, Any]:
    message = str(exc)
    metadata: dict[str, Any] = {"non_blocking": True}
    if "HTTP 429" in message:
        metadata.update(
            {
                "reason": "rate_limited",
                "operator_action": (
                    "Try again later or configure the optional API key for this feed."
                ),
            }
        )
    elif "HTTP 401" in message or "HTTP 403" in message:
        metadata.update(
            {
                "reason": "credential_rejected",
                "operator_action": "Check the configured feed credential.",
            }
        )
    else:
        metadata["reason"] = "feed_error"
    if source == "nvd":
        metadata["watchlist_only"] = True
    return metadata


def _source_status(source: str, log: CveFeedSyncLog | None) -> dict[str, Any]:
    if log is None:
        return {
            "source": source,
            "label": SOURCE_LABELS.get(source, source),
            "status": "never_synced",
            "started_at": None,
            "completed_at": None,
            "imported_count": 0,
            "updated_count": 0,
            "skipped_count": 0,
            "error": None,
            "metadata": {},
        }
    return {
        "source": source,
        "label": SOURCE_LABELS.get(source, source),
        "status": log.status,
        "started_at": log.started_at,
        "completed_at": log.completed_at,
        "imported_count": log.imported_count,
        "updated_count": log.updated_count,
        "skipped_count": log.skipped_count,
        "error": log.error_text,
        "metadata": dict(log.metadata_json or {}),
    }


def _fetch(
    url: str,
    *,
    fetcher: FeedFetcher | None,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> FeedFetchResult:
    if fetcher is None:
        response = httpx.get(url, headers=headers, params=params, timeout=timeout)
    else:
        response = fetcher(url=url, headers=headers or {}, params=params or {}, timeout=timeout)
    result = _coerce_fetch_result(response)
    if result.status_code >= 400:
        raise ValueError(f"feed fetch failed for {url}: HTTP {result.status_code}")
    return result


def _coerce_fetch_result(raw: FeedFetchResult | dict[str, Any] | tuple[Any, ...] | httpx.Response) -> FeedFetchResult:
    if isinstance(raw, FeedFetchResult):
        return raw
    if isinstance(raw, httpx.Response):
        try:
            json_data = raw.json()
        except ValueError:
            json_data = None
        return FeedFetchResult(status_code=raw.status_code, text=raw.text, json_data=json_data, headers=dict(raw.headers))
    if isinstance(raw, dict):
        text = str(raw.get("text") or "")
        json_data = raw.get("json", raw.get("json_data"))
        if json_data is not None and not text:
            text = ""
        return FeedFetchResult(status_code=int(raw.get("status_code") or 200), text=text, json_data=json_data)
    if isinstance(raw, tuple):
        status_code = int(raw[0]) if raw else 200
        body = raw[1] if len(raw) > 1 else ""
        if isinstance(body, (dict, list)):
            return FeedFetchResult(status_code=status_code, json_data=body, text="")
        return FeedFetchResult(status_code=status_code, text=str(body or ""))
    raise TypeError("unsupported feed fetch result")


def _load_watchlist_entry(session: Session, *, entry_id: UUID, tenant_id: str | None) -> CveProductWatchlistEntry | None:
    return session.scalar(
        select(CveProductWatchlistEntry).where(
            CveProductWatchlistEntry.id == entry_id,
            CveProductWatchlistEntry.tenant_id == tenant_scope_key(tenant_id),
        )
    )


def _tenant_for_inventory_snapshot(session: Session, snapshot: InventorySnapshot) -> str:
    tenant = session.scalar(select(Engagement.tenant_id).where(Engagement.id == snapshot.engagement_id))
    return tenant_scope_key(tenant)


def _nvd_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        metric = values[0] if isinstance(values[0], dict) else {}
        cvss_data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
        score = _float_or_none(cvss_data.get("baseScore"))
        severity = str(metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "").strip() or None
        return score, severity
    return None, None


def _nvd_products(cve: dict[str, Any]) -> list[str]:
    products: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            criteria = node.get("criteria") or node.get("cpe23Uri")
            if isinstance(criteria, str):
                parsed = _product_from_cpe(criteria)
                if parsed:
                    products.append(parsed)
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(cve.get("configurations"))
    return list(dict.fromkeys(products))


def _nvd_references(value: Any) -> list[str]:
    if isinstance(value, dict):
        candidates = value.get("referenceData") or value.get("references") or value.get("data") or []
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = []
    references = [
        str(ref.get("url")).strip()
        for ref in candidates
        if isinstance(ref, dict) and str(ref.get("url") or "").strip()
    ]
    return list(dict.fromkeys(references))


def _product_from_cpe(value: str) -> str | None:
    parts = value.split(":")
    if len(parts) < 6 or not value.startswith("cpe:"):
        return None
    vendor = parts[3].replace("_", " ").strip()
    product = parts[4].replace("_", " ").strip()
    return " ".join(part for part in [vendor if vendor != "*" else "", product if product != "*" else ""] if part)


def _description_from_list(values: Any) -> str | None:
    if not isinstance(values, list):
        return None
    for item in values:
        if isinstance(item, dict) and str(item.get("lang") or "").lower() == "en":
            return _clean_optional(item.get("value"))
    for item in values:
        if isinstance(item, dict):
            return _clean_optional(item.get("value"))
    return None


def _extract_flat_products(raw: dict[str, Any]) -> list[str]:
    products: list[str] = []
    for key in ("affected_products", "products", "vendors"):
        value = raw.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    products.append(item)
                elif isinstance(item, dict):
                    products.append(" ".join(part for part in [_clean_optional(item.get("vendor")), _clean_optional(item.get("product") or item.get("name"))] if part))
        elif isinstance(value, str):
            products.append(value)
    return [item for item in dict.fromkeys(product.strip() for product in products) if item]


def _xml_text(item: ElementTree.Element, child_name: str) -> str | None:
    node = item.find(child_name)
    return _clean_optional(node.text if node is not None else None)


def _first_text(raw: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        text = _clean_optional(raw.get(key))
        if text:
            return text
    return None


def _clean_optional(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _clean_required(value: Any) -> str:
    text = _clean_optional(value)
    if not text:
        raise ValueError("value is required")
    return text


def _list_or_default(value: Any, default: list[str]) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item or "").strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return list(default)


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(text)
            except (TypeError, ValueError):
                return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_or_none(value: Any) -> str | None:
    parsed = _parse_datetime(value)
    return parsed.isoformat() if parsed is not None else None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
