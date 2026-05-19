from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor, require_roles
from api.app.db import get_session
from api.app.schemas.threat_intel import (
    CveFeedSyncRunCreate,
    CveFeedSyncRunRead,
    CveFeedSyncStatusRead,
    CveInventorySuggestionCreate,
    CveProductWatchlistCreate,
    CveProductWatchlistRead,
    CveTemplateGenerationCreate,
    CveTemplateGenerationRead,
    ThreatIntelFeedImportCreate,
    ThreatIntelFeedImportRead,
    ThreatIntelIngestCreate,
    ThreatIntelRecordRead,
    ZeroDayRapidResponseRead,
    ZeroDayScanNowCreate,
    ZeroDayScanNowRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.chatgpt_oauth import chatgpt_oauth_status
from api.app.services.cve_sync import (
    approve_product_watchlist_entry,
    delete_product_watchlist_entry,
    latest_feed_sync_status,
    list_product_watchlist_entries,
    suggest_watchlist_from_inventory_snapshot,
    sync_cve_feeds,
    upsert_product_watchlist_entry,
)
from api.app.services.cve_template_generator import (
    CveTemplateUnavailable,
    NucleiTemplateValidationError,
    UnsafeNucleiTemplateError,
    existing_template_generation_payload,
    generate_cve_nuclei_template_pack,
    unavailable_generation_payload,
)
from api.app.services.settings import effective_runtime_settings
from api.app.services.tenancy import get_current_tenant_id, load_engagement_for_tenant
from api.app.services.threat_intel import (
    import_threat_intel_feed,
    load_threat_intel_record,
    search_threat_intel_records,
    upsert_threat_intel_record,
)
from api.app.services.zero_day_response import (
    build_zero_day_rapid_response,
    launch_zero_day_rapid_response_scan,
)

router = APIRouter(prefix="/api/v1", tags=["threat-intel"])


@router.post("/threat-intel/ingest", response_model=list[ThreatIntelRecordRead], status_code=status.HTTP_201_CREATED)
def ingest_threat_intel(
    payload: ThreatIntelIngestCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
) -> list[ThreatIntelRecordRead]:
    ingested = [upsert_threat_intel_record(session, record.model_dump()) for record in payload.records]
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.ingested",
        object_type="threat_intel_batch",
        object_id=str(len(ingested)),
        metadata={"record_count": len(ingested)},
    )
    session.commit()
    return [ThreatIntelRecordRead.model_validate(record) for record in ingested]


@router.post(
    "/threat-intel/feed-cache/import",
    response_model=ThreatIntelFeedImportRead,
    status_code=status.HTTP_201_CREATED,
)
def import_threat_intel_feed_cache(
    payload: ThreatIntelFeedImportCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> ThreatIntelFeedImportRead:
    try:
        imported = import_threat_intel_feed(
            session,
            feed_type=payload.feed_type,
            feed_name=payload.feed_name,
            feed_cached_at=payload.feed_cached_at,
            stale_after_days=payload.stale_after_days,
            records=[record.model_dump() for record in payload.records],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.feed_cache_imported",
        object_type="threat_intel_feed_cache",
        object_id=payload.feed_name,
        metadata={
            "feed_type": payload.feed_type,
            "record_count": imported["imported_count"],
            "external_lookup_performed": False,
        },
    )
    session.commit()
    return ThreatIntelFeedImportRead(
        **{
            **imported,
            "records": [ThreatIntelRecordRead.model_validate(record) for record in imported["records"]],
        }
    )


@router.get("/threat-intel/search", response_model=list[ThreatIntelRecordRead])
def search_threat_intel(
    q: str | None = Query(default=None),
    product: str | None = Query(default=None),
    attack_surface_type: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[ThreatIntelRecordRead]:
    records = search_threat_intel_records(
        session,
        query=q,
        product=product,
        attack_surface_type=attack_surface_type,
    )
    return [ThreatIntelRecordRead.model_validate(record) for record in records]


@router.post("/threat-intel/{record_id}/generate-template", response_model=CveTemplateGenerationRead)
def generate_threat_intel_nuclei_template(
    record_id: UUID,
    payload: CveTemplateGenerationCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CveTemplateGenerationRead:
    engagement = load_engagement_for_tenant(session, payload.engagement_id, tenant_id)
    record = load_threat_intel_record(session, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="threat-intel record not found")

    existing = existing_template_generation_payload(record)
    if existing is not None:
        return CveTemplateGenerationRead(**existing)

    settings = effective_runtime_settings(session, tenant_id=tenant_id)
    status_payload = chatgpt_oauth_status(
        session=session,
        engagement_id=engagement.id,
        settings=settings,
    )
    if not status_payload.connected:
        unavailable = unavailable_generation_payload(
            record=record,
            message="ChatGPT OAuth is not connected for this engagement.",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="threat_intel.template_generation_unavailable",
            object_type="threat_intel_record",
            object_id=str(record.id),
            metadata={
                "engagement_id": str(engagement.id),
                "provider": "chatgpt_oauth",
                "connected": False,
                "token_exposed": False,
            },
        )
        session.commit()
        return CveTemplateGenerationRead(**unavailable)

    try:
        result = generate_cve_nuclei_template_pack(
            session=session,
            record=record,
            engagement_id=engagement.id,
            actor=actor,
            settings=settings,
        )
    except CveTemplateUnavailable as exc:
        unavailable = unavailable_generation_payload(record=record, message=str(exc))
        write_audit_event(
            session=session,
            actor=actor,
            action="threat_intel.template_generation_unavailable",
            object_type="threat_intel_record",
            object_id=str(record.id),
            metadata={
                "engagement_id": str(engagement.id),
                "provider": "chatgpt_oauth",
                "reason": str(exc),
                "token_exposed": False,
            },
        )
        session.commit()
        return CveTemplateGenerationRead(**unavailable)
    except UnsafeNucleiTemplateError as exc:
        session.rollback()
        raise HTTPException(status_code=422, detail=f"generated template rejected: {exc}") from exc
    except NucleiTemplateValidationError as exc:
        session.rollback()
        raise HTTPException(status_code=422, detail=f"generated template validation failed: {exc}") from exc

    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.nuclei_template_generated",
        object_type="threat_intel_record",
        object_id=str(record.id),
        metadata={
            "engagement_id": str(engagement.id),
            "pack_id": str(result.get("pack_id")),
            "artifact_id": str(result.get("artifact_id")),
            "provider": "chatgpt_oauth",
            "detection_only": True,
            "auto_deploy": False,
            "pack_lifecycle_required": True,
        },
    )
    session.commit()
    return CveTemplateGenerationRead(**result)


@router.get("/threat-intel/feed-sync/status", response_model=CveFeedSyncStatusRead)
def get_cve_feed_sync_status(
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CveFeedSyncStatusRead:
    return CveFeedSyncStatusRead(**latest_feed_sync_status(session, tenant_id=tenant_id))


@router.get(
    "/engagements/{engagement_id}/threat-intel/zero-day-response",
    response_model=ZeroDayRapidResponseRead,
)
def get_zero_day_rapid_response(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ZeroDayRapidResponseRead:
    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    return ZeroDayRapidResponseRead.model_validate(
        build_zero_day_rapid_response(session, engagements=[engagement])
    )


@router.post(
    "/engagements/{engagement_id}/threat-intel/zero-day-response/{record_id}/scan-now",
    response_model=ZeroDayScanNowRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def scan_zero_day_rapid_response(
    engagement_id: UUID,
    record_id: UUID,
    payload: ZeroDayScanNowCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ZeroDayScanNowRead:
    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        result = launch_zero_day_rapid_response_scan(
            session,
            engagement=engagement,
            record_id=record_id,
            actor=actor,
            target=payload.target,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return ZeroDayScanNowRead.model_validate(result)


@router.post("/threat-intel/feed-sync/run", response_model=CveFeedSyncRunRead)
def run_cve_feed_sync(
    payload: CveFeedSyncRunCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CveFeedSyncRunRead:
    settings = effective_runtime_settings(session, tenant_id=tenant_id)
    result = sync_cve_feeds(
        session,
        tenant_id=tenant_id,
        settings=settings,
        source_names=payload.sources or None,
        force=True,
    )
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.cve_feed_sync_requested",
        object_type="cve_feed_sync",
        object_id=result["tenant_id"],
        metadata={
            "sources": [source["source"] for source in result["sources"]],
            "imported_count": result["imported_count"],
            "updated_count": result["updated_count"],
            "skipped_count": result["skipped_count"],
            "finding_time_external_lookup": False,
        },
    )
    session.commit()
    return CveFeedSyncRunRead(**result)


@router.get("/threat-intel/product-watchlist", response_model=list[CveProductWatchlistRead])
def list_cve_product_watchlist(
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[CveProductWatchlistRead]:
    entries = list_product_watchlist_entries(session, tenant_id=tenant_id)
    return [CveProductWatchlistRead.model_validate(entry) for entry in entries]


@router.post(
    "/threat-intel/product-watchlist",
    response_model=CveProductWatchlistRead,
    status_code=status.HTTP_201_CREATED,
)
def add_cve_product_watchlist_entry(
    payload: CveProductWatchlistCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CveProductWatchlistRead:
    try:
        entry = upsert_product_watchlist_entry(
            session,
            tenant_id=tenant_id,
            query=payload.query,
            vendor=payload.vendor,
            product=payload.product,
            status="approved",
            source="operator",
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.product_watchlist.updated",
        object_type="cve_product_watchlist_entry",
        object_id=str(entry.id),
        metadata={"query": entry.query, "status": entry.status},
    )
    session.commit()
    session.refresh(entry)
    return CveProductWatchlistRead.model_validate(entry)


@router.post(
    "/threat-intel/product-watchlist/suggest-from-inventory",
    response_model=list[CveProductWatchlistRead],
)
def suggest_cve_product_watchlist_entries(
    payload: CveInventorySuggestionCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[CveProductWatchlistRead]:
    try:
        entries = suggest_watchlist_from_inventory_snapshot(
            session,
            inventory_snapshot_id=payload.inventory_snapshot_id,
            tenant_id=tenant_id,
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.product_watchlist.suggested",
        object_type="inventory_snapshot",
        object_id=str(payload.inventory_snapshot_id),
        metadata={"suggestion_count": len(entries)},
    )
    session.commit()
    return [CveProductWatchlistRead.model_validate(entry) for entry in entries]


@router.post("/threat-intel/product-watchlist/{entry_id}/approve", response_model=CveProductWatchlistRead)
def approve_cve_product_watchlist_entry(
    entry_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CveProductWatchlistRead:
    entry = approve_product_watchlist_entry(session, entry_id=entry_id, tenant_id=tenant_id, actor=actor)
    if entry is None:
        raise HTTPException(status_code=404, detail="product watchlist entry not found")
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.product_watchlist.approved",
        object_type="cve_product_watchlist_entry",
        object_id=str(entry.id),
        metadata={"query": entry.query},
    )
    session.commit()
    session.refresh(entry)
    return CveProductWatchlistRead.model_validate(entry)


@router.delete("/threat-intel/product-watchlist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_cve_product_watchlist_entry(
    entry_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> None:
    deleted = delete_product_watchlist_entry(session, entry_id=entry_id, tenant_id=tenant_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="product watchlist entry not found")
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.product_watchlist.deleted",
        object_type="cve_product_watchlist_entry",
        object_id=str(entry_id),
        metadata={},
    )
    session.commit()


@router.get("/threat-intel/{record_id}", response_model=ThreatIntelRecordRead)
def get_threat_intel_record(
    record_id: UUID,
    session: Session = Depends(get_session),
) -> ThreatIntelRecordRead:
    record = load_threat_intel_record(session, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="threat intel record not found")
    return ThreatIntelRecordRead.model_validate(record)
