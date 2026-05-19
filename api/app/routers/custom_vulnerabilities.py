from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.schemas.custom_vulnerabilities import (
    CustomVulnerabilityCreate,
    CustomVulnerabilityEngagementToggleCreate,
    CustomVulnerabilityExportRead,
    CustomVulnerabilityImportCreate,
    CustomVulnerabilityImportRead,
    CustomVulnerabilityListRead,
    CustomVulnerabilityPatch,
    CustomVulnerabilityRead,
    CustomVulnerabilityScanOptionRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.custom_vulnerabilities import (
    CustomVulnerabilityError,
    build_read_payload,
    build_scan_options,
    create_custom_vulnerability,
    export_custom_vulnerabilities,
    import_custom_vulnerabilities,
    list_custom_vulnerabilities,
    load_custom_vulnerability,
    set_custom_vulnerability_engagement_enabled,
    soft_delete_custom_vulnerability,
    update_custom_vulnerability,
)
from api.app.services.tenancy import get_current_tenant_id, load_engagement_for_tenant

router = APIRouter(prefix="/api/v1", tags=["custom-vulnerabilities"])


@router.get("/custom-vulnerabilities", response_model=CustomVulnerabilityListRead)
def list_custom_vulnerability_library(
    q: str | None = Query(default=None),
    product: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    include_deleted: bool = Query(default=False),
    engagement_id: UUID | None = Query(default=None),
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityListRead:
    if engagement_id is not None:
        load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        records = list_custom_vulnerabilities(
            session,
            tenant_id=tenant_id,
            query=q,
            product=product,
            severity=severity,
            status=status_filter,
            include_deleted=include_deleted,
            engagement_id=engagement_id,
        )
    except CustomVulnerabilityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CustomVulnerabilityListRead(
        items=[CustomVulnerabilityRead(**build_read_payload(session, record, engagement_id=engagement_id)) for record in records],
        total=len(records),
        filters={
            "q": q,
            "product": product,
            "severity": severity,
            "status": status_filter,
            "include_deleted": include_deleted,
            "engagement_id": str(engagement_id) if engagement_id else None,
        },
    )


@router.post(
    "/custom-vulnerabilities",
    response_model=CustomVulnerabilityRead,
    status_code=status.HTTP_201_CREATED,
)
def create_custom_vulnerability_definition(
    payload: CustomVulnerabilityCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityRead:
    try:
        record = create_custom_vulnerability(
            session,
            tenant_id=tenant_id,
            payload=payload.model_dump(),
            actor=actor,
        )
    except CustomVulnerabilityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="custom_vulnerability.created",
        object_type="custom_vulnerability",
        object_id=str(record.id),
        metadata={
            "tenant_id": record.tenant_id,
            "custom_id": record.custom_id,
            "severity": record.severity,
            "pack_gate_bypassed": False,
        },
    )
    session.commit()
    return CustomVulnerabilityRead(**build_read_payload(session, record))


@router.get("/custom-vulnerabilities/{vulnerability_id:uuid}", response_model=CustomVulnerabilityRead)
def get_custom_vulnerability_definition(
    vulnerability_id: UUID,
    include_deleted: bool = Query(default=False),
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityRead:
    record = load_custom_vulnerability(
        session,
        vulnerability_id=vulnerability_id,
        tenant_id=tenant_id,
        include_deleted=include_deleted,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="custom vulnerability not found")
    return CustomVulnerabilityRead(**build_read_payload(session, record))


@router.patch("/custom-vulnerabilities/{vulnerability_id:uuid}", response_model=CustomVulnerabilityRead)
def update_custom_vulnerability_definition(
    vulnerability_id: UUID,
    payload: CustomVulnerabilityPatch,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityRead:
    record = load_custom_vulnerability(session, vulnerability_id=vulnerability_id, tenant_id=tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="custom vulnerability not found")
    try:
        updated = update_custom_vulnerability(
            session,
            record=record,
            patch=payload.model_dump(),
            fields_set=set(payload.model_fields_set),
        )
    except CustomVulnerabilityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="custom_vulnerability.updated",
        object_type="custom_vulnerability",
        object_id=str(updated.id),
        metadata={
            "custom_id": updated.custom_id,
            "fields": sorted(payload.model_fields_set),
            "pack_gate_bypassed": False,
        },
    )
    session.commit()
    return CustomVulnerabilityRead(**build_read_payload(session, updated))


@router.delete("/custom-vulnerabilities/{vulnerability_id:uuid}", response_model=CustomVulnerabilityRead)
def delete_custom_vulnerability_definition(
    vulnerability_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityRead:
    record = load_custom_vulnerability(session, vulnerability_id=vulnerability_id, tenant_id=tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="custom vulnerability not found")
    deleted = soft_delete_custom_vulnerability(session, record=record)
    write_audit_event(
        session=session,
        actor=actor,
        action="custom_vulnerability.deleted",
        object_type="custom_vulnerability",
        object_id=str(deleted.id),
        metadata={"custom_id": deleted.custom_id, "soft_delete": True},
    )
    session.commit()
    return CustomVulnerabilityRead(**build_read_payload(session, deleted))


@router.post(
    "/custom-vulnerabilities/import",
    response_model=CustomVulnerabilityImportRead,
    status_code=status.HTTP_201_CREATED,
)
def import_custom_vulnerability_definitions(
    payload: CustomVulnerabilityImportCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
    settings: Settings = Depends(get_settings),
) -> CustomVulnerabilityImportRead:
    if payload.engagement_id is not None:
        load_engagement_for_tenant(session, payload.engagement_id, tenant_id)
    try:
        imported = import_custom_vulnerabilities(
            session,
            tenant_id=tenant_id,
            import_format=payload.format,
            payload=payload.payload,
            default_status=payload.default_status,
            actor=actor,
            settings=settings,
            engagement_id=payload.engagement_id,
            use_ai=payload.use_ai,
        )
    except CustomVulnerabilityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="custom_vulnerability.imported",
        object_type="custom_vulnerability_batch",
        object_id=payload.format,
        metadata={
            "format": payload.format,
            "imported_count": imported["imported_count"],
            "updated_count": imported["updated_count"],
            "skipped_count": imported["skipped_count"],
            "ai_assistance": imported["ai_assistance"],
        },
    )
    session.commit()
    return CustomVulnerabilityImportRead(
        imported_count=imported["imported_count"],
        updated_count=imported["updated_count"],
        skipped_count=imported["skipped_count"],
        ai_assistance=imported["ai_assistance"],
        items=[CustomVulnerabilityRead(**build_read_payload(session, record)) for record in imported["items"]],
    )


@router.get("/custom-vulnerabilities/export", response_model=CustomVulnerabilityExportRead)
def export_custom_vulnerability_library(
    include_deleted: bool = Query(default=False),
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityExportRead:
    exported = export_custom_vulnerabilities(session, tenant_id=tenant_id, include_deleted=include_deleted)
    write_audit_event(
        session=session,
        actor=actor,
        action="custom_vulnerability.exported",
        object_type="custom_vulnerability_batch",
        object_id=exported["tenant_id"],
        metadata={"item_count": len(exported["items"]), "include_deleted": include_deleted},
    )
    session.commit()
    return CustomVulnerabilityExportRead(**exported)


@router.get(
    "/engagements/{engagement_id}/custom-vulnerabilities/scan-options",
    response_model=list[CustomVulnerabilityScanOptionRead],
)
def list_custom_vulnerability_scan_options(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[CustomVulnerabilityScanOptionRead]:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    return [
        CustomVulnerabilityScanOptionRead(**item)
        for item in build_scan_options(session, tenant_id=tenant_id, engagement_id=engagement_id)
    ]


@router.post(
    "/engagements/{engagement_id:uuid}/custom-vulnerabilities/{vulnerability_id:uuid}/toggle",
    response_model=CustomVulnerabilityRead,
)
def toggle_custom_vulnerability_for_engagement(
    engagement_id: UUID,
    vulnerability_id: UUID,
    payload: CustomVulnerabilityEngagementToggleCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CustomVulnerabilityRead:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    record = load_custom_vulnerability(session, vulnerability_id=vulnerability_id, tenant_id=tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail="custom vulnerability not found")
    set_custom_vulnerability_engagement_enabled(
        session,
        record=record,
        engagement_id=engagement_id,
        enabled=payload.enabled,
        actor=actor,
    )
    write_audit_event(
        session=session,
        actor=actor,
        action="custom_vulnerability.engagement_setting.updated",
        object_type="custom_vulnerability",
        object_id=str(record.id),
        metadata={
            "engagement_id": str(engagement_id),
            "custom_id": record.custom_id,
            "enabled": payload.enabled,
            "runtime_binding_required": True,
        },
    )
    session.commit()
    return CustomVulnerabilityRead(**build_read_payload(session, record, engagement_id=engagement_id))
