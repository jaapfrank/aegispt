from __future__ import annotations

import re
from uuid import UUID

from fastapi import Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Engagement, EvidenceArtifact, Finding, InventorySnapshot, Run, Task

TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")


def get_current_tenant_id(x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> str | None:
    return normalize_tenant_id(x_tenant_id)


def normalize_tenant_id(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if not TENANT_ID_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=400, detail="invalid X-Tenant-ID header")
    return normalized


def resolve_created_tenant_id(payload_tenant_id: str | None, header_tenant_id: str | None) -> str | None:
    payload_value = normalize_tenant_id(payload_tenant_id)
    if header_tenant_id is not None and payload_value is not None and header_tenant_id != payload_value:
        raise HTTPException(status_code=409, detail="payload tenant_id does not match X-Tenant-ID")
    return header_tenant_id or payload_value


def engagement_query_for_tenant(session: Session, tenant_id: str | None):
    query = (
        select(Engagement)
        .where(Engagement.deleted_at.is_(None))
        .order_by(Engagement.created_at.desc(), Engagement.id.desc())
    )
    if tenant_id is not None:
        query = query.where(Engagement.tenant_id == tenant_id)
    return query


def assert_engagement_tenant(engagement: Engagement, tenant_id: str | None) -> None:
    if engagement.deleted_at is not None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if tenant_id is not None and engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="engagement not found")


def load_engagement_for_tenant(session: Session, engagement_id: UUID, tenant_id: str | None) -> Engagement:
    engagement = session.scalar(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    assert_engagement_tenant(engagement, tenant_id)
    return engagement


def assert_run_tenant(run: Run, tenant_id: str | None) -> None:
    if run.deleted_at is not None:
        raise HTTPException(status_code=404, detail="run not found")
    if run.engagement is None:
        raise HTTPException(status_code=404, detail="run not found")
    if run.engagement.deleted_at is not None:
        raise HTTPException(status_code=404, detail="run not found")
    if tenant_id is not None and run.engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="run not found")


def assert_finding_tenant(finding: Finding, tenant_id: str | None) -> None:
    if finding.run is None:
        if tenant_id is None:
            return
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.run.engagement is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.run.deleted_at is not None or finding.run.engagement.deleted_at is not None:
        raise HTTPException(status_code=404, detail="finding not found")
    if tenant_id is not None and finding.run.engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="finding not found")


def assert_inventory_tenant(snapshot: InventorySnapshot, tenant_id: str | None) -> None:
    if snapshot.engagement is None or snapshot.engagement.deleted_at is not None:
        raise HTTPException(status_code=404, detail="inventory snapshot not found")
    if tenant_id is not None and snapshot.engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="inventory snapshot not found")


def assert_task_tenant(task: Task, tenant_id: str | None) -> None:
    if task.run is None or task.run.engagement is None:
        raise HTTPException(status_code=404, detail="task not found")
    if task.run.deleted_at is not None or task.run.engagement.deleted_at is not None:
        raise HTTPException(status_code=404, detail="task not found")
    if tenant_id is not None and task.run.engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="task not found")


def assert_artifact_tenant(artifact: EvidenceArtifact, tenant_id: str | None) -> None:
    execution = artifact.execution
    task = execution.task if execution is not None else None
    run = task.run if task is not None else None
    engagement = run.engagement if run is not None else None
    if engagement is None or run is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    if run.deleted_at is not None or engagement.deleted_at is not None:
        raise HTTPException(status_code=404, detail="artifact not found")
    if tenant_id is not None and engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="artifact not found")
