from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import InstanceSetting
from api.app.schemas.deception import (
    DeceptionAlertRead,
    DeceptionBoundaryRead,
    DeceptionProbeRead,
    DeceptionTrapCreate,
    DeceptionTrapRead,
)
from api.app.services.audit import write_audit_event

DEFAULT_TENANT = "default"
TRAPS_SETTING_KEY = "deception.traps"
ALERTS_SETTING_KEY = "deception.alerts"
MAX_ALERT_HISTORY = 100


def _tenant_id(value: str | None) -> str:
    return value or DEFAULT_TENANT


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _boundary() -> dict[str, bool]:
    return DeceptionBoundaryRead().model_dump()


def _setting(session: Session, *, tenant_id: str, key: str) -> InstanceSetting | None:
    return session.scalar(
        select(InstanceSetting).where(
            InstanceSetting.tenant_id == tenant_id,
            InstanceSetting.setting_key == key,
        )
    )


def _read_records(session: Session, *, tenant_id: str, key: str) -> list[dict[str, Any]]:
    setting = _setting(session, tenant_id=tenant_id, key=key)
    if setting is None:
        return []
    value = setting.value_json if isinstance(setting.value_json, dict) else {}
    records = value.get("records")
    if isinstance(records, list):
        return [record for record in records if isinstance(record, dict)]
    return []


def _write_records(
    session: Session,
    *,
    tenant_id: str,
    key: str,
    records: list[dict[str, Any]],
    actor: str,
) -> None:
    setting = _setting(session, tenant_id=tenant_id, key=key)
    value = {"records": records, "updated_at": _iso(_now())}
    if setting is None:
        session.add(
            InstanceSetting(
                tenant_id=tenant_id,
                setting_key=key,
                value_json=value,
                sensitive=False,
                display_label=key,
                metadata_json={
                    "managed_by": "deception_fixture_service",
                    "local_controlled_fixture": True,
                },
                created_by=actor,
                updated_by=actor,
            )
        )
        return
    setting.value_json = value
    setting.updated_by = actor


def _endpoint_path(trap_id: str) -> str:
    return f"/api/v1/deception/traps/{trap_id}/probe"


def _build_payload(trap: dict[str, Any], *, depth: int) -> tuple[dict[str, Any], str | None]:
    max_depth = int(trap["max_depth"])
    trap_id = str(trap["id"])
    next_depth = depth + 1
    next_path = f"{_endpoint_path(trap_id)}?depth={next_depth}" if next_depth <= max_depth else None
    base = {
        "fixture": "aegispt-local-deception",
        "trap_id": trap_id,
        "depth": depth,
        "max_depth": max_depth,
        "bounded": True,
        "local_controlled_fixture": True,
        "next": next_path,
    }
    kind = trap["trap_kind"]
    if kind == "fake_admin_api":
        base.update(
            {
                "resource": "admin-console-shadow-index",
                "records": [
                    {
                        "id": f"admin-shadow-{depth}",
                        "label": "decoy privileged workflow",
                        "confidence": "deception-fixture",
                    }
                ],
                "warning": "No credential material or live administrative data is present in this fixture.",
            }
        )
    elif kind == "canary_document":
        base.update(
            {
                "document": {
                    "title": "Synthetic Review Notes",
                    "classification": "decoy",
                    "canary_ref": f"deception:{trap_id}:{depth}",
                },
                "warning": "This controlled document is synthetic and not customer evidence.",
            }
        )
    else:
        base.update(
            {
                "resource": "recursive-api-map",
                "routes": [
                    {"path": next_path, "relationship": "bounded-recursive-pointer"},
                ]
                if next_path
                else [],
                "warning": "Recursive links are bounded and do not perform network-level tarpitting.",
            }
        )
    return base, next_path


def _trap_read(record: dict[str, Any]) -> DeceptionTrapRead:
    return DeceptionTrapRead(
        id=UUID(str(record["id"])),
        tenant_id=str(record["tenant_id"]),
        name=str(record["name"]),
        trap_kind=record["trap_kind"],
        enabled=bool(record["enabled"]),
        local_only=bool(record["local_only"]),
        max_depth=int(record["max_depth"]),
        endpoint_path=str(record["endpoint_path"]),
        response_preview=dict(record["response_preview"]),
        boundary=DeceptionBoundaryRead(**dict(record["boundary"])),
        operator_note=record.get("operator_note"),
        created_at=_parse_datetime(record["created_at"]),
        updated_at=_parse_datetime(record["updated_at"]),
        created_by=str(record["created_by"]),
        updated_by=str(record["updated_by"]),
    )


def _alert_read(record: dict[str, Any]) -> DeceptionAlertRead:
    return DeceptionAlertRead(
        id=UUID(str(record["id"])),
        tenant_id=str(record["tenant_id"]),
        trap_id=UUID(str(record["trap_id"])),
        trap_name=str(record["trap_name"]),
        trap_kind=record["trap_kind"],
        probed_path=str(record["probed_path"]),
        actor=str(record["actor"]),
        user_agent=record.get("user_agent"),
        source=str(record.get("source") or "local_controlled_probe"),
        created_at=_parse_datetime(record["created_at"]),
        evidence_ref=str(record["evidence_ref"]),
        boundary=DeceptionBoundaryRead(**dict(record["boundary"])),
    )


def list_deception_traps(session: Session, *, tenant_id: str | None) -> list[DeceptionTrapRead]:
    records = _read_records(session, tenant_id=_tenant_id(tenant_id), key=TRAPS_SETTING_KEY)
    return [_trap_read(record) for record in records]


def create_deception_trap(
    session: Session,
    *,
    tenant_id: str | None,
    payload: DeceptionTrapCreate,
    actor: str,
) -> DeceptionTrapRead:
    if not payload.local_only:
        raise HTTPException(status_code=422, detail="deception traps must remain local_only controlled fixtures")

    tenant = _tenant_id(tenant_id)
    trap_id = str(uuid4())
    created_at = _now()
    record: dict[str, Any] = {
        "id": trap_id,
        "tenant_id": tenant,
        "name": payload.name.strip(),
        "trap_kind": payload.trap_kind,
        "enabled": payload.enabled,
        "local_only": True,
        "max_depth": payload.max_depth,
        "endpoint_path": _endpoint_path(trap_id),
        "boundary": _boundary(),
        "operator_note": payload.operator_note,
        "created_at": _iso(created_at),
        "updated_at": _iso(created_at),
        "created_by": actor,
        "updated_by": actor,
    }
    preview, _ = _build_payload(record, depth=0)
    record["response_preview"] = preview

    records = _read_records(session, tenant_id=tenant, key=TRAPS_SETTING_KEY)
    records.append(record)
    _write_records(session, tenant_id=tenant, key=TRAPS_SETTING_KEY, records=records, actor=actor)
    write_audit_event(
        session,
        actor=actor,
        action="deception.trap.created",
        object_type="deception_trap",
        object_id=trap_id,
        metadata={
            "tenant_id": tenant,
            "trap_kind": payload.trap_kind,
            "local_only": True,
            "automatic_live_deployment": False,
            "network_tarpitting": False,
            "dispatches_runtime_work": False,
        },
    )
    return _trap_read(record)


def record_deception_probe(
    session: Session,
    *,
    tenant_id: str | None,
    trap_id: UUID,
    actor: str,
    probed_path: str,
    user_agent: str | None,
    depth: int,
) -> DeceptionProbeRead:
    tenant = _tenant_id(tenant_id)
    records = _read_records(session, tenant_id=tenant, key=TRAPS_SETTING_KEY)
    trap = next((record for record in records if str(record.get("id")) == str(trap_id)), None)
    if trap is None or not bool(trap.get("enabled", True)):
        raise HTTPException(status_code=404, detail="deception trap not found")

    safe_depth = max(0, min(depth, int(trap["max_depth"])))
    payload, next_path = _build_payload(trap, depth=safe_depth)
    alert_id = str(uuid4())
    created_at = _now()
    alert = {
        "id": alert_id,
        "tenant_id": tenant,
        "trap_id": str(trap_id),
        "trap_name": trap["name"],
        "trap_kind": trap["trap_kind"],
        "probed_path": probed_path,
        "actor": actor,
        "user_agent": user_agent,
        "source": "local_controlled_probe",
        "created_at": _iso(created_at),
        "evidence_ref": f"deception-alert:{alert_id}",
        "boundary": _boundary(),
    }
    alerts = _read_records(session, tenant_id=tenant, key=ALERTS_SETTING_KEY)
    _write_records(
        session,
        tenant_id=tenant,
        key=ALERTS_SETTING_KEY,
        records=([alert] + alerts)[:MAX_ALERT_HISTORY],
        actor=actor,
    )
    write_audit_event(
        session,
        actor=actor,
        action="deception.trap.probed",
        object_type="deception_trap",
        object_id=str(trap_id),
        metadata={
            "tenant_id": tenant,
            "alert_id": alert_id,
            "probed_path": probed_path,
            "local_controlled_fixture": True,
            "automatic_live_deployment": False,
            "network_tarpitting": False,
            "dispatches_runtime_work": False,
        },
    )
    return DeceptionProbeRead(
        trap_id=trap_id,
        trap_kind=trap["trap_kind"],
        name=str(trap["name"]),
        depth=safe_depth,
        max_depth=int(trap["max_depth"]),
        payload=payload,
        next_path=next_path,
        alert_id=UUID(alert_id),
        boundary=DeceptionBoundaryRead(**_boundary()),
    )


def list_deception_alerts(session: Session, *, tenant_id: str | None) -> list[DeceptionAlertRead]:
    records = _read_records(session, tenant_id=_tenant_id(tenant_id), key=ALERTS_SETTING_KEY)
    return [_alert_read(record) for record in records]
