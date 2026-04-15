from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from api.app.models import AuditEvent


def write_audit_event(
    session: Session,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        metadata_json=metadata or {},
    )
    session.add(event)
    return event
