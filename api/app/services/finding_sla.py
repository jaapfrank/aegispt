from __future__ import annotations

from datetime import UTC, datetime, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import Engagement, Finding, Run
from api.app.services.settings import read_instance_settings

SLA_SETTING_DEFAULTS = {
    "critical": ("remediation.sla_days_critical", 1),
    "high": ("remediation.sla_days_high", 7),
    "medium": ("remediation.sla_days_medium", 30),
    "low": ("remediation.sla_days_low", 90),
}
SLA_CLOSED_STATUSES = {"resolved", "false_positive", "accepted_risk"}


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _severity(value: str | None) -> str:
    return str(value or "unknown").strip().lower()


def tenant_id_for_finding(session: Session, finding: Finding) -> str | None:
    run = getattr(finding, "run", None)
    engagement = getattr(run, "engagement", None)
    if engagement is not None:
        return engagement.tenant_id
    if finding.run_id is None:
        return None
    return session.scalar(
        select(Engagement.tenant_id).join(Run, Engagement.id == Run.engagement_id).where(Run.id == finding.run_id)
    )


def sla_days_by_severity(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
) -> dict[str, int | None]:
    values: dict[str, object] = {}
    settings_read = read_instance_settings(session, tenant_id=tenant_id, settings=settings)
    for section in settings_read.sections:
        for setting in section.settings:
            values[setting.key] = setting.value

    days: dict[str, int | None] = {"info": None, "unknown": None}
    for severity, (key, default) in SLA_SETTING_DEFAULTS.items():
        value = values.get(key, default)
        try:
            normalized = int(value)
        except (TypeError, ValueError):
            normalized = default
        days[severity] = max(1, normalized)
    return days


def apply_finding_sla(
    session: Session,
    finding: Finding,
    *,
    settings: Settings,
    generated_at: datetime | None = None,
    tenant_id: str | None = None,
) -> bool:
    changed = False
    now = _utc(generated_at)
    severity = _severity(finding.severity)
    due_date = finding.remediation_due_date

    if due_date is None:
        effective_tenant_id = tenant_id if tenant_id is not None else tenant_id_for_finding(session, finding)
        days = sla_days_by_severity(session, tenant_id=effective_tenant_id, settings=settings).get(severity)
        if days is not None:
            finding.remediation_due_date = _utc(finding.created_at) + timedelta(days=days)
            due_date = finding.remediation_due_date
            changed = True

    breached = False
    if due_date is not None and str(finding.status or "").strip().lower() not in SLA_CLOSED_STATUSES:
        breached = now > _utc(due_date)

    if bool(finding.sla_breached) != breached:
        finding.sla_breached = breached
        changed = True
    return changed


def apply_findings_sla(
    session: Session,
    findings: list[Finding],
    *,
    settings: Settings,
    generated_at: datetime | None = None,
    tenant_id: str | None = None,
) -> bool:
    changed = False
    for finding in findings:
        if apply_finding_sla(
            session,
            finding,
            settings=settings,
            generated_at=generated_at,
            tenant_id=tenant_id,
        ):
            changed = True
    return changed
