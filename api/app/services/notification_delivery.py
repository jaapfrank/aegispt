from __future__ import annotations

import smtplib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Callable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import AssessmentChain, Finding, InstanceSetting, Run
from api.app.services.audit import write_audit_event
from api.app.services.secrets import decrypt_secret_value
from api.app.services.settings import tenant_scope_key

NOTIFICATION_EVENT_CRITICAL_FINDING = "critical_finding"
NOTIFICATION_EVENT_RUN_COMPLETION = "run_completion"
NOTIFICATION_EVENT_PHASE_APPROVAL_NEEDED = "phase_approval_needed"

NOTIFICATION_SOURCE = "aegispt-operator-notification"


@dataclass(frozen=True, slots=True)
class NotificationDeliveryReceipt:
    channel: str
    delivered: bool
    event_kind: str
    skipped: bool = False
    blocked: bool = False
    error: str | None = None
    http_status: int | None = None
    finding_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    assessment_chain_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class EmailNotificationConfig:
    enabled: bool
    host: str
    port: int
    sender: str
    recipients: tuple[str, ...]
    username: str | None
    password: str | None
    use_tls: bool


@dataclass(frozen=True, slots=True)
class NotificationConfig:
    tenant_key: str
    email: EmailNotificationConfig
    slack_webhook_url: str | None
    teams_webhook_url: str | None
    run_completion_enabled: bool
    phase_approval_needed_enabled: bool
    app_public_base_url: str
    timeout_seconds: float
    configuration_errors: dict[str, str]


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    event_kind: str
    subject: str
    summary: str
    details: tuple[tuple[str, str], ...]
    action_label: str | None = None
    action_url: str | None = None
    finding_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    assessment_chain_id: uuid.UUID | None = None


HttpPost = Callable[..., httpx.Response]
SmtpFactory = Callable[..., Any]


def deliver_critical_finding_notifications(
    *,
    session: Session,
    finding_ids: list[uuid.UUID],
    actor: str,
    settings: Settings,
    http_post: HttpPost | None = None,
    smtp_factory: SmtpFactory | None = None,
) -> list[NotificationDeliveryReceipt]:
    if not finding_ids:
        return []

    findings = list(
        session.scalars(
            select(Finding)
            .options(selectinload(Finding.run).selectinload(Run.engagement))
            .where(Finding.id.in_(finding_ids))
        )
    )
    receipts: list[NotificationDeliveryReceipt] = []
    for finding in findings:
        if str(finding.severity or "").lower() != "critical":
            continue
        run = finding.run
        if run is None:
            continue
        config = _load_notification_config(
            session=session,
            tenant_id=getattr(run.engagement, "tenant_id", None),
            settings=settings,
        )
        message = _critical_finding_message(finding=finding, config=config)
        receipts.extend(
            _deliver_message(
                session=session,
                config=config,
                message=message,
                actor=actor,
                http_post=http_post,
                smtp_factory=smtp_factory,
            )
        )
    return receipts


def deliver_run_completion_notifications(
    *,
    session: Session,
    run_id: uuid.UUID,
    actor: str,
    settings: Settings,
    http_post: HttpPost | None = None,
    smtp_factory: SmtpFactory | None = None,
) -> list[NotificationDeliveryReceipt]:
    run = session.scalar(
        select(Run)
        .options(selectinload(Run.engagement), selectinload(Run.profile), selectinload(Run.findings))
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )
    if run is None or run.status not in {"completed", "completed_with_errors"}:
        return []

    config = _load_notification_config(
        session=session,
        tenant_id=getattr(run.engagement, "tenant_id", None),
        settings=settings,
    )
    if not config.run_completion_enabled:
        return []
    message = _run_completion_message(run=run)
    return _deliver_message(
        session=session,
        config=config,
        message=message,
        actor=actor,
        http_post=http_post,
        smtp_factory=smtp_factory,
    )


def deliver_phase_approval_needed_notifications(
    *,
    session: Session,
    chain_id: uuid.UUID,
    actor: str,
    settings: Settings,
    http_post: HttpPost | None = None,
    smtp_factory: SmtpFactory | None = None,
) -> list[NotificationDeliveryReceipt]:
    chain = session.scalar(
        select(AssessmentChain)
        .options(selectinload(AssessmentChain.engagement))
        .where(AssessmentChain.id == chain_id)
    )
    if chain is None or chain.status != "pending_phase_approval":
        return []

    config = _load_notification_config(
        session=session,
        tenant_id=getattr(chain.engagement, "tenant_id", None),
        settings=settings,
    )
    if not config.phase_approval_needed_enabled:
        return []
    message = _phase_approval_needed_message(chain=chain, config=config)
    return _deliver_message(
        session=session,
        config=config,
        message=message,
        actor=actor,
        http_post=http_post,
        smtp_factory=smtp_factory,
    )


def _load_notification_config(
    *,
    session: Session,
    tenant_id: str | None,
    settings: Settings,
) -> NotificationConfig:
    tenant_key = tenant_scope_key(tenant_id)
    rows = {
        row.setting_key: row
        for row in session.scalars(select(InstanceSetting).where(InstanceSetting.tenant_id == tenant_key)).all()
    }
    errors: dict[str, str] = {}

    def plain(key: str, default: Any = None) -> Any:
        row = rows.get(key)
        if row is None or row.sensitive:
            return default
        value_json = row.value_json if isinstance(row.value_json, dict) else {}
        return value_json.get("value", default)

    def sensitive(key: str, *, channel: str) -> str | None:
        row = rows.get(key)
        if row is None or not row.sensitive or not row.encrypted_value:
            return None
        try:
            return decrypt_secret_value(
                row.encrypted_value,
                settings,
                storage_backend=row.storage_backend or "encrypted_local",
            )
        except Exception as exc:  # pragma: no cover - corrupted local state guard
            errors[channel] = f"could not decrypt {key}: {exc}"
            return None

    recipients = _string_list(plain("notifications.smtp_to", getattr(settings, "settings_smtp_to", "")))
    email = EmailNotificationConfig(
        enabled=_bool(
            plain(
                "notifications.email_enabled",
                getattr(settings, "settings_email_notifications_enabled", False),
            )
        ),
        host=str(plain("notifications.smtp_host", getattr(settings, "settings_smtp_host", "")) or "").strip(),
        port=_bounded_port(plain("notifications.smtp_port", getattr(settings, "settings_smtp_port", 587))),
        sender=str(plain("notifications.smtp_from", getattr(settings, "settings_smtp_from", "")) or "").strip(),
        recipients=tuple(recipients),
        username=_optional_string(
            plain("notifications.smtp_username", getattr(settings, "settings_smtp_username", None))
        ),
        password=sensitive("notifications.smtp_password", channel="email"),
        use_tls=_bool(plain("notifications.smtp_use_tls", getattr(settings, "settings_smtp_use_tls", True))),
    )
    return NotificationConfig(
        tenant_key=tenant_key,
        email=email,
        slack_webhook_url=sensitive("integrations.slack_webhook_url", channel="slack"),
        teams_webhook_url=sensitive("integrations.teams_webhook_url", channel="teams"),
        run_completion_enabled=_bool(
            plain("notifications.run_completion", getattr(settings, "settings_notify_on_run_completion", False))
        ),
        phase_approval_needed_enabled=_bool(
            plain(
                "notifications.phase_approval_needed",
                getattr(settings, "settings_notify_on_phase_approval_needed", True),
            )
        ),
        app_public_base_url=str(settings.app_public_base_url or "http://127.0.0.1:8000").rstrip("/"),
        timeout_seconds=float(
            plain(
                "notifications.delivery_timeout_seconds",
                getattr(settings, "settings_notification_timeout_seconds", 10.0),
            )
            or 10.0
        ),
        configuration_errors=errors,
    )


def _deliver_message(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    http_post: HttpPost | None,
    smtp_factory: SmtpFactory | None,
) -> list[NotificationDeliveryReceipt]:
    receipts: list[NotificationDeliveryReceipt] = []
    if config.email.enabled or _email_has_partial_configuration(config.email):
        receipts.append(
            _deliver_email(
                session=session,
                config=config,
                message=message,
                actor=actor,
                smtp_factory=smtp_factory,
            )
        )
    if config.slack_webhook_url or "slack" in config.configuration_errors:
        receipts.append(
            _deliver_slack(
                session=session,
                config=config,
                message=message,
                actor=actor,
                http_post=http_post,
            )
        )
    if config.teams_webhook_url or "teams" in config.configuration_errors:
        receipts.append(
            _deliver_teams(
                session=session,
                config=config,
                message=message,
                actor=actor,
                http_post=http_post,
            )
        )
    return receipts


def _deliver_email(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    smtp_factory: SmtpFactory | None,
) -> NotificationDeliveryReceipt:
    channel = "email"
    if config.configuration_errors.get(channel):
        return _blocked_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=config.configuration_errors[channel],
        )
    missing = _missing_email_fields(config.email)
    if missing:
        return _blocked_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=f"email notification is missing required setting(s): {', '.join(missing)}",
        )

    email_message = EmailMessage()
    email_message["Subject"] = message.subject
    email_message["From"] = config.email.sender
    email_message["To"] = ", ".join(config.email.recipients)
    email_message.set_content(_plain_text_body(message))
    factory = smtp_factory or smtplib.SMTP
    try:
        with factory(config.email.host, config.email.port, timeout=config.timeout_seconds) as smtp:
            if config.email.use_tls:
                smtp.starttls()
            if config.email.username or config.email.password:
                smtp.login(config.email.username or "", config.email.password or "")
            smtp.send_message(email_message)
    except Exception as exc:  # pragma: no cover - exercised through tests with local fakes
        return _failed_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=f"email delivery failed: {exc}",
        )

    return _delivered_receipt(session=session, config=config, message=message, actor=actor, channel=channel)


def _deliver_slack(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    http_post: HttpPost | None,
) -> NotificationDeliveryReceipt:
    channel = "slack"
    if config.configuration_errors.get(channel):
        return _blocked_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=config.configuration_errors[channel],
        )
    if not config.slack_webhook_url:
        return _skipped_receipt(message=message, channel=channel)
    payload = _slack_payload(message)
    return _post_json_webhook(
        session=session,
        config=config,
        message=message,
        actor=actor,
        channel=channel,
        url=config.slack_webhook_url,
        payload=payload,
        http_post=http_post,
    )


def _deliver_teams(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    http_post: HttpPost | None,
) -> NotificationDeliveryReceipt:
    channel = "teams"
    if config.configuration_errors.get(channel):
        return _blocked_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=config.configuration_errors[channel],
        )
    if not config.teams_webhook_url:
        return _skipped_receipt(message=message, channel=channel)
    payload = _teams_payload(message)
    return _post_json_webhook(
        session=session,
        config=config,
        message=message,
        actor=actor,
        channel=channel,
        url=config.teams_webhook_url,
        payload=payload,
        http_post=http_post,
    )


def _post_json_webhook(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    channel: str,
    url: str,
    payload: dict[str, Any],
    http_post: HttpPost | None,
) -> NotificationDeliveryReceipt:
    sender = http_post or httpx.post
    try:
        response = sender(
            url,
            json=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-AegisPT-Event": message.event_kind,
            },
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )
    except Exception as exc:
        return _failed_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=f"{channel} delivery failed: {exc}",
        )
    if response.status_code >= 400:
        return _failed_receipt(
            session=session,
            config=config,
            message=message,
            actor=actor,
            channel=channel,
            error=f"{channel} delivery failed with HTTP {response.status_code}",
            http_status=response.status_code,
        )
    return _delivered_receipt(
        session=session,
        config=config,
        message=message,
        actor=actor,
        channel=channel,
        http_status=response.status_code,
    )


def _critical_finding_message(*, finding: Finding, config: NotificationConfig) -> NotificationMessage:
    finding_url = f"{config.app_public_base_url}/app/?finding_id={finding.id}"
    autofix = finding.autofix_json if isinstance(finding.autofix_json, dict) else {}
    remediation = str(
        autofix.get("remediation_summary")
        or autofix.get("suggested_fix")
        or autofix.get("summary")
        or ""
    ).strip() or (
        "Review the Finding Theater evidence and apply the remediation guidance recorded with this finding."
    )
    return NotificationMessage(
        event_kind=NOTIFICATION_EVENT_CRITICAL_FINDING,
        subject=f"[AegisPT] Critical finding: {finding.title}",
        summary=f"Critical finding on {finding.target_id}: {finding.summary or finding.title}",
        details=(
            ("Severity", str(finding.severity or "critical")),
            ("Target", str(finding.target_id or "unknown")),
            ("Finding ID", str(finding.id)),
            ("Remediation", remediation),
        ),
        action_label="Open finding",
        action_url=finding_url,
        finding_id=finding.id,
        run_id=finding.run_id,
    )


def _run_completion_message(*, run: Run) -> NotificationMessage:
    findings = list(run.findings or [])
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.severity or "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    severity_summary = ", ".join(f"{key}: {value}" for key, value in sorted(severity_counts.items())) or "none"
    profile_name = getattr(run.profile, "name", None) or "assessment run"
    return NotificationMessage(
        event_kind=NOTIFICATION_EVENT_RUN_COMPLETION,
        subject=f"[AegisPT] Run {str(run.id)[:8]} {run.status}",
        summary=f"{profile_name} finished with status {run.status}.",
        details=(
            ("Run ID", str(run.id)),
            ("Status", str(run.status)),
            ("Findings", str(len(findings))),
            ("Severity counts", severity_summary),
        ),
        run_id=run.id,
    )


def _phase_approval_needed_message(*, chain: AssessmentChain, config: NotificationConfig) -> NotificationMessage:
    phase = _pending_approval_phase(chain)
    previous_phase = _previous_completed_phase(chain, phase)
    phase_label = _phase_label(phase)
    phase_key = str(phase.get("key") or phase.get("id") or phase.get("slug") or chain.current_phase_index)
    approval_url = f"{config.app_public_base_url}/app/?assessment_chain_id={chain.id}&phase={phase_key}"
    previous_label = _phase_label(previous_phase) if previous_phase else "Previous phase"
    summary = f"{previous_label} completed; {phase_label} is waiting for operator approval."
    return NotificationMessage(
        event_kind=NOTIFICATION_EVENT_PHASE_APPROVAL_NEEDED,
        subject=f"[AegisPT] Phase approval needed: {phase_label}",
        summary=summary,
        details=(
            ("Assessment mode", str(chain.assessment_mode or "assessment chain")),
            ("Current phase", phase_label),
            ("Chain ID", str(chain.id)),
            ("Approval required", "yes"),
        ),
        action_label="Open phase approval",
        action_url=approval_url,
        assessment_chain_id=chain.id,
        run_id=chain.current_run_id or chain.last_completed_run_id,
    )


def _slack_payload(message: NotificationMessage) -> dict[str, Any]:
    fields = [
        {"type": "mrkdwn", "text": f"*{label}*\n{value}"}
        for label, value in message.details[:10]
    ]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": message.subject[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": message.summary}},
    ]
    if fields:
        blocks.append({"type": "section", "fields": fields})
    if message.action_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": message.action_label or "Open in AegisPT"},
                        "url": message.action_url,
                    }
                ],
            }
        )
    return {
        "text": f"{message.subject}: {message.summary}",
        "blocks": blocks,
        "metadata": _message_metadata(message),
    }


def _teams_payload(message: NotificationMessage) -> dict[str, Any]:
    facts = [{"title": label, "value": value} for label, value in message.details[:10]]
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": message.subject, "wrap": True},
        {"type": "TextBlock", "text": message.summary, "wrap": True},
    ]
    if facts:
        body.append({"type": "FactSet", "facts": facts})
    actions = []
    if message.action_url:
        actions.append(
            {
                "type": "Action.OpenUrl",
                "title": message.action_label or "Open in AegisPT",
                "url": message.action_url,
            }
        )
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": actions,
                    "metadata": _message_metadata(message),
                },
            }
        ],
    }


def _plain_text_body(message: NotificationMessage) -> str:
    lines = [
        message.subject,
        "",
        message.summary,
        "",
        *[f"{label}: {value}" for label, value in message.details],
    ]
    if message.action_url:
        lines.extend(["", f"{message.action_label or 'Open in AegisPT'}: {message.action_url}"])
    return "\n".join(lines)


def _message_metadata(message: NotificationMessage) -> dict[str, Any]:
    return {
        "source": NOTIFICATION_SOURCE,
        "event_kind": message.event_kind,
        "finding_id": str(message.finding_id) if message.finding_id else None,
        "run_id": str(message.run_id) if message.run_id else None,
        "assessment_chain_id": str(message.assessment_chain_id) if message.assessment_chain_id else None,
    }


def _delivered_receipt(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    channel: str,
    http_status: int | None = None,
) -> NotificationDeliveryReceipt:
    receipt = NotificationDeliveryReceipt(
        channel=channel,
        delivered=True,
        event_kind=message.event_kind,
        http_status=http_status,
        finding_id=message.finding_id,
        run_id=message.run_id,
        assessment_chain_id=message.assessment_chain_id,
    )
    _write_delivery_audit(
        session=session,
        config=config,
        message=message,
        actor=actor,
        channel=channel,
        receipt=receipt,
    )
    return receipt


def _failed_receipt(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    channel: str,
    error: str,
    http_status: int | None = None,
) -> NotificationDeliveryReceipt:
    receipt = NotificationDeliveryReceipt(
        channel=channel,
        delivered=False,
        event_kind=message.event_kind,
        error=error[:1000],
        http_status=http_status,
        finding_id=message.finding_id,
        run_id=message.run_id,
        assessment_chain_id=message.assessment_chain_id,
    )
    _write_delivery_audit(
        session=session,
        config=config,
        message=message,
        actor=actor,
        channel=channel,
        receipt=receipt,
    )
    return receipt


def _blocked_receipt(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    channel: str,
    error: str,
) -> NotificationDeliveryReceipt:
    receipt = NotificationDeliveryReceipt(
        channel=channel,
        delivered=False,
        event_kind=message.event_kind,
        blocked=True,
        error=error[:1000],
        finding_id=message.finding_id,
        run_id=message.run_id,
        assessment_chain_id=message.assessment_chain_id,
    )
    _write_delivery_audit(
        session=session,
        config=config,
        message=message,
        actor=actor,
        channel=channel,
        receipt=receipt,
    )
    return receipt


def _skipped_receipt(*, message: NotificationMessage, channel: str) -> NotificationDeliveryReceipt:
    return NotificationDeliveryReceipt(
        channel=channel,
        delivered=False,
        event_kind=message.event_kind,
        skipped=True,
        finding_id=message.finding_id,
        run_id=message.run_id,
        assessment_chain_id=message.assessment_chain_id,
    )


def _write_delivery_audit(
    *,
    session: Session,
    config: NotificationConfig,
    message: NotificationMessage,
    actor: str,
    channel: str,
    receipt: NotificationDeliveryReceipt,
) -> None:
    object_type = "notification_event"
    object_id = str(message.finding_id or message.run_id or message.assessment_chain_id or message.event_kind)
    status = "delivered" if receipt.delivered else ("blocked" if receipt.blocked else "failed")
    write_audit_event(
        session=session,
        actor=actor,
        action=f"notification.delivery.{status}",
        object_type=object_type,
        object_id=object_id,
        metadata={
            "tenant_id": config.tenant_key,
            "source": NOTIFICATION_SOURCE,
            "channel": channel,
            "event_kind": message.event_kind,
            "http_status": receipt.http_status,
            "error": receipt.error,
            "finding_id": str(message.finding_id) if message.finding_id else None,
            "run_id": str(message.run_id) if message.run_id else None,
            "assessment_chain_id": str(message.assessment_chain_id) if message.assessment_chain_id else None,
            "external_delivery_attempted": not receipt.blocked,
            "sensitive_plaintext_exposed": False,
        },
    )


def _missing_email_fields(config: EmailNotificationConfig) -> list[str]:
    missing = []
    if not config.enabled:
        missing.append("notifications.email_enabled")
    if not config.host:
        missing.append("notifications.smtp_host")
    if not config.sender:
        missing.append("notifications.smtp_from")
    if not config.recipients:
        missing.append("notifications.smtp_to")
    return missing


def _email_has_partial_configuration(config: EmailNotificationConfig) -> bool:
    return any((config.enabled, config.host, config.sender, config.recipients, config.username, config.password))


def _pending_approval_phase(chain: AssessmentChain) -> dict[str, Any]:
    phases = [phase for phase in list(chain.phases_json or []) if isinstance(phase, dict)]
    for phase in phases:
        if phase.get("status") == "pending_approval":
            return phase
    if 0 <= chain.current_phase_index < len(phases):
        return phases[chain.current_phase_index]
    return phases[-1] if phases else {}


def _previous_completed_phase(chain: AssessmentChain, current_phase: dict[str, Any]) -> dict[str, Any] | None:
    phases = [phase for phase in list(chain.phases_json or []) if isinstance(phase, dict)]
    try:
        index = phases.index(current_phase)
    except ValueError:
        index = chain.current_phase_index
    for phase in reversed(phases[: max(index, 0)]):
        if str(phase.get("status") or "").startswith("completed"):
            return phase
    return None


def _phase_label(phase: dict[str, Any] | None) -> str:
    if not isinstance(phase, dict):
        return "Assessment phase"
    return str(phase.get("label") or phase.get("name") or phase.get("key") or "Assessment phase")


def _optional_string(value: Any) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _bounded_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 587
    return port if 1 <= port <= 65535 else 587


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value or "").split(",") if item.strip()]
