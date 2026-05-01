from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import Engagement, Finding, FindingIntegrationLink, IntegrationConfiguration, Run
from api.app.schemas.integrations import (
    IntegrationConfigurationRead,
    JiraFindingLinkRead,
    JiraFindingLinkUpsert,
    JiraIntegrationConfigurationUpsert,
    PortfolioIntegrationConfigurationUpsert,
    ProviderFindingHandoffRead,
    ProviderFindingHandoffRequest,
    RepositoryAuthorizationCompleteRead,
    RepositoryAuthorizationStartRead,
    RepositoryIntegrationRead,
    SiemIntegrationCollectionRead,
    SiemIntegrationConfigurationRead,
    SiemIntegrationConfigurationUpsert,
    WebhookFindingHandoffRead,
    WebhookFindingHandoffRequest,
    WebhookIntegrationConfigurationUpsert,
)
from api.app.services.audit import write_audit_event
from api.app.services.integrations import (
    IntegrationHandoffError,
    is_named_handoff_provider,
    named_handoff_provider_label,
    normalize_integration_provider,
    prepare_named_provider_handoff,
)
from api.app.services.jira import JiraSyncError, sync_jira_issue
from api.app.services.repository_integration import (
    RepositoryIntegrationError,
    complete_repository_authorization,
    list_repository_integrations,
    start_repository_authorization,
)
from api.app.services.siem_push import (
    SUPPORTED_SIEM_PROVIDERS,
    credential_configured_for_configuration,
    credential_display_label_for_configuration,
    is_siem_provider,
    normalize_siem_provider,
    siem_provider_label,
    store_or_update_siem_credential,
)
from api.app.services.tenancy import get_current_tenant_id, load_engagement_for_tenant
from api.app.services.webhooks import WebhookHandoffError, send_finding_webhook_handoff

router = APIRouter(prefix="/api/v1/engagements/{engagement_id}/integrations", tags=["integrations"])


def _ensure_engagement(session: Session, engagement_id: UUID) -> Engagement:
    engagement = session.scalar(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    return engagement


def _jira_configuration_query(engagement_id: UUID):
    return _integration_configuration_query(engagement_id, "jira")


def _webhook_configuration_query(engagement_id: UUID):
    return _integration_configuration_query(engagement_id, "webhook")


def _integration_configuration_query(engagement_id: UUID, integration_type: str):
    return select(IntegrationConfiguration).where(
        IntegrationConfiguration.engagement_id == engagement_id,
        IntegrationConfiguration.integration_type == integration_type,
    )


def _ensure_named_provider(provider: str) -> str:
    normalized = normalize_integration_provider(provider)
    if not is_named_handoff_provider(normalized):
        raise HTTPException(status_code=400, detail=f"unsupported integration provider: {provider}")
    return normalized


def _ensure_siem_provider(provider: str) -> str:
    normalized = normalize_siem_provider(provider)
    if not is_siem_provider(normalized):
        raise HTTPException(status_code=400, detail=f"unsupported SIEM provider: {provider}")
    return normalized


def _ensure_finding_for_engagement(session: Session, engagement_id: UUID, finding_id: UUID) -> Finding:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found for engagement")
    if finding.run_id is None:
        raise HTTPException(status_code=409, detail="finding has no source run engagement for Jira linking")

    run = session.scalar(select(Run).where(Run.id == finding.run_id, Run.deleted_at.is_(None)))
    if run is None:
        raise HTTPException(status_code=409, detail="source run not found for finding")
    if run.engagement_id != engagement_id:
        raise HTTPException(status_code=404, detail="finding not found for engagement")
    return finding


def _provider_handoff_read(provider: str, link: FindingIntegrationLink) -> ProviderFindingHandoffRead:
    return ProviderFindingHandoffRead(
        id=link.id,
        finding_id=link.finding_id,
        integration_configuration_id=link.integration_configuration_id,
        integration_type=provider,
        handoff_key=link.issue_key,
        handoff_url=link.issue_url,
        handoff_status=link.issue_status,
        last_sync_state=link.last_sync_state,
        last_synced_at=link.last_synced_at,
        last_sync_error=link.last_sync_error,
        last_sync_payload_json=dict(link.last_sync_payload_json or {}),
        created_by=link.created_by,
        updated_by=link.updated_by,
        created_at=link.created_at,
        updated_at=link.updated_at,
    )


def _siem_configuration_read(
    session: Session,
    configuration: IntegrationConfiguration,
) -> SiemIntegrationConfigurationRead:
    settings_json = configuration.settings_json if isinstance(configuration.settings_json, dict) else {}
    provider = _ensure_siem_provider(configuration.integration_type)
    return SiemIntegrationConfigurationRead(
        id=configuration.id,
        engagement_id=configuration.engagement_id,
        integration_type=provider,  # type: ignore[arg-type]
        provider_label=siem_provider_label(provider),
        display_name=configuration.display_name,
        base_url=configuration.base_url,
        enabled=bool(settings_json.get("enabled", True)),
        push_on_run_completion=bool(settings_json.get("push_on_run_completion", True)),
        push_on_critical_finding=bool(settings_json.get("push_on_critical_finding", True)),
        include_sigma=bool(settings_json.get("include_sigma", False)),
        index_name=(
            str(settings_json.get("index_name")).strip()
            if isinstance(settings_json.get("index_name"), str) and str(settings_json.get("index_name")).strip()
            else None
        ),
        sourcetype=(
            str(settings_json.get("sourcetype")).strip()
            if isinstance(settings_json.get("sourcetype"), str) and str(settings_json.get("sourcetype")).strip()
            else None
        ),
        custom_log_table=(
            str(settings_json.get("custom_log_table")).strip()
            if isinstance(settings_json.get("custom_log_table"), str)
            and str(settings_json.get("custom_log_table")).strip()
            else None
        ),
        stream_name=(
            str(settings_json.get("stream_name")).strip()
            if isinstance(settings_json.get("stream_name"), str) and str(settings_json.get("stream_name")).strip()
            else None
        ),
        timeout_seconds=(
            float(settings_json.get("timeout_seconds"))
            if isinstance(settings_json.get("timeout_seconds"), (int, float))
            else None
        ),
        credential_configured=credential_configured_for_configuration(session=session, configuration=configuration),
        credential_display_label=credential_display_label_for_configuration(
            session=session,
            configuration=configuration,
        ),
        token_exposed=False,
        created_by=configuration.created_by,
        updated_by=configuration.updated_by,
        created_at=configuration.created_at,
        updated_at=configuration.updated_at,
    )


def _webhook_handoff_read(link: FindingIntegrationLink) -> WebhookFindingHandoffRead:
    return WebhookFindingHandoffRead(
        id=link.id,
        finding_id=link.finding_id,
        integration_configuration_id=link.integration_configuration_id,
        handoff_key=link.issue_key,
        handoff_url=link.issue_url,
        handoff_status=link.issue_status,
        last_sync_state=link.last_sync_state,
        last_synced_at=link.last_synced_at,
        last_sync_error=link.last_sync_error,
        last_sync_payload_json=dict(link.last_sync_payload_json or {}),
        created_by=link.created_by,
        updated_by=link.updated_by,
        created_at=link.created_at,
        updated_at=link.updated_at,
    )


@router.get("", response_model=list[IntegrationConfigurationRead])
def list_engagement_integrations(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> list[IntegrationConfigurationRead]:
    _ensure_engagement(session, engagement_id)
    configurations = session.scalars(
        select(IntegrationConfiguration)
        .where(IntegrationConfiguration.engagement_id == engagement_id)
        .order_by(IntegrationConfiguration.created_at.desc(), IntegrationConfiguration.id.desc())
    ).all()
    return [IntegrationConfigurationRead.model_validate(configuration) for configuration in configurations]


@router.get("/repositories", response_model=list[RepositoryIntegrationRead])
def list_engagement_repository_integrations(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[RepositoryIntegrationRead]:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    return [
        RepositoryIntegrationRead.model_validate(integration)
        for integration in list_repository_integrations(session=session, engagement_id=engagement_id)
    ]


@router.get("/repositories/{provider}/authorize", response_model=RepositoryAuthorizationStartRead)
def authorize_repository_integration(
    engagement_id: UUID,
    provider: str,
    repository_url: str,
    default_branch: str | None = None,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RepositoryAuthorizationStartRead:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        authorization = start_repository_authorization(
            session=session,
            engagement_id=engagement_id,
            provider=provider,
            repository_url=repository_url,
            default_branch=default_branch,
            settings=settings,
        )
    except RepositoryIntegrationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    return RepositoryAuthorizationStartRead(
        provider=authorization.provider,
        authorization_url=authorization.authorization_url,
        redirect_uri=authorization.redirect_uri,
        state=authorization.state,
        token_exposed=False,
    )


@router.get("/repositories/{provider}/callback", response_model=RepositoryAuthorizationCompleteRead)
def complete_repository_integration_callback(
    engagement_id: UUID,
    provider: str,
    code: str,
    state: str,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RepositoryAuthorizationCompleteRead:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        completed = complete_repository_authorization(
            session=session,
            engagement_id=engagement_id,
            provider=provider,
            code=code,
            state=state,
            settings=settings,
        )
    except RepositoryIntegrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session.commit()
    return RepositoryAuthorizationCompleteRead(
        provider=completed.provider,
        connected=completed.connected,
        repository_url=completed.repository_url,
        repository_path=completed.repository_path,
        default_branch=completed.default_branch,
        account_login=completed.account_login,
        token_exposed=False,
    )


@router.get("/jira", response_model=IntegrationConfigurationRead)
def get_jira_integration_configuration(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> IntegrationConfigurationRead:
    _ensure_engagement(session, engagement_id)
    configuration = session.scalar(_jira_configuration_query(engagement_id))
    if configuration is None:
        raise HTTPException(status_code=404, detail="jira integration configuration not found")
    return IntegrationConfigurationRead.model_validate(configuration)


@router.put("/jira", response_model=IntegrationConfigurationRead)
def upsert_jira_integration_configuration(
    engagement_id: UUID,
    payload: JiraIntegrationConfigurationUpsert,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> IntegrationConfigurationRead:
    engagement = _ensure_engagement(session, engagement_id)
    configuration = session.scalar(_jira_configuration_query(engagement.id))
    action = "integration.configuration.updated"

    if configuration is None:
        configuration = IntegrationConfiguration(
            engagement_id=engagement.id,
            integration_type="jira",
            created_by=actor,
            updated_by=actor,
        )
        session.add(configuration)
        action = "integration.configuration.created"

    configuration.display_name = payload.display_name
    configuration.base_url = payload.base_url
    configuration.project_key = payload.project_key
    configuration.auth_ref = payload.auth_ref
    configuration.settings_json = payload.settings_json
    configuration.updated_by = actor
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="integration_configuration",
        object_id=str(configuration.id),
        metadata={
            "engagement_id": str(engagement.id),
            "integration_type": "jira",
            "project_key": configuration.project_key,
        },
    )

    session.commit()
    session.refresh(configuration)
    return IntegrationConfigurationRead.model_validate(configuration)


@router.get("/webhook", response_model=IntegrationConfigurationRead)
def get_webhook_integration_configuration(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> IntegrationConfigurationRead:
    _ensure_engagement(session, engagement_id)
    configuration = session.scalar(_webhook_configuration_query(engagement_id))
    if configuration is None:
        raise HTTPException(status_code=404, detail="webhook integration configuration not found")
    return IntegrationConfigurationRead.model_validate(configuration)


@router.put("/webhook", response_model=IntegrationConfigurationRead)
def upsert_webhook_integration_configuration(
    engagement_id: UUID,
    payload: WebhookIntegrationConfigurationUpsert,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> IntegrationConfigurationRead:
    engagement = _ensure_engagement(session, engagement_id)
    configuration = session.scalar(_webhook_configuration_query(engagement.id))
    action = "integration.configuration.updated"

    if configuration is None:
        configuration = IntegrationConfiguration(
            engagement_id=engagement.id,
            integration_type="webhook",
            created_by=actor,
            updated_by=actor,
        )
        session.add(configuration)
        action = "integration.configuration.created"

    configuration.display_name = payload.display_name
    configuration.base_url = payload.base_url
    configuration.project_key = None
    configuration.auth_ref = payload.auth_ref
    configuration.settings_json = payload.settings_json
    configuration.updated_by = actor
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="integration_configuration",
        object_id=str(configuration.id),
        metadata={
            "engagement_id": str(engagement.id),
            "integration_type": "webhook",
            "endpoint": configuration.base_url,
        },
    )

    session.commit()
    session.refresh(configuration)
    return IntegrationConfigurationRead.model_validate(configuration)


@router.get("/siem", response_model=SiemIntegrationCollectionRead)
def list_siem_integration_configurations(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> SiemIntegrationCollectionRead:
    _ensure_engagement(session, engagement_id)
    configurations = session.scalars(
        select(IntegrationConfiguration)
        .where(
            IntegrationConfiguration.engagement_id == engagement_id,
            IntegrationConfiguration.integration_type.in_(SUPPORTED_SIEM_PROVIDERS),
        )
        .order_by(IntegrationConfiguration.created_at.desc(), IntegrationConfiguration.id.desc())
    ).all()
    ordered = sorted(
        configurations,
        key=lambda configuration: SUPPORTED_SIEM_PROVIDERS.index(
            _ensure_siem_provider(configuration.integration_type)
        ),
    )
    return SiemIntegrationCollectionRead(
        engagement_id=engagement_id,
        providers=[_siem_configuration_read(session, configuration) for configuration in ordered],
        sensitive_plaintext_exposed=False,
    )


@router.get("/siem/{provider}", response_model=SiemIntegrationConfigurationRead)
def get_siem_integration_configuration(
    engagement_id: UUID,
    provider: str,
    session: Session = Depends(get_session),
) -> SiemIntegrationConfigurationRead:
    _ensure_engagement(session, engagement_id)
    provider_name = _ensure_siem_provider(provider)
    configuration = session.scalar(_integration_configuration_query(engagement_id, provider_name))
    if configuration is None:
        raise HTTPException(status_code=404, detail=f"{provider_name} SIEM integration configuration not found")
    return _siem_configuration_read(session, configuration)


@router.put("/siem/{provider}", response_model=SiemIntegrationConfigurationRead)
def upsert_siem_integration_configuration(
    engagement_id: UUID,
    provider: str,
    payload: SiemIntegrationConfigurationUpsert,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> SiemIntegrationConfigurationRead:
    engagement = _ensure_engagement(session, engagement_id)
    provider_name = _ensure_siem_provider(provider)
    payload_provider = _ensure_siem_provider(payload.integration_type)
    if payload_provider != provider_name:
        raise HTTPException(
            status_code=400,
            detail=f"integration_type must match route provider {provider_name}",
        )

    configuration = session.scalar(_integration_configuration_query(engagement.id, provider_name))
    action = "integration.configuration.updated"
    if configuration is None:
        configuration = IntegrationConfiguration(
            engagement_id=engagement.id,
            integration_type=provider_name,
            created_by=actor,
            updated_by=actor,
        )
        session.add(configuration)
        action = "integration.configuration.created"

    configuration.display_name = payload.display_name
    configuration.base_url = payload.base_url
    configuration.project_key = None
    configuration.settings_json = {
        "enabled": payload.enabled,
        "push_on_run_completion": payload.push_on_run_completion,
        "push_on_critical_finding": payload.push_on_critical_finding,
        "include_sigma": payload.include_sigma,
        **({"index_name": payload.index_name} if payload.index_name else {}),
        **({"sourcetype": payload.sourcetype} if payload.sourcetype else {}),
        **({"custom_log_table": payload.custom_log_table} if payload.custom_log_table else {}),
        **({"stream_name": payload.stream_name} if payload.stream_name else {}),
        **({"timeout_seconds": payload.timeout_seconds} if payload.timeout_seconds is not None else {}),
    }
    configuration.updated_by = actor
    session.flush()

    if payload.credential:
        store_or_update_siem_credential(
            session=session,
            engagement_id=engagement.id,
            configuration=configuration,
            provider=provider_name,
            credential=payload.credential,
            settings=settings,
        )

    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="integration_configuration",
        object_id=str(configuration.id),
        metadata={
            "engagement_id": str(engagement.id),
            "integration_type": provider_name,
            "provider_label": siem_provider_label(provider_name),
            "credential_configured": credential_configured_for_configuration(
                session=session,
                configuration=configuration,
            ),
            "push_on_run_completion": payload.push_on_run_completion,
            "push_on_critical_finding": payload.push_on_critical_finding,
            "include_sigma": payload.include_sigma,
        },
    )

    session.commit()
    session.refresh(configuration)
    return _siem_configuration_read(session, configuration)


@router.get("/{provider}", response_model=IntegrationConfigurationRead)
def get_named_integration_configuration(
    engagement_id: UUID,
    provider: str,
    session: Session = Depends(get_session),
) -> IntegrationConfigurationRead:
    _ensure_engagement(session, engagement_id)
    provider_name = _ensure_named_provider(provider)
    configuration = session.scalar(_integration_configuration_query(engagement_id, provider_name))
    if configuration is None:
        raise HTTPException(status_code=404, detail=f"{provider_name} integration configuration not found")
    return IntegrationConfigurationRead.model_validate(configuration)


@router.put("/{provider}", response_model=IntegrationConfigurationRead)
def upsert_named_integration_configuration(
    engagement_id: UUID,
    provider: str,
    payload: PortfolioIntegrationConfigurationUpsert,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> IntegrationConfigurationRead:
    engagement = _ensure_engagement(session, engagement_id)
    provider_name = _ensure_named_provider(provider)
    payload_provider = normalize_integration_provider(payload.integration_type)
    if payload_provider != provider_name:
        raise HTTPException(
            status_code=400,
            detail=f"integration_type must match route provider {provider_name}",
        )

    configuration = session.scalar(_integration_configuration_query(engagement.id, provider_name))
    action = "integration.configuration.updated"

    if configuration is None:
        configuration = IntegrationConfiguration(
            engagement_id=engagement.id,
            integration_type=provider_name,
            created_by=actor,
            updated_by=actor,
        )
        session.add(configuration)
        action = "integration.configuration.created"

    configuration.display_name = payload.display_name
    configuration.base_url = payload.base_url
    configuration.project_key = payload.project_key
    configuration.auth_ref = payload.auth_ref
    configuration.settings_json = payload.settings_json
    configuration.updated_by = actor
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="integration_configuration",
        object_id=str(configuration.id),
        metadata={
            "engagement_id": str(engagement.id),
            "integration_type": provider_name,
            "provider_label": named_handoff_provider_label(provider_name),
            "auth_ref_present": bool(configuration.auth_ref),
        },
    )

    session.commit()
    session.refresh(configuration)
    return IntegrationConfigurationRead.model_validate(configuration)


@router.get("/jira/findings/{finding_id}", response_model=JiraFindingLinkRead)
def get_jira_finding_link(
    engagement_id: UUID,
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> JiraFindingLinkRead:
    engagement = _ensure_engagement(session, engagement_id)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_jira_configuration_query(engagement.id))
    if configuration is None:
        raise HTTPException(status_code=409, detail="jira integration configuration required before linking findings")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if link is None:
        raise HTTPException(status_code=404, detail="jira finding link not found")
    return JiraFindingLinkRead.model_validate(link)


@router.put("/jira/findings/{finding_id}", response_model=JiraFindingLinkRead)
def upsert_jira_finding_link(
    engagement_id: UUID,
    finding_id: UUID,
    payload: JiraFindingLinkUpsert,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> JiraFindingLinkRead:
    engagement = _ensure_engagement(session, engagement_id)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_jira_configuration_query(engagement.id))
    if configuration is None:
        raise HTTPException(status_code=409, detail="jira integration configuration required before linking findings")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    action = "finding.integration_link.updated"
    if link is None:
        link = FindingIntegrationLink(
            finding_id=finding.id,
            integration_configuration_id=configuration.id,
            last_sync_state="not_synced",
            last_sync_payload_json={},
            created_by=actor,
            updated_by=actor,
        )
        session.add(link)
        action = "finding.integration_link.created"

    link.issue_key = payload.issue_key
    link.issue_url = payload.issue_url
    link.issue_status = payload.issue_status
    link.updated_by = actor
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="finding_integration_link",
        object_id=str(link.id),
        metadata={
            "engagement_id": str(engagement.id),
            "finding_id": str(finding.id),
            "integration_type": "jira",
            "integration_configuration_id": str(configuration.id),
            "issue_key": link.issue_key,
            "last_sync_state": link.last_sync_state,
        },
    )

    session.commit()
    session.refresh(link)
    return JiraFindingLinkRead.model_validate(link)


@router.get("/webhook/findings/{finding_id}", response_model=WebhookFindingHandoffRead)
def get_webhook_finding_handoff(
    engagement_id: UUID,
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> WebhookFindingHandoffRead:
    engagement = _ensure_engagement(session, engagement_id)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_webhook_configuration_query(engagement.id))
    if configuration is None:
        raise HTTPException(status_code=409, detail="webhook integration configuration required before handoff")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if link is None:
        raise HTTPException(status_code=404, detail="webhook finding handoff not found")
    return _webhook_handoff_read(link)


@router.post("/webhook/findings/{finding_id}/handoff", response_model=WebhookFindingHandoffRead)
def trigger_webhook_finding_handoff(
    engagement_id: UUID,
    finding_id: UUID,
    payload: WebhookFindingHandoffRequest,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> WebhookFindingHandoffRead:
    engagement = _ensure_engagement(session, engagement_id)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_webhook_configuration_query(engagement.id))
    if configuration is None:
        raise HTTPException(status_code=409, detail="webhook integration configuration required before handoff")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if link is None:
        link = FindingIntegrationLink(
            finding_id=finding.id,
            integration_configuration_id=configuration.id,
            issue_key=payload.handoff_key or f"AEGIS-{finding.id.hex[:12]}",
            issue_url=payload.handoff_url or configuration.base_url,
            issue_status="handoff_requested",
            last_sync_state="pending",
            last_sync_payload_json={},
            created_by=actor,
            updated_by=actor,
        )
        session.add(link)
    else:
        link.issue_key = payload.handoff_key or link.issue_key
        link.issue_url = payload.handoff_url or link.issue_url or configuration.base_url
        link.issue_status = "handoff_requested"
        link.last_sync_state = "pending"
        link.last_sync_error = None
        link.updated_by = actor
    session.flush()

    try:
        send_finding_webhook_handoff(
            configuration=configuration,
            finding=finding,
            link=link,
            actor=actor,
            operator_note=payload.operator_note,
        )
    except WebhookHandoffError as exc:
        link.updated_by = actor
        session.flush()
        write_audit_event(
            session=session,
            actor=actor,
            action="finding.integration_link.webhook_failed",
            object_type="finding_integration_link",
            object_id=str(link.id),
            metadata={
                "engagement_id": str(engagement.id),
                "finding_id": str(finding.id),
                "integration_type": "webhook",
                "integration_configuration_id": str(configuration.id),
                "handoff_key": link.issue_key,
                "last_sync_state": link.last_sync_state,
                "error": link.last_sync_error,
            },
        )
        session.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    link.updated_by = actor
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.integration_link.webhook_delivered",
        object_type="finding_integration_link",
        object_id=str(link.id),
        metadata={
            "engagement_id": str(engagement.id),
            "finding_id": str(finding.id),
            "integration_type": "webhook",
            "integration_configuration_id": str(configuration.id),
            "handoff_key": link.issue_key,
            "handoff_status": link.issue_status,
            "last_sync_state": link.last_sync_state,
        },
    )

    session.commit()
    session.refresh(link)
    return _webhook_handoff_read(link)


@router.get("/{provider}/findings/{finding_id}", response_model=ProviderFindingHandoffRead)
def get_named_provider_finding_handoff(
    engagement_id: UUID,
    provider: str,
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> ProviderFindingHandoffRead:
    engagement = _ensure_engagement(session, engagement_id)
    provider_name = _ensure_named_provider(provider)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_integration_configuration_query(engagement.id, provider_name))
    if configuration is None:
        raise HTTPException(status_code=409, detail=f"{provider_name} integration configuration required before handoff")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if link is None:
        raise HTTPException(status_code=404, detail=f"{provider_name} finding handoff not found")
    return _provider_handoff_read(provider_name, link)


@router.post("/{provider}/findings/{finding_id}/handoff", response_model=ProviderFindingHandoffRead)
def trigger_named_provider_finding_handoff(
    engagement_id: UUID,
    provider: str,
    finding_id: UUID,
    payload: ProviderFindingHandoffRequest,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> ProviderFindingHandoffRead:
    engagement = _ensure_engagement(session, engagement_id)
    provider_name = _ensure_named_provider(provider)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_integration_configuration_query(engagement.id, provider_name))
    if configuration is None:
        raise HTTPException(status_code=409, detail=f"{provider_name} integration configuration required before handoff")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if link is None:
        link = FindingIntegrationLink(
            finding_id=finding.id,
            integration_configuration_id=configuration.id,
            issue_key=payload.handoff_key or f"{provider_name.upper()}-{finding.id.hex[:10]}",
            issue_url=payload.handoff_url or configuration.base_url,
            issue_status="handoff_requested",
            last_sync_state="pending",
            last_sync_payload_json={},
            created_by=actor,
            updated_by=actor,
        )
        session.add(link)
    else:
        link.issue_key = payload.handoff_key or link.issue_key
        link.issue_url = payload.handoff_url or link.issue_url or configuration.base_url
        link.issue_status = "handoff_requested"
        link.last_sync_state = "pending"
        link.last_sync_error = None
        link.updated_by = actor
    session.flush()

    try:
        prepare_named_provider_handoff(
            configuration=configuration,
            finding=finding,
            link=link,
            actor=actor,
            operator_note=payload.operator_note,
        )
    except IntegrationHandoffError as exc:
        link.updated_by = actor
        session.flush()
        write_audit_event(
            session=session,
            actor=actor,
            action=(
                "finding.integration_link.provider_failed"
                if exc.status_code >= 500
                else "finding.integration_link.provider_blocked"
            ),
            object_type="finding_integration_link",
            object_id=str(link.id),
            metadata={
                "engagement_id": str(engagement.id),
                "finding_id": str(finding.id),
                "integration_type": provider_name,
                "integration_configuration_id": str(configuration.id),
                "handoff_key": link.issue_key,
                "handoff_status": link.issue_status,
                "last_sync_state": link.last_sync_state,
                "error": link.last_sync_error,
            },
        )
        session.commit()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    link.updated_by = actor
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.integration_link.provider_prepared",
        object_type="finding_integration_link",
        object_id=str(link.id),
        metadata={
            "engagement_id": str(engagement.id),
            "finding_id": str(finding.id),
            "integration_type": provider_name,
            "integration_configuration_id": str(configuration.id),
            "handoff_key": link.issue_key,
            "handoff_status": link.issue_status,
            "last_sync_state": link.last_sync_state,
        },
    )

    session.commit()
    session.refresh(link)
    return _provider_handoff_read(provider_name, link)


@router.post("/jira/findings/{finding_id}/sync", response_model=JiraFindingLinkRead)
def sync_jira_finding_link(
    engagement_id: UUID,
    finding_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> JiraFindingLinkRead:
    engagement = _ensure_engagement(session, engagement_id)
    finding = _ensure_finding_for_engagement(session, engagement.id, finding_id)
    configuration = session.scalar(_jira_configuration_query(engagement.id))
    if configuration is None:
        raise HTTPException(status_code=409, detail="jira integration configuration required before syncing findings")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if link is None:
        raise HTTPException(status_code=404, detail="jira finding link not found")

    try:
        sync_jira_issue(configuration=configuration, link=link)
    except JiraSyncError as exc:
        session.flush()
        write_audit_event(
            session=session,
            actor=actor,
            action="finding.integration_link.sync_failed",
            object_type="finding_integration_link",
            object_id=str(link.id),
            metadata={
                "engagement_id": str(engagement.id),
                "finding_id": str(finding.id),
                "integration_type": "jira",
                "issue_key": link.issue_key,
                "last_sync_state": link.last_sync_state,
                "error": link.last_sync_error,
            },
        )
        session.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    link.updated_by = actor
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.integration_link.synced",
        object_type="finding_integration_link",
        object_id=str(link.id),
        metadata={
            "engagement_id": str(engagement.id),
            "finding_id": str(finding.id),
            "integration_type": "jira",
            "issue_key": link.issue_key,
            "issue_status": link.issue_status,
            "last_sync_state": link.last_sync_state,
        },
    )

    session.commit()
    session.refresh(link)
    return JiraFindingLinkRead.model_validate(link)
