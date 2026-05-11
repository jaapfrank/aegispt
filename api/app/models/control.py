from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.app.models.base import Base, TimestampMixin, UUIDMixin


class Engagement(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "engagements"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    client: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    roe_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    authorization_confirmed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="draft")
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scopes: Mapped[list["Scope"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    inventory_snapshots: Mapped[list["InventorySnapshot"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    relevance_decisions: Mapped[list["RelevanceDecision"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    capability_packs: Mapped[list["CapabilityPack"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    pack_deployments: Mapped[list["CapabilityPackDeployment"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    internal_validation_sessions: Mapped[list["InternalValidationSession"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    integration_configurations: Mapped[list["IntegrationConfiguration"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    repo_integrations: Mapped[list["RepositoryIntegration"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    scheduled_runs: Mapped[list["ScheduledRun"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    cicd_triggers: Mapped[list["CicdTrigger"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    exposure_scores: Mapped[list["ExposureScore"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    assessment_chains: Mapped[list["AssessmentChain"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    custom_vulnerability_settings: Mapped[list["CustomVulnerabilityEngagementSetting"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    casebook_entries: Mapped[list["EngagementCasebookEntry"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    runs: Mapped[list["Run"]] = relationship(back_populates="engagement")


class Scope(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scopes"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    allowlist_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    denylist_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="scopes")


class IntegrationConfiguration(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "integration_configurations"
    __table_args__ = (
        UniqueConstraint(
            "engagement_id",
            "integration_type",
            name="uq_integration_configurations_engagement_type",
        ),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    integration_type: Mapped[str] = mapped_column(String(50), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    project_key: Mapped[str | None] = mapped_column(String(100), nullable=True)
    auth_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")

    engagement: Mapped["Engagement"] = relationship(back_populates="integration_configurations")
    finding_links: Mapped[list["FindingIntegrationLink"]] = relationship(
        back_populates="integration_configuration",
        cascade="all, delete-orphan",
    )


class RepositoryIntegration(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "repo_integrations"
    __table_args__ = (
        UniqueConstraint(
            "engagement_id",
            "provider",
            "repository_url",
            name="uq_repo_integrations_engagement_provider_url",
        ),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    token_secret_ref_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("secrets_refs.id"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    repository_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    repository_path: Mapped[str] = mapped_column(String(512), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    account_login: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="connected")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="repo_integrations")
    token_secret_ref: Mapped["SecretRef"] = relationship(foreign_keys=[token_secret_ref_id])
    finding_links: Mapped[list["FindingRepositoryLink"]] = relationship(
        back_populates="repo_integration",
        cascade="all, delete-orphan",
    )


class RunProfile(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "run_profiles"

    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    run_class: Mapped[str] = mapped_column(String(50), nullable=False, default="passive")
    limits_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    runs: Mapped[list["Run"]] = relationship(back_populates="profile")


class Run(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "runs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    assessment_chain_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assessment_chains.id"),
        nullable=True,
        index=True,
    )
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("run_profiles.id"), nullable=True
    )
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"),
        nullable=True,
    )
    bound_pack_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_packs.id"), nullable=True
    )
    bound_pack_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    bound_pack_deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_pack_deployments.id"),
        nullable=True,
    )
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="requested")
    configuration_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    autonomous_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    autonomous_intrusive_allowed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="runs")
    assessment_chain: Mapped["AssessmentChain | None"] = relationship(
        back_populates="runs",
        foreign_keys=[assessment_chain_id],
    )
    profile: Mapped["RunProfile | None"] = relationship(back_populates="runs")
    source_inventory_snapshot: Mapped["InventorySnapshot | None"] = relationship(
        back_populates="runs",
        foreign_keys=[source_inventory_snapshot_id],
    )
    bound_pack: Mapped["CapabilityPack | None"] = relationship(
        back_populates="bound_runs",
        foreign_keys=[bound_pack_id],
    )
    bound_pack_deployment: Mapped["CapabilityPackDeployment | None"] = relationship(
        back_populates="bound_runs",
        foreign_keys=[bound_pack_deployment_id],
    )
    approvals: Mapped[list["Approval"]] = relationship(back_populates="run")
    internal_validation_steps: Mapped[list["InternalValidationStep"]] = relationship(
        back_populates="launched_run"
    )
    tasks: Mapped[list["Task"]] = relationship(back_populates="run")
    findings: Mapped[list["Finding"]] = relationship(back_populates="run")
    agent_reasoning_records: Mapped[list["AgentReasoning"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )
    agent_proposals: Mapped[list["AgentProposal"]] = relationship(
        back_populates="run",
    )
    finding_chains: Mapped[list["FindingChain"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )
    exposure_scores: Mapped[list["ExposureScore"]] = relationship(back_populates="run")
    drift_summary: Mapped["RunDrift | None"] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        foreign_keys="RunDrift.run_id",
        uselist=False,
    )
    context_documents: Mapped[list["TargetContextDocument"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )
    rationale_ledger_entries: Mapped[list["RationaleLedgerEntry"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
    )


class AssessmentChain(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "assessment_chains"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id"),
        nullable=False,
        index=True,
    )
    current_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id"),
        nullable=True,
        index=True,
    )
    last_completed_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id"),
        nullable=True,
        index=True,
    )
    assessment_mode: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    current_phase_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_step_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auto_advance_on_phase_complete: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    halt_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    phases_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    configuration_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="assessment_chains")
    current_run: Mapped["Run | None"] = relationship(
        foreign_keys=[current_run_id], post_update=True
    )
    last_completed_run: Mapped["Run | None"] = relationship(
        foreign_keys=[last_completed_run_id],
        post_update=True,
    )
    runs: Mapped[list["Run"]] = relationship(
        back_populates="assessment_chain",
        foreign_keys="Run.assessment_chain_id",
    )


class ExposureScore(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "exposure_scores"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id"), nullable=False, index=True
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id"), nullable=True, index=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity_breakdown_json: Mapped[dict[str, int]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    open_critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    remediated_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verified_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    trend: Mapped[str] = mapped_column(String(20), nullable=False, default="stable")
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    engagement: Mapped["Engagement"] = relationship(back_populates="exposure_scores")
    run: Mapped["Run | None"] = relationship(back_populates="exposure_scores")


class RunDrift(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "run_drifts"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_run_drifts_run_id"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    previous_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    new_finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exposure_delta: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    run: Mapped["Run"] = relationship(back_populates="drift_summary", foreign_keys=[run_id])
    previous_run: Mapped["Run"] = relationship(foreign_keys=[previous_run_id])


class EngagementCasebookEntry(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "engagement_casebook_entries"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)
    entry_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_refs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="recorded", index=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="casebook_entries")


class ScheduledRun(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scheduled_runs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    profile_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"),
        nullable=True,
    )
    cadence: Mapped[str] = mapped_column(String(20), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    timezone: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="enabled")
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_launched_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id"), nullable=True
    )
    configuration_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paused_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="scheduled_runs")
    source_inventory_snapshot: Mapped["InventorySnapshot | None"] = relationship(
        foreign_keys=[source_inventory_snapshot_id],
    )
    last_launched_run: Mapped["Run | None"] = relationship(foreign_keys=[last_launched_run_id])


class CicdTrigger(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cicd_triggers"
    __table_args__ = (
        UniqueConstraint(
            "engagement_id",
            "trigger_source",
            name="uq_cicd_triggers_engagement_source",
        ),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    webhook_secret_ref_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("secrets_refs.id"), nullable=False
    )
    trigger_source: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="enabled")
    enabled_profiles_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    branch_filters_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope_override_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_triggered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="cicd_triggers")
    webhook_secret_ref: Mapped["SecretRef"] = relationship(foreign_keys=[webhook_secret_ref_id])
    last_run: Mapped["Run | None"] = relationship(foreign_keys=[last_run_id])
    events: Mapped[list["CicdTriggerEvent"]] = relationship(
        back_populates="trigger",
        cascade="all, delete-orphan",
    )


class CicdTriggerEvent(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cicd_trigger_events"

    cicd_trigger_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cicd_triggers.id"), nullable=False
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    trigger_source: Mapped[str] = mapped_column(String(50), nullable=False)
    profile_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="received")
    status_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scope_override_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    override_target_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    trigger: Mapped["CicdTrigger"] = relationship(back_populates="events")
    run: Mapped["Run | None"] = relationship(foreign_keys=[run_id])


class InstanceSetting(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "instance_settings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "setting_key", name="uq_instance_settings_tenant_key"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(100), nullable=False, default="default", index=True
    )
    setting_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    storage_backend: Mapped[str | None] = mapped_column(String(50), nullable=True)
    encrypted_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    display_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")


class Approval(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "approvals"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False)
    step_id: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)

    run: Mapped["Run"] = relationship(back_populates="approvals")


class InternalValidationSession(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "internal_validation_sessions"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(100), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="draft")
    preflight_state: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    preflight_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="internal_validation_sessions")
    steps: Mapped[list["InternalValidationStep"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
    )


class InternalValidationStep(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "internal_validation_steps"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("internal_validation_sessions.id"), nullable=False
    )
    launched_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    step_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    profile_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending_preflight")
    approval_count_required: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    session: Mapped["InternalValidationSession"] = relationship(back_populates="steps")
    launched_run: Mapped["Run | None"] = relationship(back_populates="internal_validation_steps")
    approvals: Mapped[list["InternalValidationApproval"]] = relationship(
        back_populates="step",
        cascade="all, delete-orphan",
    )


class InternalValidationApproval(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "internal_validation_approvals"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("internal_validation_sessions.id"), nullable=False
    )
    step_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("internal_validation_steps.id"), nullable=False
    )
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)

    step: Mapped["InternalValidationStep"] = relationship(back_populates="approvals")


class AuditEvent(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "audit_events"

    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    object_type: Mapped[str] = mapped_column(String(255), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ApiKey(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "api_keys"

    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="operator")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InventorySnapshot(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "inventory_snapshots"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="completed")
    source_tools_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    raw_inputs_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    normalized_inventory_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    environment_notes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assumptions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    engagement: Mapped["Engagement"] = relationship(back_populates="inventory_snapshots")
    runs: Mapped[list["Run"]] = relationship(
        back_populates="source_inventory_snapshot",
        foreign_keys="Run.source_inventory_snapshot_id",
    )
    relevance_decisions: Mapped[list["RelevanceDecision"]] = relationship(
        back_populates="inventory_snapshot",
        cascade="all, delete-orphan",
    )
    capability_packs: Mapped[list["CapabilityPack"]] = relationship(
        back_populates="source_inventory_snapshot",
        cascade="all, delete-orphan",
    )


class ThreatIntelRecord(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "threat_intel_records"

    source: Mapped[str] = mapped_column(String(100), nullable=False)
    advisory_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_products_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    affected_versions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    product_match_hints_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    architecture_hints_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    attack_surface_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    suggested_test_patterns_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    references_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    advisory_updated_at: Mapped[datetime | None] = mapped_column(
        "advisory_updated_at",
        DateTime(timezone=True),
        nullable=True,
    )
    normalization_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="normalized"
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    custom_vulnerabilities: Mapped[list["CustomVulnerability"]] = relationship(
        back_populates="linked_threat_intel_record",
    )


class CveProductWatchlistEntry(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cve_product_watchlist_entries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "normalized_query", name="uq_cve_watchlist_tenant_query"),
    )

    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    query: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_query: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="approved", index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="operator")
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"), nullable=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class CveFeedSyncLog(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cve_feed_sync_logs"

    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    imported_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class CustomVulnerability(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "custom_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "custom_id", name="uq_custom_vulnerabilities_tenant_custom_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)
    custom_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="medium", index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    affected_products_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    cwe_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    discovery_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reporter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="draft", index=True)
    linked_nuclei_template_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    linked_threat_intel_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threat_intel_records.id"),
        nullable=True,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    linked_threat_intel_record: Mapped["ThreatIntelRecord | None"] = relationship(
        back_populates="custom_vulnerabilities",
    )
    engagement_settings: Mapped[list["CustomVulnerabilityEngagementSetting"]] = relationship(
        back_populates="custom_vulnerability",
        cascade="all, delete-orphan",
    )


class CustomVulnerabilityEngagementSetting(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "custom_vulnerability_engagement_settings"
    __table_args__ = (
        UniqueConstraint(
            "custom_vulnerability_id",
            "engagement_id",
            name="uq_custom_vulnerability_engagement_setting",
        ),
    )

    custom_vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("custom_vulnerabilities.id"),
        nullable=False,
        index=True,
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id"),
        nullable=False,
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    enabled_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    custom_vulnerability: Mapped["CustomVulnerability"] = relationship(
        back_populates="engagement_settings",
    )
    engagement: Mapped["Engagement"] = relationship(
        back_populates="custom_vulnerability_settings",
    )


class RelevanceDecision(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "relevance_decisions"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    inventory_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("inventory_snapshots.id"), nullable=False
    )
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="completed")
    threat_intel_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    prior_finding_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    methodology_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommendations_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    justification_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_basis_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    engagement: Mapped["Engagement"] = relationship(back_populates="relevance_decisions")
    inventory_snapshot: Mapped["InventorySnapshot"] = relationship(
        back_populates="relevance_decisions"
    )
    capability_packs: Mapped[list["CapabilityPack"]] = relationship(
        back_populates="relevance_decision",
        cascade="all, delete-orphan",
    )


class CapabilityPack(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_packs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    relevance_decision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("relevance_decisions.id"), nullable=True
    )
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"),
        nullable=True,
    )
    parent_pack_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_packs.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="generated")
    generated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    generation_mode: Mapped[str] = mapped_column(
        String(100), nullable=False, default="codex-supervised"
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_threat_intel_refs_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    methodology_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="capability_packs")
    relevance_decision: Mapped["RelevanceDecision | None"] = relationship(
        back_populates="capability_packs"
    )
    source_inventory_snapshot: Mapped["InventorySnapshot | None"] = relationship(
        back_populates="capability_packs"
    )
    parent_pack: Mapped["CapabilityPack | None"] = relationship(
        remote_side="CapabilityPack.id",
        back_populates="derived_packs",
        foreign_keys=[parent_pack_id],
    )
    derived_packs: Mapped[list["CapabilityPack"]] = relationship(
        back_populates="parent_pack",
        foreign_keys="CapabilityPack.parent_pack_id",
    )
    artifacts: Mapped[list["CapabilityPackArtifact"]] = relationship(
        back_populates="pack",
        cascade="all, delete-orphan",
    )
    validation_results: Mapped[list["CapabilityPackValidationResult"]] = relationship(
        back_populates="pack",
        cascade="all, delete-orphan",
    )
    approvals: Mapped[list["CapabilityPackApproval"]] = relationship(
        back_populates="pack",
        cascade="all, delete-orphan",
    )
    deployments: Mapped[list["CapabilityPackDeployment"]] = relationship(
        back_populates="pack",
        cascade="all, delete-orphan",
        foreign_keys="CapabilityPackDeployment.pack_id",
    )
    bound_runs: Mapped[list["Run"]] = relationship(
        back_populates="bound_pack",
        foreign_keys="Run.bound_pack_id",
    )
    generated_findings: Mapped[list["Finding"]] = relationship(
        back_populates="source_pack",
        foreign_keys="Finding.source_pack_id",
    )


class CapabilityPackArtifact(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_pack_artifacts"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_packs.id"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False)
    logical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="generated")
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    methodology_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    content_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    pack: Mapped["CapabilityPack"] = relationship(back_populates="artifacts")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="source_pack_artifact",
        foreign_keys="Finding.source_pack_artifact_id",
    )


class CapabilityPackValidationResult(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_pack_validation_results"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_packs.id"), nullable=False)
    validator: Mapped[str] = mapped_column(String(100), nullable=False)
    executed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_results_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    validation_artifacts_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    blocking_issues_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    pack: Mapped["CapabilityPack"] = relationship(back_populates="validation_results")


class CapabilityPackApproval(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_pack_approvals"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_packs.id"), nullable=False)
    approval_step: Mapped[str] = mapped_column(
        String(100), nullable=False, default="pack.promotion"
    )
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False, default="approved")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    pack: Mapped["CapabilityPack"] = relationship(back_populates="approvals")


class CapabilityPackDeployment(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_pack_deployments"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_packs.id"), nullable=False)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    deployed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    deployment_target: Mapped[str] = mapped_column(
        String(100), nullable=False, default="engagement-runtime"
    )
    run_profile_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="deployed")
    rollback_from_pack_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_packs.id"), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    runtime_binding_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    pack: Mapped["CapabilityPack"] = relationship(
        back_populates="deployments",
        foreign_keys=[pack_id],
    )
    engagement: Mapped["Engagement"] = relationship(back_populates="pack_deployments")
    rollback_from_pack: Mapped["CapabilityPack | None"] = relationship(
        foreign_keys=[rollback_from_pack_id],
    )
    bound_runs: Mapped[list["Run"]] = relationship(
        back_populates="bound_pack_deployment",
        foreign_keys="Run.bound_pack_deployment_id",
    )


class SecretRef(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "secrets_refs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    vault_pointer: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_kind: Mapped[str] = mapped_column(String(50), nullable=False, default="reference")
    storage_backend: Mapped[str] = mapped_column(
        String(50), nullable=False, default="external_pointer"
    )
    display_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Task(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "tasks"

    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    source_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id"),
        nullable=True,
    )
    tool: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")

    run: Mapped["Run | None"] = relationship(back_populates="tasks")
    source_finding: Mapped["Finding | None"] = relationship(
        back_populates="validation_tasks",
        foreign_keys=[source_finding_id],
    )
    executions: Mapped[list["ToolExecution"]] = relationship(back_populates="task")
    agent_reasoning_records: Mapped[list["AgentReasoning"]] = relationship(back_populates="task")
    validation_records: Mapped[list["FindingValidationRecord"]] = relationship(
        back_populates="task",
    )


class ToolExecution(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "tool_executions"

    task_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tasks.id"), nullable=False)
    runner_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(255), nullable=False)
    exit_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stdout_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    task: Mapped["Task"] = relationship(back_populates="executions")
    artifacts: Mapped[list["EvidenceArtifact"]] = relationship(back_populates="execution")
    validation_records: Mapped[list["FindingValidationRecord"]] = relationship(
        back_populates="tool_execution",
    )


class AgentReasoning(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "agent_reasoning"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tasks.id"), nullable=True, index=True
    )
    reasoning_type: Mapped[str] = mapped_column(String(100), nullable=False, default="analysis")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="recorded")
    context_snapshot_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    observations_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    hypotheses_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    proposals_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    provider: Mapped[str] = mapped_column(String(100), nullable=False, default="not-configured")
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    llm_tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    run: Mapped["Run"] = relationship(back_populates="agent_reasoning_records")
    task: Mapped["Task | None"] = relationship(back_populates="agent_reasoning_records")
    proposals: Mapped[list["AgentProposal"]] = relationship(
        back_populates="agent_reasoning",
        cascade="all, delete-orphan",
    )

    @property
    def summary_text(self) -> str:
        metadata = self.metadata_json if isinstance(self.metadata_json, dict) else {}
        return str(metadata.get("summary_text") or "")

    @property
    def thought_text(self) -> str:
        metadata = self.metadata_json if isinstance(self.metadata_json, dict) else {}
        return str(metadata.get("thought_text") or "")

    @property
    def action_text(self) -> str:
        metadata = self.metadata_json if isinstance(self.metadata_json, dict) else {}
        return str(metadata.get("action_text") or "")


class AgentProposal(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "agent_proposals"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    agent_reasoning_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agent_reasoning.id"), nullable=False, index=True
    )
    proposed_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    proposed_target: Mapped[str] = mapped_column(String(255), nullable=False)
    proposed_params_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    reasoning_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_tier: Mapped[str] = mapped_column(String(50), nullable=False, default="passive")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending_review")
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    run: Mapped["Run"] = relationship(back_populates="agent_proposals")
    agent_reasoning: Mapped["AgentReasoning"] = relationship(back_populates="proposals")


class EvidenceArtifact(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence_artifacts"

    tool_execution_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tool_executions.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    uri: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    redaction_state: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    timestamp_token_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    timestamp_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    execution: Mapped["ToolExecution"] = relationship(back_populates="artifacts")


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    source_pack_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_packs.id"), nullable=True
    )
    source_pack_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_pack_artifacts.id"),
        nullable=True,
    )
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"),
        nullable=True,
    )
    source_relevance_decision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("relevance_decisions.id"),
        nullable=True,
    )
    source_pack_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    finding_origin: Mapped[str] = mapped_column(String(50), nullable=False, default="standard")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")
    remediation_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive_confirmed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="unvalidated",
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    autofix_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    replay_recipe_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    methodology_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    ptes_phase: Mapped[str | None] = mapped_column(String(50), nullable=True)
    nist_phase: Mapped[str | None] = mapped_column(String(50), nullable=True)
    wstg_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    wstg_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    asvs_reference: Mapped[str | None] = mapped_column(String(50), nullable=True)
    control_family: Mapped[str | None] = mapped_column(String(100), nullable=True)

    run: Mapped["Run | None"] = relationship(back_populates="findings")
    source_pack: Mapped["CapabilityPack | None"] = relationship(
        back_populates="generated_findings",
        foreign_keys=[source_pack_id],
    )
    source_pack_artifact: Mapped["CapabilityPackArtifact | None"] = relationship(
        back_populates="findings",
        foreign_keys=[source_pack_artifact_id],
    )
    source_inventory_snapshot: Mapped["InventorySnapshot | None"] = relationship(
        foreign_keys=[source_inventory_snapshot_id],
    )
    source_relevance_decision: Mapped["RelevanceDecision | None"] = relationship(
        foreign_keys=[source_relevance_decision_id],
    )
    remediation: Mapped["FindingRemediation | None"] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        uselist=False,
    )
    ai_enrichment: Mapped["FindingAiEnrichment | None"] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        uselist=False,
    )
    integration_links: Mapped[list["FindingIntegrationLink"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    repository_links: Mapped[list["FindingRepositoryLink"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    validation_tasks: Mapped[list["Task"]] = relationship(
        back_populates="source_finding",
        foreign_keys="Task.source_finding_id",
    )
    validation_records: Mapped[list["FindingValidationRecord"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class FindingValidationRecord(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_validation_records"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tasks.id"), nullable=True)
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tool_executions.id"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="validation_queued")
    validation_profile_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    validator_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    validator_target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="validation_records")
    run: Mapped["Run | None"] = relationship()
    task: Mapped["Task | None"] = relationship(back_populates="validation_records")
    tool_execution: Mapped["ToolExecution | None"] = relationship(
        back_populates="validation_records"
    )


class FindingRepositoryLink(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_repo_links"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "repo_integration_id",
            name="uq_finding_repo_links_finding_repo",
        ),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    repo_integration_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repo_integrations.id"), nullable=False
    )
    repository_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    repository_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    highlighted_line: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    snippet_language: Mapped[str | None] = mapped_column(String(50), nullable=True)
    snippet_text: Mapped[str] = mapped_column(Text, nullable=False)
    external_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="repository_links")
    repo_integration: Mapped["RepositoryIntegration"] = relationship(back_populates="finding_links")


class FindingAiEnrichment(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_ai_enrichments"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id"), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="succeeded")
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    business_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    technical_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="ai_enrichment")


class FindingRemediation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_remediations"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id"), nullable=False, unique=True
    )
    state: Mapped[str] = mapped_column(String(50), nullable=False, default="not_started")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ai_fix_suggestion: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")

    finding: Mapped["Finding"] = relationship(back_populates="remediation")


class FindingIntegrationLink(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_integration_links"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "integration_configuration_id",
            name="uq_finding_integration_links_finding_configuration",
        ),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    integration_configuration_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("integration_configurations.id"),
        nullable=False,
    )
    issue_key: Mapped[str] = mapped_column(String(100), nullable=False)
    issue_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    issue_status: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_sync_state: Mapped[str] = mapped_column(String(50), nullable=False, default="not_synced")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sync_payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")

    finding: Mapped["Finding"] = relationship(back_populates="integration_links")
    integration_configuration: Mapped["IntegrationConfiguration"] = relationship(
        back_populates="finding_links"
    )


class FindingChain(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_chains"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "pattern_id",
            "component_hash",
            name="uq_finding_chains_run_pattern_components",
        ),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    pattern_id: Mapped[str] = mapped_column(String(100), nullable=False)
    component_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="detected")
    component_finding_ids_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    combined_impact_text: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    rationale_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    run: Mapped["Run"] = relationship(back_populates="finding_chains")


class TargetContextDocument(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "target_context_documents"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    parent_context_document_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("target_context_documents.id"), nullable=True, index=True
    )
    layer_name: Mapped[str] = mapped_column(String(255), nullable=False, default="phase_0_recon")
    context_kind: Mapped[str] = mapped_column(String(100), nullable=False, default="target_context")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="recorded")
    source_targets_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    technologies_detected_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    endpoints_discovered_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_tools_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    micro_plan_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    context_summary: Mapped[str] = mapped_column(Text, nullable=False)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    run: Mapped["Run"] = relationship(back_populates="context_documents")
    parent_context_document: Mapped["TargetContextDocument | None"] = relationship(
        remote_side="TargetContextDocument.id",
    )
    rationale_ledger_entries: Mapped[list["RationaleLedgerEntry"]] = relationship(
        back_populates="context_document",
    )


class RationaleLedgerEntry(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "rationale_ledger_entries"

    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("runs.id"), nullable=False, index=True)
    context_document_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("target_context_documents.id"), nullable=True)
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    agent_proposal_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_proposals.id"), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False, default="tool_dispatch")
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rationale_text: Mapped[str] = mapped_column(Text, nullable=False)
    decision_source_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="recorded")
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    run: Mapped["Run"] = relationship(back_populates="rationale_ledger_entries")
    context_document: Mapped["TargetContextDocument | None"] = relationship(
        back_populates="rationale_ledger_entries",
    )


class EngagementMemory(UUIDMixin, TimestampMixin, Base):
    """Persistent AI memory scoped to an engagement. The AI reads and writes here across runs."""

    __tablename__ = "engagement_memory"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id"), nullable=False, index=True
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id"), nullable=True, index=True
    )
    memory_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    memory_value: Mapped[str] = mapped_column(Text, nullable=False)
    memory_type: Mapped[str] = mapped_column(String(50), nullable=False, default="fact")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="ai_analysis")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship()
