from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.app.models.base import Base, TimestampMixin, UUIDMixin


class Engagement(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "engagements"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    client: Mapped[str | None] = mapped_column(String(255), nullable=True)
    roe_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="draft")
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scopes: Mapped[list["Scope"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
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
    runs: Mapped[list["Run"]] = relationship(back_populates="engagement")


class Scope(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scopes"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    allowlist_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    denylist_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="scopes")


class RunProfile(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "run_profiles"

    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    run_class: Mapped[str] = mapped_column(String(50), nullable=False, default="passive")
    limits_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    runs: Mapped[list["Run"]] = relationship(back_populates="profile")


class Run(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "runs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    profile_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("run_profiles.id"), nullable=True)
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"),
        nullable=True,
    )
    bound_pack_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("capability_packs.id"), nullable=True)
    bound_pack_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    bound_pack_deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_pack_deployments.id"),
        nullable=True,
    )
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="requested")
    configuration_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="runs")
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
    internal_validation_steps: Mapped[list["InternalValidationStep"]] = relationship(back_populates="launched_run")
    tasks: Mapped[list["Task"]] = relationship(back_populates="run")
    findings: Mapped[list["Finding"]] = relationship(back_populates="run")


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

    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("internal_validation_sessions.id"), nullable=False)
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

    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("internal_validation_sessions.id"), nullable=False)
    step_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("internal_validation_steps.id"), nullable=False)
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


class InventorySnapshot(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "inventory_snapshots"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="completed")
    source_tools_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    raw_inputs_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    normalized_inventory_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
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
    suggested_test_patterns_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    references_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    advisory_updated_at: Mapped[datetime | None] = mapped_column(
        "advisory_updated_at",
        DateTime(timezone=True),
        nullable=True,
    )
    normalization_status: Mapped[str] = mapped_column(String(50), nullable=False, default="normalized")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class RelevanceDecision(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "relevance_decisions"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    inventory_snapshot_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("inventory_snapshots.id"), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="completed")
    threat_intel_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    prior_finding_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    methodology_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommendations_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    justification_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_basis_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    engagement: Mapped["Engagement"] = relationship(back_populates="relevance_decisions")
    inventory_snapshot: Mapped["InventorySnapshot"] = relationship(back_populates="relevance_decisions")
    capability_packs: Mapped[list["CapabilityPack"]] = relationship(
        back_populates="relevance_decision",
        cascade="all, delete-orphan",
    )


class CapabilityPack(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_packs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    relevance_decision_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("relevance_decisions.id"), nullable=True)
    source_inventory_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_snapshots.id"),
        nullable=True,
    )
    parent_pack_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("capability_packs.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="generated")
    generated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    generation_mode: Mapped[str] = mapped_column(String(100), nullable=False, default="codex-supervised")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_threat_intel_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    methodology_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    engagement: Mapped["Engagement"] = relationship(back_populates="capability_packs")
    relevance_decision: Mapped["RelevanceDecision | None"] = relationship(back_populates="capability_packs")
    source_inventory_snapshot: Mapped["InventorySnapshot | None"] = relationship(back_populates="capability_packs")
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
    artifact_results_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    validation_artifacts_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    blocking_issues_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    pack: Mapped["CapabilityPack"] = relationship(back_populates="validation_results")


class CapabilityPackApproval(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_pack_approvals"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_packs.id"), nullable=False)
    approval_step: Mapped[str] = mapped_column(String(100), nullable=False, default="pack.promotion")
    approver_id: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False, default="approved")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    pack: Mapped["CapabilityPack"] = relationship(back_populates="approvals")


class CapabilityPackDeployment(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "capability_pack_deployments"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("capability_packs.id"), nullable=False)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    deployed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    deployment_target: Mapped[str] = mapped_column(String(100), nullable=False, default="engagement-runtime")
    run_profile_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="deployed")
    rollback_from_pack_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("capability_packs.id"), nullable=True)
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
    storage_backend: Mapped[str] = mapped_column(String(50), nullable=False, default="external_pointer")
    display_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Task(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "tasks"

    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    tool: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")

    run: Mapped["Run | None"] = relationship(back_populates="tasks")
    executions: Mapped[list["ToolExecution"]] = relationship(back_populates="task")


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


class EvidenceArtifact(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence_artifacts"

    tool_execution_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tool_executions.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    uri: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    redaction_state: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    execution: Mapped["ToolExecution"] = relationship(back_populates="artifacts")


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    source_pack_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("capability_packs.id"), nullable=True)
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
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
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


class FindingRemediation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_remediations"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(50), nullable=False, default="not_started")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")

    finding: Mapped["Finding"] = relationship(back_populates="remediation")
