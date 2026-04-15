from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
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
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="requested")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="runs")
    profile: Mapped["RunProfile | None"] = relationship(back_populates="runs")
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


class SecretRef(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "secrets_refs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    vault_pointer: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(255), nullable=False)


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
