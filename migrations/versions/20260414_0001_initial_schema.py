"""initial schema"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260414_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("client", sa.String(length=255), nullable=True),
        sa.Column("roe_ref", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "run_profiles",
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("run_class", sa.String(length=50), nullable=False),
        sa.Column("limits_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "audit_events",
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("object_type", sa.String(length=255), nullable=False),
        sa.Column("object_id", sa.String(length=255), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "scopes",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("allowlist_json", sa.JSON(), nullable=False),
        sa.Column("denylist_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "runs",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("profile_id", sa.Uuid(), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["profile_id"], ["run_profiles.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "approvals",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("step_id", sa.String(length=255), nullable=False),
        sa.Column("approver_id", sa.String(length=255), nullable=False),
        sa.Column("decision", sa.String(length=50), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "secrets_refs",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("vault_pointer", sa.String(length=255), nullable=False),
        sa.Column("purpose", sa.String(length=255), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "tasks",
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("tool", sa.String(length=100), nullable=False),
        sa.Column("target_id", sa.String(length=255), nullable=False),
        sa.Column("params_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "findings",
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("target_id", sa.String(length=255), nullable=False),
        sa.Column("evidence_ref", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "tool_executions",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("runner_digest", sa.String(length=255), nullable=False),
        sa.Column("tool_version", sa.String(length=255), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=False),
        sa.Column("stdout_text", sa.Text(), nullable=True),
        sa.Column("stderr_text", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "evidence_artifacts",
        sa.Column("tool_execution_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=100), nullable=False),
        sa.Column("uri", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("redaction_state", sa.String(length=50), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tool_execution_id"], ["tool_executions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("evidence_artifacts")
    op.drop_table("tool_executions")
    op.drop_table("findings")
    op.drop_table("tasks")
    op.drop_table("secrets_refs")
    op.drop_table("approvals")
    op.drop_table("runs")
    op.drop_table("scopes")
    op.drop_table("audit_events")
    op.drop_table("run_profiles")
    op.drop_table("engagements")
