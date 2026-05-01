"""add finding validation layer"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260423_0020"
down_revision = "20260423_0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "validation_status",
            sa.String(length=50),
            nullable=False,
            server_default="unvalidated",
        ),
    )
    op.add_column(
        "tasks",
        sa.Column("source_finding_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_tasks_source_finding_id_findings",
        "tasks",
        "findings",
        ["source_finding_id"],
        ["id"],
    )
    op.create_table(
        "finding_validation_records",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("tool_execution_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="validation_queued"),
        sa.Column("validation_profile_name", sa.String(length=100), nullable=True),
        sa.Column("validator_tool", sa.String(length=100), nullable=True),
        sa.Column("validator_target_id", sa.String(length=255), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("evidence_ref", sa.String(length=255), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.ForeignKeyConstraint(["tool_execution_id"], ["tool_executions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("finding_validation_records")
    op.drop_constraint("fk_tasks_source_finding_id_findings", "tasks", type_="foreignkey")
    op.drop_column("tasks", "source_finding_id")
    op.drop_column("findings", "validation_status")
