"""add ai agent reasoning ledger records"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260422_0013"
down_revision = "20260421_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_reasoning",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("reasoning_type", sa.String(length=100), nullable=False, server_default="analysis"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="recorded"),
        sa.Column("context_snapshot_json", sa.JSON(), nullable=False),
        sa.Column("observations_json", sa.JSON(), nullable=False),
        sa.Column("hypotheses_json", sa.JSON(), nullable=False),
        sa.Column("proposals_json", sa.JSON(), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False, server_default="not-configured"),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("llm_tokens_used", sa.Integer(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_reasoning_run_id", "agent_reasoning", ["run_id"])
    op.create_index("ix_agent_reasoning_task_id", "agent_reasoning", ["task_id"])

    op.create_table(
        "agent_proposals",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("agent_reasoning_id", sa.Uuid(), nullable=False),
        sa.Column("proposed_tool", sa.String(length=100), nullable=False),
        sa.Column("proposed_target", sa.String(length=255), nullable=False),
        sa.Column("proposed_params_json", sa.JSON(), nullable=False),
        sa.Column("reasoning_text", sa.Text(), nullable=True),
        sa.Column("risk_tier", sa.String(length=50), nullable=False, server_default="passive"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending_review"),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["agent_reasoning_id"], ["agent_reasoning.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_proposals_agent_reasoning_id", "agent_proposals", ["agent_reasoning_id"])
    op.create_index("ix_agent_proposals_run_id", "agent_proposals", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_proposals_run_id", table_name="agent_proposals")
    op.drop_index("ix_agent_proposals_agent_reasoning_id", table_name="agent_proposals")
    op.drop_table("agent_proposals")
    op.drop_index("ix_agent_reasoning_task_id", table_name="agent_reasoning")
    op.drop_index("ix_agent_reasoning_run_id", table_name="agent_reasoning")
    op.drop_table("agent_reasoning")
