"""add evidence_observations table for runner-side entity emission"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260515_0033"
down_revision = "2594463d9e10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "evidence_observations" in inspector.get_table_names():
        return
    op.create_table(
        "evidence_observations",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id"), nullable=False, index=True),
        sa.Column("task_id", sa.Uuid(), sa.ForeignKey("tasks.id"), nullable=True, index=True),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_source_id", sa.String(255), nullable=False),
        sa.Column("entity_label", sa.String(512), nullable=False),
        sa.Column("entity_subtype", sa.String(64), nullable=True),
        sa.Column("attributes_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.7"),
        sa.Column("emitted_by_tool", sa.String(100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_evidence_observations_run_type",
        "evidence_observations",
        ["run_id", "entity_type"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "evidence_observations" not in inspector.get_table_names():
        return
    op.drop_index("ix_evidence_observations_run_type", table_name="evidence_observations")
    op.drop_table("evidence_observations")
