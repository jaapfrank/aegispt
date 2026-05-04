"""add run drift summaries"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260429_0031"
down_revision = "20260429_0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "run_drifts" in inspector.get_table_names():
        return

    op.create_table(
        "run_drifts",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("previous_run_id", sa.Uuid(), nullable=False),
        sa.Column("new_finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("exposure_delta", sa.Float(), nullable=False, server_default="0"),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["previous_run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", name="uq_run_drifts_run_id"),
    )
    op.create_index("ix_run_drifts_run_id", "run_drifts", ["run_id"], unique=False)
    op.create_index("ix_run_drifts_previous_run_id", "run_drifts", ["previous_run_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "run_drifts" not in inspector.get_table_names():
        return
    indexes = {index["name"] for index in inspector.get_indexes("run_drifts")}
    if "ix_run_drifts_previous_run_id" in indexes:
        op.drop_index("ix_run_drifts_previous_run_id", table_name="run_drifts")
    if "ix_run_drifts_run_id" in indexes:
        op.drop_index("ix_run_drifts_run_id", table_name="run_drifts")
    op.drop_table("run_drifts")
