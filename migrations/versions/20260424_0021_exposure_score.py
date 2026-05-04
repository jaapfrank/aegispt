"""add exposure score history"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260424_0021"
down_revision = "20260423_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exposure_scores",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("severity_breakdown_json", sa.JSON(), nullable=False),
        sa.Column("open_critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("remediated_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("trend", sa.String(length=20), nullable=False, server_default="stable"),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_exposure_scores_engagement_id", "exposure_scores", ["engagement_id"], unique=False)
    op.create_index("ix_exposure_scores_run_id", "exposure_scores", ["run_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_exposure_scores_run_id", table_name="exposure_scores")
    op.drop_index("ix_exposure_scores_engagement_id", table_name="exposure_scores")
    op.drop_table("exposure_scores")
