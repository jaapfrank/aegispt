"""add additive finding chain records"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260422_0014"
down_revision = "20260422_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_chains",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("pattern_id", sa.String(length=100), nullable=False),
        sa.Column("component_hash", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="detected"),
        sa.Column("component_finding_ids_json", sa.JSON(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("combined_impact_text", sa.Text(), nullable=False),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("rationale_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "pattern_id", "component_hash", name="uq_finding_chains_run_pattern_components"),
    )
    op.create_index("ix_finding_chains_run_id", "finding_chains", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_finding_chains_run_id", table_name="finding_chains")
    op.drop_table("finding_chains")
