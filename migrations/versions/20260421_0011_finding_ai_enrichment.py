"""add finding ai enrichment records"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260421_0011"
down_revision = "20260421_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_ai_enrichments",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="succeeded"),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("business_impact", sa.Text(), nullable=True),
        sa.Column("technical_context", sa.Text(), nullable=True),
        sa.Column("remediation_narrative", sa.Text(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", name="uq_finding_ai_enrichments_finding_id"),
    )


def downgrade() -> None:
    op.drop_table("finding_ai_enrichments")
