"""add jira integration configuration records"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260421_0008"
down_revision = "20260421_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_configurations",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("integration_type", sa.String(length=50), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("project_key", sa.String(length=100), nullable=True),
        sa.Column("auth_ref", sa.String(length=255), nullable=True),
        sa.Column("settings_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id",
            "integration_type",
            name="uq_integration_configurations_engagement_type",
        ),
    )


def downgrade() -> None:
    op.drop_table("integration_configurations")
