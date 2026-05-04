"""add jira finding integration links"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260421_0009"
down_revision = "20260421_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_integration_links",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("integration_configuration_id", sa.Uuid(), nullable=False),
        sa.Column("issue_key", sa.String(length=100), nullable=False),
        sa.Column("issue_url", sa.String(length=2048), nullable=False),
        sa.Column("issue_status", sa.String(length=100), nullable=True),
        sa.Column("last_sync_state", sa.String(length=50), nullable=False, server_default="not_synced"),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_error", sa.Text(), nullable=True),
        sa.Column("last_sync_payload_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["integration_configuration_id"], ["integration_configurations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id",
            "integration_configuration_id",
            name="uq_finding_integration_links_finding_configuration",
        ),
    )


def downgrade() -> None:
    op.drop_table("finding_integration_links")
