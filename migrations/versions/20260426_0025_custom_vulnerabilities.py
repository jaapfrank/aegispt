"""add custom vulnerability library tables"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260426_0025"
down_revision = "20260426_0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_vulnerabilities",
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("custom_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("affected_products_json", sa.JSON(), nullable=False),
        sa.Column("cwe_ids_json", sa.JSON(), nullable=False),
        sa.Column("discovery_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reporter", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("linked_nuclei_template_ref", sa.String(length=255), nullable=True),
        sa.Column("linked_threat_intel_record_id", sa.Uuid(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["linked_threat_intel_record_id"],
            ["threat_intel_records.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "custom_id",
            name="uq_custom_vulnerabilities_tenant_custom_id",
        ),
    )
    op.create_index("ix_custom_vulnerabilities_tenant_id", "custom_vulnerabilities", ["tenant_id"], unique=False)
    op.create_index("ix_custom_vulnerabilities_custom_id", "custom_vulnerabilities", ["custom_id"], unique=False)
    op.create_index("ix_custom_vulnerabilities_severity", "custom_vulnerabilities", ["severity"], unique=False)
    op.create_index("ix_custom_vulnerabilities_status", "custom_vulnerabilities", ["status"], unique=False)
    op.create_index("ix_custom_vulnerabilities_deleted_at", "custom_vulnerabilities", ["deleted_at"], unique=False)

    op.create_table(
        "custom_vulnerability_engagement_settings",
        sa.Column("custom_vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("enabled_by", sa.String(length=255), nullable=True),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["custom_vulnerability_id"], ["custom_vulnerabilities.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "custom_vulnerability_id",
            "engagement_id",
            name="uq_custom_vulnerability_engagement_setting",
        ),
    )
    op.create_index(
        "ix_custom_vulnerability_engagement_settings_custom_vulnerability_id",
        "custom_vulnerability_engagement_settings",
        ["custom_vulnerability_id"],
        unique=False,
    )
    op.create_index(
        "ix_custom_vulnerability_engagement_settings_engagement_id",
        "custom_vulnerability_engagement_settings",
        ["engagement_id"],
        unique=False,
    )
    op.create_index(
        "ix_custom_vulnerability_engagement_settings_enabled",
        "custom_vulnerability_engagement_settings",
        ["enabled"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_custom_vulnerability_engagement_settings_enabled",
        table_name="custom_vulnerability_engagement_settings",
    )
    op.drop_index(
        "ix_custom_vulnerability_engagement_settings_engagement_id",
        table_name="custom_vulnerability_engagement_settings",
    )
    op.drop_index(
        "ix_custom_vulnerability_engagement_settings_custom_vulnerability_id",
        table_name="custom_vulnerability_engagement_settings",
    )
    op.drop_table("custom_vulnerability_engagement_settings")
    op.drop_index("ix_custom_vulnerabilities_deleted_at", table_name="custom_vulnerabilities")
    op.drop_index("ix_custom_vulnerabilities_status", table_name="custom_vulnerabilities")
    op.drop_index("ix_custom_vulnerabilities_severity", table_name="custom_vulnerabilities")
    op.drop_index("ix_custom_vulnerabilities_custom_id", table_name="custom_vulnerabilities")
    op.drop_index("ix_custom_vulnerabilities_tenant_id", table_name="custom_vulnerabilities")
    op.drop_table("custom_vulnerabilities")
