"""add CVE feed sync watchlist and status tables"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260426_0024"
down_revision = "20260425_0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_product_watchlist_entries",
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("query", sa.String(length=255), nullable=False),
        sa.Column("normalized_query", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("source_inventory_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_inventory_snapshot_id"], ["inventory_snapshots.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "normalized_query", name="uq_cve_watchlist_tenant_query"),
    )
    op.create_index("ix_cve_product_watchlist_entries_tenant_id", "cve_product_watchlist_entries", ["tenant_id"], unique=False)
    op.create_index(
        "ix_cve_product_watchlist_entries_normalized_query",
        "cve_product_watchlist_entries",
        ["normalized_query"],
        unique=False,
    )
    op.create_index("ix_cve_product_watchlist_entries_status", "cve_product_watchlist_entries", ["status"], unique=False)

    op.create_table(
        "cve_feed_sync_logs",
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_count", sa.Integer(), nullable=False),
        sa.Column("updated_count", sa.Integer(), nullable=False),
        sa.Column("skipped_count", sa.Integer(), nullable=False),
        sa.Column("error_text", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cve_feed_sync_logs_tenant_id", "cve_feed_sync_logs", ["tenant_id"], unique=False)
    op.create_index("ix_cve_feed_sync_logs_source", "cve_feed_sync_logs", ["source"], unique=False)
    op.create_index("ix_cve_feed_sync_logs_status", "cve_feed_sync_logs", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cve_feed_sync_logs_status", table_name="cve_feed_sync_logs")
    op.drop_index("ix_cve_feed_sync_logs_source", table_name="cve_feed_sync_logs")
    op.drop_index("ix_cve_feed_sync_logs_tenant_id", table_name="cve_feed_sync_logs")
    op.drop_table("cve_feed_sync_logs")
    op.drop_index("ix_cve_product_watchlist_entries_status", table_name="cve_product_watchlist_entries")
    op.drop_index("ix_cve_product_watchlist_entries_normalized_query", table_name="cve_product_watchlist_entries")
    op.drop_index("ix_cve_product_watchlist_entries_tenant_id", table_name="cve_product_watchlist_entries")
    op.drop_table("cve_product_watchlist_entries")
