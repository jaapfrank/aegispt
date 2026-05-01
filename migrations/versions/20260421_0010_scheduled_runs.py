"""add scheduled run records"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260421_0010"
down_revision = "20260421_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scheduled_runs",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("profile_name", sa.String(length=100), nullable=False),
        sa.Column("source_inventory_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("cadence", sa.String(length=20), nullable=False),
        sa.Column("cron_expression", sa.String(length=100), nullable=False),
        sa.Column("timezone", sa.String(length=100), nullable=False, server_default="UTC"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="enabled"),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_launched_run_id", sa.Uuid(), nullable=True),
        sa.Column("configuration_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("paused_by", sa.String(length=255), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["source_inventory_snapshot_id"], ["inventory_snapshots.id"]),
        sa.ForeignKeyConstraint(["last_launched_run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("scheduled_runs")
