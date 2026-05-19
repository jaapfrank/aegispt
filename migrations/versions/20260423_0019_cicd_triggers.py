"""add cicd triggers and trigger events"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260423_0019"
down_revision = "20260423_0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cicd_triggers",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("webhook_secret_ref_id", sa.Uuid(), nullable=False),
        sa.Column("trigger_source", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="enabled"),
        sa.Column("enabled_profiles_json", sa.JSON(), nullable=False),
        sa.Column("branch_filters_json", sa.JSON(), nullable=False),
        sa.Column("scope_override_allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_id", sa.Uuid(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["last_run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["webhook_secret_ref_id"], ["secrets_refs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id",
            "trigger_source",
            name="uq_cicd_triggers_engagement_source",
        ),
    )
    op.create_table(
        "cicd_trigger_events",
        sa.Column("cicd_trigger_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("trigger_source", sa.String(length=50), nullable=False),
        sa.Column("profile_name", sa.String(length=100), nullable=True),
        sa.Column("ref", sa.String(length=255), nullable=True),
        sa.Column("commit_sha", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="received"),
        sa.Column("status_detail", sa.Text(), nullable=True),
        sa.Column("signature_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("scope_override_applied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("override_target_url", sa.String(length=2048), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["cicd_trigger_id"], ["cicd_triggers.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("cicd_trigger_events")
    op.drop_table("cicd_triggers")
