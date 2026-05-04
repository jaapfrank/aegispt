"""add tenant scoped instance settings"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260423_0015"
down_revision = "20260422_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "instance_settings",
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("setting_key", sa.String(length=255), nullable=False),
        sa.Column("value_json", sa.JSON(), nullable=False),
        sa.Column("sensitive", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("storage_backend", sa.String(length=50), nullable=True),
        sa.Column("encrypted_value", sa.Text(), nullable=True),
        sa.Column("display_label", sa.String(length=255), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "setting_key", name="uq_instance_settings_tenant_key"),
    )
    op.create_index("ix_instance_settings_tenant_id", "instance_settings", ["tenant_id"])
    op.create_index("ix_instance_settings_setting_key", "instance_settings", ["setting_key"])


def downgrade() -> None:
    op.drop_index("ix_instance_settings_setting_key", table_name="instance_settings")
    op.drop_index("ix_instance_settings_tenant_id", table_name="instance_settings")
    op.drop_table("instance_settings")
