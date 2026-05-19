"""add api keys and engagement authorization confirmation"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260429_0029"
down_revision = "20260429_0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "api_keys" not in table_names:
        op.create_table(
            "api_keys",
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("actor_name", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=50), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)

    engagement_columns = {column["name"] for column in inspector.get_columns("engagements")}
    if "authorization_confirmed_by" not in engagement_columns:
        op.add_column(
            "engagements",
            sa.Column("authorization_confirmed_by", sa.String(length=255), nullable=True),
        )
    if "authorization_confirmed_at" not in engagement_columns:
        op.add_column(
            "engagements",
            sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    engagement_columns = {column["name"] for column in inspector.get_columns("engagements")}
    if "authorization_confirmed_at" in engagement_columns:
        op.drop_column("engagements", "authorization_confirmed_at")
    if "authorization_confirmed_by" in engagement_columns:
        op.drop_column("engagements", "authorization_confirmed_by")

    if "api_keys" in set(inspector.get_table_names()):
        op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
        op.drop_table("api_keys")
