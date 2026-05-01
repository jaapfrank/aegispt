"""add engagement data retention policy"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20260428_0026"
down_revision = "20260426_0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("engagements")}
    if "retention_days" not in columns:
        op.add_column(
            "engagements",
            sa.Column("retention_days", sa.Integer(), nullable=False, server_default="90"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("engagements")}
    if "retention_days" in columns:
        op.drop_column("engagements", "retention_days")
