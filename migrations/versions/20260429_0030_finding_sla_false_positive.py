"""add finding SLA and false positive fields"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260429_0030"
down_revision = "20260429_0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("findings")}

    if "remediation_due_date" not in columns:
        op.add_column(
            "findings",
            sa.Column("remediation_due_date", sa.DateTime(timezone=True), nullable=True),
        )
    if "sla_breached" not in columns:
        op.add_column(
            "findings",
            sa.Column("sla_breached", sa.Boolean(), server_default=sa.false(), nullable=False),
        )
    if "false_positive_reason" not in columns:
        op.add_column("findings", sa.Column("false_positive_reason", sa.Text(), nullable=True))
    if "false_positive_confirmed_by" not in columns:
        op.add_column(
            "findings",
            sa.Column("false_positive_confirmed_by", sa.String(length=255), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("findings")}

    if "false_positive_confirmed_by" in columns:
        op.drop_column("findings", "false_positive_confirmed_by")
    if "false_positive_reason" in columns:
        op.drop_column("findings", "false_positive_reason")
    if "sla_breached" in columns:
        op.drop_column("findings", "sla_breached")
    if "remediation_due_date" in columns:
        op.drop_column("findings", "remediation_due_date")
