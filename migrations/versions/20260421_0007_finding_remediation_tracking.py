"""add finding remediation tracking records"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260421_0007"
down_revision = "20260415_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_remediations",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(length=50), nullable=False, server_default="not_started"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id"),
    )


def downgrade() -> None:
    op.drop_table("finding_remediations")
