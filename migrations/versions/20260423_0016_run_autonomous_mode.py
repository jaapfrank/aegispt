"""add autonomous run mode flags"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260423_0016"
down_revision = "20260423_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column(
            "autonomous_mode",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "runs",
        sa.Column(
            "autonomous_intrusive_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("runs", "autonomous_intrusive_allowed")
    op.drop_column("runs", "autonomous_mode")
