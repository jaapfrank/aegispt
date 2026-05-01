"""add finding autofix json"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260423_0017"
down_revision = "20260423_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("autofix_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "autofix_json")
