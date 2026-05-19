"""methodology metadata for findings"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260415_0003"
down_revision = "20260415_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("methodology_tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column("findings", sa.Column("ptes_phase", sa.String(length=50), nullable=True))
    op.add_column("findings", sa.Column("nist_phase", sa.String(length=50), nullable=True))
    op.add_column("findings", sa.Column("wstg_id", sa.String(length=50), nullable=True))
    op.add_column("findings", sa.Column("wstg_version", sa.String(length=20), nullable=True))
    op.add_column("findings", sa.Column("asvs_reference", sa.String(length=50), nullable=True))
    op.add_column("findings", sa.Column("control_family", sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "control_family")
    op.drop_column("findings", "asvs_reference")
    op.drop_column("findings", "wstg_version")
    op.drop_column("findings", "wstg_id")
    op.drop_column("findings", "nist_phase")
    op.drop_column("findings", "ptes_phase")
    op.drop_column("findings", "methodology_tags")
