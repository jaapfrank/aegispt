"""add ai fix suggestion to finding remediations"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20260429_0032"
down_revision = "20260429_0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "finding_remediations" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("finding_remediations")}
    if "ai_fix_suggestion" not in columns:
        op.add_column("finding_remediations", sa.Column("ai_fix_suggestion", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "finding_remediations" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("finding_remediations")}
    if "ai_fix_suggestion" in columns:
        op.drop_column("finding_remediations", "ai_fix_suggestion")
