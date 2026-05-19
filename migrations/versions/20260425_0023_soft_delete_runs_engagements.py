"""add soft delete markers for runs and engagements"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260425_0023"
down_revision = "20260424_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("engagements", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("runs", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_engagements_deleted_at", "engagements", ["deleted_at"], unique=False)
    op.create_index("ix_runs_deleted_at", "runs", ["deleted_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_runs_deleted_at", table_name="runs")
    op.drop_index("ix_engagements_deleted_at", table_name="engagements")
    op.drop_column("runs", "deleted_at")
    op.drop_column("engagements", "deleted_at")
