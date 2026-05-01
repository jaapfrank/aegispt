"""add optional engagement tenant id"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260421_0012"
down_revision = "20260421_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("engagements", sa.Column("tenant_id", sa.String(length=100), nullable=True))
    op.create_index("ix_engagements_tenant_id", "engagements", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_engagements_tenant_id", table_name="engagements")
    op.drop_column("engagements", "tenant_id")
