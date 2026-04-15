"""add run configuration json for UI-driven assessment wizard"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260415_0005"
down_revision = "20260415_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runs", recreate="auto") as batch_op:
        batch_op.add_column(
            sa.Column("configuration_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table("runs", recreate="auto") as batch_op:
        batch_op.drop_column("configuration_json")
