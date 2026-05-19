"""extend secret references for encrypted local storage metadata"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260415_0006"
down_revision = "20260415_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("secrets_refs", recreate="auto") as batch_op:
        batch_op.add_column(
            sa.Column("secret_kind", sa.String(length=50), nullable=False, server_default="reference")
        )
        batch_op.add_column(
            sa.Column(
                "storage_backend",
                sa.String(length=50),
                nullable=False,
                server_default="external_pointer",
            )
        )
        batch_op.add_column(sa.Column("display_label", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("encrypted_value", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table("secrets_refs", recreate="auto") as batch_op:
        batch_op.drop_column("metadata_json")
        batch_op.drop_column("encrypted_value")
        batch_op.drop_column("display_label")
        batch_op.drop_column("storage_backend")
        batch_op.drop_column("secret_kind")
