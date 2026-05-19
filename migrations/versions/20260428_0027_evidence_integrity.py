"""add evidence replay recipe and enforce artifact hash baseline"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260428_0027"
down_revision = "20260428_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    finding_columns = {column["name"] for column in inspect(bind).get_columns("findings")}
    if "replay_recipe_json" not in finding_columns:
        op.add_column("findings", sa.Column("replay_recipe_json", sa.JSON(), nullable=True))

    artifact_columns = {column["name"] for column in inspect(bind).get_columns("evidence_artifacts")}
    if "sha256" in artifact_columns:
        op.execute("UPDATE evidence_artifacts SET sha256 = 'hash-unavailable' WHERE sha256 IS NULL")
        with op.batch_alter_table("evidence_artifacts", recreate="auto") as batch_op:
            batch_op.alter_column(
                "sha256",
                existing_type=sa.String(length=64),
                nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    finding_columns = {column["name"] for column in inspect(bind).get_columns("findings")}
    if "replay_recipe_json" in finding_columns:
        op.drop_column("findings", "replay_recipe_json")
