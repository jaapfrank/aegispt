"""add evidence timestamp columns and finding cvss fields"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "20260429_0028"
down_revision = "20260428_0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    artifact_columns = {column["name"] for column in inspect(bind).get_columns("evidence_artifacts")}
    if "timestamp_token_uri" not in artifact_columns:
        op.add_column(
            "evidence_artifacts",
            sa.Column("timestamp_token_uri", sa.String(length=512), nullable=True),
        )
    if "timestamp_verified_at" not in artifact_columns:
        op.add_column(
            "evidence_artifacts",
            sa.Column("timestamp_verified_at", sa.DateTime(timezone=True), nullable=True),
        )

    finding_columns = {column["name"] for column in inspect(bind).get_columns("findings")}
    if "cvss_score" not in finding_columns:
        op.add_column("findings", sa.Column("cvss_score", sa.Float(), nullable=True))
    if "cvss_vector" not in finding_columns:
        op.add_column("findings", sa.Column("cvss_vector", sa.String(length=64), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()

    finding_columns = {column["name"] for column in inspect(bind).get_columns("findings")}
    if "cvss_vector" in finding_columns:
        op.drop_column("findings", "cvss_vector")
    if "cvss_score" in finding_columns:
        op.drop_column("findings", "cvss_score")

    artifact_columns = {column["name"] for column in inspect(bind).get_columns("evidence_artifacts")}
    if "timestamp_verified_at" in artifact_columns:
        op.drop_column("evidence_artifacts", "timestamp_verified_at")
    if "timestamp_token_uri" in artifact_columns:
        op.drop_column("evidence_artifacts", "timestamp_token_uri")
