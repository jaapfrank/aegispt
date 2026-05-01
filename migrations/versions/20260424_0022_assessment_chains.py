"""add assessment chains"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260424_0022"
down_revision = "20260424_0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_chains",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("current_run_id", sa.Uuid(), nullable=True),
        sa.Column("last_completed_run_id", sa.Uuid(), nullable=True),
        sa.Column("assessment_mode", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("current_phase_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_step_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "auto_advance_on_phase_complete",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("halt_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("phases_json", sa.JSON(), nullable=False),
        sa.Column("configuration_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["current_run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["last_completed_run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_assessment_chains_engagement_id",
        "assessment_chains",
        ["engagement_id"],
        unique=False,
    )
    op.create_index(
        "ix_assessment_chains_current_run_id",
        "assessment_chains",
        ["current_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_assessment_chains_last_completed_run_id",
        "assessment_chains",
        ["last_completed_run_id"],
        unique=False,
    )

    with op.batch_alter_table("runs") as batch_op:
        batch_op.add_column(sa.Column("assessment_chain_id", sa.Uuid(), nullable=True))
        batch_op.create_index("ix_runs_assessment_chain_id", ["assessment_chain_id"], unique=False)
        batch_op.create_foreign_key(
            "fk_runs_assessment_chain_id_assessment_chains",
            "assessment_chains",
            ["assessment_chain_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("runs") as batch_op:
        batch_op.drop_constraint(
            "fk_runs_assessment_chain_id_assessment_chains",
            type_="foreignkey",
        )
        batch_op.drop_index("ix_runs_assessment_chain_id")
        batch_op.drop_column("assessment_chain_id")

    op.drop_index("ix_assessment_chains_last_completed_run_id", table_name="assessment_chains")
    op.drop_index("ix_assessment_chains_current_run_id", table_name="assessment_chains")
    op.drop_index("ix_assessment_chains_engagement_id", table_name="assessment_chains")
    op.drop_table("assessment_chains")
