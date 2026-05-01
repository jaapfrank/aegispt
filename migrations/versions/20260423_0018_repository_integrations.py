"""add repository integrations and finding repo links"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260423_0018"
down_revision = "20260423_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repo_integrations",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("token_secret_ref_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("repository_url", sa.String(length=2048), nullable=False),
        sa.Column("repository_path", sa.String(length=512), nullable=False),
        sa.Column("default_branch", sa.String(length=255), nullable=False, server_default="main"),
        sa.Column("account_login", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="connected"),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["token_secret_ref_id"], ["secrets_refs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id",
            "provider",
            "repository_url",
            name="uq_repo_integrations_engagement_provider_url",
        ),
    )
    op.create_table(
        "finding_repo_links",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("repo_integration_id", sa.Uuid(), nullable=False),
        sa.Column("repository_path", sa.String(length=1024), nullable=False),
        sa.Column("repository_branch", sa.String(length=255), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("line_end", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("highlighted_line", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("snippet_language", sa.String(length=50), nullable=True),
        sa.Column("snippet_text", sa.Text(), nullable=False),
        sa.Column("external_url", sa.String(length=2048), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["repo_integration_id"], ["repo_integrations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "repo_integration_id", name="uq_finding_repo_links_finding_repo"),
    )


def downgrade() -> None:
    op.drop_table("finding_repo_links")
    op.drop_table("repo_integrations")
