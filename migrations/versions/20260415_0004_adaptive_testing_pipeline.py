"""adaptive testing pipeline and pack provenance"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260415_0004"
down_revision = "20260415_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "inventory_snapshots",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="completed"),
        sa.Column("source_tools_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("raw_inputs_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("normalized_inventory_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("summary_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("environment_notes_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("assumptions_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "threat_intel_records",
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("advisory_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("affected_products_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("affected_versions_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("product_match_hints_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("architecture_hints_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("attack_surface_type", sa.String(length=100), nullable=True),
        sa.Column("suggested_test_patterns_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("references_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("advisory_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("normalization_status", sa.String(length=50), nullable=False, server_default="normalized"),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "relevance_decisions",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("inventory_snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="completed"),
        sa.Column("threat_intel_refs_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("prior_finding_refs_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("methodology_tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("recommendations_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("justification_text", sa.Text(), nullable=True),
        sa.Column("evidence_basis_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["inventory_snapshot_id"], ["inventory_snapshots.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "capability_packs",
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("relevance_decision_id", sa.Uuid(), nullable=True),
        sa.Column("source_inventory_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("parent_pack_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="generated"),
        sa.Column("generated_by", sa.String(length=255), nullable=False),
        sa.Column("generation_mode", sa.String(length=100), nullable=False, server_default="codex-supervised"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_threat_intel_refs_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("methodology_tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("manifest_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("provenance_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["parent_pack_id"], ["capability_packs.id"]),
        sa.ForeignKeyConstraint(["relevance_decision_id"], ["relevance_decisions.id"]),
        sa.ForeignKeyConstraint(["source_inventory_snapshot_id"], ["inventory_snapshots.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "capability_pack_artifacts",
        sa.Column("pack_id", sa.Uuid(), nullable=False),
        sa.Column("artifact_type", sa.String(length=100), nullable=False),
        sa.Column("logical_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="generated"),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=False),
        sa.Column("methodology_tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("content_text", sa.Text(), nullable=True),
        sa.Column("content_json", sa.JSON(), nullable=True),
        sa.Column("provenance_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["pack_id"], ["capability_packs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "capability_pack_validation_results",
        sa.Column("pack_id", sa.Uuid(), nullable=False),
        sa.Column("validator", sa.String(length=100), nullable=False),
        sa.Column("executed_by", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("artifact_results_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("validation_artifacts_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("blocking_issues_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["pack_id"], ["capability_packs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "capability_pack_approvals",
        sa.Column("pack_id", sa.Uuid(), nullable=False),
        sa.Column("approval_step", sa.String(length=100), nullable=False, server_default="pack.promotion"),
        sa.Column("approver_id", sa.String(length=255), nullable=False),
        sa.Column("decision", sa.String(length=50), nullable=False, server_default="approved"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["pack_id"], ["capability_packs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "capability_pack_deployments",
        sa.Column("pack_id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("deployed_by", sa.String(length=255), nullable=False),
        sa.Column("deployment_target", sa.String(length=100), nullable=False, server_default="engagement-runtime"),
        sa.Column("run_profile_name", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="deployed"),
        sa.Column("rollback_from_pack_id", sa.Uuid(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("runtime_binding_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["pack_id"], ["capability_packs.id"]),
        sa.ForeignKeyConstraint(["rollback_from_pack_id"], ["capability_packs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    with op.batch_alter_table("runs", recreate="auto") as batch_op:
        batch_op.add_column(sa.Column("source_inventory_snapshot_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("bound_pack_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("bound_pack_version", sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column("bound_pack_deployment_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_runs_source_inventory_snapshot_id",
            "inventory_snapshots",
            ["source_inventory_snapshot_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_runs_bound_pack_id",
            "capability_packs",
            ["bound_pack_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_runs_bound_pack_deployment_id",
            "capability_pack_deployments",
            ["bound_pack_deployment_id"],
            ["id"],
        )

    with op.batch_alter_table("findings", recreate="auto") as batch_op:
        batch_op.add_column(sa.Column("source_pack_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("source_pack_artifact_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("source_inventory_snapshot_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("source_relevance_decision_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("source_pack_version", sa.String(length=50), nullable=True))
        batch_op.add_column(
            sa.Column("finding_origin", sa.String(length=50), nullable=False, server_default="standard")
        )
        batch_op.create_foreign_key(
            "fk_findings_source_pack_id",
            "capability_packs",
            ["source_pack_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_findings_source_pack_artifact_id",
            "capability_pack_artifacts",
            ["source_pack_artifact_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_findings_source_inventory_snapshot_id",
            "inventory_snapshots",
            ["source_inventory_snapshot_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_findings_source_relevance_decision_id",
            "relevance_decisions",
            ["source_relevance_decision_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("findings", recreate="auto") as batch_op:
        batch_op.drop_constraint("fk_findings_source_relevance_decision_id", type_="foreignkey")
        batch_op.drop_constraint("fk_findings_source_inventory_snapshot_id", type_="foreignkey")
        batch_op.drop_constraint("fk_findings_source_pack_artifact_id", type_="foreignkey")
        batch_op.drop_constraint("fk_findings_source_pack_id", type_="foreignkey")
        batch_op.drop_column("finding_origin")
        batch_op.drop_column("source_pack_version")
        batch_op.drop_column("source_relevance_decision_id")
        batch_op.drop_column("source_inventory_snapshot_id")
        batch_op.drop_column("source_pack_artifact_id")
        batch_op.drop_column("source_pack_id")

    with op.batch_alter_table("runs", recreate="auto") as batch_op:
        batch_op.drop_constraint("fk_runs_bound_pack_deployment_id", type_="foreignkey")
        batch_op.drop_constraint("fk_runs_bound_pack_id", type_="foreignkey")
        batch_op.drop_constraint("fk_runs_source_inventory_snapshot_id", type_="foreignkey")
        batch_op.drop_column("bound_pack_deployment_id")
        batch_op.drop_column("bound_pack_version")
        batch_op.drop_column("bound_pack_id")
        batch_op.drop_column("source_inventory_snapshot_id")

    op.drop_table("capability_pack_deployments")
    op.drop_table("capability_pack_approvals")
    op.drop_table("capability_pack_validation_results")
    op.drop_table("capability_pack_artifacts")
    op.drop_table("capability_packs")
    op.drop_table("relevance_decisions")
    op.drop_table("threat_intel_records")
    op.drop_table("inventory_snapshots")
