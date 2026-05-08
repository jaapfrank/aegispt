"""add ai contextual profiling models"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "de2575b07013"
down_revision = "20260429_0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "target_context_documents" not in existing_tables:
        op.create_table(
            "target_context_documents",
            sa.Column("run_id", sa.Uuid(), nullable=False),
            sa.Column("parent_context_document_id", sa.Uuid(), nullable=True),
            sa.Column("layer_name", sa.String(length=255), nullable=False, server_default="phase_0_recon"),
            sa.Column("context_kind", sa.String(length=100), nullable=False, server_default="target_context"),
            sa.Column("status", sa.String(length=50), nullable=False, server_default="recorded"),
            sa.Column("source_targets_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("technologies_detected_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("endpoints_discovered_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("recommended_tools_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("micro_plan_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("evidence_refs_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("context_summary", sa.Text(), nullable=False),
            sa.Column("provenance_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["parent_context_document_id"], ["target_context_documents.id"]),
            sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_target_context_documents_parent_context_document_id", "target_context_documents", ["parent_context_document_id"])
        op.create_index("ix_target_context_documents_run_id", "target_context_documents", ["run_id"])

    if "rationale_ledger_entries" not in existing_tables:
        op.create_table(
            "rationale_ledger_entries",
            sa.Column("run_id", sa.Uuid(), nullable=False),
            sa.Column("context_document_id", sa.Uuid(), nullable=True),
            sa.Column("task_id", sa.Uuid(), nullable=True),
            sa.Column("agent_proposal_id", sa.Uuid(), nullable=True),
            sa.Column("action_type", sa.String(length=100), nullable=False, server_default="tool_dispatch"),
            sa.Column("tool_name", sa.String(length=100), nullable=False),
            sa.Column("target", sa.String(length=255), nullable=True),
            sa.Column("rationale_text", sa.Text(), nullable=False),
            sa.Column("decision_source_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("parameters_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("status", sa.String(length=50), nullable=False, server_default="recorded"),
            sa.Column("provenance_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["agent_proposal_id"], ["agent_proposals.id"]),
            sa.ForeignKeyConstraint(["context_document_id"], ["target_context_documents.id"]),
            sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
            sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_rationale_ledger_entries_agent_proposal_id", "rationale_ledger_entries", ["agent_proposal_id"])
        op.create_index("ix_rationale_ledger_entries_context_document_id", "rationale_ledger_entries", ["context_document_id"])
        op.create_index("ix_rationale_ledger_entries_run_id", "rationale_ledger_entries", ["run_id"])
        op.create_index("ix_rationale_ledger_entries_task_id", "rationale_ledger_entries", ["task_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "rationale_ledger_entries" in existing_tables:
        existing_indexes = {index["name"] for index in inspector.get_indexes("rationale_ledger_entries")}
        for index_name in (
            "ix_rationale_ledger_entries_task_id",
            "ix_rationale_ledger_entries_run_id",
            "ix_rationale_ledger_entries_context_document_id",
            "ix_rationale_ledger_entries_agent_proposal_id",
        ):
            if index_name in existing_indexes:
                op.drop_index(index_name, table_name="rationale_ledger_entries")
        op.drop_table("rationale_ledger_entries")

    if "target_context_documents" in existing_tables:
        existing_indexes = {index["name"] for index in inspector.get_indexes("target_context_documents")}
        for index_name in (
            "ix_target_context_documents_run_id",
            "ix_target_context_documents_parent_context_document_id",
        ):
            if index_name in existing_indexes:
                op.drop_index(index_name, table_name="target_context_documents")
        op.drop_table("target_context_documents")
