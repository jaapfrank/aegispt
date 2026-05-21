"""backlog-410: agent_episodic_memory table (ADDITIVE — memory_backend untouched).

Cross-advance + cross-run queryable memory layer. Embedding column type
depends on what the PostgreSQL instance supports:
- pgvector extension present -> `vector(1536)` column for native cosine.
- extension absent           -> `jsonb` column holding the embedding array
  and `_python_cosine_similarity` does the math at query time.

Per Codex contamination guard: `is_benchmark` boolean isolates benchmark
writes; the service-layer query default excludes those from production
recalls.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

revision = "20260521_0034"
down_revision = "20260515_0033"
branch_labels = None
depends_on = None


def _pgvector_available(bind) -> bool:
    """Best-effort check that the pgvector extension is available on the bound DB."""
    try:
        result = bind.exec_driver_sql(
            "SELECT 1 FROM pg_available_extensions WHERE name = 'vector'"
        )
        return result.first() is not None
    except Exception:  # noqa: BLE001
        return False


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "agent_episodic_memory" in inspector.get_table_names():
        return

    use_pgvector = _pgvector_available(bind)
    if use_pgvector:
        try:
            bind.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS vector")
        except Exception:  # noqa: BLE001
            use_pgvector = False

    embedding_type: sa.types.TypeEngine
    if use_pgvector:
        # Cast through text() to avoid importing pgvector.sqlalchemy at
        # migration time (the python pkg may not be installed). The DDL is
        # all that matters here.
        op.execute(text("""
            CREATE TABLE agent_episodic_memory (
                id UUID PRIMARY KEY,
                run_id UUID NOT NULL REFERENCES runs(id),
                engagement_id UUID NULL REFERENCES engagements(id),
                action_type VARCHAR(64) NOT NULL,
                action_context_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                outcome_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                success_marker VARCHAR(64) NULL,
                embedding vector(1536) NULL,
                is_benchmark BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        op.create_index("ix_agent_episodic_memory_run_id", "agent_episodic_memory", ["run_id"])
        op.create_index(
            "ix_agent_episodic_memory_engagement_id",
            "agent_episodic_memory",
            ["engagement_id"],
        )
        op.create_index(
            "ix_agent_episodic_memory_is_benchmark",
            "agent_episodic_memory",
            ["is_benchmark"],
        )
        # ANN index — IVFFlat with 100 lists is a sane default for <100k rows.
        try:
            bind.exec_driver_sql(
                "CREATE INDEX ix_agent_episodic_memory_embedding_cosine "
                "ON agent_episodic_memory "
                "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
            )
        except Exception:  # noqa: BLE001
            # IVFFlat needs at least a few rows; fall back to no ANN index.
            pass
    else:
        # Fallback path — JSON storage; similarity computed in Python at query time.
        embedding_type = sa.JSON()
        op.create_table(
            "agent_episodic_memory",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id"), nullable=False, index=True),
            sa.Column(
                "engagement_id",
                sa.Uuid(),
                sa.ForeignKey("engagements.id"),
                nullable=True,
                index=True,
            ),
            sa.Column("action_type", sa.String(64), nullable=False),
            sa.Column("action_context_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("outcome_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("success_marker", sa.String(64), nullable=True),
            sa.Column("embedding", embedding_type, nullable=True),
            sa.Column(
                "is_benchmark",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
                index=True,
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "agent_episodic_memory" not in inspector.get_table_names():
        return
    op.drop_table("agent_episodic_memory")
