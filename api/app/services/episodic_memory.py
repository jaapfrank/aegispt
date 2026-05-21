"""Cross-advance + cross-run queryable episodic memory.

Per backlog-410 (sprint mythos-exploitation-foundation, task 4/15) + Codex
refinement: ADDITIVE layer on top of the existing file-backed
``memory_backend.py`` (short-term scratchpad). This module owns the
*queryable* layer: every advance can write a structured (action, context,
outcome, success_marker) episode and recall semantically similar past
episodes via embedding similarity.

Design notes:

- ``memory_backend.py`` is left UNTOUCHED per Codex refinement #3. The
  scratchpad and the episodic store are different lifecycles.
- Embeddings provider is pluggable via ``EPISODIC_EMBED_PROVIDER`` env:
  ``openai`` (default, requires ``OPENAI_API_KEY``) or ``local_hash``
  (deterministic test fallback — DO NOT use in production; emits a
  hashed-feature vector that approximates similarity badly enough to be
  obviously a placeholder).
- When pgvector is installed, the migration provisioned a native
  ``vector(1536)`` column and an IVFFlat index. When it isn't (current
  dev DB), the embedding lives in a JSON column and similarity is
  computed in Python at recall time — slower but functional, and the
  service still gives the picker the SAME shape of result so swapping
  to pgvector is transparent.
- Per Codex contamination guard: every write tags ``is_benchmark`` based
  on whether the engagement is a benchmark engagement; the default
  recall query excludes benchmark rows so benchmark experience never
  contaminates production recalls.
- Per Claude Code lesson: every recall is a HINT, not an authoritative
  fact. :func:`skeptical_recall_with_verify_hint` prefixes every result
  with a ``[HINT, VERIFY BEFORE USE]`` marker so downstream prompts can't
  treat past episodes as proof.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


EMBEDDING_DIM = 1536


# --------------------------------------------------------------------------
# Public dataclasses
# --------------------------------------------------------------------------


@dataclass
class EpisodeRecord:
    """In-memory representation of an agent_episodic_memory row."""

    id: UUID
    run_id: UUID
    engagement_id: UUID | None
    action_type: str
    action_context: dict[str, Any]
    outcome: dict[str, Any]
    success_marker: str | None
    is_benchmark: bool
    created_at: datetime
    similarity: float | None = None  # populated on recall

    def as_hint(self) -> dict[str, Any]:
        """Return the episode as a structured HINT envelope (skeptical)."""
        return {
            "marker": "[HINT, VERIFY BEFORE USE]",
            "episode_id": str(self.id),
            "action_type": self.action_type,
            "success_marker": self.success_marker,
            "context": self.action_context,
            "outcome": self.outcome,
            "similarity": self.similarity,
            "created_at": self.created_at.isoformat(),
        }


# --------------------------------------------------------------------------
# Embeddings provider
# --------------------------------------------------------------------------


def _local_hash_embedding(text: str) -> list[float]:
    """Deterministic 1536-dim embedding from text — TEST FALLBACK ONLY.

    SHA-256 fed through a bucketed feature hash: not a real semantic
    embedding, but stable for unit tests so we can assert
    write+read+similarity round-trip without an LLM call.
    """
    vec = [0.0] * EMBEDDING_DIM
    buf = (text or "").encode("utf-8", errors="replace")
    if not buf:
        return vec
    digest = hashlib.sha256(buf).digest()
    # Repeatedly hash to fill all 1536 buckets.
    pos = 0
    seed = digest
    while pos < EMBEDDING_DIM:
        for byte in seed:
            if pos >= EMBEDDING_DIM:
                break
            vec[pos] = (byte - 127.5) / 127.5  # roughly [-1, 1]
            pos += 1
        seed = hashlib.sha256(seed).digest()
    # L2-normalize so cosine similarity is just a dot product.
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _openai_embedding(text_to_embed: str) -> list[float]:
    """Real OpenAI text-embedding-3-small call. Raises if API key missing."""
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not configured; cannot use openai embedding provider")
    import httpx
    resp = httpx.post(
        "https://api.openai.com/v1/embeddings",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": "text-embedding-3-small", "input": text_to_embed[:8000]},
        timeout=20.0,
    )
    resp.raise_for_status()
    return list(resp.json()["data"][0]["embedding"])


def embed(text_to_embed: str) -> list[float]:
    """Return an embedding for the input text using the configured provider.

    Falls back to ``local_hash`` (deterministic test stub) when the
    chosen provider isn't usable so writes don't crash the agent runtime.
    Per `feedback_anti_drift_contract` Rule 1 — observability/memory
    never breaks the agent.
    """
    provider = os.environ.get("EPISODIC_EMBED_PROVIDER", "openai").strip().lower()
    if provider == "local_hash":
        return _local_hash_embedding(text_to_embed)
    try:
        return _openai_embedding(text_to_embed)
    except Exception as exc:  # noqa: BLE001
        logger.warning("episodic_memory: embedding provider %s unavailable (%s); falling back to local_hash", provider, exc)
        return _local_hash_embedding(text_to_embed)


def _cosine(a: Iterable[float], b: Iterable[float]) -> float:
    a_list = list(a)
    b_list = list(b)
    if not a_list or not b_list or len(a_list) != len(b_list):
        return 0.0
    dot = sum(x * y for x, y in zip(a_list, b_list, strict=False))
    na = math.sqrt(sum(x * x for x in a_list)) or 1.0
    nb = math.sqrt(sum(y * y for y in b_list)) or 1.0
    return dot / (na * nb)


# --------------------------------------------------------------------------
# Storage helpers
# --------------------------------------------------------------------------


def _summarize_for_embedding(action_type: str, context: dict[str, Any], outcome: dict[str, Any]) -> str:
    """Compose the text representation used to derive the embedding."""
    parts = [f"action={action_type}"]
    ctx_json = json.dumps(context, sort_keys=True, default=str)
    out_json = json.dumps(outcome, sort_keys=True, default=str)
    parts.append(f"context={ctx_json[:1500]}")
    parts.append(f"outcome={out_json[:1500]}")
    return " | ".join(parts)


def _is_benchmark_engagement(run) -> bool:
    """Detect benchmark engagements without coupling to XBOW specifics.

    Benchmark mode flips the AEGISPT_MEMORY_ROOT env to a path containing
    `bench` or `xbow` (see scripts/xbow_benchmark.py anti-contamination
    guard); the harness also names benchmark engagements `xbow-bench-*`.
    A run's configuration_json may also have `is_benchmark=true` if a
    future harness sets it. Any of these signals tags the episode.
    """
    cfg = getattr(run, "configuration_json", None) or {}
    if isinstance(cfg, dict) and bool(cfg.get("is_benchmark")):
        return True
    eng = getattr(run, "engagement", None)
    if eng is not None:
        name = str(getattr(eng, "name", "") or "").lower()
        if name.startswith("xbow-bench") or "benchmark" in name:
            return True
    memory_root = os.environ.get("AEGISPT_MEMORY_ROOT", "").lower()
    if "bench" in memory_root or "xbow" in memory_root:
        return True
    return False


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def write_episode(
    session: Session,
    *,
    run,
    action_type: str,
    context: dict[str, Any],
    outcome: dict[str, Any],
    success_marker: str | None = None,
) -> EpisodeRecord:
    """Persist one episode tied to a run. Returns the new EpisodeRecord."""
    summary = _summarize_for_embedding(action_type, context, outcome)
    vector = embed(summary)
    is_bench = _is_benchmark_engagement(run)
    new_id = uuid4()

    session.execute(
        text(
            "INSERT INTO agent_episodic_memory "
            "(id, run_id, engagement_id, action_type, action_context_json, outcome_json, "
            " success_marker, embedding, is_benchmark, created_at) "
            "VALUES "
            "(:id, :run_id, :engagement_id, :action_type, "
            " CAST(:action_context AS JSON), CAST(:outcome AS JSON), "
            " :success_marker, CAST(:embedding AS JSON), :is_benchmark, NOW())"
        ),
        {
            "id": new_id,
            "run_id": run.id,
            "engagement_id": getattr(run, "engagement_id", None),
            "action_type": action_type,
            "action_context": json.dumps(context, default=str),
            "outcome": json.dumps(outcome, default=str),
            "success_marker": success_marker,
            "embedding": json.dumps(vector),
            "is_benchmark": is_bench,
        },
    )
    session.flush()
    return EpisodeRecord(
        id=new_id,
        run_id=run.id,
        engagement_id=getattr(run, "engagement_id", None),
        action_type=action_type,
        action_context=context,
        outcome=outcome,
        success_marker=success_marker,
        is_benchmark=is_bench,
        created_at=datetime.now(UTC),
    )


def recall_similar(
    session: Session,
    *,
    query: str,
    k: int = 5,
    filter_run_id: UUID | None = None,
    include_benchmark: bool = False,
) -> list[EpisodeRecord]:
    """Return up to ``k`` most-similar episodes to the query text.

    Default ``include_benchmark=False`` enforces the Codex contamination
    guard at recall time. Set ``filter_run_id`` to scope to a single run
    (cross-advance memory within one engagement).
    """
    query_vec = embed(query)
    # Pull a bounded candidate set; in pgvector path this would be ORDER BY
    # embedding <=> query LIMIT k, but the JSON-fallback path can't push
    # the math into the database. Bound to 200 rows to keep memory small.
    # Cast bind parameters explicitly — psycopg can't infer types when a
    # bound parameter only appears inside `IS NULL` / equality, hence the
    # CAST AS uuid below.
    sql = """
        SELECT id, run_id, engagement_id, action_type, action_context_json,
               outcome_json, success_marker, embedding, is_benchmark, created_at
        FROM agent_episodic_memory
        WHERE (CAST(:include_benchmark AS BOOLEAN) OR is_benchmark = FALSE)
          AND (CAST(:filter_run_id AS UUID) IS NULL OR run_id = CAST(:filter_run_id AS UUID))
        ORDER BY created_at DESC
        LIMIT 200
    """
    rows = session.execute(
        text(sql),
        {"include_benchmark": include_benchmark, "filter_run_id": filter_run_id},
    ).all()

    scored: list[EpisodeRecord] = []
    for row in rows:
        emb_raw = row.embedding
        if isinstance(emb_raw, str):
            try:
                emb = json.loads(emb_raw)
            except json.JSONDecodeError:
                emb = []
        elif isinstance(emb_raw, list):
            emb = emb_raw
        else:
            emb = []
        sim = _cosine(query_vec, emb) if emb else 0.0
        ctx = row.action_context_json if isinstance(row.action_context_json, dict) else (
            json.loads(row.action_context_json) if isinstance(row.action_context_json, str) else {}
        )
        out = row.outcome_json if isinstance(row.outcome_json, dict) else (
            json.loads(row.outcome_json) if isinstance(row.outcome_json, str) else {}
        )
        scored.append(
            EpisodeRecord(
                id=row.id,
                run_id=row.run_id,
                engagement_id=row.engagement_id,
                action_type=row.action_type,
                action_context=ctx,
                outcome=out,
                success_marker=row.success_marker,
                is_benchmark=bool(row.is_benchmark),
                created_at=row.created_at,
                similarity=sim,
            )
        )
    scored.sort(key=lambda r: r.similarity or 0.0, reverse=True)
    return scored[:k]


def skeptical_recall_with_verify_hint(
    session: Session,
    *,
    query: str,
    k: int = 5,
    filter_run_id: UUID | None = None,
) -> list[dict[str, Any]]:
    """Recall envelope: every result wears the ``[HINT, VERIFY BEFORE USE]``
    marker so downstream picker prompts can't conflate past experience
    with current proof.
    """
    episodes = recall_similar(
        session,
        query=query,
        k=k,
        filter_run_id=filter_run_id,
        include_benchmark=False,
    )
    return [ep.as_hint() for ep in episodes]


__all__ = [
    "EMBEDDING_DIM",
    "EpisodeRecord",
    "embed",
    "recall_similar",
    "skeptical_recall_with_verify_hint",
    "write_episode",
]
