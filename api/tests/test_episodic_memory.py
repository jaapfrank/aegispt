"""Unit tests for backlog-410 episodic memory layer.

Verifies the embedding fallback math (cosine round-trip), the is_benchmark
isolation guard, the skeptical-hint envelope, and the write+recall path
against the live dev Postgres (where the migration has run). The OpenAI
provider is bypassed by forcing ``EPISODIC_EMBED_PROVIDER=local_hash``.
"""
from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Force the deterministic fallback before importing the module.
os.environ["EPISODIC_EMBED_PROVIDER"] = "local_hash"

from api.app.services.episodic_memory import (  # noqa: E402
    EMBEDDING_DIM,
    EpisodeRecord,
    _cosine,
    _local_hash_embedding,
    embed,
    recall_similar,
    skeptical_recall_with_verify_hint,
    write_episode,
)


DEFAULT_DB = "postgresql+psycopg://aegispt:aegispt_dev_pw@127.0.0.1:5432/aegispt"


def _has_db() -> bool:
    try:
        engine = create_engine(os.environ.get("DATABASE_URL", DEFAULT_DB))
        with engine.connect() as conn:
            from sqlalchemy import text as sa_text
            row = conn.execute(
                sa_text("SELECT 1 FROM agent_episodic_memory LIMIT 1"),
            )
            row.first()
        return True
    except Exception:
        return False


# --- pure helpers (no DB) -------------------------------------------------


def test_local_hash_embedding_is_correct_dim() -> None:
    vec = _local_hash_embedding("hello world")
    assert len(vec) == EMBEDDING_DIM
    assert all(-1.05 <= v <= 1.05 for v in vec)


def test_local_hash_embedding_is_deterministic() -> None:
    a = _local_hash_embedding("same text")
    b = _local_hash_embedding("same text")
    assert a == b


def test_local_hash_empty_input_returns_zeros() -> None:
    assert _local_hash_embedding("") == [0.0] * EMBEDDING_DIM


def test_cosine_self_similarity_is_one() -> None:
    vec = _local_hash_embedding("auth bypass via test:test credentials")
    assert pytest.approx(_cosine(vec, vec), abs=1e-6) == 1.0


def test_cosine_unrelated_texts_lower_similarity() -> None:
    a = _local_hash_embedding("post username=admin password=admin")
    b = _local_hash_embedding("nmap port scan of internal subnet")
    sim = _cosine(a, b)
    assert -1.0 <= sim <= 1.0


def test_embed_falls_back_to_local_hash() -> None:
    # provider="local_hash" already set; identical inputs yield identical embeddings.
    v1 = embed("login form post")
    v2 = embed("login form post")
    assert v1 == v2
    assert len(v1) == EMBEDDING_DIM


def test_episode_record_as_hint_wraps_with_marker() -> None:
    from datetime import UTC, datetime
    rec = EpisodeRecord(
        id=uuid4(),
        run_id=uuid4(),
        engagement_id=None,
        action_type="exec_plan",
        action_context={"step": "post-login"},
        outcome={"http_status": 200},
        success_marker=None,
        is_benchmark=False,
        created_at=datetime.now(UTC),
        similarity=0.91,
    )
    hint = rec.as_hint()
    assert hint["marker"] == "[HINT, VERIFY BEFORE USE]"
    assert hint["similarity"] == 0.91
    assert hint["action_type"] == "exec_plan"


# --- live DB round-trip ---------------------------------------------------


pytestmark = pytest.mark.skipif(
    not _has_db(),
    reason="agent_episodic_memory table not reachable; migration not applied to this DB",
)


@pytest.fixture()
def db_session():
    engine = create_engine(os.environ.get("DATABASE_URL", DEFAULT_DB))
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _make_fake_run(run_id, engagement_id=None, *, configuration: dict[str, Any] | None = None):
    """Lightweight stand-in for an SQLA Run model — episodic_memory only
    reads .id / .engagement_id / .configuration_json / .engagement.
    """
    from types import SimpleNamespace
    return SimpleNamespace(
        id=run_id,
        engagement_id=engagement_id,
        configuration_json=configuration or {},
        engagement=None,
    )


def _seed_engagement_and_run(db_session, *, engagement_name: str) -> tuple[Any, Any]:
    """Insert a minimal engagement + run via the ORM (uses model defaults
    for all NOT NULL columns)."""
    from api.app.models import Engagement, Run
    eng = Engagement(name=engagement_name)
    db_session.add(eng)
    db_session.flush()
    run = Run(
        engagement_id=eng.id,
        status="running",
        requested_by="episodic-test",
        configuration_json={},
    )
    db_session.add(run)
    db_session.flush()
    return eng, run


def test_write_and_recall_round_trip(db_session) -> None:
    _eng, real_run = _seed_engagement_and_run(db_session, engagement_name="episodic-memory-test")
    run_id = real_run.id
    eng_id = real_run.engagement_id

    fake_run = _make_fake_run(run_id, eng_id)
    ep = write_episode(
        db_session,
        run=fake_run,
        action_type="exec_plan",
        context={"target": "http://127.0.0.1:8080/login", "username_field": "username"},
        outcome={"http_status": 401, "body_snippet": "invalid credentials"},
        success_marker="no_progress",
    )
    assert isinstance(ep, EpisodeRecord)
    assert ep.is_benchmark is False  # no benchmark signals on this run

    # Recall with same context should rank this episode at the top.
    hits = recall_similar(
        db_session,
        query="exec_plan attempt against /login with username field",
        k=3,
        filter_run_id=run_id,
    )
    assert len(hits) >= 1
    assert any(h.id == ep.id for h in hits)


def test_benchmark_write_isolated_from_production_recall(db_session) -> None:
    _eng, real_run = _seed_engagement_and_run(db_session, engagement_name="xbow-bench-isolation-check")
    run_id = real_run.id
    eng_id = real_run.engagement_id

    # Patch the fake run so _is_benchmark_engagement returns True via the engagement.name path.
    from types import SimpleNamespace
    fake_run = SimpleNamespace(
        id=run_id,
        engagement_id=eng_id,
        configuration_json={},
        engagement=SimpleNamespace(name="xbow-bench-isolation-check"),
    )
    ep = write_episode(
        db_session,
        run=fake_run,
        action_type="benchmark_attempt",
        context={"challenge": "synthetic"},
        outcome={"flag_captured": False},
    )
    assert ep.is_benchmark is True

    # Default recall (production) must NOT return this episode.
    prod_hits = recall_similar(
        db_session,
        query="benchmark_attempt synthetic",
        k=10,
        filter_run_id=run_id,  # scope to this run so other batch noise doesn't mask the assertion
    )
    assert all(h.id != ep.id for h in prod_hits)

    # Opt-in recall returns it (still scoped to this run so a polluted DB
    # of prior benchmark episodes doesn't push our episode past k).
    bench_hits = recall_similar(
        db_session,
        query="benchmark_attempt synthetic",
        k=10,
        include_benchmark=True,
        filter_run_id=run_id,
    )
    assert any(h.id == ep.id for h in bench_hits)


def test_skeptical_recall_envelope_marks_hint(db_session) -> None:
    _eng, real_run = _seed_engagement_and_run(db_session, engagement_name="skeptical-envelope-test")
    run_id = real_run.id
    eng_id = real_run.engagement_id

    fake_run = _make_fake_run(run_id, eng_id)
    write_episode(
        db_session,
        run=fake_run,
        action_type="recon",
        context={"endpoint": "/openapi.json"},
        outcome={"status": 200, "size_bytes": 12_345},
    )
    hints = skeptical_recall_with_verify_hint(db_session, query="recon /openapi.json", k=3)
    assert hints
    for h in hints:
        assert h["marker"] == "[HINT, VERIFY BEFORE USE]"
        assert "episode_id" in h
