"""Relevance-ranked memory recall (slice #1 of the OpenClaw/SOTA memory upgrade).

The old recall was recency-only, which fills the small local-LLM context with the NEWEST facts
instead of the most RELEVANT ones. These tests pin the fix: relevance dominates recency.
"""
import uuid
from datetime import UTC, datetime, timedelta

from api.app.services.ai_memory import _tokenize, relevance_score, search_memory

NOW = datetime(2026, 6, 9, tzinfo=UTC)


def test_tokenize():
    assert _tokenize("Admin Password /login?x=1") == {"admin", "password", "login"}
    assert _tokenize("") == set()


def test_relevance_beats_recency():
    qt = _tokenize("admin password login")
    relevant_old = relevance_score(
        qt, key="admin creds", value="found admin password at /login",
        confidence=1.0, updated_at=NOW - timedelta(days=10), now=NOW,
    )
    irrelevant_new = relevance_score(
        qt, key="server header", value="nginx version banner",
        confidence=1.0, updated_at=NOW, now=NOW,
    )
    assert relevant_old > irrelevant_new


def test_empty_query_falls_back_to_recency_signal():
    s_new = relevance_score(set(), key="x", value="y", confidence=1.0, updated_at=NOW, now=NOW)
    s_old = relevance_score(
        set(), key="x", value="y", confidence=1.0, updated_at=NOW - timedelta(days=5), now=NOW)
    assert s_new > s_old


class _FakeMem:
    def __init__(self, key, value, confidence, updated_at):
        self.memory_key = key
        self.memory_value = value
        self.confidence = confidence
        self.updated_at = updated_at
        self.memory_type = "fact"
        self.source = "test"
        self.run_id = None


class _FakeSession:
    def __init__(self, mems):
        self._mems = mems

    def scalars(self, _query):
        return list(self._mems)


def test_search_memory_ranks_relevant_over_recent():
    mems = [
        _FakeMem("server header", "nginx banner", 1.0, NOW),                       # newest, irrelevant
        _FakeMem("admin creds", "admin password at /login", 1.0, NOW - timedelta(days=10)),  # old, relevant
    ]
    out = search_memory(_FakeSession(mems), engagement_id=uuid.uuid4(), query="admin password login")
    assert out[0]["key"] == "admin creds"
    assert out[0]["value"] == "admin password at /login"
