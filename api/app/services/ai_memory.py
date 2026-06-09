"""
AI Memory & Fetch capabilities for AegisPT.

Replaces MCP server integrations with native Python implementations:
- fetch_for_ai(): fetches a URL and returns clean text for the AI
- store_memory() / recall_memory(): persistent per-engagement AI memory
- These feed into the ChatGPT post-task analysis context.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import EngagementMemory

_FETCH_TIMEOUT = 8.0
_FETCH_MAX_BYTES = 32_000
_MEMORY_RECALL_LIMIT = 30


def fetch_for_ai(url: str, *, scope_allowlist: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fetch a URL and return clean text suitable for AI context injection."""
    from api.app.services.runs import web_target_value_is_allowed_with_path

    if scope_allowlist:
        if not web_target_value_is_allowed_with_path(scope_allowlist, url):
            return {"url": url, "ok": False, "error": "URL outside approved scope", "text": ""}

    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return {"url": url, "ok": False, "error": "Only http/https supported", "text": ""}

        with httpx.Client(follow_redirects=True, timeout=_FETCH_TIMEOUT) as client:
            response = client.get(url, headers={"User-Agent": "AegisPT-AI-Context/1.0"})

        content_type = response.headers.get("content-type", "")
        raw = response.content[:_FETCH_MAX_BYTES]

        if "text" in content_type or "json" in content_type or "xml" in content_type:
            text = raw.decode("utf-8", errors="replace")
        else:
            text = f"[Binary content: {content_type}, {len(response.content)} bytes]"

        # Strip excessive whitespace for AI consumption
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        clean_text = "\n".join(lines[:500])

        return {
            "url": url,
            "ok": response.status_code < 400,
            "status_code": response.status_code,
            "content_type": content_type,
            "text": clean_text,
            "truncated": len(response.content) > _FETCH_MAX_BYTES,
        }
    except Exception as exc:
        return {"url": url, "ok": False, "error": str(exc), "text": ""}


def store_memory(
    session: Session,
    *,
    engagement_id: uuid.UUID,
    run_id: uuid.UUID | None,
    key: str,
    value: str,
    memory_type: str = "fact",
    confidence: float = 1.0,
    source: str = "ai_analysis",
    metadata: dict[str, Any] | None = None,
) -> EngagementMemory:
    """Store an AI memory entry. Overwrites existing entry with same key."""
    existing = session.scalar(
        select(EngagementMemory).where(
            EngagementMemory.engagement_id == engagement_id,
            EngagementMemory.memory_key == key,
        )
    )
    if existing is not None:
        existing.memory_value = value
        existing.memory_type = memory_type
        existing.confidence = confidence
        existing.source = source
        existing.metadata_json = metadata or {}
        existing.updated_at = datetime.now(UTC)
        if run_id is not None:
            existing.run_id = run_id
        session.flush()
        return existing

    entry = EngagementMemory(
        engagement_id=engagement_id,
        run_id=run_id,
        memory_key=key,
        memory_value=value,
        memory_type=memory_type,
        confidence=confidence,
        source=source,
        metadata_json=metadata or {},
    )
    session.add(entry)
    session.flush()
    return entry


def recall_memory(
    session: Session,
    *,
    engagement_id: uuid.UUID,
    memory_type: str | None = None,
    limit: int = _MEMORY_RECALL_LIMIT,
) -> list[dict[str, Any]]:
    """Recall AI memory entries for an engagement, sorted by most recent."""
    query = select(EngagementMemory).where(
        EngagementMemory.engagement_id == engagement_id
    )
    if memory_type:
        query = query.where(EngagementMemory.memory_type == memory_type)
    query = query.order_by(EngagementMemory.updated_at.desc()).limit(limit)
    entries = list(session.scalars(query))
    return [
        {
            "key": e.memory_key,
            "value": e.memory_value,
            "type": e.memory_type,
            "confidence": e.confidence,
            "source": e.source,
            "run_id": str(e.run_id) if e.run_id else None,
            "recorded_at": e.updated_at.isoformat() if e.updated_at else None,
        }
        for e in entries
    ]


def _tokenize(text: str | None) -> set[str]:
    return set(re.findall(r"[a-z0-9]{2,}", (text or "").lower()))


def relevance_score(
    query_tokens: set[str],
    *,
    key: str | None,
    value: str | None,
    confidence: float | None,
    updated_at: datetime | None,
    now: datetime | None = None,
) -> float:
    """Lightweight, dependency-free relevance: keyword overlap with the query DOMINATES, with
    confidence + recency as boosts. Replaces recency-only recall so the small local-LLM context
    window is packed with the MOST RELEVANT facts (2026 hybrid-memory best practice), not just
    the newest ones."""
    doc = _tokenize(key) | _tokenize(value)
    overlap = (len(query_tokens & doc) / len(query_tokens)) if (query_tokens and doc) else 0.0
    rec = 1.0
    if updated_at is not None:
        ref = now or datetime.now(UTC)
        age_days = max((ref - updated_at).total_seconds() / 86400.0, 0.0)
        rec = 1.0 / (1.0 + age_days)
    return overlap * 2.0 + (confidence or 0.0) * 0.3 + rec * 0.5


def search_memory(
    session: Session,
    *,
    engagement_id: uuid.UUID,
    query: str,
    memory_type: str | None = None,
    limit: int = _MEMORY_RECALL_LIMIT,
) -> list[dict[str, Any]]:
    """Relevance-ranked recall (vs ``recall_memory``'s recency-only). Ranks an engagement's
    memories by ``relevance_score`` against ``query`` and returns the top ``limit``. Falls back
    to recency when the query has no usable tokens, so it is a safe drop-in for recency recall."""
    q = select(EngagementMemory).where(EngagementMemory.engagement_id == engagement_id)
    if memory_type:
        q = q.where(EngagementMemory.memory_type == memory_type)
    entries = list(session.scalars(q))
    qt = _tokenize(query)
    if qt:
        entries.sort(
            key=lambda e: relevance_score(
                qt, key=e.memory_key, value=e.memory_value,
                confidence=e.confidence, updated_at=e.updated_at,
            ),
            reverse=True,
        )
    else:
        entries.sort(key=lambda e: e.updated_at or datetime.min.replace(tzinfo=UTC), reverse=True)
    return [
        {
            "key": e.memory_key,
            "value": e.memory_value,
            "type": e.memory_type,
            "confidence": e.confidence,
            "source": e.source,
            "run_id": str(e.run_id) if e.run_id else None,
            "recorded_at": e.updated_at.isoformat() if e.updated_at else None,
        }
        for e in entries[:limit]
    ]


def build_ai_context_with_memory(
    session: Session,
    *,
    engagement_id: uuid.UUID,
    run_id: uuid.UUID | None,
    target_urls: list[str],
    scope_allowlist: dict[str, Any] | None = None,
    fetch_targets: bool = True,
) -> dict[str, Any]:
    """Build enriched AI context: existing memory + optionally fetched live page content."""
    # Relevance-rank the recall against what is being assessed (the target URLs) so the limited
    # context holds the MOST RELEVANT memories, not just the newest (OpenClaw/SOTA memory upgrade,
    # slice 2 — wires the search_memory ranking into the live context path). Recency fallback when
    # there is no usable query.
    query = " ".join(target_urls or [])
    memory = (
        search_memory(session, engagement_id=engagement_id, query=query)
        if query.strip()
        else recall_memory(session, engagement_id=engagement_id)
    )

    fetched: list[dict[str, Any]] = []
    if fetch_targets:
        for url in target_urls[:3]:  # max 3 fetches per analysis to stay fast
            result = fetch_for_ai(url, scope_allowlist=scope_allowlist)
            if result["ok"]:
                fetched.append(result)

    return {
        "engagement_memory": memory,
        "live_page_context": fetched,
        "memory_count": len(memory),
        "fetch_count": len(fetched),
    }
