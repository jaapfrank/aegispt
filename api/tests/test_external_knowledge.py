"""Unit tests for backlog-416 external knowledge lookup."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import api.app.services.external_knowledge as ek
from api.app.services.external_knowledge import (
    CACHE_ROOT_ENV,
    SOURCE_WEIGHT,
    ExternalKnowledgeHint,
    _hint_from_cached,
    cache_age_seconds,
    lookup_cve_details,
    lookup_exploits,
)

_real_client = httpx.Client


def _client_factory(handler):
    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return _real_client(transport=httpx.MockTransport(handler), **kwargs)
    return factory


# --- Hint envelope contract ----------------------------------------


def test_hint_always_marked_hint_only() -> None:
    from datetime import UTC, datetime
    hint = ExternalKnowledgeHint(
        source="cisa_kev",
        source_url="https://x",
        title="test",
        fetched_at=datetime.now(UTC),
        applicability_score=0.8,
    )
    assert hint.marked_as_hint_only is True
    env = hint.to_picker_envelope()
    assert env["marker"].startswith("[KB HINT")
    assert "NEVER CLAIM IMPACT" in env["marker"]


def test_hint_from_cached_handles_iso_string_dates() -> None:
    cached = {
        "source": "exploitdb",
        "source_url": "http://x",
        "title": "y",
        "fetched_at": "2026-05-21T00:00:00+00:00",
        "applicability_score": 0.4,
    }
    h = _hint_from_cached(cached)
    assert h.marked_as_hint_only is True
    assert h.title == "y"


# --- Read-only surface ---------------------------------------------


def test_module_attribute_lookup_blocks_write_helpers() -> None:
    with pytest.raises(AttributeError, match="READ-ONLY"):
        _ = ek.write_kev_entry  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="READ-ONLY"):
        _ = ek.submit_exploitdb_post  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="READ-ONLY"):
        _ = ek.publish_cve_advisory  # type: ignore[attr-defined]


def test_public_surface_lists_only_read_functions() -> None:
    assert "lookup_exploits" in ek.__all__
    assert "lookup_cve_details" in ek.__all__
    # No write/submit/publish in the public surface.
    for entry in ek.__all__:
        assert not entry.startswith(("write_", "submit_", "publish_", "upload_"))


# --- KEV lookup (mocked) ------------------------------------------


def test_kev_lookup_exact_cve_match_scores_highest(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    feed_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-12345",
                "vendorProject": "Acme",
                "product": "WebApp",
                "vulnerabilityName": "Acme WebApp RCE",
                "shortDescription": "Remote code execution",
                "dueDate": "2026-06-01",
                "requiredAction": "Patch",
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=feed_payload)

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    hits = lookup_exploits(cve_id="CVE-2024-12345")
    assert hits, "expected at least one hit"
    top = hits[0]
    assert top.source == "cisa_kev"
    assert top.cve_id == "CVE-2024-12345"
    assert top.applicability_score == pytest.approx(SOURCE_WEIGHT["cisa_kev"])


def test_kev_lookup_product_match_returns_lower_score(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    feed_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-99999",
                "vendorProject": "Acme",
                "product": "WebApp",
                "vulnerabilityName": "Some flaw",
                "shortDescription": "x",
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=feed_payload)

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    hits = lookup_exploits(product="webapp")
    assert hits
    assert hits[0].applicability_score < SOURCE_WEIGHT["cisa_kev"]


def test_kev_lookup_no_match_returns_empty(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": []})

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    hits = lookup_exploits(cve_id="CVE-9999-99999")
    assert hits == []


# --- NVD lookup (mocked) ------------------------------------------


def test_nvd_lookup_returns_description(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    nvd_payload = {
        "vulnerabilities": [{
            "cve": {
                "descriptions": [{"lang": "en", "value": "Buffer overflow in libfoo"}],
                "references": [{"url": "https://example.com/advisory"}],
            }
        }]
    }
    kev_payload = {"vulnerabilities": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if "cisa.gov" in str(request.url):
            return httpx.Response(200, json=kev_payload)
        return httpx.Response(200, json=nvd_payload)

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    detail = lookup_cve_details("CVE-2024-00001")
    assert detail is not None
    assert "Buffer overflow" in detail.body_excerpt
    assert detail.source == "nvd"
    assert detail.references == ["https://example.com/advisory"]


def test_nvd_lookup_rejects_non_cve_input(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    assert lookup_cve_details("not-a-cve") is None


# --- Cache behavior ----------------------------------------------


def test_cache_hit_avoids_second_http_call(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    feed_payload = {
        "vulnerabilities": [{
            "cveID": "CVE-2024-12345",
            "vendorProject": "Acme",
            "product": "WebApp",
            "vulnerabilityName": "x",
            "shortDescription": "y",
        }]
    }
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=feed_payload)

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    lookup_exploits(cve_id="CVE-2024-12345")
    first_count = calls["count"]
    lookup_exploits(cve_id="CVE-2024-12345")
    assert calls["count"] == first_count, "second call should have hit the cache"


def test_cache_age_helper(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    assert cache_age_seconds("nvd_cve", cve="CVE-X") is None
    # Write a cache entry directly so we can inspect age semantics.
    from api.app.services.external_knowledge import _cache_key, _cache_put
    path = _cache_key("nvd_cve", cve="CVE-X")
    _cache_put(path, {"x": 1})
    age = cache_age_seconds("nvd_cve", cve="CVE-X")
    assert age is not None
    assert age < 5  # just-written


# --- ExploitDB (provider disabled fallback) -----------------------


def test_exploitdb_returns_empty_without_endpoint(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    monkeypatch.delenv("EXPLOITDB_MCP_URL", raising=False)
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"vulnerabilities": []}))).get(*a, **kw))
    hits = lookup_exploits(product="apache")
    # KEV returned nothing in this test; ExploitDB is disabled → all empty.
    assert hits == []


def test_exploitdb_uses_endpoint_when_configured(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    monkeypatch.setenv("EXPLOITDB_MCP_URL", "http://mcp.example/exploitdb")

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "cisa.gov" in url:
            return httpx.Response(200, json={"vulnerabilities": []})
        if "nvd" in url:
            return httpx.Response(200, json={"vulnerabilities": []})
        # ExploitDB MCP returns a list of hits.
        return httpx.Response(200, json={
            "hits": [{
                "title": "Sample exploit",
                "url": "https://example.com/edb-1",
                "description": "PoC writeup",
                "cve_id": "CVE-2024-12345",
            }]
        })

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    hits = lookup_exploits(cve_id="CVE-2024-12345")
    edb_hits = [h for h in hits if h.source == "exploitdb"]
    assert edb_hits, "ExploitDB hit expected when EXPLOITDB_MCP_URL is set"
    assert edb_hits[0].marked_as_hint_only is True
    assert edb_hits[0].cve_id == "CVE-2024-12345"


# --- Dedup + ordering -------------------------------------------


def test_results_sorted_by_applicability_score_desc(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CACHE_ROOT_ENV, str(tmp_path))
    feed_payload = {
        "vulnerabilities": [{
            "cveID": "CVE-2024-12345",
            "vendorProject": "Acme",
            "product": "WebApp",
            "vulnerabilityName": "exact match — score 1.0",
            "shortDescription": "x",
        }]
    }
    nvd_payload = {
        "vulnerabilities": [{
            "cve": {
                "descriptions": [{"lang": "en", "value": "NVD entry — score 0.5"}],
                "references": [],
            }
        }]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "cisa.gov" in url:
            return httpx.Response(200, json=feed_payload)
        return httpx.Response(200, json=nvd_payload)

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _real_client(transport=httpx.MockTransport(handler)).get(*a, **kw))
    hits = lookup_exploits(cve_id="CVE-2024-12345")
    assert len(hits) >= 2
    # First entry must be the KEV exact match (score 1.0), then NVD (0.5).
    assert hits[0].source == "cisa_kev"
    assert hits[0].applicability_score >= hits[-1].applicability_score
