"""Tests for the #327 auth-pattern cache layer.

Covers the four success-criteria scenarios:
- fresh hit
- stale hit (aged out + failure-cooldown)
- miss
- replay-failure-marks-stale

All tests redirect the memory backend root to a tmp_path via the
``AEGISPT_MEMORY_ROOT`` env var. No live HTTP — replay verification is
exercised with httpx MockTransport.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from api.app.services.auth_discoverer import (
    CACHE_DIR_LOGICAL,
    CACHE_FAILURE_COOLDOWN_SECONDS,
    CACHE_MAX_AGE_SECONDS,
    CACHE_MAX_FILE_BYTES,
    CACHE_MAX_TOTAL_BYTES,
    CACHE_SCHEMA_VERSION,
    VERDICT_ABSENT,
    VERDICT_FRESH,
    VERDICT_STALE,
    _cache_path_for,
    _current_cache_size_bytes,
    lookup_recipe,
    mark_recipe_stale,
    store_recipe,
    verify_recipe,
)


@pytest.fixture
def memory_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Per-test memory root. Fully isolated."""
    root = tmp_path / "memories"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(root))
    return root


@pytest.fixture
def fp() -> dict:
    return {
        "stack_hints": ["python_gruyere"],
        "register_form": {
            "action": "http://example.local/saveprofile",
            "method": "GET",
            "fields": [{"name": "uid", "type": "text", "required": False}],
            "score": 5,
        },
        "login_form": None,
        "session_cookie_hint": "GRUYERE",
        "fingerprint_hash": "a" * 64,
        "fingerprint_version": "auth-discoverer-v1",
    }


@pytest.fixture
def recipe(fp: dict) -> dict:
    return {
        "recipe_version": "auth-recipe-v1",
        "fingerprint_hash": fp["fingerprint_hash"],
        "model": "claude-haiku-4-5-20251001",
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "POST",
                "url": "http://example.local/saveprofile",
                "field_mappings": {"uid": "username"},
                "expected_status": [200],
                "description": "x",
            }
        ],
        "verification": {
            "method": "GET",
            "url": "http://example.local/",
            "expect_status": [200],
            "expect_set_cookie": "GRUYERE",
            "expect_body_contains": [],
            "description": "x",
        },
    }


# ---------------------------------------------------------------------------
# lookup_recipe — absent / fresh / stale
# ---------------------------------------------------------------------------


def test_lookup_returns_absent_for_empty_cache(memory_root: Path, fp: dict) -> None:
    result, verdict = lookup_recipe(fp)
    assert result is None
    assert verdict == VERDICT_ABSENT


def test_lookup_returns_fresh_after_store(memory_root: Path, fp: dict, recipe: dict) -> None:
    assert store_recipe(fp, recipe, confidence=0.9) is True
    result, verdict = lookup_recipe(fp)
    assert verdict == VERDICT_FRESH
    assert result is not None
    assert result["steps"][0]["url"] == "http://example.local/saveprofile"


def test_lookup_returns_stale_after_aging_out(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    """Entry written 31 days ago is stale."""
    base = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    store_recipe(fp, recipe, now=base - timedelta(days=31))
    result, verdict = lookup_recipe(fp, now=base)
    assert verdict == VERDICT_STALE
    assert result is not None  # caller still sees the recipe to decide what to do


def test_lookup_returns_fresh_at_30_day_boundary(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    """Entry written exactly 30 days ago is still fresh (boundary)."""
    base = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    store_recipe(fp, recipe, now=base - timedelta(seconds=CACHE_MAX_AGE_SECONDS))
    _, verdict = lookup_recipe(fp, now=base)
    assert verdict == VERDICT_FRESH


def test_lookup_returns_stale_during_failure_cooldown(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    base = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    store_recipe(fp, recipe, now=base - timedelta(hours=2))
    mark_recipe_stale(fp, now=base - timedelta(minutes=30))
    _, verdict = lookup_recipe(fp, now=base)
    assert verdict == VERDICT_STALE


def test_lookup_returns_fresh_after_cooldown_passes(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    base = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    store_recipe(fp, recipe, now=base - timedelta(hours=2))
    mark_recipe_stale(fp, now=base - timedelta(seconds=CACHE_FAILURE_COOLDOWN_SECONDS + 1))
    _, verdict = lookup_recipe(fp, now=base)
    assert verdict == VERDICT_FRESH


def test_lookup_rejects_non_dict_input(memory_root: Path) -> None:
    result, verdict = lookup_recipe("not a dict")  # type: ignore[arg-type]
    assert result is None
    assert verdict == VERDICT_ABSENT


def test_lookup_rejects_empty_fingerprint_hash(memory_root: Path) -> None:
    result, verdict = lookup_recipe({"fingerprint_hash": ""})
    assert result is None
    assert verdict == VERDICT_ABSENT


# ---------------------------------------------------------------------------
# store_recipe — size caps + overwrite
# ---------------------------------------------------------------------------


def test_store_rejects_oversized_entry(memory_root: Path, fp: dict, recipe: dict) -> None:
    # Pack the description with garbage until we breach 2 KB.
    huge_recipe = dict(recipe)
    huge_recipe["steps"] = [
        {
            **recipe["steps"][0],
            "description": "x" * 5000,
        }
    ]
    assert store_recipe(fp, huge_recipe) is False
    # Nothing got written.
    result, verdict = lookup_recipe(fp)
    assert verdict == VERDICT_ABSENT
    assert result is None


def test_store_rejects_when_dir_cap_breached(
    memory_root: Path, recipe: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the dir is full, further stores are refused."""
    # Pre-populate 50 KB of fixtures by writing many small entries
    # directly via store_recipe with distinct fingerprint hashes.
    written = 0
    for idx in range(200):
        fp_i = {"fingerprint_hash": f"abcdef{idx:06d}" * 4}
        ok = store_recipe(fp_i, recipe)
        if not ok:
            written = idx
            break
    assert written > 0, "expected dir cap to engage before 200 entries"
    # Confirm a subsequent fingerprint also gets rejected.
    new_fp = {"fingerprint_hash": "z" * 64}
    assert store_recipe(new_fp, recipe) is False


def test_store_overwrites_existing_entry(memory_root: Path, fp: dict, recipe: dict) -> None:
    assert store_recipe(fp, recipe, confidence=0.5) is True
    bumped = dict(recipe)
    bumped["steps"] = [
        {**recipe["steps"][0], "description": "second version"}
    ]
    assert store_recipe(fp, bumped, confidence=0.9) is True
    cached, verdict = lookup_recipe(fp)
    assert verdict == VERDICT_FRESH
    assert cached is not None
    assert cached["steps"][0]["description"] == "second version"


def test_store_clamps_confidence_to_unit_range(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    assert store_recipe(fp, recipe, confidence=2.5) is True
    # And below 0 is also clamped.
    assert store_recipe(fp, recipe, confidence=-1.0) is True


def test_store_rejects_non_dict_fingerprint(memory_root: Path, recipe: dict) -> None:
    assert store_recipe("oops", recipe) is False  # type: ignore[arg-type]
    assert store_recipe({}, recipe) is False  # missing fingerprint_hash


def test_store_rejects_non_dict_recipe(memory_root: Path, fp: dict) -> None:
    assert store_recipe(fp, None) is False  # type: ignore[arg-type]
    assert store_recipe(fp, []) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# mark_recipe_stale
# ---------------------------------------------------------------------------


def test_mark_stale_no_op_when_no_entry(memory_root: Path, fp: dict) -> None:
    assert mark_recipe_stale(fp) is False


def test_mark_stale_increments_replay_failures(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    store_recipe(fp, recipe)
    assert mark_recipe_stale(fp) is True
    assert mark_recipe_stale(fp) is True
    # Re-read raw file to inspect counter.
    logical = _cache_path_for(fp["fingerprint_hash"])
    assert logical is not None
    raw = (memory_root / logical.removeprefix("/memories/")).read_text()
    entry = json.loads(raw)
    assert entry["replay_failures"] == 2
    assert entry["last_replay_failure_at"] is not None


# ---------------------------------------------------------------------------
# verify_recipe — replay-before-trust
# ---------------------------------------------------------------------------


def test_verify_recipe_passes_on_status_and_cookie(recipe: dict) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "http://example.local/"
        return httpx.Response(
            200,
            headers={"set-cookie": "GRUYERE=abc123; Path=/"},
            text="<html><body>Welcome</body></html>",
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    try:
        assert verify_recipe(recipe, http_client=client) is True
    finally:
        client.close()


def test_verify_recipe_fails_on_wrong_status(recipe: dict) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        assert verify_recipe(recipe, http_client=client) is False
    finally:
        client.close()


def test_verify_recipe_fails_when_cookie_missing(recipe: dict) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")  # no Set-Cookie

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        assert verify_recipe(recipe, http_client=client) is False
    finally:
        client.close()


def test_verify_recipe_checks_body_tokens(recipe: dict) -> None:
    recipe_with_body = dict(recipe)
    recipe_with_body["verification"] = dict(recipe["verification"])
    recipe_with_body["verification"]["expect_body_contains"] = ["logout"]
    recipe_with_body["verification"]["expect_set_cookie"] = None

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="welcome — click logout")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        assert verify_recipe(recipe_with_body, http_client=client) is True
    finally:
        client.close()

    def handler_no_token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="welcome")

    client2 = httpx.Client(transport=httpx.MockTransport(handler_no_token))
    try:
        assert verify_recipe(recipe_with_body, http_client=client2) is False
    finally:
        client2.close()


def test_verify_recipe_returns_false_on_network_error(recipe: dict) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        assert verify_recipe(recipe, http_client=client) is False
    finally:
        client.close()


def test_verify_recipe_rejects_missing_verification_block() -> None:
    assert verify_recipe({"recipe_version": "x", "steps": []}) is False
    assert verify_recipe({"verification": None}) is False
    assert verify_recipe("not a dict") is False  # type: ignore[arg-type]
    assert verify_recipe({"verification": {"method": "OPTIONS", "url": "http://x/"}}) is False


# ---------------------------------------------------------------------------
# Replay-failure-marks-stale integration
# ---------------------------------------------------------------------------


def test_replay_failure_marks_recipe_stale_on_next_lookup(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    """Full success-criteria scenario: stored recipe → replay fails →
    mark_stale → next lookup returns stale, NOT fresh."""
    store_recipe(fp, recipe)
    base = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        ok = verify_recipe(recipe, http_client=client)
    finally:
        client.close()
    assert ok is False
    assert mark_recipe_stale(fp, now=base) is True

    _, verdict = lookup_recipe(fp, now=base + timedelta(minutes=15))
    assert verdict == VERDICT_STALE


# ---------------------------------------------------------------------------
# Cache-hit path performs zero AI calls (acceptance criterion)
# ---------------------------------------------------------------------------


def test_cache_hit_does_not_invoke_build_recipe(
    memory_root: Path, fp: dict, recipe: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lookup path must not transitively call build_recipe or any AI
    client. We assert this by monkey-patching build_recipe to raise."""
    from api.app.services import auth_discoverer

    def _explode(*args, **kwargs):  # pragma: no cover — must not run
        raise AssertionError(
            "build_recipe must not be called on cache hit"
        )

    monkeypatch.setattr(auth_discoverer, "build_recipe", _explode)
    store_recipe(fp, recipe)
    cached, verdict = lookup_recipe(fp)
    assert verdict == VERDICT_FRESH
    assert cached is not None


# ---------------------------------------------------------------------------
# Path sanitization
# ---------------------------------------------------------------------------


def test_cache_path_rejects_traversal(memory_root: Path) -> None:
    assert _cache_path_for("../../etc/passwd") == f"{CACHE_DIR_LOGICAL}/etcpasswd.json"
    # The sanitization strips slashes and dots, so the resulting path is
    # safe — still under CACHE_DIR_LOGICAL.
    assert _cache_path_for("") is None
    assert _cache_path_for(None) is None  # type: ignore[arg-type]
    assert _cache_path_for("!@#$%^&*") is None  # nothing survives sanitization


def test_corrupt_cache_file_returns_absent(
    memory_root: Path, fp: dict
) -> None:
    """A garbled file under the cache dir must not raise — lookup
    returns absent so the caller falls through to fresh discovery."""
    logical = _cache_path_for(fp["fingerprint_hash"])
    assert logical is not None
    rel = logical.removeprefix("/memories/")
    target = memory_root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{not valid json")
    result, verdict = lookup_recipe(fp)
    assert verdict == VERDICT_ABSENT
    assert result is None


def test_schema_version_mismatch_returns_absent(memory_root: Path, fp: dict) -> None:
    logical = _cache_path_for(fp["fingerprint_hash"])
    assert logical is not None
    rel = logical.removeprefix("/memories/")
    target = memory_root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"schema_version": "wrong", "recipe": {}}))
    result, verdict = lookup_recipe(fp)
    assert verdict == VERDICT_ABSENT
    assert result is None


# ---------------------------------------------------------------------------
# Caps sanity
# ---------------------------------------------------------------------------


def test_constants_are_reasonable() -> None:
    assert CACHE_MAX_FILE_BYTES == 2048
    assert CACHE_MAX_TOTAL_BYTES == 50 * 1024
    assert CACHE_MAX_AGE_SECONDS == 30 * 24 * 60 * 60
    assert CACHE_FAILURE_COOLDOWN_SECONDS == 3600
    assert CACHE_SCHEMA_VERSION == "auth-recipe-cache-v1"


def test_current_cache_size_includes_only_recipe_files(
    memory_root: Path, fp: dict, recipe: dict
) -> None:
    assert _current_cache_size_bytes() == 0
    store_recipe(fp, recipe)
    assert _current_cache_size_bytes() > 0
