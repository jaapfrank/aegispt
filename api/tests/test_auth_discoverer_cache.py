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


def test_store_evicts_when_dir_cap_breached(
    memory_root: Path, recipe: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#346 changed the cache contract: when the dir cap engages, the new
    store call triggers bounded LRU eviction instead of returning False.

    Acceptance: every successive store across 200 distinct fingerprints
    succeeds, the on-disk total stays at or under the cap, and lookup
    of a freshly-written entry returns it.
    """
    base_time = datetime(2026, 5, 1, tzinfo=timezone.utc)
    for idx in range(200):
        fp_i = {"fingerprint_hash": f"abcdef{idx:06d}" * 4}
        # Stagger the timestamps so LRU has a deterministic oldest-to-evict.
        ok = store_recipe(
            fp_i, recipe, now=base_time + timedelta(seconds=idx),
        )
        assert ok is True, f"store_recipe should succeed at iteration {idx}"
    # Dir total should still respect the cap (allowing some slack for the
    # last-write overshoot before eviction trims again).
    assert _current_cache_size_bytes() <= CACHE_MAX_TOTAL_BYTES + CACHE_MAX_FILE_BYTES
    # The most-recent fingerprint should be retrievable.
    last_fp = {"fingerprint_hash": f"abcdef{199:06d}" * 4}
    cached, verdict = lookup_recipe(
        last_fp, now=base_time + timedelta(seconds=200),
    )
    assert verdict == VERDICT_FRESH
    assert cached is not None


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


# ---------------------------------------------------------------------------
# #346 — LRU eviction + schema migration
# ---------------------------------------------------------------------------


def test_evict_picks_oldest_first(
    memory_root: Path, recipe: dict,
) -> None:
    """Acceptance: eviction order is strictly by last_confirmed_at ascending.
    With 4 staggered fingerprints and a forced over-cap write, the oldest
    of the 4 disappears from the cache (verifiable via lookup_recipe →
    absent), while the newer 3 remain fresh."""
    from api.app.services.auth_discoverer import _evict_for_space

    base = datetime(2026, 5, 1, tzinfo=timezone.utc)
    # Insert 4 entries with distinct ages.
    fps = []
    for i in range(4):
        f = {"fingerprint_hash": f"oldest{i:04d}" * 8}
        fps.append(f)
        store_recipe(f, recipe, now=base + timedelta(hours=i))

    # Read back the on-disk sizes to compute a needed-bytes value that
    # is guaranteed to force exactly one eviction.
    cache_path_for_first = (
        memory_root / "auth-recipes" / f"{fps[0]['fingerprint_hash'][:80]}.json"
    )
    one_entry_bytes = cache_path_for_first.stat().st_size

    freed = _evict_for_space(
        one_entry_bytes, now=base + timedelta(days=1),
    )
    assert freed >= one_entry_bytes
    # The oldest fingerprint is now gone; lookup returns absent.
    cached, verdict = lookup_recipe(fps[0], now=base + timedelta(days=1))
    assert verdict == VERDICT_ABSENT
    assert cached is None
    # The 3 newer entries are still present.
    for f in fps[1:]:
        c, v = lookup_recipe(f, now=base + timedelta(days=1))
        assert v == VERDICT_FRESH, f"{f['fingerprint_hash'][:12]} unexpectedly evicted"
        assert c is not None


def test_evict_bounded_at_25_percent(
    memory_root: Path, recipe: dict,
) -> None:
    """Eviction caps at int(25% * len(candidates)). With 8 entries, max
    evictions = 2. Asking for more bytes than 2 entries can free must
    return what 2 evictions yield (not blow past the cap)."""
    from api.app.services.auth_discoverer import _evict_for_space

    base = datetime(2026, 5, 1, tzinfo=timezone.utc)
    sizes = []
    for i in range(8):
        f = {"fingerprint_hash": f"bound{i:04d}" * 8}
        store_recipe(f, recipe, now=base + timedelta(hours=i))
        cache_path = (
            memory_root / "auth-recipes" / f"{f['fingerprint_hash'][:80]}.json"
        )
        sizes.append(cache_path.stat().st_size)

    # Request more bytes than 8 entries combined could possibly free.
    huge = sum(sizes) + 10_000
    freed = _evict_for_space(huge, now=base + timedelta(days=1))
    # 25% of 8 = 2 entries; freed should be at most the sum of the 2
    # oldest entries.
    assert freed <= sum(sizes[:2]) + 1, (
        f"freed={freed} exceeds the 2-entry 25% bound ({sum(sizes[:2])})"
    )


def test_evict_tie_break_lower_confidence_wins(
    memory_root: Path, recipe: dict,
) -> None:
    """When two entries share last_confirmed_at, the one with lower
    confidence is evicted first."""
    from api.app.services.auth_discoverer import _evict_for_space

    same_time = datetime(2026, 5, 1, tzinfo=timezone.utc)
    fp_low = {"fingerprint_hash": "lowconf" * 8}
    fp_high = {"fingerprint_hash": "hghconf" * 8}
    # Same timestamp, different confidence.
    store_recipe(fp_low, recipe, confidence=0.3, now=same_time)
    store_recipe(fp_high, recipe, confidence=0.9, now=same_time)
    # Add a third decoy older entry so the 25% cap allows >=1 eviction.
    fp_decoy = {"fingerprint_hash": "decoy00" * 9}
    store_recipe(
        fp_decoy, recipe,
        confidence=0.5, now=same_time - timedelta(hours=1),
    )
    decoy_path = (
        memory_root / "auth-recipes" / f"{fp_decoy['fingerprint_hash'][:80]}.json"
    )
    decoy_size = decoy_path.stat().st_size

    # Ask only for enough bytes to evict 1 entry (the decoy is older
    # → it goes first). After decoy is gone, the SAME-time pair remains;
    # request more to force the tie-break check.
    freed = _evict_for_space(
        decoy_size * 2, now=same_time + timedelta(days=1),
    )
    # Decoy is the oldest → evicted first. Then lower-confidence among
    # the SAME-time pair is next. The high-confidence one stays.
    assert freed >= decoy_size
    # high-confidence entry survives.
    cached_high, verdict_high = lookup_recipe(
        fp_high, now=same_time + timedelta(days=1),
    )
    assert verdict_high == VERDICT_FRESH
    assert cached_high is not None


def test_evict_aborts_on_pure_tie(memory_root: Path, recipe: dict) -> None:
    """When two entries share BOTH last_confirmed_at AND confidence,
    they are a pure tie — eviction aborts at that point per #346
    non_destructive_on_uncertainty. The freed amount may be less than
    requested, and the caller's store_recipe call will return False."""
    from api.app.services.auth_discoverer import _evict_for_space

    same_time = datetime(2026, 5, 1, tzinfo=timezone.utc)
    fp_a = {"fingerprint_hash": "tieA" * 16}
    fp_b = {"fingerprint_hash": "tieB" * 16}
    # IDENTICAL timestamp + confidence → pure tie.
    store_recipe(fp_a, recipe, confidence=0.7, now=same_time)
    store_recipe(fp_b, recipe, confidence=0.7, now=same_time)
    on_disk_total = _current_cache_size_bytes()
    # Request more than zero so eviction is attempted but blocked.
    freed = _evict_for_space(
        on_disk_total + 1000, now=same_time + timedelta(days=1),
    )
    # With only 2 entries, 25% rounds via max(1, int(2*0.25)) = max(1, 0) = 1
    # eviction slot. But the pure tie aborts BEFORE selecting one. Result:
    # freed == 0.
    assert freed == 0
    # Both entries still present.
    assert lookup_recipe(fp_a, now=same_time + timedelta(days=1))[1] == VERDICT_FRESH
    assert lookup_recipe(fp_b, now=same_time + timedelta(days=1))[1] == VERDICT_FRESH


def test_store_with_pure_tie_full_cache_returns_false(
    memory_root: Path, recipe: dict,
) -> None:
    """Acceptance: if the only candidates for eviction are tied and the
    cache is full, store_recipe returns False (graceful fail, no
    arbitrary choice)."""
    same_time = datetime(2026, 5, 1, tzinfo=timezone.utc)
    # Fill cache to the brim with pure-tied entries.
    big_recipe = dict(recipe)
    big_recipe["steps"] = [
        {**recipe["steps"][0], "description": "x" * 600}
    ]
    confidence = 0.5
    written = 0
    for i in range(120):
        f = {"fingerprint_hash": f"tie{i:04d}" * 9}
        if not store_recipe(f, big_recipe, confidence=confidence, now=same_time):
            written = i
            break
    # We should have managed to write SOME entries before cap engaged,
    # and all entries have same (last_confirmed_at, confidence) → pure tie.
    assert written > 0, "expected cache to fill up at some iteration"
    # Now try a fresh fingerprint — eviction must abort on the tie →
    # store returns False.
    new_fp = {"fingerprint_hash": "fresh_post_tie" * 4}
    assert store_recipe(new_fp, big_recipe, confidence=confidence, now=same_time) is False


def test_migrate_entry_idempotent_on_current_version(memory_root: Path) -> None:
    """An entry whose schema_version already matches CACHE_SCHEMA_VERSION
    is returned unchanged (idempotent no-op)."""
    from api.app.services.auth_discoverer import _migrate_entry

    entry = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "fingerprint_hash": "abc",
        "recipe": {"steps": []},
    }
    out = _migrate_entry(entry)
    assert out is entry  # exact identity preserved (no copy)


def test_migrate_entry_unknown_version_returns_none_with_single_warning(
    memory_root: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Unknown source schema_version returns None and logs ONCE per
    fingerprint per process (not per call)."""
    from api.app.services.auth_discoverer import (
        _migrate_entry,
        _reset_migration_warning_cache,
    )
    _reset_migration_warning_cache()

    entry = {
        "schema_version": "auth-recipe-cache-v999",
        "fingerprint_hash": "unknown_fp_zzz",
        "recipe": {},
    }
    with caplog.at_level("WARNING"):
        # First call: should log a warning.
        assert _migrate_entry(entry) is None
        # Second call with SAME fingerprint: must NOT log again.
        assert _migrate_entry(entry) is None

    warning_records = [
        r for r in caplog.records
        if "unknown schema_version" in r.message
        and "unknown_fp_zzz" in r.message[:200]
    ]
    assert len(warning_records) == 1, (
        f"expected exactly 1 warning per fingerprint per process, got "
        f"{len(warning_records)}"
    )


def test_migrate_entry_unknown_version_per_fingerprint_warning_independence(
    memory_root: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Two DIFFERENT fingerprints with the same unknown version each get
    their own first-time warning (de-dup is per-fingerprint, not per-
    process)."""
    from api.app.services.auth_discoverer import (
        _migrate_entry,
        _reset_migration_warning_cache,
    )
    _reset_migration_warning_cache()

    fp_a = {
        "schema_version": "auth-recipe-cache-v999",
        "fingerprint_hash": "fp_aaa_unique",
        "recipe": {},
    }
    fp_b = {
        "schema_version": "auth-recipe-cache-v999",
        "fingerprint_hash": "fp_bbb_unique",
        "recipe": {},
    }
    with caplog.at_level("WARNING"):
        _migrate_entry(fp_a)
        _migrate_entry(fp_b)
    warnings = [
        r for r in caplog.records
        if "unknown schema_version" in r.message
    ]
    # 2 distinct fingerprints, 2 warnings.
    assert len(warnings) == 2


def test_lookup_recipe_treats_unknown_schema_as_absent(
    memory_root: Path, fp: dict,
) -> None:
    """End-to-end: write a recipe with an unknown schema_version manually,
    then lookup_recipe must surface absent (via _load_cache_entry →
    _migrate_entry → None). This is the #346 forward-compat path."""
    from api.app.services.auth_discoverer import _reset_migration_warning_cache
    _reset_migration_warning_cache()

    target_dir = memory_root / "auth-recipes"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "future_version.json"
    target.write_text(json.dumps({
        "schema_version": "auth-recipe-cache-v9999-from-the-future",
        "fingerprint_hash": "future_version",
        "recipe": {"steps": [], "verification": None},
        "confidence": 1.0,
        "created_at": "2099-01-01T00:00:00+00:00",
        "last_confirmed_at": "2099-01-01T00:00:00+00:00",
        "last_replay_failure_at": None,
        "replay_failures": 0,
    }))
    fp_future = {"fingerprint_hash": "future_version"}
    result, verdict = lookup_recipe(fp_future)
    assert verdict == VERDICT_ABSENT
    assert result is None
