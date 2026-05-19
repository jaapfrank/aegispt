"""Tests for #338 / backlog-400 — workers/runners/_path_augmentation.py

Covers the public surface:
- paths_for_stack(stack_hints, category) returning per-stack additions
- stack_hints_from_observations() normalizing raw target_intel strings
- end-to-end smoke: info_disclosure_probe gets /dump.gtl in its probe
  set when stack_hints=['python_gruyere'] is supplied
- per-stack registry rationale documented in module docstring
"""
from __future__ import annotations

import httpx
import pytest

from workers.runners._path_augmentation import (
    KNOWN_CATEGORIES,
    paths_for_stack,
    stack_hints_from_observations,
)


# ---------------------------------------------------------------------------
# paths_for_stack — pure helper
# ---------------------------------------------------------------------------


def test_paths_for_stack_empty_input_returns_empty() -> None:
    assert paths_for_stack(None, "debug-dump") == []
    assert paths_for_stack([], "debug-dump") == []
    assert paths_for_stack([""], "debug-dump") == []


def test_paths_for_stack_unknown_hint_returns_empty() -> None:
    assert paths_for_stack(["windows_iis_legacy_xyz"], "debug-dump") == []


def test_paths_for_stack_unknown_category_returns_empty() -> None:
    # Known hint, unknown category → no augmentation, no error.
    assert paths_for_stack(["python_gruyere"], "no-such-category") == []


def test_paths_for_stack_python_gruyere_debug_dump_includes_dump_gtl() -> None:
    """Acceptance: the catalog Gruyere's /dump.gtl path was stripped
    from in #328 is reachable again via the stack-hint registry."""
    out = paths_for_stack(["python_gruyere"], "debug-dump")
    paths = [p for p, _ in out]
    assert "/dump.gtl" in paths
    assert "/debug.gtl" in paths
    # Each entry is (path, label) tuple.
    for entry in out:
        assert isinstance(entry, tuple) and len(entry) == 2


def test_paths_for_stack_aspnet_debug_dump_includes_elmah() -> None:
    out = paths_for_stack(["aspnet"], "debug-dump")
    paths = [p for p, _ in out]
    assert "/elmah.axd" in paths
    assert "/trace.axd" in paths


def test_paths_for_stack_php_debug_dump_includes_phpinfo() -> None:
    out = paths_for_stack(["php"], "debug-dump")
    paths = [p for p, _ in out]
    assert "/info.php" in paths or "/phpinfo.php" in paths


def test_paths_for_stack_multi_hint_unions_and_dedupes() -> None:
    """Two hints contributing distinct paths → union with no duplicates."""
    out = paths_for_stack(["python_gruyere", "aspnet"], "debug-dump")
    paths = [p for p, _ in out]
    assert "/dump.gtl" in paths
    assert "/elmah.axd" in paths
    # No path appears twice.
    assert len(paths) == len(set(paths))


def test_paths_for_stack_case_insensitive_hint_and_category() -> None:
    """Both hint and category are case-insensitive."""
    upper = paths_for_stack(["PYTHON_GRUYERE"], "DEBUG-DUMP")
    lower = paths_for_stack(["python_gruyere"], "debug-dump")
    assert upper == lower


def test_paths_for_stack_known_categories_documented() -> None:
    """KNOWN_CATEGORIES is the public contract — operators reading
    fingerprints expect at least these 4 categories to exist."""
    assert "debug-dump" in KNOWN_CATEGORIES
    assert "file-upload-target" in KNOWN_CATEGORIES
    assert "register-action" in KNOWN_CATEGORIES
    assert "stored-xss-page" in KNOWN_CATEGORIES


# ---------------------------------------------------------------------------
# stack_hints_from_observations — normalization
# ---------------------------------------------------------------------------


def test_stack_hints_from_observations_empty_returns_empty() -> None:
    assert stack_hints_from_observations(None) == []
    assert stack_hints_from_observations([]) == []
    assert stack_hints_from_observations([{}]) == []


def test_stack_hints_from_observations_extracts_gruyere_from_tech_stack() -> None:
    """A target_intel observation with technology_stack mentioning
    Gruyere normalizes to the registry's python_gruyere hint."""
    obs = [{
        "attributes_json": {
            "technology_stack": [
                "Google App Engine — Gruyere training app",
                "HTML 4.01 Transitional",
            ],
        },
    }]
    hints = stack_hints_from_observations(obs)
    assert "python_gruyere" in hints


def test_stack_hints_from_observations_normalizes_aspnet() -> None:
    obs = [{
        "attributes_json": {
            "technology_stack": ["ASP.NET 4.x", "IIS 8.5"],
        },
    }]
    hints = stack_hints_from_observations(obs)
    assert "aspnet" in hints


def test_stack_hints_from_observations_normalizes_multiple_stacks() -> None:
    """Multi-stack environment (front Rails + Tomcat backend) produces
    multiple hints. Output is deterministic via sort()."""
    obs = [{
        "attributes_json": {
            "technology_stack": ["Ruby on Rails 7.0", "Apache Tomcat 9"],
        },
    }]
    hints = stack_hints_from_observations(obs)
    assert "ruby_rails" in hints
    assert "java_servlet" in hints


def test_stack_hints_from_observations_accepts_attributes_key_too() -> None:
    """Convenience: helper accepts either `attributes_json` or `attributes`
    so test fixtures don't need to mirror the SQLAlchemy column name."""
    obs = [{"attributes": {"technology_stack": ["Django 4.2"]}}]
    hints = stack_hints_from_observations(obs)
    assert "python_django" in hints


def test_stack_hints_from_observations_no_tech_stack_returns_empty() -> None:
    """Observations without a technology_stack attribute (e.g. api
    endpoints, captured_value entries) don't contribute hints."""
    obs = [{
        "attributes_json": {"site_type": "blog", "discovered_endpoint": "/api/v1"},
    }]
    assert stack_hints_from_observations(obs) == []


def test_stack_hints_from_observations_handles_string_tech_stack() -> None:
    """Defensive: tolerate string-instead-of-list under technology_stack."""
    obs = [{"attributes_json": {"technology_stack": "Django and PHP frontend"}}]
    hints = stack_hints_from_observations(obs)
    assert "python_django" in hints
    assert "php" in hints


def test_stack_hints_from_observations_deterministic_output() -> None:
    """Same input → identical (sorted) output across calls."""
    obs = [{
        "attributes_json": {
            "technology_stack": ["Tomcat", "PHP", "Rails"],
        },
    }]
    a = stack_hints_from_observations(obs)
    b = stack_hints_from_observations(obs)
    assert a == b
    assert a == sorted(a)


# ---------------------------------------------------------------------------
# Smoke test — info_disclosure_probe end-to-end with stack_hints
# ---------------------------------------------------------------------------


def test_info_disclosure_probe_with_python_gruyere_hint_probes_dump_gtl() -> None:
    """End-to-end: the probe with stack_hints=['python_gruyere'] DOES
    request /dump.gtl (the path #328 stripped). Validates that #338's
    augmentation reaches the wire."""
    from workers.runners.info_disclosure_probe.runner import execute_info_disclosure_probe

    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        if request.url.path.endswith("/dump.gtl"):
            return httpx.Response(
                200,
                text="<title>Debug Dump</title>"
                     "_cookie: {'is_admin': False, 'is_author': False, 'uid': None}",
            )
        return httpx.Response(404, text="")

    # Monkey-patch httpx.Client to use our transport.
    import httpx as _httpx_module
    from workers.runners.info_disclosure_probe import runner as _probe_module

    original_client = _probe_module.httpx_client.Client
    transport = _httpx.MockTransport(handler) if False else httpx.MockTransport(handler)

    def patched_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    # We must reach into the module's `httpx_client` alias.
    monkeypatched_module = _probe_module.httpx_client
    setattr(monkeypatched_module, "Client", patched_client)
    try:
        result = execute_info_disclosure_probe(
            targets=["http://target.test/"],
            scope_allowlist={"urls": ["http://target.test/"]},
            stack_hints=["python_gruyere"],
        )
    finally:
        setattr(monkeypatched_module, "Client", original_client)

    # The probe must have requested /dump.gtl somewhere in its scan.
    dump_gtl_paths = [p for p in seen_paths if p.endswith("/dump.gtl")]
    assert dump_gtl_paths, (
        f"info_disclosure_probe did not probe /dump.gtl despite "
        f"stack_hints=['python_gruyere']; seen_paths={seen_paths[:30]}"
    )
    # And the probe should have produced a finding from it.
    assert result.exit_code in (0,)
    # The raw artifact carries probes / findings.
    import json as _json
    artifact = result.artifacts[0]
    payload = _json.loads(artifact.data.decode("utf-8"))
    assert payload["probe_count"] > 0
    finding_titles = [f["title"] for f in payload.get("findings") or []]
    # The Debug Dump page leaked session-state — should be flagged HIGH.
    assert any("debug-dump" in title or "phpinfo" in title or "info disclosure" in title.lower()
               for title in finding_titles), (
        f"No info-disclosure finding emitted from /dump.gtl; "
        f"findings={finding_titles}"
    )


def test_info_disclosure_probe_baseline_unchanged_without_stack_hints() -> None:
    """Backward-compat: without stack_hints, the probe path set equals
    the baseline PROBE_PATHS. /dump.gtl is NOT requested (the old #328
    behavior is preserved for callers that don't supply hints)."""
    from workers.runners.info_disclosure_probe.runner import execute_info_disclosure_probe

    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(404)

    from workers.runners.info_disclosure_probe import runner as _probe_module

    original_client = _probe_module.httpx_client.Client
    transport = httpx.MockTransport(handler)

    def patched_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    setattr(_probe_module.httpx_client, "Client", patched_client)
    try:
        execute_info_disclosure_probe(
            targets=["http://target.test/"],
            scope_allowlist={"urls": ["http://target.test/"]},
            # No stack_hints kwarg → defaults to None.
        )
    finally:
        setattr(_probe_module.httpx_client, "Client", original_client)
    dump_gtl_paths = [p for p in seen_paths if p.endswith("/dump.gtl")]
    assert dump_gtl_paths == [], (
        "baseline call still probed /dump.gtl; the augmentation leaked "
        f"into the default path set; seen={[p for p in seen_paths[:10]]}"
    )
