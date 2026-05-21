"""Unit tests for backlog-423 failure analysis."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.app.services.failure_analysis import (
    FAILURE_TAXONOMY,
    classify_result,
    cluster_failures,
    summarize_patterns,
)

# --- Classifier ----------------------------------------------------


def test_classify_solved_short_circuits() -> None:
    assert classify_result({"solved": True, "error": ""}) == "solved"


def test_classify_agent_attempted_no_flag() -> None:
    assert classify_result(
        {"solved": False, "error": "", "run_status": "completed", "tool_chain_length": 5},
    ) == "agent_attempted_no_flag"


def test_classify_api_timeout() -> None:
    assert classify_result({"solved": False, "error": "API call failed: timed out"}) == "api_timeout"


def test_classify_api_disconnected() -> None:
    assert classify_result(
        {"solved": False, "error": "API call failed: Server disconnected without response"},
    ) == "api_disconnected"


def test_classify_docker_build_failed() -> None:
    assert classify_result(
        {"solved": False, "error": "docker compose build failed (exit 1): Dockerfile parse"},
    ) == "docker_build_failed"


def test_classify_docker_up_failed() -> None:
    assert classify_result(
        {"solved": False, "error": "docker compose up failed (exit 1): Network conflict"},
    ) == "docker_up_failed"


def test_classify_port_resolution() -> None:
    assert classify_result(
        {"solved": False, "error": "could not resolve published host port after docker compose up"},
    ) == "port_resolution_failed"


def test_classify_port_collision_refused() -> None:
    assert classify_result(
        {"solved": False, "error": "challenge published port 8000 collides with the AegisPT API"},
    ) == "scope_collision_refused"


def test_classify_unknown_when_no_match() -> None:
    assert classify_result({"solved": False, "error": "weird mystery error"}) == "unknown"


def test_classify_unknown_when_no_error_and_no_attempt() -> None:
    assert classify_result(
        {"solved": False, "error": "", "run_status": "", "tool_chain_length": 0},
    ) == "unknown"


# --- Taxonomy completeness --------------------------------------


def test_taxonomy_has_canonical_modes() -> None:
    expected = {
        "api_timeout", "api_disconnected", "docker_build_failed",
        "docker_up_failed", "port_resolution_failed",
        "scope_collision_refused", "agent_attempted_no_flag",
        "subprocess_timeout", "out_of_scope_rejection", "unknown",
    }
    assert expected.issubset(set(FAILURE_TAXONOMY))


# --- Clustering against a synthetic baseline -------------------


def _write_baseline(tmp_path: Path, results: list[dict]) -> Path:
    path = tmp_path / "baseline.json"
    payload = {"phase": "baseline", "date": "2026-05-21", "results": results}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_cluster_failures_groups_by_mode_and_sorts_desc(tmp_path) -> None:
    baseline = _write_baseline(tmp_path, [
        {"challenge_id": "C1", "solved": False, "error": "API call failed: timed out"},
        {"challenge_id": "C2", "solved": False, "error": "API call failed: timed out"},
        {"challenge_id": "C3", "solved": False, "error": "docker compose build failed (exit 1): X"},
        {"challenge_id": "C4", "solved": True, "error": ""},
        {"challenge_id": "C5", "solved": False, "error": "", "run_status": "completed", "tool_chain_length": 10},
    ])
    patterns = cluster_failures(baseline)
    assert len(patterns) == 3  # api_timeout (2), docker_build_failed (1), agent_attempted_no_flag (1)
    # Sorted descending by affected-challenge count.
    assert len(patterns[0].affected_challenges) >= len(patterns[-1].affected_challenges)
    api_timeout = next(p for p in patterns if p.failure_mode == "api_timeout")
    assert api_timeout.affected_challenges == ["C1", "C2"]
    assert api_timeout.change_kind == "infra"
    capability = next(p for p in patterns if p.failure_mode == "agent_attempted_no_flag")
    assert capability.change_kind == "prompt"


def test_cluster_failures_skips_solved(tmp_path: Path) -> None:
    """Solved entries don't appear in any cluster (they're not failures)."""
    baseline = _write_baseline(tmp_path, [
        {"challenge_id": "C1", "solved": True, "error": ""},
        {"challenge_id": "C2", "solved": False, "error": "API call failed: timed out"},
    ])
    patterns = cluster_failures(baseline)
    assert len(patterns) == 1
    assert "C1" not in patterns[0].affected_challenges
    assert "C2" in patterns[0].affected_challenges


def test_cluster_failures_empty_results_returns_empty(tmp_path) -> None:
    baseline = _write_baseline(tmp_path, [])
    assert cluster_failures(baseline) == []


def test_cluster_failures_missing_file_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        cluster_failures(tmp_path / "missing.json")


# --- Summary helper ---------------------------------------------


def test_summarize_patterns_returns_by_change_kind(tmp_path) -> None:
    baseline = _write_baseline(tmp_path, [
        {"challenge_id": "A", "solved": False, "error": "API call failed: timed out"},
        {"challenge_id": "B", "solved": False, "error": "API call failed: timed out"},
        {"challenge_id": "C", "solved": False, "error": "", "run_status": "completed", "tool_chain_length": 4},
    ])
    patterns = cluster_failures(baseline)
    summary = summarize_patterns(patterns)
    assert summary["total_failed"] == 3
    assert summary["cluster_count"] == 2
    assert summary["by_change_kind"]["infra"] == 2
    assert summary["by_change_kind"]["prompt"] == 1


# --- Live-data smoke ----------------------------------------------


def test_against_live_baseline_if_present() -> None:
    """If the 2026-05-21 live baseline is committed (it is — see release gate),
    classify it end-to-end and assert the expected high-level shape."""
    live = Path(__file__).resolve().parents[2] / "docs/validation/xbow-2026-05-21-baseline.json"
    if not live.is_file():
        pytest.skip("live baseline not present")
    patterns = cluster_failures(live)
    summary = summarize_patterns(patterns)
    # 25 challenges total, 0 solved → at least 1 cluster.
    assert summary["cluster_count"] >= 1
    assert summary["total_failed"] >= 1
    # Per the release-gate report: ~13 api_timeout + 4 docker bugs + 5 attempted-no-flag.
    modes = {p.failure_mode for p in patterns}
    assert "api_timeout" in modes or "api_disconnected" in modes
    assert "agent_attempted_no_flag" in modes
