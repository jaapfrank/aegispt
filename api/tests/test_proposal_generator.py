"""Unit tests for backlog-423 proposal generator."""
from __future__ import annotations

import json
from pathlib import Path

from api.app.services.failure_analysis import FailurePattern, cluster_failures
from api.app.services.proposal_generator import (
    _next_rev,
    _slug_component,
    generate_proposals,
    proposal_summary,
    render_proposal,
)


def _baseline(tmp_path: Path, results) -> Path:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"results": results}), encoding="utf-8")
    return path


# --- Slug + rev helpers ------------------------------------------


def test_slug_component_handles_spaces_and_punctuation() -> None:
    assert _slug_component("scripts/xbow_benchmark.py + helper") == "scripts-xbow-benchmark-py-helper"
    assert _slug_component("") == "general"
    long = _slug_component("a" * 100)
    assert len(long) <= 60


def test_next_rev_increments(tmp_path: Path) -> None:
    today = "2026-05-21"
    slug = "recon"
    (tmp_path / f"{today}-{slug}-rev1.md").write_text("x", encoding="utf-8")
    (tmp_path / f"{today}-{slug}-rev3.md").write_text("x", encoding="utf-8")
    assert _next_rev(tmp_path, today, slug) == 4
    assert _next_rev(tmp_path, today, "other") == 1


# --- Single proposal rendering ------------------------------------


def test_render_proposal_always_starts_with_approve_false() -> None:
    pattern = FailurePattern(
        cluster_name="infra:api_timeout",
        failure_mode="api_timeout",
        change_kind="infra",
        affected_challenges=["C1", "C2"],
        representative_error="API call failed: timed out",
        root_cause_hypothesis="Anthropic API timed out",
        proposed_change_summary="bump picker retry budget",
        proposed_target_component="api/app/services/assessment_loop.py",
    )
    body = render_proposal(pattern, today="2026-05-21")
    assert body.startswith("approve: false")
    assert "title: infra:api_timeout" in body
    assert "change_kind: infra" in body
    assert "C1, C2" in body
    assert "Operator approval checklist" in body
    assert "aegispt_promote_proposal.py" in body


def test_render_proposal_truncates_long_challenge_lists() -> None:
    pattern = FailurePattern(
        cluster_name="x:y", failure_mode="y", change_kind="prompt",
        affected_challenges=[f"C{i}" for i in range(40)],
    )
    body = render_proposal(pattern)
    assert "…" in body  # ellipsis for >25 challenges
    assert "C0" in body
    assert "C24" in body
    assert "C39" not in body


# --- generate_proposals end-to-end ---------------------------


def test_generate_proposals_writes_one_file_per_pattern(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path, [
        {"challenge_id": "C1", "solved": False, "error": "API call failed: timed out"},
        {"challenge_id": "C2", "solved": False, "error": "docker compose build failed (exit 1): X"},
    ])
    patterns = cluster_failures(baseline)
    written = generate_proposals(patterns, output_dir=tmp_path / "out", today="2026-05-21")
    assert len(written) == len(patterns)
    for path in written:
        assert path.exists()
        body = path.read_text(encoding="utf-8")
        assert body.startswith("approve: false")


def test_proposal_filename_contains_date_and_slug(tmp_path: Path) -> None:
    pattern = FailurePattern(
        cluster_name="infra:api_timeout", failure_mode="api_timeout",
        change_kind="infra", affected_challenges=["C1"],
    )
    written = generate_proposals([pattern], output_dir=tmp_path, today="2026-05-21")
    assert "2026-05-21" in written[0].name
    assert "infra" in written[0].name
    assert "rev1" in written[0].name


def test_proposal_summary_lists_files(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path, [
        {"challenge_id": "C1", "solved": False, "error": "API call failed: timed out"},
    ])
    patterns = cluster_failures(baseline)
    written = generate_proposals(patterns, output_dir=tmp_path / "out", today="2026-05-21")
    summary = proposal_summary(patterns, written)
    assert summary["proposals_generated"] == len(written)
    assert summary["patterns_clustered"] == len(patterns)
    assert "promote-proposal" in summary["next_step"] or "aegispt_promote_proposal" in summary["next_step"]


# --- Safety: never writes to prompts/active ---------------------


def test_generator_never_writes_to_active_directory(tmp_path: Path, monkeypatch) -> None:
    """Sentinel: the proposal generator MUST stay in `prompts/proposals/`
    (or the operator-provided output_dir). Touching `prompts/active/` is
    the discipline tripwire enforced by `approve_prompt_change` — never
    by the auto-generator.
    """
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    active_dir = tmp_path / "active"
    pattern = FailurePattern(
        cluster_name="x", failure_mode="api_timeout", change_kind="infra",
        affected_challenges=["C1"],
    )
    # Use the default output_dir (prompts/proposals under PROMPTS_ROOT).
    generate_proposals([pattern], today="2026-05-21")
    # Active dir must not exist or must be empty.
    if active_dir.exists():
        assert not list(active_dir.iterdir())
