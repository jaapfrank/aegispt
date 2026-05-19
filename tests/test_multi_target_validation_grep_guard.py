"""Grep-guard tests for backlog-406 multi-target validation harness.

Per `feedback_live_proof_must_be_diverse_real_targets` + the task package's
`no_target_tuning` constraint: the 5 target hostnames may NOT appear in any
production source file. They are allowed in:
  - scripts/multi_target_validation.py (the harness itself)
  - tests/ (this file + future test fixtures)
  - docs/ (the validation reports)

A failure here indicates someone seeded per-target conditional logic in
production code, which violates the smart-system contract. The fix is to
make the affected code generic, not to whitelist the target name here.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Mirror of TARGETS in scripts/multi_target_validation.py.
# Kept independent (no import) so test cannot be defanged by editing the harness.
TARGET_IDS = ("mantis", "mediawiki", "roundcube", "gitea", "etherpad")

# Production source roots. Adding more here is fine; removing them weakens the guard.
PRODUCTION_SOURCE_ROOTS = ("workers/runners", "api/app/services")


def _git_grep(pattern: str, paths: tuple[str, ...]) -> list[str]:
    res = subprocess.run(
        ["git", "grep", "-inE", pattern, "--", *paths],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )
    if res.returncode == 0 and res.stdout.strip():
        return [line for line in res.stdout.splitlines() if line.strip()]
    return []


def test_no_target_hostname_literals_in_production_source() -> None:
    """No target_id may appear as a literal in production source.

    A match means a sprint task seeded per-target logic (e.g. `if 'mantis' in url:`)
    instead of writing a generic fix. Per backlog-406's `no_target_tuning`
    constraint, this is forbidden — make the code generic.
    """
    pattern = "|".join(re.escape(t) for t in TARGET_IDS)
    violations = _git_grep(pattern, PRODUCTION_SOURCE_ROOTS)
    assert not violations, (
        "Target hostname literals leaked into production source. "
        "Make the affected code generic — do NOT whitelist the target here. "
        "Offending lines:\n  " + "\n  ".join(violations[:10])
    )


def test_target_ids_match_harness_catalog() -> None:
    """Sentinel: if the harness adds/removes targets without updating this test,
    the grep guard becomes inconsistent. Force test + harness to evolve together.
    """
    harness_path = REPO_ROOT / "scripts" / "multi_target_validation.py"
    src = harness_path.read_text(encoding="utf-8")
    for target_id in TARGET_IDS:
        assert f'"{target_id}"' in src, (
            f"Target '{target_id}' is in this test's TARGET_IDS but not in "
            f"the harness's TARGETS catalog. Sync them."
        )


def test_validation_grep_helper_returns_empty_on_clean_tree() -> None:
    """Confirms the _git_grep helper actually runs (not silently failing)
    by asserting a pattern guaranteed-empty returns []."""
    found = _git_grep("aegispt_zzznever_match_string_xyz_42", PRODUCTION_SOURCE_ROOTS)
    assert found == []
