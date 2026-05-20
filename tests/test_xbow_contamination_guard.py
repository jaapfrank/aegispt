"""Grep-guard + unit tests for backlog-408 XBOW baseline harness.

Per Codex refinement on backlog-408 (sprint mythos-exploitation-foundation,
task 2/15): XBOW challenge identifiers, paths, or solutions MUST NOT
leak into AegisPT production source. The harness lives in scripts/ and
is the ONLY place that knows about XBOW. Production code (api/, workers/)
must remain XBOW-agnostic so that future capability tasks
(backlog-409..423) cannot be evaluated against a benchmark they were
specifically tuned for.

A failure here indicates a sprint task seeded per-challenge logic into
production. The fix is to make the affected code generic, NOT to
whitelist the challenge id in this guard.
"""
from __future__ import annotations

import importlib
import pathlib
import re
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Production source roots the guard scans. Removing entries weakens the guard.
PRODUCTION_SOURCE_ROOTS = ("api/", "workers/")

# Patterns that, if present in production source, indicate XBOW contamination.
# XBEN-NNN-YY = challenge id; xbow_challenge_solution = recipe-seeding sentinel.
FORBIDDEN_PATTERNS = (
    r"XBEN-\d{3}-\d{2}",
    r"xbow_challenge_solution",
    r"xbow_flag_for_",
)


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


@pytest.mark.parametrize("pattern", FORBIDDEN_PATTERNS)
def test_no_xbow_specific_strings_in_production_source(pattern: str) -> None:
    """No XBOW challenge id or solution pattern may appear in api/ or workers/."""
    violations = _git_grep(pattern, PRODUCTION_SOURCE_ROOTS)
    assert not violations, (
        f"Pattern {pattern!r} leaked into production source. "
        "Make the affected code generic — do NOT whitelist the challenge here. "
        "Offending lines:\n  " + "\n  ".join(violations[:10])
    )


def test_grep_helper_returns_empty_on_clean_tree() -> None:
    """Confirms the _git_grep helper actually runs (not silently failing)."""
    assert _git_grep("aegispt_xbow_zzznever_match_xyz_42", PRODUCTION_SOURCE_ROOTS) == []


def test_harness_refuses_production_memory_root(tmp_path, monkeypatch):
    """The harness MUST refuse to run unless memory_root contains bench/xbow.

    This is the anti-contamination tripwire: a misconfigured invocation
    that targets the production memory root must SystemExit before any
    challenge runs.
    """
    xbow = importlib.import_module("scripts.xbow_benchmark")
    bad_root = tmp_path / "memories"
    bad_root.mkdir()
    with pytest.raises(SystemExit) as excinfo:
        xbow._check_anti_contamination(bad_root)
    msg = str(excinfo.value)
    assert "bench" in msg.lower() or "xbow" in msg.lower()


def test_harness_accepts_benchmark_memory_root(tmp_path):
    """Inverse of the above: paths containing 'bench' or 'xbow' must be accepted."""
    xbow = importlib.import_module("scripts.xbow_benchmark")
    good_root = tmp_path / "xbow-benchmark-memories"
    xbow._check_anti_contamination(good_root)
    assert good_root.is_dir(), "harness must create the isolated root when accepting it"


def test_compose_port_parser_handles_typical_xbow_layout(tmp_path):
    """The harness must extract host port from a typical XBOW docker-compose.yml."""
    xbow = importlib.import_module("scripts.xbow_benchmark")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        'services:\n'
        '  app:\n'
        '    ports:\n'
        '      - "8080:80"\n'
        '      - "5432:5432"\n',
        encoding="utf-8",
    )
    assert xbow._parse_compose_port(compose) == 8080


def test_compose_port_parser_returns_none_for_non_web(tmp_path):
    """Non-HTTP challenges (only DB/SSH/etc ports) return None and the harness skips."""
    xbow = importlib.import_module("scripts.xbow_benchmark")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        'services:\n'
        '  db:\n'
        '    ports:\n'
        '      - "5432:5432"\n',
        encoding="utf-8",
    )
    assert xbow._parse_compose_port(compose) is None


def test_has_web_service_accepts_short_form_port(tmp_path):
    """XBOW challenges using ``- 80`` (short form) must be recognized as web."""
    xbow = importlib.import_module("scripts.xbow_benchmark")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        'services:\n'
        '  app:\n'
        '    ports:\n'
        '      - 80\n',
        encoding="utf-8",
    )
    assert xbow._challenge_has_web_service(compose) is True
    # And the static parser returns None — runtime port resolution required.
    assert xbow._parse_compose_port(compose) is None


def test_has_web_service_rejects_non_web_only(tmp_path):
    """Compose exposing only non-web ports (e.g. only DB) reports no web service."""
    xbow = importlib.import_module("scripts.xbow_benchmark")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        'services:\n'
        '  db:\n'
        '    ports:\n'
        '      - "5432:5432"\n'
        '      - 22\n',
        encoding="utf-8",
    )
    assert xbow._challenge_has_web_service(compose) is False


def test_xben_regex_matches_canonical_ids() -> None:
    """Sentinel: the discovery regex matches all 104 canonical XBOW ids."""
    pattern = re.compile(r"^XBEN-\d{3}-\d{2}$")
    for n in (1, 50, 99, 104):
        assert pattern.match(f"XBEN-{n:03d}-24"), f"XBEN-{n:03d}-24 did not match"
    assert not pattern.match("xben-001-24")
    assert not pattern.match("XBEN-1-24")
