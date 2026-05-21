"""Unit tests for backlog-413 PoC artifact generator."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from api.app.services.poc_artifact import PoCArtifact, build_executable_poc


def _finding(title: str, recipe: dict) -> SimpleNamespace:
    return SimpleNamespace(title=title, replay_recipe_json=recipe)


def test_artifact_has_script_text_and_sha() -> None:
    art = build_executable_poc(
        _finding("RCE example", {"steps": [{"method": "GET", "url": "/x"}], "expected_markers": ["pwned"]}),
    )
    assert isinstance(art, PoCArtifact)
    assert art.script_text.startswith("#!/usr/bin/env python3")
    assert len(art.recipe_sha) == 64  # SHA-256 hex
    assert art.title == "RCE example"
    assert art.expected_markers == ["pwned"]


def test_artifact_embeds_steps_and_markers_verbatim() -> None:
    recipe = {
        "steps": [
            {"method": "POST", "url": "/login", "body": "username=admin&password=admin"},
            {"method": "GET", "url": "/admin"},
        ],
        "expected_markers": ["welcome admin"],
    }
    art = build_executable_poc(_finding("admin compromise", recipe))
    assert "/login" in art.script_text
    assert "username=admin" in art.script_text
    assert "welcome admin" in art.script_text


def test_artifact_runs_as_standalone_script(tmp_path: Path) -> None:
    art = build_executable_poc(
        _finding("dummy", {"steps": [], "expected_markers": ["x"]}),
    )
    poc_path = tmp_path / "poc.py"
    poc_path.write_text(art.script_text, encoding="utf-8")
    # --help should exit 0 — verifies the script parses + argparse works.
    result = subprocess.run(
        [sys.executable, str(poc_path), "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert "--target" in result.stdout


def test_artifact_exit_code_2_when_marker_absent(tmp_path: Path) -> None:
    # Build a PoC against a non-existent target; without markers found exit=2 is expected.
    # Use an unreachable URL so the run hits the "missing markers" branch quickly
    # by zero-step short-circuit (no steps → observed empty → missing → exit 2).
    art = build_executable_poc(
        _finding("marker-check", {"steps": [], "expected_markers": ["never_seen_marker_xyz"]}),
    )
    poc_path = tmp_path / "poc.py"
    poc_path.write_text(art.script_text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(poc_path), "--target", "http://127.0.0.1:1"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    # No steps means observed=[] so missing=[never_seen_marker_xyz] => exit 2.
    assert result.returncode == 2
    assert "missing markers" in result.stderr


def test_artifact_recipe_sha_changes_with_recipe() -> None:
    a = build_executable_poc(_finding("a", {"steps": [{"method": "GET", "url": "/a"}], "expected_markers": ["x"]}))
    b = build_executable_poc(_finding("b", {"steps": [{"method": "GET", "url": "/b"}], "expected_markers": ["x"]}))
    assert a.recipe_sha != b.recipe_sha
