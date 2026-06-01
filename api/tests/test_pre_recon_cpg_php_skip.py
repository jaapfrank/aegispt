"""Regression: pre-recon-cpg handles PHP correctly.

Operator-flagged 2026-06-01: pre-recon-cpg "failed" for PHP and burned ~184s. The
root cause was NOT a Joern defect — Joern's php2cpg shells out to a `php` binary
(PHP 7.1+) and PHP simply was not installed. Fix: install php-cli (so php2cpg
builds a real CPG) + a fast graceful guard so that, when php is absent, the runner
skips quickly with an actionable hint instead of hanging. The guard is checked
BEFORE the Joern install check.
"""
from __future__ import annotations

import json
from pathlib import Path

import workers.runners.pre_recon_cpg.runner as cpg_runner
from workers.runners.pre_recon_cpg.runner import execute_pre_recon_cpg


def test_php_without_binary_skips_fast(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cpg_runner.shutil, "which", lambda _name: None)
    (tmp_path / "index.php").write_text(
        "<?php $a = unserialize($_COOKIE['creds']); ?>", encoding="utf-8"
    )
    r = execute_pre_recon_cpg([], source_dir=str(tmp_path))
    assert r.metadata.get("skip_reason") == "php_binary_missing"
    assert json.loads(r.stdout).get("reason") == "php_binary_missing"


def test_php_with_binary_falls_through_guard(tmp_path: Path, monkeypatch):
    # With php present, the binary-guard must NOT short-circuit; it falls through
    # to the Joern path. Point JOERN_INSTALL_DIR at an empty dir so we stop at the
    # joern_missing skip — proving the php guard did not fire.
    monkeypatch.setattr(cpg_runner.shutil, "which", lambda _name: "/usr/bin/php")
    monkeypatch.setattr(cpg_runner, "JOERN_INSTALL_DIR", tmp_path / "no-joern-here")
    (tmp_path / "index.php").write_text("<?php echo 1; ?>", encoding="utf-8")
    r = execute_pre_recon_cpg([], source_dir=str(tmp_path))
    assert r.metadata.get("skip_reason") == "joern_missing"


def test_no_recognized_files_skipped(tmp_path: Path):
    (tmp_path / "readme.txt").write_text("nothing scannable", encoding="utf-8")
    r = execute_pre_recon_cpg([], source_dir=str(tmp_path))
    assert r.metadata.get("skipped") is True


def test_missing_source_dir_skipped():
    r = execute_pre_recon_cpg([], source_dir=None)
    assert r.metadata.get("skip_reason") == "no_source_dir"
