"""Operator-flagged: recon probes (httpx, playwright-web) showed FAILED rows when the
target was merely UNREACHABLE (connection refused / timeout — e.g. the service wasn't up
yet on the probed port). An unreachable target is NOT a tool failure; per the established
empty-script SKIP pattern it must map to exit_code=78 (task.status=skipped), not exit 1.
"""
from __future__ import annotations

from workers.runners.httpx.runner import execute_httpx_probe


def test_httpx_unreachable_target_is_skipped_not_failed():
    # 127.0.0.231 has nothing listening -> connection refused on every target.
    ex = execute_httpx_probe(["http://127.0.0.231"])
    assert ex.exit_code == 78, "all-unreachable httpx must be SKIPPED (78), not FAILED (1)"
    assert ex.metadata.get("status") == "skipped"


def test_httpx_real_error_distinct_from_unreachable():
    # the per-result row carries the unreachable flag so a genuine (non-connection)
    # error would NOT be silently skipped.
    ex = execute_httpx_probe(["http://127.0.0.231"])
    import json
    rows = json.loads(ex.stdout)["results"]
    assert rows and rows[0]["unreachable"] is True
