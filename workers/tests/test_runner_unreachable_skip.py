"""Operator philosophy (2026-06-04): a recon probe that hits an UNREACHABLE target
(connection refused / timeout — e.g. the container wasn't up yet on the probed port)
must NOT spuriously fail, and must NOT be dishonestly relabelled "skipped" (it DID run).
The honest behaviour: WAIT + RETRY so it actually succeeds once the target is up; only a
target that stays down after the retries is a genuine failure (which the loop then feeds
back to the picker for the next action). Separately: 0 findings is NOT a failure.
"""
from __future__ import annotations

import json

from workers.runners.httpx.runner import (
    _MAX_PROBE_RETRIES,
    execute_httpx_probe,
)


def test_httpx_retries_unreachable_then_fails_honestly():
    # 127.0.0.231 has nothing listening -> connection refused every attempt. The probe
    # should RETRY (not skip), then honestly fail (exit 1) once the target stays down.
    ex = execute_httpx_probe(["http://127.0.0.231"])
    assert ex.exit_code == 1, "a target that stays down after retries is a genuine failure"
    assert ex.metadata.get("status") != "skipped", "must not dishonestly relabel a run as skipped"
    rows = json.loads(ex.stdout)["results"]
    assert rows and rows[0]["unreachable"] is True
    # it actually retried before giving up (proves it waited for the target to come up)
    assert rows[0]["retries"] == _MAX_PROBE_RETRIES
