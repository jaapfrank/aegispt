"""Shared http_probe resilience helper (2026-06-04)."""
from __future__ import annotations

import httpx
import pytest

from workers.runners.base import http_probe as hp


def test_is_unreachable_classifies_transport_vs_http():
    assert hp.is_unreachable(httpx.ConnectError("[Errno 111] Connection refused"))
    assert hp.is_unreachable(httpx.ReadTimeout("timed out"))
    assert not hp.is_unreachable(ValueError("404 not found"))


def test_request_with_retry_recovers_when_target_comes_up():
    calls = {"n": 0}

    def do():
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("[Errno 111] Connection refused")
        return "ok"

    out = hp.request_with_retry(do, sleep=lambda *_: None)
    assert out == "ok"
    assert calls["n"] == 3  # retried twice, succeeded on the third


def test_request_with_retry_reraises_after_exhausting():
    def do():
        raise httpx.ConnectError("[Errno 111] Connection refused")

    with pytest.raises(httpx.ConnectError):
        hp.request_with_retry(do, retries=2, sleep=lambda *_: None)


def test_request_with_retry_does_not_retry_real_http_error():
    calls = {"n": 0}

    def do():
        calls["n"] += 1
        raise httpx.HTTPStatusError("500", request=None, response=None)

    with pytest.raises(httpx.HTTPStatusError):
        hp.request_with_retry(do, sleep=lambda *_: None)
    assert calls["n"] == 1  # not retried — it's a reachable-server error


def test_probe_outcome_target_down_yields_skip():
    outcome = hp.ProbeOutcome()
    for _ in range(3):
        with pytest.raises(httpx.ConnectError):
            outcome.run(lambda: (_ for _ in ()).throw(
                httpx.ConnectError("[Errno 111] Connection refused")),
                sleep=lambda *_: None)
    assert outcome.unreachable == 3 and outcome.ok == 0
    assert outcome.exit_code() == 78          # target down -> skipped
    assert outcome.target_reachable is False


def test_probe_outcome_partial_success_completes():
    outcome = hp.ProbeOutcome()
    assert outcome.run(lambda: "resp", sleep=lambda *_: None) == "resp"
    with pytest.raises(httpx.ConnectError):
        outcome.run(lambda: (_ for _ in ()).throw(
            httpx.ConnectError("connection refused")), sleep=lambda *_: None)
    assert outcome.ok == 1 and outcome.unreachable == 1
    assert outcome.exit_code() == 0           # got data -> completed
    assert outcome.target_reachable is True


def test_reachability_exit_code_matrix():
    assert hp.reachability_exit_code(ok=2, unreachable=1, errored=0) == 0   # got data
    assert hp.reachability_exit_code(ok=0, unreachable=3, errored=0) == 78  # target down
    assert hp.reachability_exit_code(ok=0, unreachable=0, errored=1) == 1   # real error
    assert hp.reachability_exit_code(ok=0, unreachable=0, errored=0, current=1) == 1
    assert hp.reachability_exit_code(ok=0, unreachable=0, errored=0) == 0   # nothing done
