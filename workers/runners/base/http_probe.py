"""Shared HTTP-probe resilience: retry-on-unreachable + honest exit code.

A target container is often still coming up (or between restarts) when a probe
fires, so a connection-refused/timeout is NOT a probe failure. Many probe runners
historically set ``exit_code = 1`` on the first transport error, which marked the
whole task FAILED — flooding the queue with red FAILED for a target that was
simply down (operator-reported 2026-06-04). This module centralises the fix so
every probe runner behaves identically:

  - ``request_with_retry`` retries an unreachable call with backoff;
  - ``reachability_exit_code`` maps probe outcome counts to an honest task exit
    code: got data -> 0; target down -> 78 (EX_CONFIG => "skipped", not FAILED);
    a genuine error on a reachable target -> 1 (fed back to the loop).

Reference implementation: workers/runners/exec_plan/runner.py.
"""
from __future__ import annotations

import time
from typing import Callable, TypeVar

import httpx

MAX_PROBE_RETRIES = 3
PROBE_RETRY_BACKOFF_S = 2.0

# EX_CONFIG: the orchestrator (tasks.py) maps exit_code 78 -> task status
# "skipped" (a runner that could not run), distinct from a hard failure.
EX_TARGET_UNREACHABLE = 78

_UNREACHABLE_TOKENS = (
    "connection refused", "errno 111", "econnrefused", "timed out", "timeout",
    "name or service not known", "no route to host", "connecterror",
    "connecttimeout", "readtimeout", "unreachable", "all connection attempts failed",
)

T = TypeVar("T")


def is_unreachable(exc: BaseException) -> bool:
    """True if the exception looks like a target-down / unreachable condition
    (as opposed to a genuine HTTP-level error from a reachable server)."""
    return any(tok in str(exc).lower() for tok in _UNREACHABLE_TOKENS)


def request_with_retry(
    do_request: Callable[[], T],
    *,
    retries: int = MAX_PROBE_RETRIES,
    backoff_s: float = PROBE_RETRY_BACKOFF_S,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Run ``do_request`` (a zero-arg callable performing one HTTP request),
    retrying on an unreachable target. Re-raises the original error once retries
    are exhausted or the error is not an unreachable condition."""
    attempt = 0
    while True:
        try:
            return do_request()
        except httpx.HTTPError as exc:
            if is_unreachable(exc) and attempt < retries:
                attempt += 1
                sleep(backoff_s)
                continue  # target may still be coming up — wait + retry
            raise


class ProbeOutcome:
    """Accumulates probe-request outcomes so a runner can derive an honest task
    exit code with minimal, uniform changes. Usage:

        outcome = ProbeOutcome()
        ...
        try:
            response = outcome.run(lambda: client.get(url, ...))  # retries+counts
        except httpx.HTTPError as exc:
            stderr_lines.append(...); continue   # NO exit_code = 1 here
        ...
        exit_code = outcome.exit_code(exit_code)  # before returning
    """

    def __init__(self) -> None:
        self.ok = 0
        self.unreachable = 0
        self.errored = 0

    def run(self, do_request: Callable[[], T], *, sleep: Callable[[float], None] = time.sleep) -> T:
        try:
            resp = request_with_retry(do_request, sleep=sleep)
        except httpx.HTTPError as exc:
            if is_unreachable(exc):
                self.unreachable += 1
            else:
                self.errored += 1
            raise
        self.ok += 1
        return resp

    def exit_code(self, current: int = 0) -> int:
        return reachability_exit_code(
            ok=self.ok, unreachable=self.unreachable, errored=self.errored, current=current
        )

    @property
    def target_reachable(self) -> bool:
        return self.ok > 0


def reachability_exit_code(
    *, ok: int, unreachable: int, errored: int, current: int = 0
) -> int:
    """Honest task exit code from probe-outcome counts:

      - any real HTTP response (ok>0)        -> 0  (completed; partial down is fine)
      - zero responses, target unreachable   -> 78 (skipped: target down, NOT failed)
      - zero responses, real error / current -> 1  (genuine failure, fed back)
      - nothing attempted                    -> 0
    """
    if ok > 0:
        return 0
    if unreachable > 0:
        return EX_TARGET_UNREACHABLE
    if errored > 0 or current:
        return 1
    return 0
