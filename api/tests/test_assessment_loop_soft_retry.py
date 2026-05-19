"""Tests for the picker soft-retry wrapper (Mythos #331).

Covers:
- 1 fail + 1 success per advance → loop continues (decision returned)
- 3 fails per advance → loop sets `picker_retry_exhausted` flag
- `retries_this_advance` counter is updated through the budget
- Happy path (no retry needed) leaves counter at 0 and flag False
- Exhaustion is distinguishable from "no fallback candidate" via the flag

All tests exercise the wrapper directly so we don't need a DB session,
Run model, or live Anthropic client. `_claude_select_next_action` is
patched to a stub controlled by the test.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from api.app.services import assessment_loop as al


def _sequenced_picker(*outputs: dict[str, Any] | None):
    """Build a stub picker that returns ``outputs`` in order. Raises if
    it's called more times than provided values."""
    iterator = iter(outputs)

    def _stub(**_kwargs):
        try:
            return next(iterator)
        except StopIteration as exc:
            raise AssertionError(
                "_claude_select_next_action called more times than expected"
            ) from exc

    return _stub


def _call_wrapper(loop_state: dict[str, Any]) -> dict[str, Any] | None:
    return al._call_picker_with_retries(
        run=object(),  # type: ignore[arg-type]
        tested_keys=set(),
        available_tools=[],
        targets=[],
        scope=None,
        session=None,
        loop_state=loop_state,
    )


# ---------------------------------------------------------------------------
# Happy path — no retries needed
# ---------------------------------------------------------------------------


def test_first_attempt_success_no_retries(caplog: pytest.LogCaptureFixture) -> None:
    """When the picker returns a usable decision on the first attempt,
    retries_this_advance stays at 0 and picker_retry_exhausted stays
    False."""
    loop_state: dict[str, Any] = {}
    decision = {"action": "stop", "stop_reason": "exhausted", "summary": "x", "confidence": 0.5}
    with patch.object(al, "_claude_select_next_action", _sequenced_picker(decision)):
        result = _call_wrapper(loop_state)
    assert result == decision
    assert loop_state["retries_this_advance"] == 0
    assert loop_state["picker_retry_exhausted"] is False


# ---------------------------------------------------------------------------
# Soft retry recovery
# ---------------------------------------------------------------------------


def test_one_fail_then_success_continues(caplog: pytest.LogCaptureFixture) -> None:
    """The required acceptance scenario: 1 fail + 1 success → loop
    continues. retries_this_advance == 1 records the recovery."""
    loop_state: dict[str, Any] = {}
    decision = {"action": "pick", "tool": "nmap", "target": "x"}
    with patch.object(al, "_claude_select_next_action", _sequenced_picker(None, decision)):
        result = _call_wrapper(loop_state)
    assert result == decision
    assert loop_state["retries_this_advance"] == 1
    assert loop_state["picker_retry_exhausted"] is False


def test_two_fails_then_success_continues() -> None:
    """At the very edge of the retry budget — 2 fails + 1 success on
    the third (final) attempt. Decision returned; counter at 2; not
    exhausted."""
    loop_state: dict[str, Any] = {}
    decision = {"action": "level_up", "previous_phase_summary": "x"}
    with patch.object(
        al, "_claude_select_next_action",
        _sequenced_picker(None, None, decision),
    ):
        result = _call_wrapper(loop_state)
    assert result == decision
    assert loop_state["retries_this_advance"] == 2
    assert loop_state["picker_retry_exhausted"] is False


# ---------------------------------------------------------------------------
# Exhaustion — 3 fails
# ---------------------------------------------------------------------------


def test_three_fails_marks_exhausted() -> None:
    """The other required acceptance scenario: 3 consecutive Nones →
    decision is None; picker_retry_exhausted is True; counter at 2
    (= PICKER_MAX_RETRIES)."""
    loop_state: dict[str, Any] = {}
    with patch.object(
        al, "_claude_select_next_action",
        _sequenced_picker(None, None, None),
    ):
        result = _call_wrapper(loop_state)
    assert result is None
    assert loop_state["picker_retry_exhausted"] is True
    assert loop_state["retries_this_advance"] == al.PICKER_MAX_RETRIES == 2


# ---------------------------------------------------------------------------
# Telemetry: state mutations are visible mid-flight
# ---------------------------------------------------------------------------


def test_state_is_initialized_each_advance() -> None:
    """If `loop_state` carries stale values from a previous advance,
    the wrapper resets them on entry so the counter reflects only the
    current advance's retry count."""
    loop_state: dict[str, Any] = {
        "retries_this_advance": 99,
        "picker_retry_exhausted": True,
    }
    decision = {"action": "stop"}
    with patch.object(al, "_claude_select_next_action", _sequenced_picker(decision)):
        result = _call_wrapper(loop_state)
    assert result == decision
    assert loop_state["retries_this_advance"] == 0
    assert loop_state["picker_retry_exhausted"] is False


def test_logs_warning_on_exhaustion(caplog: pytest.LogCaptureFixture) -> None:
    import logging
    loop_state: dict[str, Any] = {}
    with caplog.at_level(logging.WARNING, logger="api.app.services.assessment_loop"):
        with patch.object(
            al, "_claude_select_next_action",
            _sequenced_picker(None, None, None),
        ):
            _call_wrapper(loop_state)
    assert any(
        "picker exhausted retries" in rec.message
        for rec in caplog.records
    )


def test_logs_info_on_recovery(caplog: pytest.LogCaptureFixture) -> None:
    import logging
    loop_state: dict[str, Any] = {}
    decision = {"action": "stop"}
    with caplog.at_level(logging.INFO, logger="api.app.services.assessment_loop"):
        with patch.object(
            al, "_claude_select_next_action",
            _sequenced_picker(None, decision),
        ):
            _call_wrapper(loop_state)
    assert any(
        "picker recovered after" in rec.message
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# Budget constant matches task package contract
# ---------------------------------------------------------------------------


def test_retry_budget_constant() -> None:
    """The task package fixes max retries at 2 (so 3 total attempts).
    A change to this constant should be a deliberate scope decision,
    not silent drift."""
    assert al.PICKER_MAX_RETRIES == 2


# ---------------------------------------------------------------------------
# Wrapper does not swallow non-None falsy values
# ---------------------------------------------------------------------------


def test_wrapper_treats_empty_dict_as_valid_decision() -> None:
    """An empty dict {} is still a decision (caller handles the .get
    fallback). Wrapper only retries on the explicit None sentinel."""
    loop_state: dict[str, Any] = {}
    empty_decision: dict[str, Any] = {}
    with patch.object(al, "_claude_select_next_action", _sequenced_picker(empty_decision)):
        result = _call_wrapper(loop_state)
    assert result == {}
    assert loop_state["retries_this_advance"] == 0
