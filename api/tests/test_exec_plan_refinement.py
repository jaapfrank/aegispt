"""Unit tests for backlog-403 — exec_plan iterative refinement loop.

The refinement wrapper :func:`_call_picker_with_exec_plan_refinement` sits
between the loop's main picker call site and :func:`_call_picker_with_retries`.
When the underlying picker returns ``action=exec_plan`` with an empty/malformed
plan body, the wrapper re-prompts the picker (up to ``EXEC_PLAN_MAX_REFINEMENTS``
additional attempts) with the previous plan + failure_reason in the
``extra_recent_rejections`` channel. This forces Claude to confront the specific
failure mode without waiting for the next ``/iterate`` advance.

These tests stub ``_call_picker_with_retries`` directly (the refinement wrapper
calls it; we don't exercise the full Anthropic API path).
"""
from __future__ import annotations

import json
from inspect import getsource

import pytest

from api.app.services import assessment_loop


@pytest.fixture
def fake_kwargs():
    """Common kwargs the refinement wrapper expects."""
    return {
        "run": object(),
        "tested_keys": {"target-intel|http://example.invalid/"},
        "available_tools": ["exec-plan", "smart-web-probe"],
        "targets": [{"value": "http://example.invalid/", "kind": "url"}],
        "scope": None,
        "session": None,
        "loop_state": {},
    }


def _valid_exec_plan_decision(steps: int = 2) -> dict:
    return {
        "action": "exec_plan",
        "plan_name": "test-plan",
        "tier": "active",
        "reasoning": "stub",
        "confidence": 0.9,
        "plan": {
            "name": "test-plan",
            "steps": [
                {"name": f"step{i}", "method": "GET", "url": "http://example.invalid/"}
                for i in range(steps)
            ],
        },
    }


def _empty_exec_plan_decision() -> dict:
    return {
        "action": "exec_plan",
        "plan_name": "test-plan",
        "tier": "active",
        "reasoning": "stub",
        "confidence": 0.9,
        "plan": {"name": "test-plan", "steps": []},
    }


def _malformed_exec_plan_decision() -> dict:
    return {
        "action": "exec_plan",
        "plan_name": "test-plan",
        "tier": "active",
        "reasoning": "stub",
        "confidence": 0.9,
        "plan": "this is a string, not a dict",
    }


def _pick_decision() -> dict:
    return {
        "action": "pick",
        "tool": "smart-web-probe",
        "target": "http://example.invalid/",
        "tier": "active",
        "reasoning": "stub",
        "confidence": 0.9,
        "expected_evidence": ["evidence1"],
    }


def test_first_attempt_success_no_refinement(monkeypatch, fake_kwargs):
    """Happy path — picker returns valid exec_plan on first try."""
    calls: list[dict] = []

    def fake_picker(**kwargs):
        calls.append(kwargs)
        return _valid_exec_plan_decision(steps=3)

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    assert result is not None
    assert result.get("action") == "exec_plan"
    assert len(result["plan"]["steps"]) == 3
    assert fake_kwargs["loop_state"]["exec_plan_refinements_attempted"] == 0
    assert fake_kwargs["loop_state"]["exec_plan_refinement_exhausted"] is False
    assert len(calls) == 1
    # First call should NOT pass extra_recent_rejections
    assert calls[0].get("extra_recent_rejections") is None


def test_empty_steps_then_success_refines_once(monkeypatch, fake_kwargs):
    """One refinement: first call returns empty steps, second returns valid."""
    sequence = [_empty_exec_plan_decision(), _valid_exec_plan_decision(steps=2)]
    calls: list[dict] = []

    def fake_picker(**kwargs):
        calls.append(kwargs)
        return sequence.pop(0)

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    assert result is not None
    assert result.get("action") == "exec_plan"
    assert len(result["plan"]["steps"]) == 2
    assert fake_kwargs["loop_state"]["exec_plan_refinements_attempted"] == 1
    assert fake_kwargs["loop_state"]["exec_plan_refinement_exhausted"] is False
    assert len(calls) == 2
    # Second call MUST receive the refinement note in extra_recent_rejections
    second_rejections = calls[1].get("extra_recent_rejections")
    assert second_rejections is not None
    assert len(second_rejections) == 1
    assert second_rejections[0]["reason"] == "exec_plan_refinement_needed"
    assert "steps" in second_rejections[0]["detail"].lower()


def test_three_empty_plans_marks_exhausted(monkeypatch, fake_kwargs):
    """Refinement budget exhausted — all 3 attempts return empty steps."""
    calls: list[dict] = []

    def fake_picker(**kwargs):
        calls.append(kwargs)
        return _empty_exec_plan_decision()

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    # Returns the last (still malformed) decision so caller's rejection_sink fires.
    assert result is not None
    assert result.get("action") == "exec_plan"
    assert fake_kwargs["loop_state"]["exec_plan_refinement_exhausted"] is True
    assert fake_kwargs["loop_state"]["exec_plan_refinements_attempted"] == assessment_loop.EXEC_PLAN_MAX_REFINEMENTS
    # 1 initial + EXEC_PLAN_MAX_REFINEMENTS refinements = 3 attempts total
    assert len(calls) == assessment_loop.EXEC_PLAN_MAX_REFINEMENTS + 1


def test_malformed_plan_field_is_also_refined(monkeypatch, fake_kwargs):
    """Refinement triggers when 'plan' isn't a dict (e.g. left as string)."""
    sequence = [_malformed_exec_plan_decision(), _valid_exec_plan_decision(steps=2)]

    def fake_picker(**kwargs):
        return sequence.pop(0)

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    assert result is not None
    assert isinstance(result["plan"], dict)
    assert fake_kwargs["loop_state"]["exec_plan_refinements_attempted"] == 1


def test_non_exec_plan_decision_no_refinement(monkeypatch, fake_kwargs):
    """Picker returns action=pick — refinement loop short-circuits."""
    calls: list[dict] = []

    def fake_picker(**kwargs):
        calls.append(kwargs)
        return _pick_decision()

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    assert result is not None
    assert result.get("action") == "pick"
    assert fake_kwargs["loop_state"]["exec_plan_refinements_attempted"] == 0
    assert fake_kwargs["loop_state"]["exec_plan_refinement_exhausted"] is False
    assert len(calls) == 1


def test_picker_returns_none_short_circuits(monkeypatch, fake_kwargs):
    """Underlying picker returns None — wrapper returns None immediately."""
    calls: list[dict] = []

    def fake_picker(**kwargs):
        calls.append(kwargs)
        return None

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    assert result is None
    assert len(calls) == 1
    # No refinement attempted because the underlying retry budget is already exhausted.
    assert fake_kwargs["loop_state"]["exec_plan_refinement_exhausted"] is False


def test_max_tokens_constant_is_4096() -> None:
    """Sentinel: backlog-403 raised picker max_tokens from 1024 to 4096."""
    assert assessment_loop.PICKER_MAX_TOKENS == 4096


def test_exec_plan_max_refinements_constant_is_2() -> None:
    """Sentinel: changing the refinement budget is a deliberate decision."""
    assert assessment_loop.EXEC_PLAN_MAX_REFINEMENTS == 2


def test_picker_call_site_uses_max_tokens_constant() -> None:
    """Source-grep sentinel: the messages.create call MUST use the constant
    so a future refactor doesn't silently re-introduce a hardcoded 1024."""
    src = getsource(assessment_loop._claude_select_next_action)
    assert "max_tokens=PICKER_MAX_TOKENS" in src
    assert "max_tokens=1024" not in src


def test_refinement_wrapper_is_called_from_advance_loop() -> None:
    """Source-grep sentinel: ensures the wrapper is wired in (regression
    guard if a future refactor swaps it back to _call_picker_with_retries
    directly)."""
    src = getsource(assessment_loop)
    assert src.count("_call_picker_with_exec_plan_refinement(") >= 2  # def + ≥1 call


def test_refinement_prompt_has_no_app_specific_seeds() -> None:
    """Per feedback_no_prescriptive_recipes + feedback_live_proof_must_be_diverse_real_targets:
    the refinement message must NOT seed concrete fix templates like
    'try is_admin=True' or app-specific paths.

    Greppable: extract the helper's source, assert no forbidden tokens."""
    src = getsource(assessment_loop._call_picker_with_exec_plan_refinement)
    forbidden = (
        "is_admin=true", "is_admin=True", "/saveprofile", "/dump.gtl",
        "/elmah.axd", "google-gruyere", "juice-shop", "testfire",
        "wp-login.php", "phpinfo",
    )
    for token in forbidden:
        assert token.lower() not in src.lower(), (
            f"Refinement prompt contains forbidden seed {token!r} — must stay generic"
        )


def test_refinement_decision_returned_when_exhausted_so_caller_rejection_fires(monkeypatch, fake_kwargs):
    """Critical contract: when refinement exhausts, the wrapper returns the
    final (still malformed) decision rather than None, so the loop's existing
    rejection_sink handler at line ~3262 routes it correctly."""
    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries",
                        lambda **kw: _empty_exec_plan_decision())

    result = assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    assert result is not None
    assert result["action"] == "exec_plan"
    assert result["plan"]["steps"] == []  # still malformed, propagates to caller


def test_refinement_note_includes_previous_plan_summary_truncated(monkeypatch, fake_kwargs):
    """The refinement note carries the prior plan body (truncated to 500
    chars) so Claude can see WHAT he tried last time."""
    sequence = [_empty_exec_plan_decision(), _valid_exec_plan_decision(steps=2)]
    calls: list[dict] = []

    def fake_picker(**kwargs):
        calls.append(kwargs)
        return sequence.pop(0)

    monkeypatch.setattr(assessment_loop, "_call_picker_with_retries", fake_picker)
    assessment_loop._call_picker_with_exec_plan_refinement(**fake_kwargs)

    second_rejections = calls[1].get("extra_recent_rejections") or []
    assert len(second_rejections) == 1
    detail = second_rejections[0]["detail"]
    assert "Previous plan body" in detail
    # Detail should include the JSON-encoded empty-plan body
    assert json.dumps(_empty_exec_plan_decision()["plan"])[:50] in detail
