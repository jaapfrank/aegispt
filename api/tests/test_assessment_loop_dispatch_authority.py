"""Unit tests for backlog-404 — single dispatch authority on autonomous-intrusive runs.

When ``run.autonomous_intrusive_allowed=True``, the rule-based
``select_next_best_action_for_run`` selector must return ``decision='RUN'``
for active/intrusive runners instead of ``decision='APPROVAL'``. This makes
the Claude picker (or selector fallback) the dispatch authority — not a
competing APPROVAL workflow that no operator is watching.

The plumbing: both call sites of ``select_next_best_action_for_run``
(`api/app/services/assessment_loop.py` and `api/app/services/ai_agent.py`)
must thread ``allow_active_without_review=bool(run.autonomous_intrusive_allowed)``.

These tests are mostly source-grep sentinels because the full integration
path requires a DB-loaded Run + Scope + engagement fixture. The behavioral
unit test of ``_action_decision`` covers the selector logic directly.
"""
from __future__ import annotations

from inspect import getsource

from api.app.services import ai_action_selector, ai_agent, assessment_loop


def test_action_decision_allow_active_without_review_flips_approval_to_run() -> None:
    """The core selector logic: with the flag on, active/intrusive
    runners get RUN instead of APPROVAL."""
    # Without the flag (default operator-supervised behavior)
    decision_default, _ = ai_action_selector._decision_for_runner(
        runner="metasploit",
        risk_tier="intrusive",
        required_approvals=1,
        confidence=0.9,
        matched_triggers=["finding:rce"],
        missing_prerequisites=[],
        target_present=True,
        already_tested=False,
        allow_active_without_review=False,
        blocker_ids=[],
        observed_signals=set(),
    )
    assert decision_default == "APPROVAL"

    # With the flag on (autonomous-intrusive run)
    decision_autonomous, _ = ai_action_selector._decision_for_runner(
        runner="metasploit",
        risk_tier="intrusive",
        required_approvals=1,
        confidence=0.9,
        matched_triggers=["finding:rce"],
        missing_prerequisites=[],
        target_present=True,
        already_tested=False,
        allow_active_without_review=True,
        blocker_ids=[],
        observed_signals=set(),
    )
    assert decision_autonomous == "RUN"


def test_action_decision_default_is_unchanged_for_non_active_tier() -> None:
    """The flag must not affect passive tier decisions (those never went
    through APPROVAL anyway)."""
    decision_default, _ = ai_action_selector._decision_for_runner(
        runner="httpx",
        risk_tier="passive",
        required_approvals=0,
        confidence=0.9,
        matched_triggers=[],
        missing_prerequisites=[],
        target_present=True,
        already_tested=False,
        allow_active_without_review=False,
        blocker_ids=[],
        observed_signals=set(),
    )
    decision_autonomous, _ = ai_action_selector._decision_for_runner(
        runner="httpx",
        risk_tier="passive",
        required_approvals=0,
        confidence=0.9,
        matched_triggers=[],
        missing_prerequisites=[],
        target_present=True,
        already_tested=False,
        allow_active_without_review=True,
        blocker_ids=[],
        observed_signals=set(),
    )
    # Both should be the same (LOW_IMPACT_AUTO_TOOLS contains httpx; returns RUN)
    assert decision_default == decision_autonomous


def test_assessment_loop_threads_autonomous_intrusive_allowed_to_selector() -> None:
    """Source-grep sentinel: assessment_loop.py's selector call site
    MUST pass autonomous_intrusive_allowed through as
    allow_active_without_review. If a future refactor removes this,
    the autonomous-intrusive runs regress to APPROVAL-wrapping.
    """
    src = getsource(assessment_loop)
    # Search for the call shape: select_next_best_action_for_run(...) followed
    # by allow_active_without_review=bool(getattr(run, "autonomous_intrusive_allowed", ...
    # in the same function body.
    needle = "allow_active_without_review=bool(\n            getattr(run, \"autonomous_intrusive_allowed\""
    assert needle in src, (
        "assessment_loop.py:select_next_best_action_for_run call must thread the "
        "autonomous_intrusive_allowed flag. Did you remove the bypass?"
    )


def test_ai_agent_threads_autonomous_intrusive_allowed_to_selector() -> None:
    """Source-grep sentinel: ai_agent.py's selector call site MUST
    thread the same flag. Without this gate, post-task analysis flows
    keep wrapping decisions in APPROVAL even when the operator opted
    into autonomous mode.
    """
    src = getsource(ai_agent)
    needle = "allow_active_without_review=bool(\n                    getattr(run, \"autonomous_intrusive_allowed\""
    assert needle in src, (
        "ai_agent.py:select_next_best_action_for_run call must thread the "
        "autonomous_intrusive_allowed flag."
    )


def test_action_rationale_no_pending_approval_phrasing_when_decision_is_run() -> None:
    """Per the selector's _action_rationale function, when decision=RUN
    the rationale should NOT contain 'pending approval'.

    Catches the regression where the flag is threaded but the rationale
    template still emits 'pending approval' (which would mislead operators).
    """
    rationale = ai_action_selector._action_rationale(
        runner="metasploit",
        decision="RUN",
        matched_triggers=["finding:rce"],
        missing_prerequisites=[],
        blocker_reasons=[],
    )
    assert "pending approval" not in rationale.lower()


def test_non_autonomous_run_still_gets_approval() -> None:
    """Critical regression guard: a run with autonomous_intrusive_allowed=False
    (the default for operator-supervised assessments) must keep producing
    APPROVAL decisions. This task strictly OPENS a new path; it doesn't
    CLOSE the existing operator-supervised one.
    """
    decision, reasons = ai_action_selector._decision_for_runner(
        runner="sqlmap",
        risk_tier="active",
        required_approvals=1,
        confidence=0.9,
        matched_triggers=["finding:sqli_signal"],
        missing_prerequisites=[],
        target_present=True,
        already_tested=False,
        allow_active_without_review=False,
        blocker_ids=[],
        observed_signals=set(),
    )
    assert decision == "APPROVAL"
    assert any("approval" in r.lower() for r in reasons)


def test_low_impact_runners_always_run_regardless_of_flag() -> None:
    """LOW_IMPACT_AUTO_TOOLS (httpx, nmap, easm-discover, target-intel)
    always RUN regardless of the autonomous flag. They were never gated
    on approval — they're safe-by-design discovery runners."""
    # httpx is the canonical low-impact discovery runner — used as a
    # smoke check that the LOW_IMPACT_AUTO_TOOLS short-circuit works.
    # Other tools in that set have additional prerequisite gates that
    # vary by runner; covering them all here would couple the test to
    # those gates rather than to the autonomous_intrusive_allowed flag.
    decision, _ = ai_action_selector._decision_for_runner(
        runner="httpx",
        risk_tier="active",  # even if mislabeled as active
        required_approvals=0,
        confidence=0.9,
        matched_triggers=[],
        missing_prerequisites=[],
        target_present=True,
        already_tested=False,
        allow_active_without_review=False,
        blocker_ids=[],
        observed_signals=set(),
    )
    assert decision == "RUN", "httpx must always RUN regardless of flag"
