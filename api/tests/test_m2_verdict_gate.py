"""Regression tests for the M2 verdict gate — including the bounded
DETERMINISTIC_PROOF exemption (Track B, 2026-06-01).

The exemption fixes the bug where the HTTP-oriented pre-persistence re-prober
classified raw-TCP flag captures as FALSE_POSITIVE and dropped real solves. A
captured flag literal WITH provenance is grader-matchable proof and must persist;
this must stay bounded (non-flag hypotheses and unprovenanced flags still drop).
"""
from __future__ import annotations

from types import SimpleNamespace

from api.app.services.m2_verdict_gate import (
    VERDICT_BLOCKED_BY_SECURITY,
    VERDICT_DETERMINISTIC_PROOF,
    VERDICT_EXPLOITED,
    VERDICT_FALSE_POSITIVE,
    VERDICT_UNCLASSIFIED,
    classify,
    is_deterministic_flag_proof,
)


def _finding(*, title="Test Finding", severity="high", replay_steps=None,
             evidence_ref="", target_id="", methodology_tags=()):
    return SimpleNamespace(
        id="t", title=title, summary="", severity=severity,
        replay_recipe_json=({"steps": replay_steps} if replay_steps is not None else None),
        evidence_ref=evidence_ref, target_id=target_id,
        methodology_tags=list(methodology_tags),
    )


def _flag_finding():
    return _finding(
        title="Flag captured (interactive-exploit): aegispt{lan-printer-pjl-job-leak:5433cbc0}",
        evidence_ref="aegispt://artifact/interactive-exploit-stdout.txt",
        target_id="http://127.0.0.155:8088/__tcp__/127.0.0.156:9100",
        methodology_tags=("interactive_exploit",),
    )


def _verdict(v):
    return SimpleNamespace(verdict=v)


# --- the four base verdicts still hold -------------------------------------
def test_confirmed_is_exploited_kept():
    d = classify(finding=_finding(replay_steps=[{"u": "/x"}]), verifier_verdict=_verdict("confirmed"))
    assert d.verdict == VERDICT_EXPLOITED and not d.drop


def test_failed_with_replay_is_blocked_kept():
    d = classify(finding=_finding(replay_steps=[{"u": "/x"}]), verifier_verdict=_verdict("failed"))
    assert d.verdict == VERDICT_BLOCKED_BY_SECURITY and not d.drop


def test_failed_no_replay_no_flag_is_false_positive_dropped():
    d = classify(finding=_finding(replay_steps=None), verifier_verdict=_verdict("failed"))
    assert d.verdict == VERDICT_FALSE_POSITIVE and d.drop


def test_no_verifier_is_unclassified_kept():
    d = classify(finding=_finding(severity="medium"), verifier_verdict=None)
    assert d.verdict == VERDICT_UNCLASSIFIED and not d.drop


# --- the bounded DETERMINISTIC_PROOF exemption (Track B) --------------------
def test_flag_proof_kept_despite_verifier_failure():
    """A provenanced flag literal is grader-matchable proof — never a re-prober
    false positive (the bug that lost printer/nas/dns LAN solves)."""
    assert is_deterministic_flag_proof(_flag_finding()) is True
    d = classify(finding=_flag_finding(), verifier_verdict=_verdict("failed"))
    assert d.verdict == VERDICT_DETERMINISTIC_PROOF and not d.drop


def test_non_flag_hypothesis_still_drops():
    """Bounded: a non-flag hypothesis with failed verifier + no replay still drops."""
    f = _finding(title="Reflected XSS suspected", evidence_ref="aegispt://artifact/x",
                 target_id="http://t", methodology_tags=("interactive_exploit",))
    assert is_deterministic_flag_proof(f) is False
    d = classify(finding=f, verifier_verdict=_verdict("failed"))
    assert d.verdict == VERDICT_FALSE_POSITIVE and d.drop


def test_flag_without_provenance_not_exempted():
    """Bounded: a flag literal lacking provenance (no evidence_ref) is not exempted."""
    f = _finding(title="aegispt{unprovenanced:deadbeef}", evidence_ref="",
                 target_id="http://t", methodology_tags=("interactive_exploit",))
    assert is_deterministic_flag_proof(f) is False
    d = classify(finding=f, verifier_verdict=_verdict("failed"))
    assert d.verdict == VERDICT_FALSE_POSITIVE and d.drop
