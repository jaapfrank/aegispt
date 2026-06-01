"""Regression test: a deterministic flag-literal proof verifies as `confirmed`
(not `inconclusive`), so a solved flag finding renders "verified" in the
run-truth UI instead of "awaiting verification / blocked" (2026-06-01).

The deterministic short-circuit runs before strategy selection / HTTP, so the
finding can be a lightweight stand-in and `run`/`scope` are untouched.
"""
from __future__ import annotations

from types import SimpleNamespace

from api.app.services.finding_verifier import verify_finding
from api.app.services.m2_verdict_gate import is_deterministic_flag_proof


def _flag_finding():
    return SimpleNamespace(
        id="t",
        title="Flag captured (interactive-exploit): xbow-6ef5f9c8d8ecec7a1a810171925d26cd",
        summary="",
        severity="critical",
        evidence_ref="aegispt://artifact/interactive-exploit-stdout.txt",
        target_id="http://127.0.0.209",
        methodology_tags=["interactive_exploit"],
    )


def test_deterministic_flag_capture_verifies_confirmed():
    f = _flag_finding()
    assert is_deterministic_flag_proof(f) is True
    verdict = verify_finding(f, run=None, scope=None)  # short-circuits before run/http
    assert verdict.verdict == "confirmed"
    assert verdict.verifier_used == "deterministic_flag_proof"


def test_unprovenanced_flag_not_short_circuited():
    # A flag string without provenance (no evidence_ref) is NOT deterministic
    # proof, so it must not take the confirmed short-circuit.
    f = SimpleNamespace(
        id="t", title="aegispt{unprovenanced:deadbeef}", summary="",
        severity="critical", evidence_ref="", target_id="http://t",
        methodology_tags=["interactive_exploit"],
    )
    assert is_deterministic_flag_proof(f) is False
