"""Tests for the harvester's dedup + per-challenge balancing (data-quality pass).

The harvested specialist dataset was badly imbalanced (101/160 trajectories solving
the SAME challenge, ~40% exact action-sequence duplicates). These tests pin the two
fixes: identical action sequences collapse to one, and per-challenge counts are capped.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.training.harvest_winning_trajectories import (  # noqa: E402
    _action_signature,
    harvest,
)


def _win_transcript(flag: str, *, probe_url: str = "http://t/submit", probe_body: str = "name={{7*7}}"):
    """A 2-action winning transcript carrying ``flag`` in its final observation."""
    return [
        {"step": 1, "assistant_text": "Observe the home page.",
         "request": {"method": "GET", "url": "http://t/"},
         "response": '{"status":200,"body":"hi"}'},
        {"step": 2, "assistant_text": "Send a probe.",
         "request": {"method": "POST", "url": probe_url, "body": probe_body},
         "response": json.dumps({"status": 200, "body": f"49 ... {flag}"})},
    ]


def _write(d: Path, name: str, transcript) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}-interactive-exploit-transcript.json").write_text(json.dumps(transcript))


def test_action_signature_ignores_reasoning_and_body_wording():
    a = _win_transcript("flag{a}", probe_body="name={{7*7}}")
    b = _win_transcript("flag{a}", probe_body="name={{6*6}}")  # same urls/methods, different body
    from scripts.training.harvest_winning_trajectories import transcript_to_messages
    sig_a = _action_signature(transcript_to_messages(a, "flag{a}"))
    sig_b = _action_signature(transcript_to_messages(b, "flag{a}"))
    assert sig_a == sig_b
    assert sig_a == (("GET", "http://t/"), ("POST", "http://t/submit"))


def test_identical_action_trajectories_collapse_to_one(tmp_path):
    # Three transcripts with the IDENTICAL ordered (method,url) action sequence.
    # Even though their flags differ, the action signature is the same -> dedup to one.
    _write(tmp_path / "r1", "a", _win_transcript("flag{aaaaaa}"))
    _write(tmp_path / "r2", "b", _win_transcript("flag{bbbbbb}"))
    _write(tmp_path / "r3", "c", _win_transcript("flag{cccccc}"))

    examples, stats = harvest(tmp_path, dedup=True, max_per_challenge=8)

    assert stats["won"] == 3
    assert stats["after_dedup"] == 1
    assert stats["kept"] == 1
    assert len(examples) == 1


def test_no_dedup_keeps_duplicates(tmp_path):
    _write(tmp_path / "r1", "a", _win_transcript("flag{aaaaaa}"))
    _write(tmp_path / "r2", "b", _win_transcript("flag{bbbbbb}"))

    _, stats = harvest(tmp_path, dedup=False, max_per_challenge=8)

    assert stats["won"] == 2
    assert stats["after_dedup"] == 2  # dedup disabled -> nothing dropped


def test_per_challenge_cap_is_enforced(tmp_path):
    # Five DISTINCT action sequences (so dedup keeps all five) that all solve the SAME
    # challenge (identical flag) -> per-challenge cap of 2 keeps only 2.
    flag = "flag{samechal}"
    for i in range(5):
        _write(tmp_path / f"r{i}", f"t{i}",
               _win_transcript(flag, probe_url=f"http://t/submit{i}"))

    examples, stats = harvest(tmp_path, dedup=True, max_per_challenge=2)

    assert stats["won"] == 5
    assert stats["after_dedup"] == 5  # all distinct action sequences survive dedup
    assert stats["after_balance"] == 2  # per-challenge cap clamps to 2
    assert stats["kept"] == 2
    assert stats["distinct_challenges"] == 1
    assert len(examples) == 2
    assert all(ex["meta"]["flag_sha_prefix"] == flag[:6] for ex in examples)


def test_diverse_trajectories_survive(tmp_path):
    # Distinct action sequences AND distinct challenges -> all kept; counted distinctly.
    # Flags must differ within the first 6 chars (the flag_sha_prefix challenge key).
    _write(tmp_path / "r0", "a",
           _win_transcript("flag{1one}", probe_url="http://t/login"))
    _write(tmp_path / "r1", "b",
           _win_transcript("flag{2two}", probe_url="http://t/upload"))
    _write(tmp_path / "r2", "c",
           _win_transcript("flag{3thr}", probe_url="http://t/render"))

    examples, stats = harvest(tmp_path, dedup=True, max_per_challenge=8)

    assert stats["won"] == 3
    assert stats["after_dedup"] == 3
    assert stats["after_balance"] == 3
    assert stats["kept"] == 3
    assert stats["distinct_challenges"] == 3
    assert len(examples) == 3
