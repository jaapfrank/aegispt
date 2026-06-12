"""Tests for the winning-trajectory harvester (pad B / specialist data pipeline)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.training.harvest_winning_trajectories import (  # noqa: E402
    harvest,
    transcript_to_messages,
)

_WIN = [
    {"step": 1, "assistant_text": "Observe the home page.",
     "request": {"method": "GET", "url": "http://t/"}, "response": '{"status":200,"body":"hi"}'},
    {"step": 2, "assistant_text": "Send an SSTI probe.",
     "request": {"method": "POST", "url": "http://t/submit", "body": "name={{7*7}}"},
     "response": '{"status":200,"body":"49 ... flag{ssti-win}"}'},
]
_NO_FLAG = [
    {"step": 1, "assistant_text": "Probe.",
     "request": {"method": "GET", "url": "http://t/"}, "response": '{"status":200,"body":"nothing"}'},
]


def test_transcript_to_messages_shape():
    msgs = transcript_to_messages(_WIN)
    assert msgs[0]["role"] == "system"
    assert msgs[1]["role"] == "user"
    # first action turn: assistant reasoning + an http_request tool call, then a tool result
    assistant = next(m for m in msgs if m["role"] == "assistant" and m.get("tool_calls"))
    assert assistant["tool_calls"][0]["function"]["name"] == "http_request"
    assert any(m["role"] == "tool" for m in msgs)
    # tool_call_id pairs up
    call_id = assistant["tool_calls"][0]["id"]
    assert any(m.get("tool_call_id") == call_id for m in msgs if m["role"] == "tool")


def test_harvest_keeps_only_flag_proven_wins(tmp_path):
    # one winning transcript, one with no flag -> only the win is kept (quality gate)
    d = tmp_path / "runs" / "r1" / "exec"
    d.mkdir(parents=True)
    (d / "a-interactive-exploit-transcript.json").write_text(json.dumps(_WIN))
    (d / "b-interactive-exploit-transcript.json").write_text(json.dumps(_NO_FLAG))

    examples, stats = harvest(tmp_path)

    assert stats["transcripts_found"] == 2
    assert stats["won"] == 1
    assert stats["no_flag"] == 1
    assert stats["kept"] == 1
    assert len(examples) == 1
    assert examples[0]["meta"]["flag_sha_prefix"] == "flag{s"


def test_harvest_empty_dir(tmp_path):
    examples, stats = harvest(tmp_path)
    assert examples == []
    assert stats["kept"] == 0
