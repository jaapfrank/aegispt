"""Regression for the Phase-3 jury pieces: reviewers (mocked HTTP), calibration
ledger, and the expert-iteration rollout ranker. Pure-logic / mocked -- no cloud,
no GPU."""
import json
import os
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "training"))

import jury_calibration as C  # noqa: E402
import jury_reviewers as JR  # noqa: E402
import jury_rollout as RO  # noqa: E402


# ---- calibration ledger ----------------------------------------------------
def test_calibration_reliable_outweighs_unreliable():
    led = C.CalibrationLedger()
    for _ in range(10):
        led.record("A", "good", "good")            # A: 10/10 vs evidence
    for i in range(10):
        led.record("B", "good" if i < 2 else "bad", "good")  # B: 2/10
    assert led.weight("A") > led.weight("B")
    agg = C.weighted_aggregate(
        [("A", {"verdict": "good", "confidence": 0.7}),
         ("B", {"verdict": "bad", "confidence": 0.7, "first_wrong_step": 3})], led)
    assert agg["verdict"] == "good"  # the reliable reviewer wins when evidence is silent


def test_calibration_persistence(tmp_path):
    p = str(tmp_path / "cal.json")
    led = C.CalibrationLedger(path=p)
    led.record("A", "good", "good")
    led.save()
    assert C.CalibrationLedger(path=p).weight("A") == led.weight("A")


# ---- rollout ranker --------------------------------------------------------
def test_rollout_ranks_by_env_reward(tmp_path):
    rolls = {"0": {"flag": False, "idor": True, "logged_in": True, "steps": 5},
             "1": {"flag": False, "idor": False, "logged_in": True, "steps": 4},
             "2": {"flag": False, "idor": False, "logged_in": False, "steps": 1}}
    for i, res in rolls.items():
        (tmp_path / f"res_{i}.json").write_text(json.dumps(res))
        (tmp_path / f"roll_{i}.jsonl").write_text(json.dumps({"action": f"a{i}", "tool_result": "o"}) + "\n")
    m = RO.run(str(tmp_path), out=str(tmp_path / "best.jsonl"), top_frac=0.4, min_reward=3)
    assert m["best_reward"] == 10 and m["any_idor"] is True and m["kept"] >= 1


# ---- reviewer (mocked HTTP) ------------------------------------------------
def _mock_response(content="", reasoning=""):
    msg = {}
    if content:
        msg["content"] = content
    if reasoning:
        msg["reasoning_content"] = reasoning
    payload = json.dumps({"choices": [{"message": msg}]}).encode()
    cm = mock.MagicMock()
    cm.__enter__.return_value.read.return_value = payload
    return cm


def test_reviewer_parses_content():
    rev = JR.make_reviewer(endpoint="http://x/v1/chat/completions", model="m")
    verdict = '{"verdict":"bad","confidence":0.8,"first_wrong_step":4,"safety_ok":true}'
    with mock.patch("urllib.request.urlopen", return_value=_mock_response(content=verdict)):
        v = rev([{"action": "x"}])
    assert v["verdict"] == "bad" and v["first_wrong_step"] == 4


def test_reviewer_reasoning_content_fallback():
    rev = JR.make_reviewer(endpoint="http://x/v1/chat/completions", model="m")
    verdict = 'thinking... {"verdict":"good","confidence":0.6}'
    # content empty, answer only in reasoning_content (reasoner model)
    with mock.patch("urllib.request.urlopen", return_value=_mock_response(reasoning=verdict)):
        v = rev([{"action": "x"}])
    assert v["verdict"] == "good" and v["safety_ok"] is True
