"""Tests for the teacher-knowledge trajectory generator (pad B)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.training.generate_teacher_trajectories import _TEMPLATES, generate  # noqa: E402


def test_every_template_emits_a_well_formed_winning_trajectory():
    rows = generate(per_template=1)
    assert len(rows) == len(_TEMPLATES)
    seen_classes = set()
    for r in rows:
        ms = r["messages"]
        assert ms[0]["role"] == "system"
        # ends with a done=True assistant turn (inline JSON, the trainer format)
        last = json.loads(ms[-1]["content"])
        assert last["done"] is True
        blob = json.dumps(ms)
        assert "HTTP RESPONSE" in blob          # at least one real observation turn
        assert "flag{" in blob                  # the win is grounded in a captured flag
        # action turns parse as the {"reasoning","request","done"} contract
        actions = [json.loads(m["content"]) for m in ms if m["role"] == "assistant"]
        assert all("reasoning" in a for a in actions)
        assert any(a.get("request") for a in actions)  # at least one real request
        seen_classes.add(r["meta"]["vuln_class"])
    # every vuln class is represented
    assert len(seen_classes) == len(_TEMPLATES)


def test_per_template_count_and_determinism():
    a = generate(per_template=3, seed=7)
    b = generate(per_template=3, seed=7)
    assert len(a) == 3 * len(_TEMPLATES)
    # deterministic for a fixed seed (reproducible datasets)
    assert [r["meta"]["vuln_class"] for r in a] == [r["meta"]["vuln_class"] for r in b]


def test_covers_the_multistep_chain_frontier():
    # the register->login->admin chain (the documented frontier) must be present and deep
    rows = generate(per_template=1)
    chain = next(r for r in rows if r["meta"]["vuln_class"] == "register_login_admin")
    requests = [json.loads(m["content"]).get("request") for m in chain["messages"] if m["role"] == "assistant"]
    requests = [q for q in requests if q]
    urls = " ".join(q["url"] for q in requests)
    assert "/register" in urls and "/login" in urls and "/admin" in urls
    assert len(requests) >= 4  # genuinely multi-step
