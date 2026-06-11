import json

import pytest

from scripts.training.generate_v4pro_demonstrated_chains_iter9 import DEFAULT_MODEL
from scripts.training.generate_v4pro_teacher_topup_iter10 import (
    DEFAULT_PREFIX,
    build_topup,
    deficits_from_counts,
    load_base_counts,
    make_scenario,
)


def write_base_manifest(path, counts):
    path.write_text(
        json.dumps({"stats": {"accepted_by_chain_class": counts}}, sort_keys=True),
        encoding="utf-8",
    )


def teacher_row_for_messages(messages):
    user = json.loads(messages[1]["content"])
    family = user["required_metadata"]["dataset_family"]
    lab_id = user["required_metadata"]["case_id"]
    marker = user["marker"]

    def assistant(done, next_action, reasoning, state, refs=None):
        return {
            "role": "assistant",
            "content": json.dumps(
                {
                    "done": done,
                    "evidence": {
                        "goal_satisfied": bool(done),
                        "marker": marker if done else "",
                        "refs": refs or [],
                    },
                    "next_action": next_action,
                    "reasoning": reasoning,
                    "safety": {
                        "dataset_family": family,
                        "lab_only": True,
                        "runtime_execution": False,
                    },
                    "state": {"lab": lab_id, **state},
                },
                sort_keys=True,
            ),
        }

    messages = [
        {"role": "system", "content": "fictional lab"},
        {"role": "user", "content": user["objective"]},
        assistant(
            False,
            {
                "args": {"method": "GET", "url": user["host"] + "/goal"},
                "purpose": "premature goal attempt",
                "tool": "lab_http_request",
            },
            "Attempt the goal first to observe the boundary.",
            {},
        ),
        {
            "role": "user",
            "content": "TOOL OBSERVATION: HTTP 403 blocked; hint says recover through a token resource",
        },
        assistant(
            False,
            {
                "args": {"method": "GET", "url": user["host"] + "/token-resource"},
                "purpose": "recover from blocked goal",
                "tool": "lab_http_request",
            },
            "Backtrack to the hinted token resource.",
            {"blocked_goal": True},
            ["obs-blocked"],
        ),
        {"role": "user", "content": "TOOL OBSERVATION: scoped recovery token observed"},
        assistant(
            False,
            {
                "args": {"body": "token=observed", "method": "POST", "url": user["host"] + "/proof"},
                "purpose": "exchange recovered token",
                "tool": "lab_http_request",
            },
            "Exchange the recovered token for a proof.",
            {"blocked_goal": True, "used_revealed_token": True},
            ["obs-blocked", "obs-token"],
        ),
        {"role": "user", "content": "TOOL OBSERVATION: proof token issued"},
        assistant(
            False,
            {
                "args": {"headers": {"X-Proof": "issued"}, "method": "GET", "url": user["host"] + "/goal"},
                "purpose": "retry blocked goal",
                "tool": "lab_http_request",
            },
            "Retry the blocked goal with the proof.",
            {"blocked_goal": True, "proof": "issued", "used_revealed_token": True},
            ["obs-proof"],
        ),
        {"role": "user", "content": "TOOL OBSERVATION: goal marker returned successfully"},
        assistant(
            True,
            {
                "args": {},
                "purpose": "goal complete",
                "tool": "none",
            },
            "Use the revealed token to retry the goal successfully.",
            {"proof": "issued", "used_revealed_token": True},
            ["obs-blocked", "obs-token", "obs-proof", "obs-final"],
        ),
    ]

    return {
        "messages": messages,
        "metadata": user["required_metadata"],
    }


def test_v4pro_topup_deficits_are_scoped_to_requested_classes():
    counts = {
        "auth_logic_session_forgery": 3,
        "nosql_filter_bypass_chain": 1,
        "ssti_template_context_pivot": 8,
    }

    deficits = deficits_from_counts(
        counts,
        target_min=8,
        only_classes=["auth_logic_session_forgery", "ssti_template_context_pivot"],
    )

    assert deficits == {"auth_logic_session_forgery": 5}


def test_v4pro_topup_noops_when_base_quota_is_satisfied(monkeypatch, tmp_path):
    counts = {
        "auth_logic_session_forgery": 8,
        "nosql_filter_bypass_chain": 8,
    }
    base = tmp_path / "base.json"
    write_base_manifest(base, counts)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")

    manifest = build_topup(
        base_manifest=base,
        out_dir=tmp_path / "out",
        only_classes=["auth_logic_session_forgery", "nosql_filter_bypass_chain"],
    )

    assert manifest["base_manifest"] == str(base)
    assert manifest["stats"]["accepted_count"] == 0
    assert manifest["stats"]["stopped_reason"] == "already_satisfied"


def test_v4pro_topup_generates_missing_rows_through_ingest(monkeypatch, tmp_path):
    base = tmp_path / "base.json"
    write_base_manifest(base, {"nosql_filter_bypass_chain": 7})

    def fake_call(**kwargs):
        return teacher_row_for_messages(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_topup(
        base_manifest=base,
        out_dir=tmp_path / "out",
        max_attempts=2,
        sleep_seconds=0,
        only_classes=["nosql_filter_bypass_chain"],
        target_min=8,
    )

    train_rows = [
        json.loads(line)
        for line in (tmp_path / "out" / f"{DEFAULT_PREFIX}_train.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert manifest["dataset"] == DEFAULT_PREFIX
    assert manifest["model"] == DEFAULT_MODEL
    assert manifest["stats"]["accepted_count"] == 1
    assert manifest["stats"]["accepted_by_chain_class"] == {"nosql_filter_bypass_chain": 1}
    assert manifest["stats"]["deficits_remaining"] == {}
    assert train_rows[0]["metadata"]["dataset_family"] == DEFAULT_PREFIX


def test_v4pro_topup_requires_known_chain_class():
    with pytest.raises(ValueError, match="unknown chain"):
        deficits_from_counts({}, target_min=8, only_classes=["not_a_class"])


def test_v4pro_topup_scenario_is_non_held_out():
    scenario = make_scenario("nosql_filter_bypass_chain", index=1, seed=123)

    assert "shop.lab" not in scenario.host
    assert "/notes/" not in scenario.objective
    assert scenario.chain_class == "nosql_filter_bypass_chain"
    assert scenario.scenario_hash


def test_v4pro_topup_loads_base_counts(tmp_path):
    base = tmp_path / "base.json"
    write_base_manifest(base, {"nosql_filter_bypass_chain": 2})

    counts = load_base_counts(base)

    assert counts["nosql_filter_bypass_chain"] == 2
    assert counts["auth_logic_session_forgery"] == 0
