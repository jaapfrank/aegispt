import json

import pytest

from scripts.training.generate_v4pro_web_source_gap_topup_iter10 import (
    DEFAULT_PREFIX,
    WEB_SOURCE_GAP_CHAIN_CLASSES,
    build_topup,
    make_scenario,
    parse_classes,
    teacher_messages,
)
from scripts.training.web_source_gap_recovery_envs_iter10 import scenario_specs


def teacher_row_for_messages(messages):
    user = json.loads(messages[1]["content"])
    metadata = user["required_metadata"]
    contract = user["allowed_route_contract"]
    marker = user["marker"]
    host = user["host"]

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
                        "dataset_family": metadata["dataset_family"],
                        "lab_only": True,
                        "payload_free": True,
                        "runtime_execution": False,
                    },
                    "state": {"lab": metadata["case_id"], **state},
                },
                sort_keys=True,
            ),
        }

    return {
        "messages": [
            {"role": "system", "content": "fictional lab"},
            {"role": "user", "content": user["objective"]},
            assistant(
                False,
                {
                    "args": {"headers": {}, "method": "GET", "url": host + contract["blocked_goal_path"]},
                    "purpose": "premature goal attempt",
                    "tool": "lab_http_request",
                },
                "Attempt the goal first to observe the boundary.",
                {},
            ),
            {
                "role": "user",
                "content": "TOOL OBSERVATION: HTTP 403 blocked; recover through hinted evidence resource",
            },
            assistant(
                False,
                {
                    "args": {"headers": {}, "method": "GET", "url": host + contract["evidence_path"]},
                    "purpose": "recover from blocked goal",
                    "tool": "lab_http_request",
                },
                "Backtrack to the hinted recovery resource.",
                {"blocked_goal": True, "recovery": True},
                ["obs-blocked"],
            ),
            {
                "role": "user",
                "content": f"TOOL OBSERVATION: recovery token observed: {contract['recovery_token']}",
            },
            assistant(
                False,
                {
                    "args": {
                        "body": json.dumps({"evidence_token": contract["recovery_token"]}, sort_keys=True),
                        "headers": {},
                        "method": "POST",
                        "url": host + contract["recovery_path"],
                    },
                    "purpose": "bounded recovery proof",
                    "tool": "lab_http_request",
                },
                "Use the revealed token to request the bounded proof.",
                {"used_revealed_token": True},
                ["obs-token"],
            ),
            {"role": "user", "content": f"TOOL OBSERVATION: proof ready {contract['proof_value']}"},
            assistant(
                True,
                {"args": {}, "purpose": "goal complete", "tool": "none"},
                "Retry succeeds using the revealed recovery proof.",
                {"done": True, "used_revealed_value": True},
                ["obs-final"],
            ),
        ],
        "metadata": metadata,
    }


def teacher_row_without_recovery_arc(messages):
    row = teacher_row_for_messages(messages)
    row["messages"] = [message for message in row["messages"] if "403 blocked" not in message.get("content", "")]
    return row


def teacher_row_with_unsafe_body(messages):
    row = teacher_row_for_messages(messages)
    payload = json.loads(row["messages"][2]["content"])
    payload["next_action"]["args"]["body"] = json.dumps({"query": "select marker from private"}, sort_keys=True)
    row["messages"][2]["content"] = json.dumps(payload, sort_keys=True)
    return row


def test_web_source_gap_prompt_contains_e2_contract():
    spec = make_scenario(scenario_specs()[0], index=0, seed=123)
    messages = teacher_messages(spec)
    payload = json.loads(messages[1]["content"])

    assert payload["required_metadata"]["chain_class"] == spec.chain_class
    assert payload["required_metadata"]["scenario_hash"] == spec.scenario_hash
    assert payload["allowed_route_contract"]["recovery_token"] == spec.recovery_token
    assert payload["allowed_route_contract"]["recovery_header"] == spec.recovery_header
    assert payload["blocked_goal_recovery_required"]["must_use_revealed_value_after_block"] is True
    assert "shop.lab" in payload["forbidden_strings"]
    assert "/admin/config" in payload["forbidden_strings"]


def test_web_source_gap_v4pro_topup_generates_each_requested_class(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_for_messages(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_topup(
        out_dir=tmp_path,
        max_attempts=len(WEB_SOURCE_GAP_CHAIN_CLASSES),
        sleep_seconds=0,
        target_min_per_class=1,
    )

    train_rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_train.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    registry_rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_scenario_registry.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert manifest["dataset"] == DEFAULT_PREFIX
    assert manifest["stats"]["accepted_count"] == len(WEB_SOURCE_GAP_CHAIN_CLASSES)
    assert manifest["quality_report"]["deficits_remaining"] == {}
    assert {row["metadata"]["chain_class"] for row in train_rows} == set(WEB_SOURCE_GAP_CHAIN_CLASSES)
    assert len(registry_rows) == len(train_rows)
    assert all(row["metadata"]["dataset_family"] == DEFAULT_PREFIX for row in train_rows)


def test_web_source_gap_v4pro_topup_can_scope_classes(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_for_messages(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_topup(
        out_dir=tmp_path,
        max_attempts=1,
        only_classes=["sqli_filter_bypass"],
        sleep_seconds=0,
        target_min_per_class=1,
    )

    assert manifest["stats"]["accepted_by_chain_class"]["sqli_filter_bypass"] == 1
    assert manifest["stats"]["target_chain_classes"] == ["sqli_filter_bypass"]


def test_web_source_gap_v4pro_topup_rejects_missing_recovery_arc(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_without_recovery_arc(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_topup(
        out_dir=tmp_path,
        max_attempts=1,
        only_classes=["sqli_filter_bypass"],
        sleep_seconds=0,
        target_min_per_class=1,
    )

    assert manifest["stats"]["accepted_count"] == 0
    assert manifest["quality_report"]["rejected_by_reason"] == {"missing_blocked_goal_recovery_arc": 1}
    assert manifest["stats"]["stopped_reason"] == "attempt_limit"


def test_web_source_gap_v4pro_topup_rejects_payload_like_bodies(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_with_unsafe_body(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_topup(
        out_dir=tmp_path,
        max_attempts=1,
        only_classes=["sqli_filter_bypass"],
        sleep_seconds=0,
        target_min_per_class=1,
    )

    assert manifest["stats"]["accepted_count"] == 0
    assert manifest["quality_report"]["rejected_by_reason"] == {"unsafe_body_payload": 1}


def test_web_source_gap_v4pro_topup_requires_known_classes():
    assert parse_classes(["sqli_filter_bypass,file_upload_webroot"]) == [
        "sqli_filter_bypass",
        "file_upload_webroot",
    ]
    with pytest.raises(ValueError, match="unknown web source-gap"):
        parse_classes(["not_a_real_class"])


def test_web_source_gap_v4pro_topup_requires_key(monkeypatch, tmp_path):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        build_topup(out_dir=tmp_path, secret_file=tmp_path / "missing")
