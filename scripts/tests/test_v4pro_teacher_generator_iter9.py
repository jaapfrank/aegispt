import json

import pytest

from scripts.training.generate_v4pro_demonstrated_chains_iter9 import (
    DEFAULT_MODEL,
    DEFAULT_PREFIX,
    TEACHER_CHAIN_CLASSES,
    build_dataset,
    read_secret_key,
    scenario_plan,
    teacher_messages,
)


def teacher_row_for_prompt(messages):
    user = json.loads(messages[1]["content"])
    lab_id = user["required_metadata"]["case_id"]
    marker = user["marker"]
    family = user["required_metadata"]["dataset_family"]
    assistant_1 = {
        "done": False,
        "evidence": {"goal_satisfied": False, "refs": []},
        "next_action": {
            "args": {"method": "GET", "url": user["host"] + "/admin/marker"},
            "purpose": "premature bounded goal attempt",
            "tool": "lab_http_request",
        },
        "reasoning": "Attempt the goal endpoint, then use any bounded hint if blocked.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"lab": lab_id},
    }
    assistant_2 = {
        "done": False,
        "evidence": {"goal_satisfied": False, "refs": ["obs-403"]},
        "next_action": {
            "args": {"method": "GET", "url": user["host"] + "/hinted-resource"},
            "purpose": "recover from blocked goal by exploring the hinted resource",
            "tool": "lab_http_request",
        },
        "reasoning": "The 403 named a safe intermediate resource, so backtrack there.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"blocked_goal": True, "lab": lab_id},
    }
    assistant_3 = {
        "done": False,
        "evidence": {"goal_satisfied": False, "refs": ["obs-403", "obs-pivot"]},
        "next_action": {
            "args": {
                "body": "{\"token\":\"bounded-recovery-token\"}",
                "method": "POST",
                "url": user["host"] + "/admin/marker/retry",
            },
            "purpose": "retry the blocked goal with the revealed bounded token",
            "tool": "lab_http_request",
        },
        "reasoning": "The hinted resource revealed a bounded token; retry the goal with that observed value.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"lab": lab_id, "retrying_goal": True, "used_revealed_token": True},
    }
    assistant_4 = {
        "done": False,
        "evidence": {"goal_satisfied": False, "marker_preview": marker, "refs": ["obs-final"]},
        "next_action": {
            "args": {"method": "GET", "url": user["host"] + "/admin/marker/proof"},
            "purpose": "read the final proof marker after successful retry",
            "tool": "lab_http_request",
        },
        "reasoning": "The retry succeeded and exposed a marker preview; read the final proof evidence.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"lab": lab_id, "successful_retry": True},
    }
    assistant_5 = {
        "done": True,
        "evidence": {"goal_satisfied": True, "marker": marker, "refs": ["obs-403", "obs-pivot", "obs-final"]},
        "next_action": {
            "args": {},
            "purpose": "goal complete",
            "tool": "none",
        },
        "reasoning": "The revealed token was used to retry the goal and evidence the marker.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"marker": marker, "used_revealed_token": True},
    }
    return {
        "messages": [
            {"role": "system", "content": "synthetic lab"},
            {"role": "user", "content": user["objective"]},
            {"role": "assistant", "content": json.dumps(assistant_1, sort_keys=True)},
            {"role": "user", "content": "TOOL OBSERVATION: HTTP 403 blocked; hint: explore /hinted-resource for a scoped token"},
            {"role": "assistant", "content": json.dumps(assistant_2, sort_keys=True)},
            {"role": "user", "content": "TOOL OBSERVATION: pivot token observed for bounded retry"},
            {"role": "assistant", "content": json.dumps(assistant_3, sort_keys=True)},
            {"role": "user", "content": f"TOOL OBSERVATION: retry successful; marker preview {marker}"},
            {"role": "assistant", "content": json.dumps(assistant_4, sort_keys=True)},
            {"role": "user", "content": f"TOOL OBSERVATION: final proof marker {marker}"},
            {"role": "assistant", "content": json.dumps(assistant_5, sort_keys=True)},
        ],
        "metadata": user["required_metadata"],
    }


def teacher_row_without_recovery_arc(messages):
    user = json.loads(messages[1]["content"])
    lab_id = user["required_metadata"]["case_id"]
    marker = user["marker"]
    family = user["required_metadata"]["dataset_family"]
    assistant_1 = {
        "done": False,
        "evidence": {"goal_satisfied": False, "refs": []},
        "next_action": {
            "args": {"method": "GET", "url": user["host"] + "/start"},
            "purpose": "start bounded fictional lab chain",
            "tool": "lab_http_request",
        },
        "reasoning": "Start from the fictional lab entrypoint.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"lab": lab_id},
    }
    assistant_2 = {
        "done": True,
        "evidence": {"goal_satisfied": True, "refs": ["obs-1", "obs-2"]},
        "next_action": {
            "args": {},
            "purpose": "goal complete",
            "tool": "none",
        },
        "reasoning": "The fictional marker is evidenced.",
        "safety": {
            "dataset_family": family,
            "lab_only": True,
            "runtime_execution": False,
        },
        "state": {"marker": marker},
    }
    return {
        "messages": [
            {"role": "system", "content": "synthetic lab"},
            {"role": "user", "content": user["objective"]},
            {"role": "assistant", "content": json.dumps(assistant_1, sort_keys=True)},
            {"role": "user", "content": "TOOL OBSERVATION: fictional pivot observed"},
            {"role": "assistant", "content": json.dumps(assistant_2, sort_keys=True)},
        ],
        "metadata": user["required_metadata"],
    }


def test_teacher_prompt_contains_non_held_out_constraints():
    spec = scenario_plan(1)[0]
    messages = teacher_messages(spec)

    payload = json.loads(messages[1]["content"])
    assert payload["required_metadata"]["case_id"] == spec.lab_id
    assert payload["required_metadata"]["scenario_hash"] == spec.scenario_hash
    assert payload["blocked_goal_recovery_required"]["must_use_revealed_value_after_block"] is True
    assert "shop.lab" in payload["forbidden_strings"]
    assert "/admin/config" in payload["forbidden_strings"]


def test_scenario_plan_rotates_all_d1_chain_classes():
    scenarios = scenario_plan(len(TEACHER_CHAIN_CLASSES) * 2)
    classes = [scenario.chain_class for scenario in scenarios]

    expected = [item.chain_class for item in TEACHER_CHAIN_CLASSES]
    assert classes[: len(expected)] == expected
    assert classes[len(expected) :] == expected


def test_secret_reader_supports_export_format(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    secret = tmp_path / "secrets"
    secret.write_text("export DEEPSEEK_API_KEY='secret-value'\n", encoding="utf-8")

    assert read_secret_key(secret) == "secret-value"


def test_v4pro_teacher_generator_uses_ingest_guard(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_for_prompt(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_dataset(count=3, out_dir=tmp_path, max_attempts=3)

    assert manifest["dataset"] == DEFAULT_PREFIX
    assert manifest["model"] == DEFAULT_MODEL
    assert manifest["stats"]["accepted_count"] == 3
    assert manifest["stats"]["stopped_reason"] == "completed"
    assert manifest["policy"]["blocked_goal_recovery_required"] is True
    assert manifest["policy"]["completion_recovery_required"] is True
    assert manifest["policy"]["minimum_assistant_turns"] == 5
    assert manifest["policy"]["secret_committed"] is False
    train_rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_train.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    registry_rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_scenario_registry.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(train_rows) == 3
    assert len(registry_rows) == 3
    assert all(row["metadata"]["dataset_family"] == DEFAULT_PREFIX for row in train_rows)


def test_v4pro_teacher_generator_enforces_per_class_quota(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_for_prompt(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_dataset(
        count=len(TEACHER_CHAIN_CLASSES),
        out_dir=tmp_path,
        max_attempts=len(TEACHER_CHAIN_CLASSES),
        min_per_chain_class=1,
    )

    expected_classes = [item.chain_class for item in TEACHER_CHAIN_CLASSES]
    assert manifest["stats"]["accepted_count"] == len(expected_classes)
    assert manifest["stats"]["min_per_chain_class"] == 1
    assert manifest["stats"]["stopped_reason"] == "completed"
    assert manifest["quality_report"]["assistant_turn_distribution"] == {"5": len(expected_classes)}
    assert set(manifest["quality_report"]["accepted_by_chain_class"]) == set(expected_classes)
    assert all(
        manifest["quality_report"]["accepted_by_chain_class"][chain_class] == 1
        for chain_class in expected_classes
    )
    assert all(manifest["quality_report"]["class_quota_satisfied"].values())


def test_v4pro_teacher_generator_rejects_missing_blocked_recovery_arc(monkeypatch, tmp_path):
    def fake_call(**kwargs):
        return teacher_row_without_recovery_arc(kwargs["messages"])

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(
        "scripts.training.generate_v4pro_demonstrated_chains_iter9.call_deepseek",
        fake_call,
    )

    manifest = build_dataset(count=1, out_dir=tmp_path, max_attempts=1)

    rejected_rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_rejected.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    raw_rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_raw_teacher.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert manifest["stats"]["accepted_count"] == 0
    assert manifest["stats"]["rejected_count"] == 1
    assert manifest["stats"]["rejected_by_reason"] == {"missing_blocked_goal_recovery_arc": 1}
    assert manifest["stats"]["stopped_reason"] == "attempt_limit"
    assert "missing_blocked_goal_recovery_arc" in rejected_rows[0]["detail"]
    assert len(raw_rows) == 1


def test_v4pro_teacher_generator_requires_key(monkeypatch, tmp_path):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        build_dataset(count=1, out_dir=tmp_path, secret_file=tmp_path / "missing")
