import json

import pytest

from scripts.training.generate_v4pro_demonstrated_chains_iter9 import (
    DEFAULT_MODEL,
    DEFAULT_PREFIX,
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
            "args": {"method": "GET", "url": user["host"] + "/start"},
            "purpose": "start bounded fictional lab chain",
            "tool": "lab_http_request",
        },
        "reasoning": "Start from the fictional lab entrypoint.",
        "safety": {"dataset_family": family, "lab_only": True, "runtime_execution": False},
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
        "safety": {"dataset_family": family, "lab_only": True, "runtime_execution": False},
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
    assert "shop.lab" in payload["forbidden_strings"]
    assert "/admin/config" in payload["forbidden_strings"]


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


def test_v4pro_teacher_generator_requires_key(monkeypatch, tmp_path):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        build_dataset(count=1, out_dir=tmp_path, secret_file=tmp_path / "missing")
