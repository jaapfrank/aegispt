import json

import pytest

from scripts.training.ingest_v4pro_demonstrated_chains_iter8 import (
    DEFAULT_PREFIX,
    build_dataset,
    ingest_rows,
)
from scripts.training.make_lab_truth_heldout_registry_iter6 import build_registry
from scripts.training.make_multiservice_chaintype_diversity_iter8 import generate_rows


def test_v4pro_demonstrated_ingest_normalizes_safe_non_held_out_rows(tmp_path):
    candidate = generate_rows(1, split="train")[0]
    candidate["metadata"]["dataset_family"] = "external_v4pro_export"
    candidate["metadata"]["case_id"] = "teacher-safe-non-held-out"
    registry = build_registry(
        llmsvs_count=18,
        multiturn_counts={"eval": 1, "test": 1},
        chaintype_counts={"eval": 1, "test": 1},
        multiservice_counts={"eval": 1, "test": 1},
    )

    result = ingest_rows([candidate], registry=registry)

    assert result["stats"]["accepted_count"] == 1
    assert result["stats"]["rejected_count"] == 0
    row = result["accepted"][0]
    assert row["metadata"]["dataset_family"] == DEFAULT_PREFIX
    assert row["metadata"]["source_dataset_family"] == "external_v4pro_export"
    assert row["metadata"]["original_case_id"] == "teacher-safe-non-held-out"
    assert row["metadata"]["split"] == "train"
    assert "teacher_demonstrated" in row["metadata"]["safety_tags"]

    for message in row["messages"]:
        if message["role"] != "assistant":
            continue
        parsed = json.loads(message["content"])
        assert parsed["safety"]["dataset_family"] == DEFAULT_PREFIX
        assert parsed["safety"]["runtime_execution"] is False


def test_v4pro_demonstrated_ingest_rejects_held_out_rows():
    held_out_candidate = generate_rows(1, split="eval")[0]
    registry = build_registry(
        llmsvs_count=18,
        multiturn_counts={"eval": 1, "test": 1},
        chaintype_counts={"eval": 1, "test": 1},
        multiservice_counts={"eval": 1, "test": 1},
    )

    result = ingest_rows([held_out_candidate], registry=registry, fail_on_rejected=False)

    assert result["stats"]["accepted_count"] == 0
    assert result["stats"]["rejected_count"] == 1
    assert result["rejected"][0]["reason"].startswith("held_out_scenario:")


def test_v4pro_demonstrated_ingest_fails_closed_on_rejected_rows():
    held_out_candidate = generate_rows(1, split="eval")[0]
    registry = build_registry(
        llmsvs_count=18,
        multiturn_counts={"eval": 1, "test": 1},
        chaintype_counts={"eval": 1, "test": 1},
        multiservice_counts={"eval": 1, "test": 1},
    )

    with pytest.raises(ValueError, match="rejected 1 demonstrated rows"):
        ingest_rows([held_out_candidate], registry=registry)


def test_v4pro_demonstrated_ingest_writes_train_only_dataset(tmp_path):
    candidate = generate_rows(1, split="train")[0]
    input_path = tmp_path / "teacher.jsonl"
    input_path.write_text(json.dumps(candidate, sort_keys=True) + "\n", encoding="utf-8")

    manifest = build_dataset(
        input_paths=[input_path],
        out_dir=tmp_path,
        allow_rejected=False,
        teacher_model="v4-pro-test",
    )

    assert manifest["policy"]["train_only"] is True
    assert manifest["policy"]["held_out_guard"] is True
    assert manifest["stats"]["accepted_count"] == 1
    assert manifest["teacher_model"] == "v4-pro-test"
    rows = [
        json.loads(line)
        for line in (tmp_path / f"{DEFAULT_PREFIX}_train.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 1
    assert rows[0]["metadata"]["teacher_model"] == "v4-pro-test"
