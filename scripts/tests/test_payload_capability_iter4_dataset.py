import json

from scripts.training.make_payload_capability_iter4_dataset import (
    DEFAULT_PREFIX,
    VULN_CLASSES,
    build_dataset,
    generate_rows,
    validate_rows,
)


def test_payload_capability_iter4_covers_all_classes_and_is_lab_only():
    rows = generate_rows(60, split="test", seed=1337)

    stats = validate_rows(rows)

    assert set(stats["vulnerability_classes"]) == set(VULN_CLASSES)
    assert set(stats["domains"]) == {"api", "web"}
    assert len(stats["payload_families"]) == len(VULN_CLASSES)

    for row in rows:
        assert row["metadata"]["dataset_family"] == DEFAULT_PREFIX
        assert row["messages"][0]["role"] == "system"
        parsed = json.loads(row["messages"][-1]["content"])
        assert parsed["safety"]["lab_only"] is True
        assert parsed["safety"]["runtime_execution"] is False
        assert parsed["payload"]["family"] == row["metadata"]["payload_family"]
        assert parsed["preconditions"]
        assert parsed["expected_evidence"]["evidence_ref"]
        assert parsed["cleanup"]
        assert parsed["finding"]["evidence_ref"]
        assert "target_not_in_scope" in parsed["safety"]["blocked_if"]


def test_payload_capability_iter4_builds_separate_dataset_family(tmp_path):
    manifest = build_dataset(
        tmp_path,
        DEFAULT_PREFIX,
        {"train": 30, "eval": 15, "test": 15},
        seed=2026,
    )

    assert manifest["dataset"] == DEFAULT_PREFIX
    assert "aegispt_full_coverage_dora_loraplus_unsloth" in manifest["does_not_modify"]
    assert "aegispt_open_corpus_iter3" in manifest["does_not_modify"]
    assert manifest["policy"]["raw_external_poc_dump"] is False
    assert manifest["policy"]["runtime_execution"] is False

    for split, expected_count in {"train": 30, "eval": 15, "test": 15}.items():
        path = tmp_path / f"{DEFAULT_PREFIX}_{split}.jsonl"
        assert path.exists()
        assert sum(1 for _ in path.open(encoding="utf-8")) == expected_count
