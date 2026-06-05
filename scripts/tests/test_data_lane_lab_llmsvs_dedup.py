import json

from scripts.training.make_live_lab_target_specs_iter5 import (
    ALL_CLASSES,
    generate_specs,
    validate_specs,
)
from scripts.training.make_live_lab_target_specs_iter5 import (
    DEFAULT_PREFIX as LIVE_LAB_PREFIX,
)
from scripts.training.make_live_lab_target_specs_iter5 import (
    build_dataset as build_live_lab_dataset,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    ATTACK_CATEGORIES,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    DEFAULT_PREFIX as LLMSVS_PREFIX,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    build_dataset as build_llmsvs_dataset,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    generate_rows as generate_llmsvs_rows,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    validate_rows as validate_llmsvs_rows,
)
from scripts.training.make_near_duplicate_flags_iter5 import (
    DEFAULT_PREFIX as DEDUP_PREFIX,
)
from scripts.training.make_near_duplicate_flags_iter5 import (
    build_dataset as build_dedup_dataset,
)
from scripts.training.make_near_duplicate_flags_iter5 import (
    find_duplicate_flags,
    load_records,
)


def test_live_lab_specs_cover_every_payload_class_without_runtime_binding(tmp_path):
    specs = generate_specs(variants=1)
    stats = validate_specs(specs)

    assert set(stats["classes"]) == set(ALL_CLASSES)
    assert stats["target_count"] == len(ALL_CLASSES)
    assert set(stats["source_families"]) == {
        "aegispt_payload_capability_iter4",
        "aegispt_payload_domain_extension_iter4",
    }

    for spec in specs:
        assert spec["data_lane_only"] is True
        assert spec["runner_contract"]["runtime_binding"] is False
        assert spec["runner_contract"]["manual_approval_required"] is True
        assert spec["expected_evidence"]["must_capture"]
        assert spec["cleanup"]["required"] is True
        assert spec["scope"]["allowed_hosts"][0].endswith(".aegispt-lab.internal")

    manifest = build_live_lab_dataset(tmp_path, LIVE_LAB_PREFIX, variants=1)
    assert manifest["policy"]["runtime_execution"] is False
    assert (tmp_path / f"{LIVE_LAB_PREFIX}.jsonl").exists()


def test_llmsvs_adversarial_eval_covers_owasp_categories_without_tool_calls(tmp_path):
    rows = generate_llmsvs_rows(45, seed=2026)
    stats = validate_llmsvs_rows(rows)

    assert set(stats["attack_categories"]) == set(ATTACK_CATEGORIES)
    assert {"V5.11", "V5.12", "V6.4", "V6.11"}.issubset(stats["llmsvs_controls"])

    for row in rows:
        metadata = row["metadata"]
        expected = row["expected_behavior"]
        assert metadata["dataset_family"] == LLMSVS_PREFIX
        assert metadata["eval_only"] is True
        assert metadata["runtime_execution"] is False
        assert expected["tool_policy"]["should_call_tools"] is False
        assert expected["must"]
        assert expected["must_not"]
        assert row["messages"][0]["role"] == "system"

    manifest = build_llmsvs_dataset(tmp_path, LLMSVS_PREFIX, count=45, seed=2026)
    assert manifest["policy"]["eval_only"] is True
    assert manifest["policy"]["tool_calls_expected"] is False


def write_jsonl(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_near_duplicate_flags_are_review_only_and_detect_exact_plus_near(tmp_path):
    train_rows = [
        {
            "messages": [
                {"role": "system", "content": "AegisPT lab mode."},
                {
                    "role": "user",
                    "content": "Lab target https://lab-111.example marker AEGISPT_PROOF_1111 run a safe baseline check. Store request hash.",
                },
            ],
            "metadata": {
                "case_id": "demo-train-1",
                "dataset_family": "aegispt_demo_family",
                "split": "train",
            },
        },
        {
            "messages": [
                {"role": "system", "content": "AegisPT lab mode."},
                {
                    "role": "user",
                    "content": "Lab target https://lab-222.example marker AEGISPT_PROOF_2222 run a safe baseline check. Store request hash.",
                },
            ],
            "metadata": {
                "case_id": "demo-train-2",
                "dataset_family": "aegispt_demo_family",
                "split": "train",
            },
        },
    ]
    eval_rows = [
        {
            "messages": [
                {"role": "system", "content": "AegisPT lab mode."},
                {
                    "role": "user",
                    "content": "Lab target https://lab-333.example marker AEGISPT_PROOF_3333 run safe baseline check and store response hash.",
                },
            ],
            "metadata": {
                "case_id": "demo-eval-1",
                "dataset_family": "aegispt_demo_family",
                "split": "eval",
            },
        }
    ]
    write_jsonl(tmp_path / "aegispt_demo_family_train.jsonl", train_rows)
    write_jsonl(tmp_path / "aegispt_demo_family_eval.jsonl", eval_rows)

    records = load_records(sorted(tmp_path.glob("aegispt_demo_family_*.jsonl")))
    flags = find_duplicate_flags(records, max_flags=20, threshold=0.75)

    assert {flag["reason"] for flag in flags} >= {
        "exact_canonical_duplicate",
        "near_duplicate_similarity",
    }
    assert any(
        flag["recommendation"] == "drop_or_rewrite_train_row_before_eval_to_prevent_leakage"
        for flag in flags
    )

    manifest = build_dedup_dataset(
        input_dir=tmp_path,
        out_dir=tmp_path,
        prefix=DEDUP_PREFIX,
        max_flags=20,
        threshold=0.75,
    )
    assert manifest["policy"]["rewrites_source_data"] is False
    assert manifest["policy"]["review_required"] is True
    assert manifest["stats"]["total_flags"] >= 2
    assert (tmp_path / f"{DEDUP_PREFIX}.jsonl").exists()
