import json

from scripts.training.make_curated_sft_mix_iter5 import (
    DEFAULT_FAMILIES,
    build_mix,
)
from scripts.training.make_curated_sft_mix_iter5 import (
    DEFAULT_PREFIX as MIX_PREFIX,
)
from scripts.training.make_training_exclusions_iter5 import (
    DEFAULT_PREFIX as EXCLUSION_PREFIX,
)
from scripts.training.make_training_exclusions_iter5 import (
    build_dataset as build_exclusion_dataset,
)
from scripts.training.make_training_exclusions_iter5 import (
    build_exclusions,
)


def write_jsonl(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def ref(case_id, dataset_family, split, path="/tmp/source.jsonl", line=1):
    return {
        "case_id": case_id,
        "dataset_family": dataset_family,
        "exact_hash": f"{case_id}-hash",
        "line": line,
        "path": path,
        "split": split,
    }


def triage_row(triage_id, priority, primary, duplicate, action="review"):
    candidate = duplicate if duplicate["split"] == "train" else primary
    return {
        "action": action,
        "duplicate": duplicate,
        "primary": primary,
        "rewrite_recipe": {"candidate_row": candidate},
        "training_impact": "eval_or_test_score_may_be_inflated_if_left_unfixed",
        "triage_id": triage_id,
        "triage_priority": priority,
    }


def test_training_exclusions_include_p0_train_side_and_p1_combined_only(tmp_path):
    rows = [
        triage_row(
            "triage-p0",
            "p0_train_eval_or_test_leakage",
            ref("eval-row", "family", "eval", line=1),
            ref("train-row", "family", "train", line=2),
        ),
        triage_row(
            "triage-p1",
            "p1_combined_dataset_overlap",
            ref("combined-row", "aegispt_combined_all", "train", line=3),
            ref("source-row", "aegispt_open_corpus_iter3", "train", line=4),
        ),
        triage_row(
            "triage-p2",
            "p2_train_template_diversity",
            ref("template-a", "family", "train", line=5),
            ref("template-b", "family", "train", line=6),
        ),
    ]

    exclusions, review_only = build_exclusions(rows)

    assert [item["case_id"] for item in exclusions] == ["train-row", "combined-row"]
    assert {item["exclusion_reason"] for item in exclusions} == {
        "hard_exclude_combined_overlap",
        "hard_exclude_train_leakage",
    }
    assert len(review_only) == 1

    triage_path = tmp_path / "triage.jsonl"
    write_jsonl(triage_path, rows)
    manifest = build_exclusion_dataset(
        triage_path=triage_path,
        out_dir=tmp_path,
        prefix=EXCLUSION_PREFIX,
    )
    assert manifest["policy"]["rewrites_source_data"] is False
    assert manifest["stats"]["hard_exclusion_rows"] == 2
    assert manifest["stats"]["review_only_rows"] == 1


def sft_row(case_id, content):
    return {
        "messages": [
            {"role": "system", "content": "AegisPT lab mode."},
            {"role": "user", "content": content},
            {"role": "assistant", "content": '{"done": true, "safety": {"runtime_execution": false}}'},
        ],
        "metadata": {"case_id": case_id, "dataset_family": "test_family"},
    }


def test_curated_sft_mix_applies_exclusions_and_heldout_guard(tmp_path):
    first_family = "full_coverage"
    first_file = DEFAULT_FAMILIES[first_family]["file"]
    excluded_case = "full-excluded"
    heldout_case = "full-heldout"
    kept_case = "full-kept"

    for family, config in DEFAULT_FAMILIES.items():
        rows = [
            sft_row(f"{family}-1", f"{family} safe assessment one"),
            sft_row(f"{family}-2", f"{family} safe assessment two"),
        ]
        if family == first_family:
            rows = [
                sft_row(excluded_case, "excluded by hard exclusion"),
                sft_row(heldout_case, "same as heldout row"),
                sft_row(kept_case, "kept unique row"),
            ]
        write_jsonl(tmp_path / config["file"], rows)

    write_jsonl(
        tmp_path / "aegispt_full_coverage_dora_loraplus_unsloth_eval.jsonl",
        [sft_row("heldout-copy", "same as heldout row")],
    )
    exclusions_path = tmp_path / "aegispt_training_exclusions_iter5.jsonl"
    write_jsonl(
        exclusions_path,
        [
            {
                "case_id": excluded_case,
                "dataset_family": "aegispt_full_coverage_dora_loraplus_unsloth",
                "exclusion_reason": "hard_exclude_train_leakage",
                "line": 1,
                "path": str(tmp_path / first_file),
                "split": "train",
            }
        ],
    )

    manifest = build_mix(
        training_dir=tmp_path,
        out_dir=tmp_path,
        exclusions_path=exclusions_path,
        prefix=MIX_PREFIX,
        total=10,
        max_per_template=10,
    )

    source_map = [
        json.loads(line)
        for line in (tmp_path / f"{MIX_PREFIX}_source_map.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    selected_cases = {row["case_id"] for row in source_map}

    assert excluded_case not in selected_cases
    assert heldout_case not in selected_cases
    assert kept_case in selected_cases
    assert manifest["policy"]["dpo_data_excluded"] is True
    assert manifest["policy"]["rewrites_source_data"] is False
    assert manifest["stats"]["exclusion_rows_loaded"] == 1
    assert (tmp_path / f"{MIX_PREFIX}.jsonl").exists()
