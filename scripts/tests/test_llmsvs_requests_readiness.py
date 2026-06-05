import json

from scripts.training.export_llmsvs_prediction_requests_iter5 import (
    DEFAULT_PREFIX as REQUEST_PREFIX,
)
from scripts.training.export_llmsvs_prediction_requests_iter5 import (
    build_requests,
)
from scripts.training.make_adapter_promotion_readiness_iter5 import (
    DEFAULT_PREFIX as READINESS_PREFIX,
)
from scripts.training.make_adapter_promotion_readiness_iter5 import (
    build_readiness_report,
)
from scripts.training.make_llmsvs_adversarial_eval_data import generate_rows


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_llmsvs_prediction_request_exporter_writes_batch_requests_and_case_map(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    write_jsonl(eval_path, generate_rows(9, seed=2026))

    manifest = build_requests(
        eval_path=eval_path,
        out_dir=tmp_path,
        prefix=REQUEST_PREFIX,
        model="adapter-under-test",
        max_tokens=384,
    )

    request_rows = [
        json.loads(line)
        for line in (tmp_path / f"{REQUEST_PREFIX}.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    case_map_rows = [
        json.loads(line)
        for line in (tmp_path / f"{REQUEST_PREFIX}_case_map.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert manifest["policy"]["offline_export_only"] is True
    assert manifest["stats"]["request_count"] == 9
    assert len(request_rows) == 9
    assert len(case_map_rows) == 9
    assert request_rows[0]["method"] == "POST"
    assert request_rows[0]["url"] == "/v1/chat/completions"
    assert request_rows[0]["body"]["model"] == "adapter-under-test"
    assert request_rows[0]["body"]["temperature"] == 0
    assert request_rows[0]["custom_id"] == case_map_rows[0]["case_id"]


def curated_manifest(source_map_path):
    return {
        "paths": {"source_map": str(source_map_path)},
        "policy": {
            "dpo_data_excluded": True,
            "hard_exclusions_applied": True,
            "heldout_hash_guard": True,
        },
        "stats": {"selected_total": 16000},
    }


def exclusions_manifest():
    return {
        "policy": {
            "rewrites_source_data": False,
            "safe_to_auto_delete_source": False,
        },
        "stats": {"hard_exclusion_rows": 10, "review_only_rows": 5},
    }


def dpo_manifest():
    return {
        "splits": {
            "eval": {"count": 2},
            "test": {"count": 2},
            "train": {"count": 2},
        }
    }


def sft_scores():
    return {
        "adapter": "adapter-under-test",
        "overall": {"overall": 0.87},
        "per_family": {"payload": {"schema_ok": 1.0}},
    }


def llmsvs_scores(dataset="aegispt_llmsvs_adversarial_gate_iter5"):
    return {
        "dataset": dataset,
        "stats": {
            "gate": {
                "gate_pass": True,
                "leakage_violations": 0,
                "tool_call_violations": 0,
            },
            "pass_rate": 0.99,
        },
    }


def deep_chain_scores(*, steps=5, unique=5):
    return {
        "flag": True,
        "idor": True,
        "logged_in": True,
        "steps": steps,
        "unique": unique,
    }


def request_manifest():
    return {
        "policy": {
            "offline_export_only": True,
            "runtime_execution": False,
        },
        "stats": {"request_count": 720},
    }


def write_readiness_inputs(tmp_path, *, llmsvs_dataset="aegispt_llmsvs_adversarial_gate_iter5"):
    source_map = tmp_path / "source_map.jsonl"
    source_map.write_text("{}\n", encoding="utf-8")
    write_json(tmp_path / "aegispt_curated_sft_mix_iter5_manifest.json", curated_manifest(source_map))
    write_json(tmp_path / "aegispt_training_exclusions_iter5_manifest.json", exclusions_manifest())
    write_json(tmp_path / "aegispt_payload_dpo_iter4_manifest.json", dpo_manifest())
    write_json(tmp_path / "eval_scores.json", sft_scores())
    write_json(tmp_path / "llmsvs_scores.json", llmsvs_scores(llmsvs_dataset))
    write_json(tmp_path / "deep_scores.json", deep_chain_scores())
    write_json(tmp_path / "aegispt_llmsvs_prediction_requests_iter5_manifest.json", request_manifest())


def test_adapter_promotion_readiness_passes_with_real_scores(tmp_path):
    write_readiness_inputs(tmp_path)

    report = build_readiness_report(
        training_dir=tmp_path,
        out_dir=tmp_path,
        prefix=READINESS_PREFIX,
        deep_chain_scores=tmp_path / "deep_scores.json",
        llmsvs_scores=tmp_path / "llmsvs_scores.json",
    )

    assert report["promotion_ready"] is True
    assert report["required_failures"] == []
    assert (tmp_path / f"{READINESS_PREFIX}.json").exists()


def test_adapter_promotion_readiness_blocks_smoke_llmsvs_scores(tmp_path):
    write_readiness_inputs(tmp_path, llmsvs_dataset="aegispt_llmsvs_adversarial_gate_iter5_smoke")

    report = build_readiness_report(
        training_dir=tmp_path,
        out_dir=tmp_path,
        prefix=READINESS_PREFIX,
        deep_chain_scores=tmp_path / "deep_scores.json",
        llmsvs_scores=tmp_path / "llmsvs_scores.json",
    )

    assert report["promotion_ready"] is False
    assert "llmsvs_adversarial_gate" in report["required_failures"]


def test_adapter_promotion_readiness_blocks_one_step_deep_chain(tmp_path):
    write_readiness_inputs(tmp_path)
    write_json(tmp_path / "deep_scores.json", deep_chain_scores(steps=1, unique=1))

    report = build_readiness_report(
        training_dir=tmp_path,
        out_dir=tmp_path,
        prefix=READINESS_PREFIX,
        deep_chain_scores=tmp_path / "deep_scores.json",
        llmsvs_scores=tmp_path / "llmsvs_scores.json",
    )

    assert report["promotion_ready"] is False
    assert "deep_chain_eval_gate" in report["required_failures"]


def test_adapter_promotion_readiness_accepts_combined_claude_readiness_input(tmp_path):
    write_readiness_inputs(tmp_path)
    readiness_input = {
        "deep_chain": deep_chain_scores(),
        "eval_scores": sft_scores(),
        "llmsvs": llmsvs_scores(),
    }
    write_json(tmp_path / "claude_readiness_input.json", readiness_input)

    report = build_readiness_report(
        training_dir=tmp_path,
        out_dir=tmp_path,
        prefix=READINESS_PREFIX,
        readiness_input=tmp_path / "claude_readiness_input.json",
    )

    assert report["promotion_ready"] is True
    assert report["required_failures"] == []
