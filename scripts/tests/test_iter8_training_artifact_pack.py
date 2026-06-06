import gzip
import json

from scripts.training.build_iter8_training_artifact_pack import build_pack
from scripts.training.make_lab_truth_heldout_registry_iter6 import (
    DEFAULT_PREFIX as REGISTRY_PREFIX,
)
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    DEFAULT_PREFIX as MULTISERVICE_PREFIX,
)


def read_gzip_jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_iter8_training_artifact_pack_writes_compressed_data_and_registry(tmp_path):
    manifest = build_pack(
        out_dir=tmp_path,
        multiservice_counts={"train": 8, "eval": 8, "test": 8},
        llmsvs_count=18,
        multiturn_counts={"eval": 8, "test": 8},
        chaintype_counts={"eval": 8, "test": 8},
    )

    assert manifest["policy"]["committed_artifact_pack"] is True
    assert manifest["policy"]["multi_service_chain_type_diversity"] is True
    assert manifest["policy"]["iter8_eval_test_registered_as_held_out"] is True
    assert manifest["files"]["multiservice_train"]["row_count"] == 8
    assert manifest["files"]["multiservice_eval"]["row_count"] == 8
    assert manifest["files"]["multiservice_test"]["row_count"] == 8

    train_rows = read_gzip_jsonl(tmp_path / f"{MULTISERVICE_PREFIX}_train.jsonl.gz")
    assert train_rows[0]["metadata"]["dataset_family"] == MULTISERVICE_PREFIX
    assert train_rows[0]["metadata"]["assistant_turns"] >= 6

    registry = json.loads((tmp_path / f"{REGISTRY_PREFIX}.json").read_text(encoding="utf-8"))
    assert registry["stats"]["held_out_by_family"][MULTISERVICE_PREFIX] == 16

    held_out_rows = read_gzip_jsonl(tmp_path / f"{REGISTRY_PREFIX}_held_out.jsonl.gz")
    assert any(row["dataset_family"] == MULTISERVICE_PREFIX for row in held_out_rows)
