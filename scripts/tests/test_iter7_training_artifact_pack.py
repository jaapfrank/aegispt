import gzip
import json

from scripts.training.build_iter7_training_artifact_pack import build_pack
from scripts.training.make_lab_truth_heldout_registry_iter6 import (
    DEFAULT_PREFIX as REGISTRY_PREFIX,
)
from scripts.training.make_multiturn_chaintype_diversity_iter7 import (
    DEFAULT_PREFIX as CHAINTYPE_PREFIX,
)


def read_gzip_jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_iter7_training_artifact_pack_writes_compressed_data_and_registry(tmp_path):
    manifest = build_pack(
        out_dir=tmp_path,
        chaintype_counts={"train": 8, "eval": 8, "test": 8},
        llmsvs_count=18,
        multiturn_counts={"eval": 8, "test": 8},
    )

    assert manifest["policy"]["committed_artifact_pack"] is True
    assert manifest["policy"]["iter7_eval_test_registered_as_held_out"] is True
    assert manifest["files"]["chaintype_train"]["row_count"] == 8
    assert manifest["files"]["llmsvs_eval"]["row_count"] == 18

    train_rows = read_gzip_jsonl(tmp_path / f"{CHAINTYPE_PREFIX}_train.jsonl.gz")
    assert len(train_rows) == 8
    assert {row["metadata"]["chain_class"] for row in train_rows} == {
        "idor_object_swap_token_reuse_chain",
        "info_disclosure_credential_reuse_lateral_chain",
        "lowpriv_privilege_escalation_admin_resource_chain",
        "ssrf_internal_endpoint_admin_action_chain",
    }

    registry = json.loads((tmp_path / f"{REGISTRY_PREFIX}.json").read_text(encoding="utf-8"))
    assert registry["stats"]["held_out_by_family"][CHAINTYPE_PREFIX] == 16
    assert registry["stats"]["held_out_by_family"]["aegispt_llmsvs_adversarial_eval_iter5"] == 18

    held_out_rows = read_gzip_jsonl(tmp_path / f"{REGISTRY_PREFIX}_held_out.jsonl.gz")
    assert any(row["dataset_family"] == CHAINTYPE_PREFIX for row in held_out_rows)
    assert manifest["manifest"]["sha256"]
