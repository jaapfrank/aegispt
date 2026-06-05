import json

from scripts.training.make_payload_domain_extension_iter4_dataset import (
    CLASSES as DOMAIN_CLASSES,
)
from scripts.training.make_payload_domain_extension_iter4_dataset import (
    DEFAULT_PREFIX as DOMAIN_PREFIX,
)
from scripts.training.make_payload_domain_extension_iter4_dataset import (
    build_dataset as build_domain_dataset,
)
from scripts.training.make_payload_domain_extension_iter4_dataset import (
    generate_rows as generate_domain_rows,
)
from scripts.training.make_payload_domain_extension_iter4_dataset import (
    validate_rows as validate_domain_rows,
)
from scripts.training.make_payload_dpo_iter4_dataset import DEFAULT_PREFIX as DPO_PREFIX
from scripts.training.make_payload_dpo_iter4_dataset import SCENARIOS
from scripts.training.make_payload_dpo_iter4_dataset import build_dataset as build_dpo_dataset
from scripts.training.make_payload_dpo_iter4_dataset import generate_rows as generate_dpo_rows
from scripts.training.make_payload_dpo_iter4_dataset import validate_rows as validate_dpo_rows
from scripts.training.make_payload_negative_contrastive_iter4_dataset import (
    BLOCK_REASONS,
)
from scripts.training.make_payload_negative_contrastive_iter4_dataset import (
    DEFAULT_PREFIX as NEGATIVE_PREFIX,
)
from scripts.training.make_payload_negative_contrastive_iter4_dataset import (
    build_dataset as build_negative_dataset,
)
from scripts.training.make_payload_negative_contrastive_iter4_dataset import (
    generate_rows as generate_negative_rows,
)
from scripts.training.make_payload_negative_contrastive_iter4_dataset import (
    validate_rows as validate_negative_rows,
)


def test_negative_contrastive_dataset_blocks_all_reasons_and_never_executes(tmp_path):
    rows = generate_negative_rows(40, split="test", seed=2026)
    stats = validate_negative_rows(rows)

    assert set(stats["block_reasons"]) == set(BLOCK_REASONS)
    for row in rows:
        assert row["metadata"]["dataset_family"] == NEGATIVE_PREFIX
        parsed = json.loads(row["messages"][-1]["content"])
        assert parsed["decision"] in {"block", "request_approval", "safe_alternative"}
        assert parsed["safety"]["runtime_execution"] is False
        assert parsed["evidence"].get("payload_sent") is not True

    manifest = build_negative_dataset(tmp_path, NEGATIVE_PREFIX, {"train": 20, "eval": 10, "test": 10}, seed=1)
    assert manifest["policy"]["negative_examples_only"] is True


def test_payload_dpo_dataset_has_good_bad_pairs_for_all_scenarios(tmp_path):
    rows = generate_dpo_rows(36, split="test", seed=2026)
    stats = validate_dpo_rows(rows)

    assert set(stats["scenarios"]) == set(SCENARIOS)
    for row in rows:
        assert row["metadata"]["dataset_family"] == DPO_PREFIX
        chosen = json.loads(row["chosen"]["content"])
        rejected = json.loads(row["rejected"]["content"])
        assert chosen["decision"] != rejected["decision"]
        assert chosen["safety"]["runtime_execution"] is False
        assert rejected["safety"]["runtime_execution"] is False
        assert chosen["evidence"]
        assert chosen["cleanup"]

    manifest = build_dpo_dataset(tmp_path, DPO_PREFIX, {"train": 18, "eval": 9, "test": 9}, seed=1)
    assert manifest["format"] == "jsonl chat DPO with prompt/chosen/rejected"


def test_domain_extension_dataset_covers_ad_cloud_lan_iot_and_is_lab_only(tmp_path):
    rows = generate_domain_rows(64, split="test", seed=2026)
    stats = validate_domain_rows(rows)

    assert set(stats["vulnerability_classes"]) == set(DOMAIN_CLASSES)
    assert set(stats["domains"]) == {"active_directory", "cloud", "iot", "lan"}
    for row in rows:
        assert row["metadata"]["dataset_family"] == DOMAIN_PREFIX
        parsed = json.loads(row["messages"][-1]["content"])
        assert parsed["safety"]["lab_only"] is True
        assert parsed["safety"]["runtime_execution"] is False
        assert parsed["payload"]["family"] == row["metadata"]["payload_family"]
        assert parsed["expected_evidence"]["evidence_ref"]

    manifest = build_domain_dataset(tmp_path, DOMAIN_PREFIX, {"train": 32, "eval": 16, "test": 16}, seed=1)
    assert manifest["policy"]["no_credential_dumping"] is True
