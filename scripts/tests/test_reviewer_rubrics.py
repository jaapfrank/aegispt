import json

from scripts.training.jury_review import TRACE_FIELDS, VERDICT_FIELDS
from scripts.training.make_reviewer_rubrics_iter6 import (
    DEFAULT_PREFIX,
    build_dataset,
    generate_rows,
    validate_rows,
)


def test_reviewer_rubrics_are_prep_only_and_schema_locked():
    rows = generate_rows()
    stats = validate_rows(rows)

    assert stats["reviewer_count"] == 5
    assert set(stats["provider_slots"]) == {"claude", "codex", "deepseek", "grok", "local"}
    for row in rows:
        metadata = row["metadata"]
        serialized = json.dumps(row, sort_keys=True).lower()
        assert row["execution_enabled"] is False
        assert metadata["provider_binding"] is None
        assert metadata["runtime_execution"] is False
        assert row["input_contract"]["trace_fields"] == list(TRACE_FIELDS)
        assert row["output_schema"]["required"] == list(VERDICT_FIELDS)
        assert "do not call tools" in serialized
        assert "runner evidence" in serialized or "runner-evidence" in serialized


def test_reviewer_rubric_family_writes_manifest_without_provider_bindings(tmp_path):
    manifest = build_dataset(tmp_path, DEFAULT_PREFIX)
    path = tmp_path / f"{DEFAULT_PREFIX}.jsonl"
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert manifest["policy"]["adapters_enabled"] is False
    assert manifest["policy"]["provider_calls"] is False
    assert manifest["policy"]["runtime_execution"] is False
    assert len(rows) == manifest["stats"]["reviewer_count"]
    assert (tmp_path / f"{DEFAULT_PREFIX}_manifest.json").exists()
    assert all(row["metadata"]["provider_binding"] is None for row in rows)
