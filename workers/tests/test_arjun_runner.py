from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from workers.orchestration.findings import extract_arjun_findings
from workers.runners.arjun import runner as arjun_runner
from workers.runners.arjun.runner import (
    ARJUN_RESULTS_NAME,
    build_arjun_command,
    execute_arjun_scan,
    normalize_arjun_target,
    parse_arjun_output,
)
from workers.runners.base.contracts import EvidenceArtifact


def test_normalize_arjun_target_adds_scheme() -> None:
    assert normalize_arjun_target("example.com/api") == "https://example.com/api"
    assert normalize_arjun_target("http://example.com") == "http://example.com"
    with pytest.raises(ValueError):
        normalize_arjun_target("   ")


def test_build_arjun_command_is_structured(tmp_path: Path) -> None:
    command = build_arjun_command(
        binary="arjun",
        target="https://example.com/api",
        output_file=tmp_path / "out.json",
        methods="GET,POST",
        rate_limit=50,
        timeout_seconds=15,
    )

    assert command == [
        "arjun",
        "-u",
        "https://example.com/api",
        "-oJ",
        str(tmp_path / "out.json"),
        "-m",
        "GET,POST",
        "--rate-limit",
        "50",
        "-t",
        "15",
        "--disable-redirects",
        "--stable",
    ]


def test_parse_arjun_output_handles_dict_shape() -> None:
    raw = json.dumps(
        {
            "https://example.com/api": {
                "params": ["id", "search", "id"],
                "method": "GET",
                "headers": "",
            }
        }
    ).encode()

    parsed = parse_arjun_output(raw, target="https://example.com/api")

    assert parsed["target"] == "https://example.com/api"
    assert parsed["params"] == ["id", "search"]  # deduped, order-preserved
    assert parsed["method"] == "GET"


def test_parse_arjun_output_handles_bare_list_and_empty() -> None:
    parsed_list = parse_arjun_output(json.dumps(["file", "next"]).encode(), target="t")
    assert parsed_list["params"] == ["file", "next"]
    assert parsed_list["method"] == "GET"

    parsed_empty = parse_arjun_output(b"", target="t")
    assert parsed_empty["params"] == []


def _fake_run_factory(output_payload: dict[str, object]):
    def _fake_run(command, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        # arjun writes JSON to the path following the -oJ flag.
        out_index = command.index("-oJ") + 1
        Path(command[out_index]).write_text(json.dumps(output_payload), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return _fake_run


def test_execute_arjun_scan_parses_discovered_params(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "https://example.com/profile": {
            "params": ["id", "debug"],
            "method": "GET",
        }
    }
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(payload))
    monkeypatch.setattr(arjun_runner, "get_arjun_version", lambda binary: "arjun 2.2.5")

    execution = execute_arjun_scan(["example.com/profile"], binary="arjun")

    assert execution.tool == "arjun"
    assert execution.exit_code == 0
    assert execution.metadata["skipped"] is False
    assert execution.metadata["param_count"] == 2
    assert len(execution.artifacts) == 1

    artifact = execution.artifacts[0]
    assert artifact.name == ARJUN_RESULTS_NAME
    combined = json.loads(artifact.data.decode())
    assert combined["results"][0]["params"] == ["id", "debug"]
    assert combined["targets"] == ["https://example.com/profile"]


def test_execute_arjun_scan_degrades_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _missing(command, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(subprocess, "run", _missing)
    monkeypatch.setattr(arjun_runner, "get_arjun_version", lambda binary: "arjun")

    execution = execute_arjun_scan(["https://example.com"], binary="arjun")

    # Graceful skip: not treated as a hard failure (exit 0), flagged skipped.
    assert execution.exit_code == 0
    assert execution.metadata["skipped"] is True
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["param_count"] == 0


def test_execute_arjun_scan_requires_targets() -> None:
    with pytest.raises(ValueError):
        execute_arjun_scan([])
    with pytest.raises(ValueError):
        execute_arjun_scan(["   "])


def test_extract_arjun_findings_yields_one_per_param() -> None:
    combined = {
        "version": "arjun",
        "targets": ["https://example.com/api"],
        "results": [
            {
                "target": "https://example.com/api",
                "params": ["id", "url", "id"],  # duplicate suppressed
                "method": "POST",
            }
        ],
    }
    artifact = EvidenceArtifact(
        name=ARJUN_RESULTS_NAME,
        content_type="application/json",
        data=json.dumps(combined).encode(),
        kind="param-discovery",
    )
    artifact_record = SimpleNamespace(uri="s3://bucket/arjun-results.json")

    findings = extract_arjun_findings(
        target_id="https://example.com/api",
        artifact=artifact,
        artifact_record=artifact_record,
    )

    titles = sorted(f.title for f in findings)
    assert titles == ["Hidden HTTP parameter: id", "Hidden HTTP parameter: url"]
    assert all(f.severity == "info" for f in findings)
    assert all(f.evidence_ref == "s3://bucket/arjun-results.json" for f in findings)
    assert all("POST" in (f.summary or "") for f in findings)


def test_extract_arjun_findings_ignores_other_artifacts() -> None:
    artifact = EvidenceArtifact(
        name="nuclei-results.jsonl",
        content_type="application/x-ndjson",
        data=b"{}",
        kind="scan-results",
    )
    artifact_record = SimpleNamespace(uri="s3://bucket/other")
    assert extract_arjun_findings(
        target_id="t",
        artifact=artifact,
        artifact_record=artifact_record,
    ) == []
