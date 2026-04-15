from __future__ import annotations

from pathlib import Path

from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.httpx.runner import build_httpx_command
from workers.runners.nuclei.runner import build_nuclei_command
from workers.runners.semgrep.runner import build_semgrep_command, normalize_semgrep_rule_id
from workers.runners.zap.runner import build_zap_api_url


def test_evidence_artifact_hash_is_stable() -> None:
    artifact = EvidenceArtifact(
        name="stdout.json",
        content_type="application/json",
        data=b'{"status":"ok"}',
    )

    assert artifact.digest == "a29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288"


def test_httpx_command_is_structured() -> None:
    command = build_httpx_command(["https://example.com"], rate_limit=10)

    assert command == [
        "httpx-toolkit",
        "-silent",
        "-json",
        "-rl",
        "10",
        "-u",
        "https://example.com",
    ]


def test_nuclei_command_is_structured(tmp_path: Path) -> None:
    command = build_nuclei_command(
        binary="nuclei",
        targets_file=tmp_path / "targets.txt",
        template_file=tmp_path / "template.yaml",
        output_file=tmp_path / "output.jsonl",
        rate_limit=2,
        timeout_seconds=15,
    )

    assert command == [
        "nuclei",
        "-duc",
        "-l",
        str(tmp_path / "targets.txt"),
        "-t",
        str(tmp_path / "template.yaml"),
        "-jsonl",
        "-jsonl-export",
        str(tmp_path / "output.jsonl"),
        "-rl",
        "2",
        "-timeout",
        "15",
        "-retries",
        "0",
        "-no-stdin",
        "-nc",
    ]


def test_zap_api_url_is_structured() -> None:
    url = build_zap_api_url(
        base_url="http://zapd:8080/",
        component="core",
        category="view",
        name="version",
    )

    assert url == "http://zapd:8080/JSON/core/view/version/"


def test_semgrep_command_is_structured(tmp_path: Path) -> None:
    command = build_semgrep_command(
        binary="semgrep",
        config_file=tmp_path / "rule.yml",
        target_path=tmp_path / "repo",
        output_file=tmp_path / "results.json",
        jobs=2,
    )

    assert command == [
        "semgrep",
        "scan",
        "--config",
        str(tmp_path / "rule.yml"),
        "--json",
        "--output",
        str(tmp_path / "results.json"),
        "--jobs",
        "2",
        "--disable-version-check",
        "--metrics=off",
        "--no-git-ignore",
        "--quiet",
        str(tmp_path / "repo"),
    ]


def test_semgrep_rule_id_is_normalized() -> None:
    assert normalize_semgrep_rule_id("aegispt.python.hardcoded-secret") == "aegispt.python.hardcoded-secret"
    assert (
        normalize_semgrep_rule_id("tmp.aegispt-semgrep-rule.aegispt.python.hardcoded-secret")
        == "aegispt.python.hardcoded-secret"
    )
