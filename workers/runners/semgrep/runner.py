from __future__ import annotations

import json
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

DEFAULT_SEMGREP_RULE = """rules:
  - id: aegispt.python.hardcoded-secret
    message: Hardcoded secret assignment
    languages:
      - python
    severity: ERROR
    patterns:
      - pattern: $SECRET = "..."
      - metavariable-regex:
          metavariable: $SECRET
          regex: (?i).*(password|passwd|secret|token|api_key).*
"""

CURATED_RULE_ID = "aegispt.python.hardcoded-secret"
CURATED_RULE_SOURCE = "aegispt-curated"


def curated_semgrep_rule_sha256() -> str:
    return sha256(DEFAULT_SEMGREP_RULE.encode("utf-8")).hexdigest()


def normalize_semgrep_rule_id(check_id: str) -> str:
    normalized = check_id.strip()
    if not normalized:
        return CURATED_RULE_ID
    if normalized == CURATED_RULE_ID or normalized.endswith(f".{CURATED_RULE_ID}"):
        return CURATED_RULE_ID
    return normalized


def normalize_semgrep_payload(payload: dict[str, object]) -> dict[str, object]:
    results = payload.get("results", [])
    if not isinstance(results, list):
        return payload

    for result in results:
        if not isinstance(result, dict):
            continue
        check_id = result.get("check_id")
        if isinstance(check_id, str):
            result["check_id"] = normalize_semgrep_rule_id(check_id)

    return payload


def build_semgrep_command(
    *,
    binary: str,
    config_file: Path,
    target_path: Path,
    output_file: Path,
    jobs: int = 1,
) -> list[str]:
    if not binary.strip():
        raise ValueError("binary must not be blank")
    if jobs <= 0:
        raise ValueError("jobs must be greater than zero")

    return [
        binary,
        "scan",
        "--config",
        str(config_file),
        "--json",
        "--output",
        str(output_file),
        "--jobs",
        str(jobs),
        "--disable-version-check",
        "--metrics=off",
        "--no-git-ignore",
        "--quiet",
        str(target_path),
    ]


def get_semgrep_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    version_output = (result.stdout or result.stderr).strip()
    return version_output or "semgrep"


def execute_semgrep_scan(
    targets: list[str],
    *,
    jobs: int = 1,
    binary: str = "semgrep",
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")

    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("targets must not be blank")

    results_payloads: list[dict[str, object]] = []
    stderr_lines: list[str] = []
    exit_code = 0
    tool_version = get_semgrep_version(binary)

    with tempfile.TemporaryDirectory(prefix="aegispt-semgrep-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        config_file = temp_dir / "aegispt-semgrep-rule.yml"
        config_file.write_text(DEFAULT_SEMGREP_RULE, encoding="utf-8")

        for index, target in enumerate(normalized_targets, start=1):
            target_path = Path(target)
            if not target_path.exists():
                exit_code = 1
                stderr_lines.append(f"{target}: target path does not exist")
                results_payloads.append(
                    {
                        "version": tool_version,
                        "results": [],
                        "errors": [{"message": "target path does not exist", "path": target}],
                        "paths": {"scanned": [], "skipped": []},
                        "target": target,
                    }
                )
                continue

            output_file = temp_dir / f"semgrep-results-{index}.json"
            command = build_semgrep_command(
                binary=binary,
                config_file=config_file,
                target_path=target_path,
                output_file=output_file,
                jobs=jobs,
            )
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            if process.returncode != 0:
                exit_code = 1
                if process.stderr.strip():
                    stderr_lines.append(process.stderr.strip())

            if output_file.exists():
                try:
                    payload = json.loads(output_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    payload = {
                        "version": tool_version,
                        "results": [],
                        "errors": [{"message": "invalid semgrep json output", "path": target}],
                        "paths": {"scanned": [str(target_path)], "skipped": []},
                    }
                    exit_code = 1
            else:
                payload = {
                    "version": tool_version,
                    "results": [],
                    "errors": [{"message": "semgrep produced no output file", "path": target}],
                    "paths": {"scanned": [str(target_path)], "skipped": []},
                }
                exit_code = 1

            if isinstance(payload, dict):
                payload.setdefault("version", tool_version)
                payload["target"] = target
                payload = normalize_semgrep_payload(payload)
            results_payloads.append(payload if isinstance(payload, dict) else {"target": target})

    combined_payload = {
        "version": tool_version,
        "rule_source": CURATED_RULE_SOURCE,
        "rule_ids": [CURATED_RULE_ID],
        "rule_sha256": curated_semgrep_rule_sha256(),
        "targets": normalized_targets,
        "runs": results_payloads,
    }
    artifact = EvidenceArtifact(
        name="semgrep-results.json",
        content_type="application/json",
        data=(json.dumps(combined_payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="scan-results",
    )

    finding_count = 0
    for payload in results_payloads:
        if isinstance(payload, dict):
            results = payload.get("results", [])
            if isinstance(results, list):
                finding_count += len(results)

    return RunnerExecution(
        tool="semgrep",
        exit_code=exit_code,
        stdout=json.dumps(
            {
                "target_count": len(normalized_targets),
                "finding_count": finding_count,
                "rule_ids": [CURATED_RULE_ID],
            },
            sort_keys=True,
        ),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "normalized_targets": normalized_targets,
            "tool_version": tool_version,
            "runner_digest": "workers.semgrep.runner:v1",
            "rule_ids": [CURATED_RULE_ID],
            "rule_source": CURATED_RULE_SOURCE,
            "rule_sha256": curated_semgrep_rule_sha256(),
            "finding_count": finding_count,
        },
        artifacts=[artifact],
    )
