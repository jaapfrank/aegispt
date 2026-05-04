from __future__ import annotations

import re
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

DEFAULT_NUCLEI_TEMPLATE = """id: aegispt-http-status-200
info:
  name: AegisPT HTTP Status 200 Baseline
  author: aegispt
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
"""
CURATED_TEMPLATE_SOURCE = "aegispt-curated"
DEFAULT_TEMPLATE_ID = "aegispt-http-status-200"
DEFAULT_TEMPLATE_FILENAME = "aegispt-http-status-200.yaml"

INFRASTRUCTURE_NUCLEI_TEMPLATE = """id: aegispt-infrastructure-management-surfaces
info:
  name: AegisPT Infrastructure Management Surface Baseline
  author: aegispt
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "Remote Desktop"
          - "OpenSSH"
          - "VPN"
          - "Fortinet"
          - "Citrix"
          - "VMware"
      - type: word
        part: header
        words:
          - "Server"
"""
INFRASTRUCTURE_TEMPLATE_ID = "aegispt-infrastructure-management-surfaces"
INFRASTRUCTURE_TEMPLATE_FILENAME = "aegispt-infrastructure-management-surfaces.yaml"
INFRASTRUCTURE_TEMPLATE_SOURCE = "aegispt-curated-infrastructure"


def curated_nuclei_template_sha256(template_body: str = DEFAULT_NUCLEI_TEMPLATE) -> str:
    return sha256(template_body.encode("utf-8")).hexdigest()


def build_nuclei_command(
    binary: str,
    targets_file: Path,
    template_file: Path,
    output_file: Path,
    rate_limit: int = 1,
    timeout_seconds: float = 10.0,
) -> list[str]:
    if not binary.strip():
        raise ValueError("binary must not be blank")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    return [
        binary,
        "-duc",
        "-l",
        str(targets_file),
        "-t",
        str(template_file),
        "-jsonl",
        "-jsonl-export",
        str(output_file),
        "-rl",
        str(rate_limit),
        "-timeout",
        str(max(int(timeout_seconds), 1)),
        "-retries",
        "0",
        "-no-stdin",
        "-nc",
    ]


def get_nuclei_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    version_output = (result.stdout or result.stderr).strip()
    if not version_output:
        return "nuclei"

    cleaned_output = re.sub(r"\x1b\[[0-9;]*m", "", version_output)
    for line in cleaned_output.splitlines():
        if "Version:" in line:
            return line.split("Version:", maxsplit=1)[1].strip()

    first_line = cleaned_output.splitlines()[0].strip()
    return first_line or "nuclei"


def execute_nuclei_scan(
    targets: list[str],
    rate_limit: int = 1,
    timeout_seconds: float = 10.0,
    binary: str = "nuclei",
    template_body: str | None = DEFAULT_NUCLEI_TEMPLATE,
    template_id: str | None = DEFAULT_TEMPLATE_ID,
    template_source: str | None = CURATED_TEMPLATE_SOURCE,
    template_filename: str | None = DEFAULT_TEMPLATE_FILENAME,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")

    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("targets must not be blank")

    with tempfile.TemporaryDirectory(prefix="aegispt-nuclei-") as temp_dir_name:
        effective_template_body = template_body or DEFAULT_NUCLEI_TEMPLATE
        effective_template_id = template_id or DEFAULT_TEMPLATE_ID
        effective_template_source = template_source or CURATED_TEMPLATE_SOURCE
        effective_template_filename = template_filename or DEFAULT_TEMPLATE_FILENAME
        temp_dir = Path(temp_dir_name)
        targets_file = temp_dir / "targets.txt"
        template_file = temp_dir / effective_template_filename
        output_file = temp_dir / "nuclei-results.jsonl"

        targets_file.write_text("\n".join(normalized_targets) + "\n", encoding="utf-8")
        template_file.write_text(effective_template_body, encoding="utf-8")

        command = build_nuclei_command(
            binary=binary,
            targets_file=targets_file,
            template_file=template_file,
            output_file=output_file,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
        )
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        artifact_data = output_file.read_bytes() if output_file.exists() else b""
        artifact = EvidenceArtifact(
            name="nuclei-results.jsonl",
            content_type="application/x-ndjson",
            data=artifact_data,
            kind="scan-results",
        )

        return RunnerExecution(
            tool="nuclei",
            exit_code=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            metadata={
                "status": "ok" if process.returncode == 0 else "failed",
                "normalized_targets": normalized_targets,
                "rate_limit": rate_limit,
                "timeout_seconds": timeout_seconds,
                "tool_version": get_nuclei_version(binary),
                "runner_digest": "workers.nuclei.runner:v1",
                "template_id": effective_template_id,
                "template_source": effective_template_source,
                "template_sha256": curated_nuclei_template_sha256(effective_template_body),
            },
            artifacts=[artifact],
        )
