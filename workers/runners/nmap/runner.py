from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution


def build_nmap_command(
    binary: str,
    *,
    output_file: Path,
    targets: list[str],
    discovery_only: bool = True,
    service_detection: bool = False,
    skip_discovery: bool = False,
    top_ports: int | None = None,
) -> list[str]:
    if not binary.strip():
        raise ValueError("binary must not be blank")
    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("at least one target is required")

    command = [binary, "-n", "-oX", str(output_file)]
    if discovery_only:
        command.append("-sn")
    else:
        if skip_discovery:
            command.append("-Pn")
        if service_detection:
            command.append("-sV")
        if isinstance(top_ports, int) and top_ports > 0:
            command.extend(["--top-ports", str(top_ports)])
    command.extend(normalized_targets)
    return command


def get_nmap_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout or result.stderr).strip()
    if not output:
        return "nmap"
    return output.splitlines()[0].strip() or "nmap"


def execute_nmap_scan(
    targets: list[str],
    *,
    binary: str = "nmap",
    discovery_only: bool = True,
    service_detection: bool = False,
    skip_discovery: bool = False,
    top_ports: int | None = None,
) -> RunnerExecution:
    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("at least one target is required")

    with tempfile.TemporaryDirectory(prefix="aegispt-nmap-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        output_file = temp_dir / "nmap-results.xml"
        command = build_nmap_command(
            binary=binary,
            output_file=output_file,
            targets=normalized_targets,
            discovery_only=discovery_only,
            service_detection=service_detection,
            skip_discovery=skip_discovery,
            top_ports=top_ports,
        )
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        artifact_data = output_file.read_bytes() if output_file.exists() else b""
        artifact = EvidenceArtifact(
            name="nmap-results.xml",
            content_type="application/xml",
            data=artifact_data,
            kind="network-scan-results",
        )

        return RunnerExecution(
            tool="nmap",
            exit_code=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            metadata={
                "status": "ok" if process.returncode == 0 else "failed",
                "normalized_targets": normalized_targets,
                "discovery_only": discovery_only,
                "service_detection": service_detection,
                "skip_discovery": skip_discovery,
                "top_ports": top_ports,
                "tool_version": get_nmap_version(binary),
                "runner_digest": "workers.nmap.runner:v1",
            },
            artifacts=[artifact],
        )
