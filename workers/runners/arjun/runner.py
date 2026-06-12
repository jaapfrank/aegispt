from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

ARJUN_RESULTS_NAME = "arjun-results.json"


def normalize_arjun_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("targets must not be blank")
    if normalized.startswith(("http://", "https://")):
        return normalized
    return f"https://{normalized}"


def build_arjun_command(
    *,
    binary: str,
    target: str,
    output_file: Path,
    methods: str = "GET,POST",
    rate_limit: int = 99,
    timeout_seconds: float = 10.0,
    stable: bool = True,
) -> list[str]:
    if not binary.strip():
        raise ValueError("binary must not be blank")
    if not target.strip():
        raise ValueError("target must not be blank")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    command = [
        binary,
        "-u",
        target,
        "-oJ",
        str(output_file),
        "-m",
        methods,
        "--rate-limit",
        str(rate_limit),
        "-t",
        str(max(int(timeout_seconds), 1)),
        "--disable-redirects",
    ]
    if stable:
        command.append("--stable")
    return command


def get_arjun_version(binary: str) -> str:
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "arjun"
    version_output = (result.stdout or result.stderr).strip()
    return version_output.splitlines()[0].strip() if version_output else "arjun"


def parse_arjun_output(raw_bytes: bytes, *, target: str) -> dict[str, object]:
    """Normalize arjun's ``-oJ`` JSON into a stable per-target shape.

    arjun emits ``{"<url>": {"params": [...], "method": "GET", "headers": ""}}``
    (one or more URL keys). Older/edge builds emit a bare ``["id", "page"]``
    list. Both are flattened to ``{"target", "params", "method"}``.
    """

    discovered: list[str] = []
    method = ""
    if raw_bytes.strip():
        try:
            payload = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = None

        if isinstance(payload, dict):
            for entry in payload.values():
                if isinstance(entry, dict):
                    params = entry.get("params", [])
                    if isinstance(params, list):
                        discovered.extend(str(p) for p in params if isinstance(p, (str, int)))
                    if not method and isinstance(entry.get("method"), str):
                        method = entry["method"]
                elif isinstance(entry, list):
                    discovered.extend(str(p) for p in entry if isinstance(p, (str, int)))
        elif isinstance(payload, list):
            discovered.extend(str(p) for p in payload if isinstance(p, (str, int)))

    deduped = list(dict.fromkeys(p for p in discovered if p))
    return {"target": target, "params": deduped, "method": method or "GET"}


def execute_arjun_scan(
    targets: list[str],
    *,
    methods: str = "GET,POST",
    rate_limit: int = 99,
    timeout_seconds: float = 10.0,
    binary: str = "arjun",
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")

    normalized_targets = [normalize_arjun_target(target) for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("targets must not be blank")

    per_target: list[dict[str, object]] = []
    stderr_lines: list[str] = []
    exit_code = 0
    skipped = False
    tool_version = get_arjun_version(binary)

    with tempfile.TemporaryDirectory(prefix="aegispt-arjun-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        for index, target in enumerate(normalized_targets, start=1):
            output_file = temp_dir / f"arjun-{index}.json"
            command = build_arjun_command(
                binary=binary,
                target=target,
                output_file=output_file,
                methods=methods,
                rate_limit=rate_limit,
                timeout_seconds=timeout_seconds,
            )
            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                skipped = True
                stderr_lines.append(f"arjun binary not found: {binary}")
                per_target.append({"target": target, "params": [], "method": "GET"})
                break

            if process.returncode != 0:
                exit_code = 1
                if process.stderr.strip():
                    stderr_lines.append(process.stderr.strip())

            raw_bytes = output_file.read_bytes() if output_file.exists() else b""
            per_target.append(parse_arjun_output(raw_bytes, target=target))

    combined_payload = {
        "version": tool_version,
        "targets": normalized_targets,
        "results": per_target,
    }
    artifact = EvidenceArtifact(
        name=ARJUN_RESULTS_NAME,
        content_type="application/json",
        data=(json.dumps(combined_payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="param-discovery",
    )

    param_count = sum(
        len(entry.get("params", [])) for entry in per_target if isinstance(entry, dict)
    )

    metadata: dict[str, object] = {
        "status": "skipped" if skipped else ("ok" if exit_code == 0 else "completed_with_errors"),
        "skipped": skipped,
        "normalized_targets": normalized_targets,
        "methods": methods,
        "rate_limit": rate_limit,
        "timeout_seconds": timeout_seconds,
        "tool_version": tool_version,
        "runner_digest": "workers.arjun.runner:v1",
        "param_count": param_count,
    }

    return RunnerExecution(
        tool="arjun",
        exit_code=exit_code,
        stdout=json.dumps(
            {
                "target_count": len(normalized_targets),
                "param_count": param_count,
                "skipped": skipped,
            },
            sort_keys=True,
        ),
        stderr="\n".join(stderr_lines),
        metadata=metadata,
        artifacts=[artifact],
    )
