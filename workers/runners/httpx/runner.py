from __future__ import annotations

import json
from hashlib import sha256

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution


def build_httpx_command(targets: list[str], rate_limit: int = 25) -> list[str]:
    if not targets:
        raise ValueError("at least one target is required")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")

    command = ["httpx-toolkit", "-silent", "-json", "-rl", str(rate_limit)]
    for target in targets:
        if not target.strip():
            raise ValueError("targets must not be blank")
        command.extend(["-u", target])

    return command


def normalize_http_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("targets must not be blank")
    if normalized.startswith(("http://", "https://")):
        return normalized
    return f"https://{normalized}"


def execute_httpx_probe(
    targets: list[str],
    rate_limit: int = 25,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    results: list[dict[str, object]] = []
    stderr_lines: list[str] = []
    normalized_targets: list[str] = []
    exit_code = 0

    with httpx_client.Client(
        follow_redirects=True,
        timeout=timeout_seconds,
        headers={"User-Agent": "AegisPT/0.1"},
    ) as client:
        for target in targets:
            request_url = normalize_http_target(target)
            normalized_targets.append(request_url)

            try:
                response = client.get(request_url)
                body_bytes = response.content
                results.append(
                    {
                        "input_target": target,
                        "request_url": request_url,
                        "final_url": str(response.url),
                        "status_code": response.status_code,
                        "reason_phrase": response.reason_phrase,
                        "content_type": response.headers.get("content-type"),
                        "content_length": len(body_bytes),
                        "body_sha256": sha256(body_bytes).hexdigest(),
                        "ok": True,
                    }
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                error_message = f"{request_url}: {exc}"
                stderr_lines.append(error_message)
                results.append(
                    {
                        "input_target": target,
                        "request_url": request_url,
                        "ok": False,
                        "error": str(exc),
                    }
                )

    artifact_data = ("\n".join(json.dumps(result, sort_keys=True) for result in results) + "\n").encode()
    artifact = EvidenceArtifact(
        name="httpx-results.jsonl",
        content_type="application/x-ndjson",
        data=artifact_data,
        kind="probe-results",
    )

    return RunnerExecution(
        tool="httpx",
        exit_code=exit_code,
        stdout=json.dumps({"results": results}, sort_keys=True),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "normalized_targets": normalized_targets,
            "rate_limit": rate_limit,
            "timeout_seconds": timeout_seconds,
            "tool_version": f"python-httpx/{httpx_client.__version__}",
            "runner_digest": "workers.httpx.runner:v1",
            "result_count": len(results),
        },
        artifacts=[artifact],
    )
