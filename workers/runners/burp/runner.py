from __future__ import annotations

import json
import time
from collections import Counter
from typing import Any

import httpx as httpx_client

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

BURP_RESULTS_ARTIFACT_NAME = "burp-results.json"
BURP_EXACT_URL_SCOPE_KEYS = ("urls", "api_base_urls")
BURP_BROAD_SCOPE_KEYS = (
    "domains",
    "subdomains",
    "hosts",
    "ip_addresses",
    "cidrs",
    "cidr_ranges",
    "targets",
)


def build_burp_api_url(base_url: str, *segments: str) -> str:
    normalized_base_url = base_url.strip().rstrip("/")
    if not normalized_base_url:
        raise ValueError("base_url must not be blank")

    normalized_segments = [segment.strip().strip("/") for segment in segments if segment.strip()]
    if not normalized_segments:
        return normalized_base_url
    return f"{normalized_base_url}/{'/'.join(normalized_segments)}"


def normalize_burp_api_root(base_url: str, api_key: str | None = None) -> str:
    normalized_base_url = str(base_url or "").strip().rstrip("/")
    normalized_api_key = str(api_key or "").strip()
    if not normalized_base_url:
        raise ValueError("BURP_API_URL is not configured")

    if "/api/" in normalized_base_url:
        return normalized_base_url
    if normalized_base_url.endswith("/api"):
        if not normalized_api_key:
            raise ValueError(
                "BURP_API_KEY is required when BURP_API_URL does not already include the full REST API path"
            )
        return build_burp_api_url(normalized_base_url, normalized_api_key)
    if normalized_api_key:
        return build_burp_api_url(normalized_base_url, "api", normalized_api_key)
    raise ValueError(
        "BURP_API_KEY is required when BURP_API_URL does not already include the full REST API path"
    )


def _request_burp_json(
    client: httpx_client.Client,
    *,
    method: str,
    api_root: str,
    path: str,
    json_body: dict[str, object] | None = None,
) -> dict[str, object]:
    response = client.request(
        method.upper(),
        build_burp_api_url(api_root, path),
        json=json_body,
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"unexpected Burp API response for {path}")
    return payload


def get_burp_version(
    client: httpx_client.Client,
    *,
    api_root: str,
) -> str:
    payload = _request_burp_json(
        client,
        method="GET",
        api_root=api_root,
        path="version",
    )
    version = str(payload.get("version") or payload.get("product_version") or "").strip()
    return version or "burp-rest-api"


def _scan_id_from_payload(payload: dict[str, object]) -> str:
    for field_name in ("scan_id", "scanId", "id"):
        value = str(payload.get(field_name) or "").strip()
        if value:
            return value
    raise RuntimeError("Burp API did not return a scan identifier")


def _wait_for_scan_completion(
    client: httpx_client.Client,
    *,
    api_root: str,
    scan_id: str,
    timeout_seconds: float,
) -> dict[str, object]:
    deadline = time.monotonic() + max(timeout_seconds, 30.0)
    last_payload: dict[str, object] = {}

    while time.monotonic() < deadline:
        last_payload = _request_burp_json(
            client,
            method="GET",
            api_root=api_root,
            path=f"scan/{scan_id}",
        )
        normalized_status = str(last_payload.get("status") or "").strip().lower()
        if normalized_status in {"succeeded", "completed", "finished", "done"}:
            return last_payload
        if normalized_status in {"failed", "cancelled", "canceled", "error"}:
            raise RuntimeError(f"Burp scan {scan_id} ended with status {normalized_status}")
        time.sleep(0.5)

    raise TimeoutError(f"Burp scan {scan_id} did not finish in time")


def _collect_scan_issues(
    client: httpx_client.Client,
    *,
    api_root: str,
    scan_id: str,
    fallback_payload: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    try:
        payload = _request_burp_json(
            client,
            method="GET",
            api_root=api_root,
            path=f"scan/{scan_id}/issues",
        )
    except httpx_client.HTTPStatusError:
        issues = fallback_payload.get("issues") if isinstance(fallback_payload, dict) else []
        if isinstance(issues, list):
            return [issue for issue in issues if isinstance(issue, dict)]
        raise

    issues = payload.get("issues", [])
    if not isinstance(issues, list):
        raise RuntimeError("unexpected Burp issues payload")
    return [issue for issue in issues if isinstance(issue, dict)]


def _configured_scope_values(
    scope_allowlist: dict[str, Any],
    *,
    keys: tuple[str, ...],
) -> list[str]:
    configured: list[str] = []
    for key in keys:
        values = scope_allowlist.get(key, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            normalized_value = value.strip()
            if normalized_value:
                configured.append(normalized_value)
    return configured


def _burp_target_is_allowed(scope_allowlist: dict[str, Any], normalized_target: str) -> bool:
    exact_url_targets = {
        normalize_http_target(value)
        for value in _configured_scope_values(scope_allowlist, keys=BURP_EXACT_URL_SCOPE_KEYS)
    }
    if not exact_url_targets:
        return target_value_is_allowed(scope_allowlist, normalized_target)
    if normalized_target in exact_url_targets:
        return True

    broad_scope_values = _configured_scope_values(scope_allowlist, keys=BURP_BROAD_SCOPE_KEYS)
    if not broad_scope_values:
        return False
    return target_value_is_allowed(scope_allowlist, normalized_target)


def execute_burp_scan(
    targets: list[str],
    *,
    base_url: str,
    api_key: str | None,
    rate_limit: int = 1,
    timeout_seconds: float = 30.0,
    named_scan_configurations: list[str] | None = None,
    scan_definition: dict[str, object] | None = None,
    scope_allowlist: dict[str, object] | None = None,
    client_factory=httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    try:
        api_root = normalize_burp_api_root(base_url, api_key)
    except ValueError as exc:
        # Burp Suite Pro is not installed or not configured — skip gracefully.
        return RunnerExecution(
            tool="burp",
            # exit_code=78 (EX_CONFIG) is the project convention for "runner
            # unavailable in this deployment" — see assessment_loop.RUNNER_EXIT_CODE_SKIPPED.
            # Pre-2026-05-21 this returned 0, which made the picker think burp
            # had been tried and tested_keys locked the slot. Now the picker
            # excludes burp from available_tools after the first 78.
            exit_code=78,
            stdout=f"Burp Suite Pro is not configured ({exc}). Install Burp Suite Pro and set BURP_API_URL to enable this runner. Skipping.",
            stderr="",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": str(exc)},
        )
    scope_allowlist = scope_allowlist or {}
    normalized_targets: list[str] = []
    seen_targets: set[str] = set()
    for target in targets:
        normalized_target = normalize_http_target(target)
        if not _burp_target_is_allowed(scope_allowlist, normalized_target):
            raise ValueError(f"target outside scope: {normalized_target}")
        if normalized_target in seen_targets:
            continue
        seen_targets.add(normalized_target)
        normalized_targets.append(normalized_target)

    effective_timeout_seconds = max(timeout_seconds, 30.0)
    normalized_named_scan_configurations = [
        item.strip()
        for item in list(named_scan_configurations or [])
        if isinstance(item, str) and item.strip()
    ]
    results: list[dict[str, object]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(timeout=10.0, follow_redirects=True) as client:
        tool_version = get_burp_version(client, api_root=api_root)

        for target in normalized_targets:
            try:
                scan_payload = _request_burp_json(
                    client,
                    method="POST",
                    api_root=api_root,
                    path="scan",
                    json_body={
                        "urls": [target],
                        "named_scan_configurations": normalized_named_scan_configurations,
                        **({"scan_definition": scan_definition} if isinstance(scan_definition, dict) else {}),
                    },
                )
                scan_id = _scan_id_from_payload(scan_payload)
                completion_payload = _wait_for_scan_completion(
                    client,
                    api_root=api_root,
                    scan_id=scan_id,
                    timeout_seconds=effective_timeout_seconds,
                )
                issues = _collect_scan_issues(
                    client,
                    api_root=api_root,
                    scan_id=scan_id,
                    fallback_payload=completion_payload,
                )
                severity_counts = dict(
                    Counter(
                        str(
                            issue.get("severity")
                            or issue.get("issue_severity")
                            or "info"
                        ).strip().lower()
                        or "info"
                        for issue in issues
                    )
                )
                results.append(
                    {
                        "target": target,
                        "ok": True,
                        "scan_id": scan_id,
                        "status": str(completion_payload.get("status") or "completed"),
                        "issues": issues,
                        "issue_count": len(issues),
                        "severity_counts": severity_counts,
                    }
                )
            except (httpx_client.HTTPError, RuntimeError, TimeoutError, ValueError) as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")
                results.append(
                    {
                        "target": target,
                        "ok": False,
                        "error": str(exc),
                    }
                )

    successful_results = [result for result in results if result.get("ok")]
    issue_count = sum(int(result.get("issue_count", 0)) for result in successful_results)
    artifact_payload = {
        "results": results,
        "summary": {
            "target_count": len(normalized_targets),
            "success_count": len(successful_results),
            "issue_count": issue_count,
            "named_scan_configurations": normalized_named_scan_configurations,
        },
    }
    artifact = EvidenceArtifact(
        name=BURP_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(artifact_payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="scan-results",
    )

    return RunnerExecution(
        tool="burp",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "normalized_targets": normalized_targets,
            "rate_limit": rate_limit,
            "timeout_seconds": timeout_seconds,
            "effective_timeout_seconds": effective_timeout_seconds,
            "tool_version": tool_version,
            "runner_digest": "workers.burp.runner:v1",
            "issue_count": issue_count,
        },
        artifacts=[artifact],
    )
