from __future__ import annotations

import json
import time
from collections import Counter
from uuid import uuid4

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target


def build_zap_api_url(
    base_url: str,
    component: str,
    category: str,
    name: str,
) -> str:
    normalized_base_url = base_url.strip().rstrip("/")
    if not normalized_base_url:
        raise ValueError("base_url must not be blank")
    if not component.strip():
        raise ValueError("component must not be blank")
    if not category.strip():
        raise ValueError("category must not be blank")
    if not name.strip():
        raise ValueError("name must not be blank")

    return f"{normalized_base_url}/JSON/{component}/{category}/{name}/"


def _request_zap_json(
    client: httpx_client.Client,
    *,
    base_url: str,
    component: str,
    category: str,
    name: str,
    api_key: str,
    params: dict[str, object] | None = None,
) -> dict[str, object]:
    normalized_api_key = api_key.strip()
    if not normalized_api_key:
        raise ValueError("api_key must not be blank")

    request_params = {"apikey": normalized_api_key}
    if params:
        request_params.update(params)

    response = client.get(
        build_zap_api_url(base_url, component, category, name),
        params=request_params,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"unexpected ZAP API response for {component}/{category}/{name}")
    return payload


def get_zap_version(
    client: httpx_client.Client,
    *,
    base_url: str,
    api_key: str,
) -> str:
    payload = _request_zap_json(
        client,
        base_url=base_url,
        component="core",
        category="view",
        name="version",
        api_key=api_key,
    )
    version = str(payload.get("version", "")).strip()
    return version or "zaproxy"


def _wait_for_spider_completion(
    client: httpx_client.Client,
    *,
    base_url: str,
    api_key: str,
    scan_id: str,
    timeout_seconds: float,
) -> str:
    deadline = time.monotonic() + max(timeout_seconds, 30.0)
    last_status = "0"

    while time.monotonic() < deadline:
        payload = _request_zap_json(
            client,
            base_url=base_url,
            component="spider",
            category="view",
            name="status",
            api_key=api_key,
            params={"scanId": scan_id},
        )
        last_status = str(payload.get("status", "0")).strip() or "0"
        if last_status.isdigit() and int(last_status) >= 100:
            return last_status
        time.sleep(0.5)

    raise TimeoutError(f"ZAP spider did not finish in time; last status={last_status}")


def _wait_for_passive_queue(
    client: httpx_client.Client,
    *,
    base_url: str,
    api_key: str,
    timeout_seconds: float,
) -> int:
    deadline = time.monotonic() + max(timeout_seconds, 30.0)
    last_pending = 0

    while time.monotonic() < deadline:
        payload = _request_zap_json(
            client,
            base_url=base_url,
            component="pscan",
            category="view",
            name="recordsToScan",
            api_key=api_key,
        )
        pending = str(payload.get("recordsToScan", "0")).strip() or "0"
        last_pending = int(pending) if pending.isdigit() else 0
        if last_pending <= 0:
            return last_pending
        time.sleep(0.5)

    raise TimeoutError(f"ZAP passive queue did not drain in time; records_to_scan={last_pending}")


def _wait_for_active_scan_completion(
    client: httpx_client.Client,
    *,
    base_url: str,
    api_key: str,
    scan_id: str,
    timeout_seconds: float,
) -> str:
    deadline = time.monotonic() + max(timeout_seconds, 30.0)
    last_status = "0"

    while time.monotonic() < deadline:
        payload = _request_zap_json(
            client,
            base_url=base_url,
            component="ascan",
            category="view",
            name="status",
            api_key=api_key,
            params={"scanId": scan_id},
        )
        last_status = str(payload.get("status", "0")).strip() or "0"
        if last_status.isdigit() and int(last_status) >= 100:
            return last_status
        time.sleep(0.5)

    raise TimeoutError(f"ZAP active scan did not finish in time; last status={last_status}")


def _collect_alerts(
    client: httpx_client.Client,
    *,
    base_url: str,
    api_key: str,
    target: str,
) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    start = 0
    page_size = 500

    while True:
        payload = _request_zap_json(
            client,
            base_url=base_url,
            component="core",
            category="view",
            name="alerts",
            api_key=api_key,
            params={"baseurl": target, "start": start, "count": page_size},
        )
        page = payload.get("alerts", [])
        if not isinstance(page, list):
            raise RuntimeError("unexpected ZAP alerts payload")
        alerts.extend(alert for alert in page if isinstance(alert, dict))
        if len(page) < page_size:
            return alerts
        start += len(page)


def execute_zap_scan(
    targets: list[str],
    *,
    base_url: str,
    api_key: str,
    rate_limit: int = 1,
    timeout_seconds: float = 30.0,
    scan_mode: str = "spider-passive",
    active_scanner_ids: list[str] | None = None,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    normalized_scan_mode = scan_mode.strip().lower() or "spider-passive"
    if normalized_scan_mode not in {"spider-passive", "spider-active-passive"}:
        raise ValueError(f"unsupported ZAP scan mode: {scan_mode}")
    normalized_active_scanner_ids = [
        str(scanner_id).strip()
        for scanner_id in (active_scanner_ids or [])
        if str(scanner_id).strip().isdigit()
    ]

    normalized_targets: list[str] = []
    seen_targets: set[str] = set()
    for target in targets:
        normalized_target = normalize_http_target(target)
        if normalized_target in seen_targets:
            continue
        seen_targets.add(normalized_target)
        normalized_targets.append(normalized_target)
    effective_timeout_seconds = max(timeout_seconds, 30.0)
    results: list[dict[str, object]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with httpx_client.Client(timeout=10.0, follow_redirects=True) as client:
        tool_version = get_zap_version(client, base_url=base_url, api_key=api_key)

        for index, target in enumerate(normalized_targets, start=1):
            session_name = f"aegispt-{uuid4().hex[:12]}-{index}"
            try:
                _request_zap_json(
                    client,
                    base_url=base_url,
                    component="core",
                    category="action",
                    name="newSession",
                    api_key=api_key,
                    params={"name": session_name, "overwrite": "true"},
                )
                _request_zap_json(
                    client,
                    base_url=base_url,
                    component="core",
                    category="action",
                    name="accessUrl",
                    api_key=api_key,
                    params={"url": target, "followRedirects": "true"},
                )
                spider_payload = _request_zap_json(
                    client,
                    base_url=base_url,
                    component="spider",
                    category="action",
                    name="scan",
                    api_key=api_key,
                    params={"url": target, "recurse": "true", "maxChildren": "10"},
                )
                scan_id = str(spider_payload.get("scan", "")).strip() or "0"
                spider_status = _wait_for_spider_completion(
                    client,
                    base_url=base_url,
                    api_key=api_key,
                    scan_id=scan_id,
                    timeout_seconds=effective_timeout_seconds,
                )
                records_to_scan = _wait_for_passive_queue(
                    client,
                    base_url=base_url,
                    api_key=api_key,
                    timeout_seconds=effective_timeout_seconds,
                )
                active_scan_id = None
                active_scan_status = None
                if normalized_scan_mode == "spider-active-passive":
                    if normalized_active_scanner_ids:
                        _request_zap_json(
                            client,
                            base_url=base_url,
                            component="ascan",
                            category="action",
                            name="enableScanners",
                            api_key=api_key,
                            params={"ids": ",".join(normalized_active_scanner_ids)},
                        )
                    active_scan_payload = _request_zap_json(
                        client,
                        base_url=base_url,
                        component="ascan",
                        category="action",
                        name="scan",
                        api_key=api_key,
                        params={"url": target, "recurse": "true", "inScopeOnly": "false"},
                    )
                    active_scan_id = str(active_scan_payload.get("scan", "")).strip() or "0"
                    active_scan_status = _wait_for_active_scan_completion(
                        client,
                        base_url=base_url,
                        api_key=api_key,
                        scan_id=active_scan_id,
                        timeout_seconds=effective_timeout_seconds,
                    )
                    records_to_scan = _wait_for_passive_queue(
                        client,
                        base_url=base_url,
                        api_key=api_key,
                        timeout_seconds=effective_timeout_seconds,
                    )
                urls_payload = _request_zap_json(
                    client,
                    base_url=base_url,
                    component="core",
                    category="view",
                    name="urls",
                    api_key=api_key,
                    params={"baseurl": target},
                )
                urls = urls_payload.get("urls", [])
                if not isinstance(urls, list):
                    raise RuntimeError("unexpected ZAP urls payload")

                alerts = _collect_alerts(
                    client,
                    base_url=base_url,
                    api_key=api_key,
                    target=target,
                )
                severity_counts = dict(
                    Counter(
                        str(alert.get("risk", "informational")).strip().lower() or "informational"
                        for alert in alerts
                    )
                )
                results.append(
                    {
                        "target": target,
                        "ok": True,
                        "session_name": session_name,
                        "scan_mode": normalized_scan_mode,
                        "spider_scan_id": scan_id,
                        "spider_status": spider_status,
                        "active_scan_id": active_scan_id,
                        "active_scan_status": active_scan_status,
                        "active_scanner_ids": normalized_active_scanner_ids,
                        "records_to_scan": records_to_scan,
                        "urls": urls,
                        "alerts": alerts,
                        "alert_count": len(alerts),
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
                        "scan_mode": normalized_scan_mode,
                        "error": str(exc),
                    }
                )

    successful_results = [result for result in results if result.get("ok")]
    alert_count = sum(int(result.get("alert_count", 0)) for result in successful_results)
    url_count = sum(len(result.get("urls", [])) for result in successful_results)
    artifact_payload = {
        "results": results,
        "summary": {
            "target_count": len(normalized_targets),
            "success_count": len(successful_results),
            "alert_count": alert_count,
            "url_count": url_count,
            "scan_mode": normalized_scan_mode,
        },
    }
    artifact = EvidenceArtifact(
        name="zap-results.json",
        content_type="application/json",
        data=(json.dumps(artifact_payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="scan-results",
    )

    return RunnerExecution(
        tool="zap",
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
            "runner_digest": "workers.zap.runner:v1",
            "scan_mode": normalized_scan_mode,
            "active_scanner_ids": normalized_active_scanner_ids,
            "alert_count": alert_count,
            "url_count": url_count,
        },
        artifacts=[artifact],
    )
