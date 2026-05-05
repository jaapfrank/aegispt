from __future__ import annotations

import json
import socket
import ssl
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME = "http-smuggling-results.json"
MAX_PROBE_TIMEOUT_SECONDS = 5.0
DEFAULT_TIMING_THRESHOLD_SECONDS = 4.5
PROXY_EVIDENCE_HEADERS = ("via", "forwarded")
PROXY_EVIDENCE_HEADER_PREFIXES = ("x-forwarded-",)


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    variant: str
    description: str


@dataclass(frozen=True, slots=True)
class SmugglingProbeResult:
    variant: str
    elapsed_seconds: float
    timed_out: bool = False
    response_status_line: str | None = None
    error: str | None = None


PROBE_SPECS: tuple[ProbeSpec, ...] = (
    ProbeSpec(
        variant="CL.TE",
        description="Content-Length plus Transfer-Encoding conflict timing probe",
    ),
    ProbeSpec(
        variant="TE.CL",
        description="Transfer-Encoding plus Content-Length conflict timing probe",
    ),
    ProbeSpec(
        variant="TE.TE",
        description="Duplicate or obfuscated Transfer-Encoding timing probe",
    ),
)


def _json_artifact(
    name: str,
    payload: dict[str, Any],
    *,
    kind: str = "runner-results",
) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved HTTP smuggling/web scope: {url}")


def _normalize_targets(targets: list[str], scope_allowlist: dict[str, Any] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for target in targets:
        candidate = normalize_http_target(str(target or "").strip())
        if not candidate:
            continue
        _assert_allowed(scope_allowlist, candidate)
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("at least one target is required")
    return normalized


def _bounded_timeout(timeout_seconds: float | int | None) -> float:
    try:
        value = float(timeout_seconds if timeout_seconds is not None else MAX_PROBE_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        value = MAX_PROBE_TIMEOUT_SECONDS
    if value <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    return min(value, MAX_PROBE_TIMEOUT_SECONDS)


def _bounded_threshold(
    timing_threshold_seconds: float | int | None,
    timeout_seconds: float,
) -> float:
    try:
        value = float(
            timing_threshold_seconds
            if timing_threshold_seconds is not None
            else DEFAULT_TIMING_THRESHOLD_SECONDS
        )
    except (TypeError, ValueError):
        value = DEFAULT_TIMING_THRESHOLD_SECONDS
    if value <= 0:
        raise ValueError("timing_threshold_seconds must be greater than zero")
    return min(value, timeout_seconds)


def _is_proxy_evidence_header(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return normalized in PROXY_EVIDENCE_HEADERS or any(
        normalized.startswith(prefix) for prefix in PROXY_EVIDENCE_HEADER_PREFIXES
    )


def _safe_header_value(value: object) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:160]


def _headers_to_proxy_evidence(
    headers: httpx_client.Headers | dict[str, Any],
    *,
    source: str,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for name, value in headers.items():
        if not _is_proxy_evidence_header(str(name)):
            continue
        safe_value = _safe_header_value(value)
        if not safe_value:
            continue
        evidence.append(
            {
                "source": source,
                "header": str(name),
                "value_excerpt": safe_value,
                "value_sha256": sha256(safe_value.encode("utf-8")).hexdigest(),
            }
        )
    return evidence


def _configured_proxy_evidence_for_target(
    target: str,
    configured_proxy_evidence: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for raw_item in configured_proxy_evidence or []:
        if not isinstance(raw_item, dict):
            continue
        raw_target = str(raw_item.get("target") or raw_item.get("url") or "").strip()
        if raw_target:
            try:
                candidate = normalize_http_target(raw_target)
            except ValueError:
                continue
            if urlparse(candidate).netloc != urlparse(target).netloc:
                continue
        raw_headers = raw_item.get("headers")
        headers = raw_headers if isinstance(raw_headers, dict) else {}
        for item in _headers_to_proxy_evidence(headers, source="configured-proxy-evidence"):
            item["configured_target"] = raw_target or "all-targets"
            evidence.append(item)
    return evidence


def _request_target(parsed_url) -> str:
    path = parsed_url.path or "/"
    if parsed_url.query:
        return f"{path}?{parsed_url.query}"
    return path


def _host_header(parsed_url) -> str:
    host = parsed_url.hostname or ""
    if parsed_url.port:
        return f"{host}:{parsed_url.port}"
    return host


def _probe_request_bytes(url: str, spec: ProbeSpec) -> bytes:
    parsed = urlparse(url)
    request_target = _request_target(parsed)
    host_header = _host_header(parsed)
    base_headers = (
        f"POST {request_target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: AegisPT/http-smuggling timing-validation\r\n"
        "Accept: */*\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: close\r\n"
    )
    if spec.variant == "CL.TE":
        payload = (
            base_headers
            + "Content-Length: 6\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "\r\n"
            + "0\r\n\r\n"
        )
    elif spec.variant == "TE.CL":
        payload = (
            base_headers
            + "Transfer-Encoding: chunked\r\n"
            + "Content-Length: 4\r\n"
            + "\r\n"
            + "1\r\nx\r\n0\r\n\r\n"
        )
    elif spec.variant == "TE.TE":
        payload = (
            base_headers
            + "Transfer-Encoding: xchunked\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Content-Length: 6\r\n"
            + "\r\n"
            + "0\r\n\r\n"
        )
    else:
        raise ValueError(f"unsupported HTTP smuggling probe variant: {spec.variant}")
    return payload.encode("ascii")


def _default_probe_sender(
    target: str,
    spec: ProbeSpec,
    timeout_seconds: float,
) -> SmugglingProbeResult:
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        raise ValueError(f"target host is required: {target}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    payload = _probe_request_bytes(target, spec)
    start = time.monotonic()
    timed_out = False
    status_line: str | None = None
    error: str | None = None
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout_seconds)
        raw_sock.settimeout(timeout_seconds)
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        sock.sendall(payload)
        try:
            response = sock.recv(512)
            if response:
                status_line = response.splitlines()[0].decode("iso-8859-1", errors="replace")[:160]
        except socket.timeout:
            timed_out = True
    except socket.timeout:
        timed_out = True
    except OSError as exc:
        error = str(exc)[:240]
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    elapsed = min(time.monotonic() - start, timeout_seconds)
    return SmugglingProbeResult(
        variant=spec.variant,
        elapsed_seconds=round(elapsed, 4),
        timed_out=timed_out,
        response_status_line=status_line,
        error=error,
    )


def _append_timing_finding(
    findings: list[dict[str, Any]],
    *,
    target: str,
    spec: ProbeSpec,
    result: SmugglingProbeResult,
    timing_threshold_seconds: float,
    timeout_seconds: float,
    proxy_evidence: list[dict[str, Any]],
) -> None:
    findings.append(
        {
            "type": "http_request_smuggling_timing_confirmed",
            "title": f"HTTP Request Smuggling ({spec.variant}) - Timing Confirmed",
            "severity": "critical",
            "target": target,
            "summary": (
                f"{spec.variant} request desynchronization timing signal observed on an "
                "approved proxy-backed target."
            ),
            "confirmed": True,
            "methodology_tags": [
                "input_validation",
                "http_request_smuggling",
                "http-smuggling-validation",
            ],
            "control_family": "input_validation",
            "evidence": {
                "variant": spec.variant,
                "description": spec.description,
                "elapsed_seconds": result.elapsed_seconds,
                "timed_out": result.timed_out,
                "timing_threshold_seconds": timing_threshold_seconds,
                "timeout_seconds": timeout_seconds,
                "proxy_evidence": proxy_evidence,
                "response_status_line": result.response_status_line,
                "error": result.error,
                "timing_based_detection_only": True,
                "confirming_request_sent": False,
                "visible_side_effect_request_sent": False,
                "request_hijacking_attempted": False,
                "cache_poisoning_attempted": False,
                "internal_endpoint_access_attempted": False,
            },
            "replay_recipe": {
                "tool": "http-smuggling",
                "target": target,
                "scope": "approved-proxy-backed-web-root-only",
                "variant": spec.variant,
                "timeout_seconds": timeout_seconds,
                "timing_threshold_seconds": timing_threshold_seconds,
                "confirming_request_sent": False,
                "visible_side_effect_request_sent": False,
            },
        }
    )


def execute_http_smuggling_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    proxy_evidence: list[dict[str, Any]] | None = None,
    timing_threshold_seconds: float = DEFAULT_TIMING_THRESHOLD_SECONDS,
    timeout_seconds: float = MAX_PROBE_TIMEOUT_SECONDS,
    client_factory: Callable[..., httpx_client.Client] = httpx_client.Client,
    probe_sender: Callable[[str, ProbeSpec, float], SmugglingProbeResult] | None = None,
) -> RunnerExecution:
    normalized_targets = _normalize_targets(targets, scope_allowlist)
    bounded_timeout = _bounded_timeout(timeout_seconds)
    bounded_threshold = _bounded_threshold(timing_threshold_seconds, bounded_timeout)
    sender = probe_sender or _default_probe_sender

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0
    skipped_targets = 0
    sent_probe_count = 0

    with client_factory(
        follow_redirects=False,
        timeout=bounded_timeout,
        verify=False,
        headers={"User-Agent": "AegisPT/http-smuggling proxy-evidence-check"},
    ) as client:
        for target in normalized_targets:
            target_proxy_evidence: list[dict[str, Any]] = []
            baseline_check: dict[str, Any] = {
                "check_type": "proxy_evidence_gate",
                "target": target,
                "proxy_evidence_present": False,
                "probes_sent": 0,
            }
            try:
                response = client.get(target)
                baseline_check.update(
                    {
                        "status_code": response.status_code,
                        "response_header_count": len(response.headers),
                    }
                )
                target_proxy_evidence.extend(
                    _headers_to_proxy_evidence(
                        response.headers,
                        source="response-header",
                    )
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                message = f"proxy evidence check failed for {target}: {exc}"
                stderr_lines.append(message)
                baseline_check["error"] = str(exc)

            target_proxy_evidence.extend(
                _configured_proxy_evidence_for_target(target, proxy_evidence)
            )
            baseline_check["proxy_evidence"] = target_proxy_evidence
            baseline_check["proxy_evidence_present"] = bool(target_proxy_evidence)
            if not target_proxy_evidence:
                skipped_targets += 1
                baseline_check["skip_reason"] = "proxy evidence missing"
                checks.append(baseline_check)
                continue

            checks.append(baseline_check)
            for spec in PROBE_SPECS:
                result = sender(target, spec, bounded_timeout)
                sent_probe_count += 1
                timing_signal = result.timed_out or result.elapsed_seconds >= bounded_threshold
                checks.append(
                    {
                        "check_type": "timing_probe",
                        "target": target,
                        "variant": spec.variant,
                        "description": spec.description,
                        "elapsed_seconds": result.elapsed_seconds,
                        "timed_out": result.timed_out,
                        "timing_threshold_seconds": bounded_threshold,
                        "timeout_seconds": bounded_timeout,
                        "timing_signal": timing_signal,
                        "response_status_line": result.response_status_line,
                        "error": result.error,
                        "confirming_request_sent": False,
                        "visible_side_effect_request_sent": False,
                    }
                )
                if timing_signal:
                    _append_timing_finding(
                        findings,
                        target=target,
                        spec=spec,
                        result=result,
                        timing_threshold_seconds=bounded_threshold,
                        timeout_seconds=bounded_timeout,
                        proxy_evidence=target_proxy_evidence,
                    )

    payload = {
        "tool": "http-smuggling",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "proxy_backed_target_count": len(normalized_targets) - skipped_targets,
            "skipped_target_count": skipped_targets,
            "sent_probe_count": sent_probe_count,
            "check_count": len(checks),
            "finding_count": len(findings),
            "cl_te_findings": sum(1 for item in findings if "(CL.TE)" in str(item.get("title"))),
            "te_cl_findings": sum(1 for item in findings if "(TE.CL)" in str(item.get("title"))),
            "te_te_findings": sum(1 for item in findings if "(TE.TE)" in str(item.get("title"))),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_roots_only": True,
            "active_tier_requires_approval": True,
            "proxy_evidence_required": True,
            "probe_variants": [spec.variant for spec in PROBE_SPECS],
            "timing_based_detection_only": True,
            "max_probe_timeout_seconds": bounded_timeout,
            "timing_threshold_seconds": bounded_threshold,
            "confirming_request_sent": False,
            "visible_side_effect_request_sent": False,
            "request_hijacking_attempted": False,
            "cache_poisoning_attempted": False,
            "waf_bypass_attempted": False,
            "internal_endpoint_access_attempted": False,
            "runtime_mutation": False,
            "zap_configuration_changed": False,
            "ssl_tls_runner_changed": False,
        },
    }
    return RunnerExecution(
        tool="http-smuggling",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.http_smuggling.runner:v1",
            "tool_version": "custom-python-timing-only",
            "finding_count": len(findings),
            "check_count": len(checks),
            "sent_probe_count": sent_probe_count,
        },
        artifacts=[_json_artifact(HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME, payload)],
    )
