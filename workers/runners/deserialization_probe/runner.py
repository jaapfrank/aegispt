from __future__ import annotations

import base64
import binascii
import json
import re
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base import http_probe
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

DESERIALIZATION_RESULTS_ARTIFACT_NAME = "deserialization-results.json"
DEFAULT_CALLBACK_TOKEN = "aegispt-deserialization-oob"
JAVA_SERIALIZED_BASE64_PREFIX = "rO0AB"
JAVA_SERIALIZED_HEX_PREFIX = "aced0005"
PHP_OBJECT_PROBE = 'O:4:"Test":0:{}'
PICKLE_PROBE_BASE64 = base64.b64encode(b"\x80\x04}\x94.").decode("ascii")
DEFAULT_PARAMETER_NAMES = (
    "data",
    "payload",
    "object",
    "state",
    "serialized",
    "token",
    "viewstate",
    "__VIEWSTATE",
)
PHP_ERROR_MARKERS = (
    "unserialize()",
    "unserialize():",
    "__PHP_Incomplete_Class",
    "Error at offset",
    "object injection",
    "serialization error",
)
PICKLE_ERROR_MARKERS = (
    "pickle.UnpicklingError",
    "UnpicklingError",
    "invalid load key",
    "pickle data was truncated",
    "EOFError",
    "application/x-python-pickle",
)
NODE_SERIALIZE_MARKERS = ("node-serialize", "_$$ND_FUNC$$_", "serialized javascript function")


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
    evidence_records: object,
    candidate_paths: object,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source in (request_contexts, evidence_records):
        if isinstance(source, list):
            records.extend(item for item in source if isinstance(item, dict))
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


def _inject_query_parameter(url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    pairs[parameter] = payload
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _url_parameters(record: dict[str, Any], url: str) -> list[str]:
    configured = _normalize_string_list(record.get("parameters"), limit=20)
    if configured:
        return configured
    names = [
        name
        for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
        if name in DEFAULT_PARAMETER_NAMES or name.lower() in {item.lower() for item in DEFAULT_PARAMETER_NAMES}
    ]
    return list(dict.fromkeys(names or ["data"]))


def _callback_url(callback_url: str | None, callback_base_url: str | None, token: str) -> str | None:
    if callback_url:
        return callback_url
    if callback_base_url:
        return callback_base_url.rstrip("/") + "/" + token
    return None


def _java_urldns_probe_payload(callback_payload: str) -> str:
    # Synthetic Java serialization stream marker with URLDNS-only intent; it is not a gadget RCE chain.
    raw = (
        b"\xac\xed\x00\x05"
        + b"aegispt-ysoserial-urldns-only:"
        + callback_payload.encode("utf-8")
    )
    return base64.b64encode(raw).decode("ascii")


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


def _marker_found(text: str, markers: tuple[str, ...]) -> str | None:
    lowered = text.lower()
    for marker in markers:
        if marker.lower() in lowered:
            return marker
    return None


def _values_from_record(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("value", "payload", "body", "request_body", "raw_request", "cookie", "header"):
        value = record.get(key)
        if isinstance(value, str) and value:
            values.append(value)
    for container_key in ("parameters", "cookies", "headers"):
        container = record.get(container_key)
        if isinstance(container, dict):
            values.extend(str(value) for value in container.values() if str(value))
        elif isinstance(container, list):
            values.extend(str(value) for value in container if str(value))
    parsed = urlparse(str(record.get("url") or ""))
    values.extend(value for _, value in parse_qsl(parsed.query, keep_blank_values=True) if value)
    return values


def _has_java_serialized_marker(record: dict[str, Any]) -> bool:
    haystack = " ".join(_values_from_record(record)).strip()
    compact = re.sub(r"[^A-Za-z0-9+/=]", "", haystack)
    hex_compact = re.sub(r"[^A-Fa-f0-9]", "", haystack).lower()
    return (
        JAVA_SERIALIZED_BASE64_PREFIX in compact
        or hex_compact.startswith(JAVA_SERIALIZED_HEX_PREFIX)
        or bool(record.get("java_serialized_marker"))
    )


def _has_pickle_signal(record: dict[str, Any]) -> bool:
    content_type = str(record.get("content_type") or record.get("Content-Type") or "").lower()
    if "application/x-python-pickle" in content_type:
        return True
    for value in _values_from_record(record):
        candidate = value.strip()
        if candidate.startswith(("gAS", "gAJ", "gAN", "c__")):
            return True
        try:
            decoded = base64.b64decode(candidate + "==", validate=False)
        except (binascii.Error, ValueError):
            continue
        if decoded.startswith((b"\x80\x02", b"\x80\x03", b"\x80\x04", b"c")):
            return True
    return bool(record.get("python_pickle_signal"))


def _viewstate_values(record: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    candidates: list[tuple[str, dict[str, Any]]] = []
    params = record.get("parameters")
    if isinstance(params, dict):
        for key, value in params.items():
            if str(key).lower() == "__viewstate":
                candidates.append((str(value), params))
    if isinstance(record.get("__VIEWSTATE"), str):
        candidates.append((str(record["__VIEWSTATE"]), record))
    parsed = urlparse(str(record.get("url") or ""))
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if "__VIEWSTATE" in query:
        candidates.append((query["__VIEWSTATE"], query))
    return candidates


def _viewstate_is_unprotected(value: str, params: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    try:
        decoded = base64.b64decode(value + "==", validate=False)
    except (binascii.Error, ValueError):
        return False, {"reason": "viewstate was not decodable"}
    has_mac_field = any(str(key).lower() in {"__eventvalidation", "__viewstatemac"} for key in params)
    encrypted = any(str(key).lower() == "__viewstateencrypted" for key in params)
    looks_like_viewstate = decoded.startswith((b"\xff\x01", b"\x00\x01")) or b"System.Web.UI" in decoded
    unprotected = looks_like_viewstate and not has_mac_field and not encrypted
    return unprotected, {
        "decoded_prefix_hex": decoded[:8].hex(),
        "decoded_size": len(decoded),
        "has_eventvalidation_or_mac_field": has_mac_field,
        "has_viewstate_encrypted_field": encrypted,
    }


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
            "methodology_tags": [
                "deserialization",
                "owasp-a08",
                "input_validation",
                "deserialization-probe",
            ],
            "evidence": evidence,
            "replay_recipe": {
                "tool": "deserialization-probe",
                "target": target,
                "scope": "approved-web-root-only",
            },
        }
    )


def execute_deserialization_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    request_contexts: list[dict[str, Any]] | object = None,
    evidence_records: list[dict[str, Any]] | object = None,
    candidate_paths: list[str] | object = None,
    oob_confirmation_refs: list[dict[str, Any]] | object = None,
    callback_url: str | None = None,
    callback_base_url: str | None = None,
    callback_token: str = DEFAULT_CALLBACK_TOKEN,
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
    java_payload = _java_urldns_probe_payload(callback_payload) if callback_payload else None

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0
    outcome = http_probe.ProbeOutcome()  # retry-on-unreachable + honest exit code

    with client_factory(follow_redirects=False, timeout=timeout_seconds) as client:
        for base_target in normalized_targets:
            records = _candidate_request_records(
                base_target,
                request_contexts=request_contexts,
                evidence_records=evidence_records,
                candidate_paths=candidate_paths,
                scope_allowlist=scope_allowlist,
            )
            for record in records:
                url = str(record["url"])
                java_marker = _has_java_serialized_marker(record)
                pickle_signal = _has_pickle_signal(record)
                viewstate_entries = _viewstate_values(record)
                php_candidate = bool(record.get("php_object_candidate")) or not (
                    java_marker or pickle_signal or viewstate_entries
                )

                if java_marker and java_payload:
                    for parameter in _url_parameters(record, url):
                        requested_url = _inject_query_parameter(url, parameter, java_payload)
                        try:
                            response = outcome.run(lambda: client.get(
                                requested_url,
                                headers={
                                    "User-Agent": "AegisPT/deserialization-probe URLDNS-only",
                                },
                            ))
                        except httpx_client.HTTPError as exc:
                            stderr_lines.append(f"Java URLDNS probe failed for {url}: {exc}")
                            continue
                        check = {
                            "check_type": "java_urldns",
                            "target": requested_url,
                            "parameter": parameter,
                            "status_code": response.status_code,
                            "response_hash": _response_hash(response),
                            "serialized_marker_detected": True,
                            "payload_family": "ysoserial-url-dns-only",
                        }
                        checks.append(check)
                        oob = _confirmed_oob(java_payload, callback_token, oob_confirmation_refs)
                        if oob:
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="java_urldns_confirmed_deserialization",
                                title="Java Deserialization - Potential RCE (ysoserial URLDNS confirmed)",
                                severity="critical",
                                target=url,
                                summary="A Java serialized-object input produced governed URLDNS callback evidence. The probe used DNS-only confirmation and no command execution payload.",
                                evidence={**check, **oob},
                            )

                if php_candidate:
                    for parameter in _url_parameters(record, url):
                        requested_url = _inject_query_parameter(url, parameter, PHP_OBJECT_PROBE)
                        try:
                            response = outcome.run(lambda: client.get(
                                requested_url,
                                headers={
                                    "User-Agent": "AegisPT/deserialization-probe PHP object check",
                                },
                            ))
                        except httpx_client.HTTPError as exc:
                            stderr_lines.append(f"PHP object probe failed for {url}: {exc}")
                            continue
                        marker = _marker_found(response.text or "", PHP_ERROR_MARKERS)
                        check = {
                            "check_type": "php_object_injection",
                            "target": requested_url,
                            "parameter": parameter,
                            "status_code": response.status_code,
                            "response_hash": _response_hash(response),
                        }
                        checks.append(check)
                        if marker:
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="php_object_injection_error_signal",
                                title="PHP Object Injection - Serialized Object Accepted",
                                severity="high",
                                target=url,
                                summary="A bounded PHP serialized object probe produced unserialize/object-injection error markers.",
                                evidence={
                                    **check,
                                    "matched_marker": marker,
                                    "response_excerpt": _body_excerpt(response),
                                },
                            )

                if pickle_signal:
                    for parameter in _url_parameters(record, url):
                        requested_url = _inject_query_parameter(url, parameter, PICKLE_PROBE_BASE64)
                        try:
                            response = outcome.run(lambda: client.get(
                                requested_url,
                                headers={
                                    "User-Agent": "AegisPT/deserialization-probe pickle check",
                                },
                            ))
                        except httpx_client.HTTPError as exc:
                            stderr_lines.append(f"Python pickle probe failed for {url}: {exc}")
                            continue
                        marker = _marker_found(response.text or "", PICKLE_ERROR_MARKERS)
                        check = {
                            "check_type": "python_pickle",
                            "target": requested_url,
                            "parameter": parameter,
                            "status_code": response.status_code,
                            "response_hash": _response_hash(response),
                            "pickle_signal_detected": True,
                        }
                        checks.append(check)
                        if marker or 200 <= response.status_code < 300:
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="python_pickle_acceptance_signal",
                                title="Python Pickle Deserialization Acceptance Signal",
                                severity="high",
                                target=url,
                                summary="An explicit pickle endpoint or pickle-like input produced an acceptance/error signal for Python pickle data.",
                                evidence={
                                    **check,
                                    "matched_marker": marker or "pickle probe accepted",
                                    "response_excerpt": _body_excerpt(response),
                                },
                            )

                node_marker = _marker_found(" ".join(_values_from_record(record)), NODE_SERIALIZE_MARKERS)
                if node_marker:
                    checks.append(
                        {
                            "check_type": "node_serialize_signal",
                            "target": url,
                            "matched_marker": node_marker,
                            "active_probe_sent": False,
                        }
                    )

                for viewstate, viewstate_params in viewstate_entries:
                    unprotected, details = _viewstate_is_unprotected(viewstate, viewstate_params)
                    check = {
                        "check_type": "dotnet_viewstate",
                        "target": url,
                        **details,
                    }
                    checks.append(check)
                    if unprotected:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="dotnet_viewstate_unprotected",
                            title=".NET ViewState - Unsigned or Unencrypted State",
                            severity="medium",
                            target=url,
                            summary="A ViewState value decoded as ASP.NET state data without adjacent MAC/EventValidation or encryption indicators.",
                            evidence=check,
                        )

    payload = {
        "tool": "deserialization-probe",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "java_urldns_findings": sum(1 for finding in findings if finding.get("type") == "java_urldns_confirmed_deserialization"),
            "php_object_findings": sum(1 for finding in findings if finding.get("type") == "php_object_injection_error_signal"),
            "python_pickle_findings": sum(1 for finding in findings if finding.get("type") == "python_pickle_acceptance_signal"),
            "viewstate_findings": sum(1 for finding in findings if finding.get("type") == "dotnet_viewstate_unprotected"),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "requires_active_approval": True,
            "java_payload_family": "ysoserial-url-dns-only",
            "command_execution_payloads": False,
            "rce_gadget_chains": False,
            "commons_collections_payloads": False,
            "exfiltration": False,
        },
    }
    # Honest status: target unreachable for every probe -> skipped (78), not
    # FAILED; any real response -> completed even if some probes were refused.
    exit_code = outcome.exit_code(exit_code)
    return RunnerExecution(
        tool="deserialization-probe",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": (
                "ok" if exit_code == 0
                else "target_unreachable" if exit_code == http_probe.EX_TARGET_UNREACHABLE
                else "completed_with_errors"
            ),
            "runner_digest": "workers.deserialization_probe.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(DESERIALIZATION_RESULTS_ARTIFACT_NAME, payload)],
    )
