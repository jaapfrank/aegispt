from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

IDOR_BAC_ARTIFACT_NAME = "idor-bac-results.json"
MAX_ID_DELTA_LIMIT = 20
DEFAULT_ADMIN_PATHS = ("admin", "dashboard/admin", "api/admin/users", ".env")
UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


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


def _normalize_auth_contexts(auth_contexts: object) -> list[dict[str, Any]]:
    if not isinstance(auth_contexts, list):
        raise ValueError("idor-bac requires at least one authenticated access account")

    normalized: list[dict[str, Any]] = []
    for index, raw_context in enumerate(auth_contexts):
        if not isinstance(raw_context, dict):
            continue
        headers = raw_context.get("headers")
        normalized_headers = {
            str(key).strip(): str(value).strip()
            for key, value in (headers.items() if isinstance(headers, dict) else [])
            if str(key).strip() and str(value).strip()
        }

        basic_auth = raw_context.get("basic_auth")
        normalized_basic_auth = None
        if isinstance(basic_auth, dict):
            username = str(basic_auth.get("username") or "").strip()
            password = str(basic_auth.get("password") or "").strip()
            if username and password:
                normalized_basic_auth = (username, password)

        if not normalized_headers and normalized_basic_auth is None:
            continue

        label = str(raw_context.get("label") or raw_context.get("username") or f"Account {index + 1}").strip()
        normalized.append(
            {
                "label": label or f"Account {index + 1}",
                "role": str(raw_context.get("role") or "user").strip() or "user",
                "username": str(raw_context.get("username") or "").strip(),
                "tenant": str(raw_context.get("tenant") or raw_context.get("tenant_id") or "").strip(),
                "headers": normalized_headers,
                "basic_auth": normalized_basic_auth,
                "marker_tokens": _normalize_string_list(raw_context.get("marker_tokens"), limit=10),
                "owned_object_ids": _normalize_string_list(raw_context.get("owned_object_ids"), limit=100),
            }
        )

    if not normalized:
        raise ValueError("idor-bac requires at least one authenticated access account")
    return normalized


def _request_headers(auth_context: dict[str, Any] | None) -> dict[str, str]:
    if auth_context is None:
        return {"User-Agent": "AegisPT/idor-bac bounded access-control validation"}
    return {
        "User-Agent": "AegisPT/idor-bac bounded access-control validation",
        **dict(auth_context.get("headers") or {}),
    }


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved web scope: {url}")


def _render_url(base_target: str, value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return base_target
    if "://" in candidate:
        return normalize_http_target(candidate)
    return urljoin(base_target.rstrip("/") + "/", candidate.lstrip("/"))


def _link_urls(base_url: str, body: str) -> list[str]:
    links: list[str] = []
    for match in re.finditer(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", body, flags=re.I):
        links.append(urljoin(base_url, match.group(1)))
    return links


def _candidate_endpoint_urls(
    base_target: str,
    *,
    evidence_records: object,
    candidate_paths: object,
    scope_allowlist: dict[str, Any] | None,
) -> list[str]:
    candidates: list[str] = [base_target]
    for raw_path in _normalize_string_list(candidate_paths, limit=80):
        candidates.append(_render_url(base_target, raw_path))
    if isinstance(evidence_records, list):
        for item in evidence_records:
            if isinstance(item, str):
                candidates.append(_render_url(base_target, item))
            elif isinstance(item, dict):
                raw_url = item.get("url") or item.get("target") or item.get("request_url") or item.get("endpoint")
                if raw_url:
                    candidates.append(_render_url(base_target, str(raw_url)))

    normalized: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        url = normalize_http_target(candidate)
        if url in seen or not _allowed(scope_allowlist, url):
            continue
        seen.add(url)
        normalized.append(url)
    return normalized


def _numeric_candidate_values(original: str, known_ids: list[str], *, max_id_delta: int) -> list[str]:
    values: list[str] = []
    if not original.isdigit():
        return []
    number = int(original)
    for delta in (1, -1, 5, -5, 10, -10, max_id_delta, -max_id_delta):
        candidate = number + delta
        if candidate >= 0:
            values.append(str(candidate))
    values.extend(item for item in known_ids if item.isdigit() and abs(int(item) - number) <= max_id_delta)
    return _dedupe(values, limit=20)


def _uuid_candidate_values(original: str, known_ids: list[str]) -> list[str]:
    if not UUID_PATTERN.fullmatch(original):
        return []
    return _dedupe(
        [item for item in known_ids if UUID_PATTERN.fullmatch(item) and item.lower() != original.lower()],
        limit=20,
    )


def _dedupe(values: list[str], *, limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value).strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        result.append(candidate)
        if len(result) >= limit:
            break
    return result


def _replace_path_segment(url: str, original: str, replacement: str) -> str:
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    replaced = False
    for index, segment in enumerate(segments):
        if segment == original and not replaced:
            segments[index] = replacement
            replaced = True
    return urlunparse(parsed._replace(path="/".join(segments)))


def _replace_query_value(url: str, key: str, replacement: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(name, replacement if name == key else value) for name, value in pairs]
    return urlunparse(parsed._replace(query=urlencode(replaced)))


def _identifier_replacements(url: str, known_ids: list[str], *, max_id_delta: int) -> list[dict[str, str]]:
    parsed = urlparse(url)
    candidates: list[dict[str, str]] = []
    for segment in [item for item in parsed.path.split("/") if item]:
        replacement_values = _numeric_candidate_values(segment, known_ids, max_id_delta=max_id_delta)
        replacement_values.extend(_uuid_candidate_values(segment, known_ids))
        for replacement in _dedupe(replacement_values, limit=20):
            candidates.append(
                {
                    "source": "path",
                    "original": segment,
                    "replacement": replacement,
                    "url": _replace_path_segment(url, segment, replacement),
                }
            )
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        replacement_values = _numeric_candidate_values(value, known_ids, max_id_delta=max_id_delta)
        replacement_values.extend(_uuid_candidate_values(value, known_ids))
        for replacement in _dedupe(replacement_values, limit=20):
            candidates.append(
                {
                    "source": "query",
                    "original": value,
                    "replacement": replacement,
                    "parameter": key,
                    "url": _replace_query_value(url, key, replacement),
                }
            )
    return candidates[:40]


def _body_excerpt(response: httpx_client.Response) -> str:
    return response.text[:500].replace("\n", " ").strip()


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def _denied_status(status_code: int) -> bool:
    return status_code in {401, 403, 404}


def _foreign_marker(response_text: str, auth_contexts: list[dict[str, Any]], requester: dict[str, Any]) -> str | None:
    requester_markers = set(_normalize_string_list(requester.get("marker_tokens"), limit=20))
    requester_markers.update(
        item for item in (requester.get("username"), requester.get("label"), requester.get("tenant")) if item
    )
    for context in auth_contexts:
        if context is requester:
            continue
        markers = _normalize_string_list(context.get("marker_tokens"), limit=10)
        markers.extend(
            item
            for item in (context.get("username"), context.get("label"), context.get("tenant"))
            if item and item not in markers
        )
        for marker in markers:
            if marker and marker not in requester_markers and marker in response_text:
                return marker
    return None


def _append_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
    confirmed: bool,
) -> None:
    key = (finding_type, target, severity)
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
            "confirmed": confirmed,
            "methodology_tags": ["broken_access_control", "authorization", "idor-bac-validation"],
            "evidence": evidence,
            "replay_recipe": {
                "tool": "idor-bac",
                "target": target,
                "scope": "approved-web-root-only",
                "requires_configured_auth_context": True,
            },
        }
    )


def _mutated_query_url(url: str, parameters: dict[str, str]) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    existing_names = {name for name, _ in pairs}
    mutated = [
        (name, parameters.get(name, value))
        for name, value in pairs
    ]
    for name, value in parameters.items():
        if name not in existing_names:
            mutated.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(mutated)))


def _role_manipulation_urls(url: str) -> list[dict[str, str]]:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    interesting = {
        "role": "admin",
        "admin": "true",
        "isAdmin": "true",
        "is_admin": "true",
    }
    candidates: list[dict[str, str]] = []
    for key, value in interesting.items():
        if key in pairs:
            candidates.append({"parameter": key, "url": _mutated_query_url(url, {key: value})})
    return candidates


def _role_manipulation_requests(raw_context: dict[str, Any], url: str) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = [
        {"method": "GET", "url": item["url"], "parameter": item["parameter"]}
        for item in _role_manipulation_urls(url)
    ]
    raw_body = raw_context.get("json") or raw_context.get("json_body") or raw_context.get("body")
    if isinstance(raw_body, dict):
        for key, replacement in {
            "role": "admin",
            "admin": True,
            "isAdmin": True,
            "is_admin": True,
        }.items():
            if key not in raw_body:
                continue
            mutated_body = dict(raw_body)
            mutated_body[key] = replacement
            requests.append(
                {
                    "method": str(raw_context.get("method") or "POST").strip().upper() or "POST",
                    "url": url,
                    "parameter": key,
                    "json": mutated_body,
                }
            )
    return requests


def execute_idor_bac_probe(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object,
    scope_allowlist: dict[str, Any] | None = None,
    evidence_records: list[dict[str, Any]] | object = None,
    request_contexts: list[dict[str, Any]] | object = None,
    admin_paths: list[str] | object = None,
    candidate_paths: list[str] | object = None,
    candidate_object_ids: list[str] | object = None,
    method_override_paths: list[str] | object = None,
    max_id_delta: int = MAX_ID_DELTA_LIMIT,
    timeout_seconds: float = 10.0,
    client_factory: Any = httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    bounded_delta = min(max(int(max_id_delta or MAX_ID_DELTA_LIMIT), 1), MAX_ID_DELTA_LIMIT)
    normalized_targets = [normalize_http_target(target) for target in targets]
    for target in normalized_targets:
        _assert_allowed(scope_allowlist, target)
    try:
        normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    except ValueError as exc:
        return RunnerExecution(
            tool="idor-bac",
            exit_code=0,
            stdout=f"idor-bac skipped: {exc}. Configure authenticated access accounts via the credential vault to enable IDOR/BAC testing.",
            stderr="",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": str(exc)},
        )
    known_ids = _dedupe(
        _normalize_string_list(candidate_object_ids, limit=100)
        + [
            owned_id
            for context in normalized_auth_contexts
            for owned_id in _normalize_string_list(context.get("owned_object_ids"), limit=100)
        ],
        limit=100,
    )

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(follow_redirects=True, timeout=timeout_seconds) as client:
        for base_target in normalized_targets:
            endpoint_urls = _candidate_endpoint_urls(
                base_target,
                evidence_records=evidence_records,
                candidate_paths=candidate_paths,
                scope_allowlist=scope_allowlist,
            )

            try:
                discovery_response = client.get(
                    base_target,
                    headers=_request_headers(normalized_auth_contexts[0]),
                    auth=normalized_auth_contexts[0].get("basic_auth"),
                )
                checks.append(
                    {
                        "check_type": "authenticated_link_discovery",
                        "target": base_target,
                        "status_code": discovery_response.status_code,
                    }
                )
                if _success_status(discovery_response.status_code):
                    for link in _link_urls(str(discovery_response.url), discovery_response.text):
                        if _allowed(scope_allowlist, link) and link not in endpoint_urls:
                            endpoint_urls.append(link)
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"link discovery failed for {base_target}: {exc}")

            for endpoint_url in endpoint_urls:
                for requester in normalized_auth_contexts:
                    for candidate in _identifier_replacements(
                        endpoint_url,
                        known_ids,
                        max_id_delta=bounded_delta,
                    ):
                        candidate_url = candidate["url"]
                        if not _allowed(scope_allowlist, candidate_url):
                            continue
                        try:
                            response = client.get(
                                candidate_url,
                                headers=_request_headers(requester),
                                auth=requester.get("basic_auth"),
                            )
                        except httpx_client.HTTPError as exc:
                            exit_code = 1
                            stderr_lines.append(f"id substitution failed for {candidate_url}: {exc}")
                            continue
                        marker = _foreign_marker(response.text, normalized_auth_contexts, requester)
                        check = {
                            "check_type": "id_substitution",
                            "target": candidate_url,
                            "auth_label": requester["label"],
                            "original_id": candidate["original"],
                            "replacement_id": candidate["replacement"],
                            "status_code": response.status_code,
                            "response_hash": _response_hash(response),
                            "foreign_marker_matched": bool(marker),
                        }
                        checks.append(check)
                        if _success_status(response.status_code) and marker:
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="idor_horizontal_privilege_escalation",
                                title="IDOR - Horizontal Privilege Escalation",
                                severity="critical",
                                target=candidate_url,
                                summary=(
                                    f"{requester['label']} accessed another account/object by substituting "
                                    f"identifier {candidate['original']} with {candidate['replacement']}."
                                ),
                                confirmed=True,
                                evidence={
                                    **check,
                                    "matched_foreign_marker": marker,
                                    "response_excerpt": _body_excerpt(response),
                                },
                            )
                        elif _success_status(response.status_code):
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="idor_potential_object_access",
                                title="IDOR - Potential Object Access",
                                severity="high",
                                target=candidate_url,
                                summary=(
                                    f"{requester['label']} received a successful response after bounded "
                                    "identifier substitution, but no foreign ownership marker was available."
                                ),
                                confirmed=False,
                                evidence={**check, "response_excerpt": _body_excerpt(response)},
                            )

            contexts = request_contexts if isinstance(request_contexts, list) else []
            for raw_context in contexts:
                if not isinstance(raw_context, dict):
                    continue
                raw_url = raw_context.get("url") or raw_context.get("target") or raw_context.get("endpoint")
                if not raw_url:
                    continue
                context_url = _render_url(base_target, str(raw_url))
                if not _allowed(scope_allowlist, context_url):
                    continue
                success_markers = _normalize_string_list(raw_context.get("success_markers"), limit=10)
                for mutated in _role_manipulation_requests(raw_context, context_url):
                    requester = normalized_auth_contexts[0]
                    try:
                        if "json" in mutated:
                            response = client.request(
                                str(mutated["method"]),
                                mutated["url"],
                                headers=_request_headers(requester),
                                auth=requester.get("basic_auth"),
                                json=mutated["json"],
                            )
                        else:
                            response = client.get(
                                mutated["url"],
                                headers=_request_headers(requester),
                                auth=requester.get("basic_auth"),
                            )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"role manipulation failed for {mutated['url']}: {exc}")
                        continue
                    marker_hit = any(marker in response.text for marker in success_markers)
                    check = {
                        "check_type": "role_parameter_manipulation",
                        "target": mutated["url"],
                        "auth_label": requester["label"],
                        "parameter": mutated["parameter"],
                        "status_code": response.status_code,
                        "success_marker_matched": marker_hit,
                        "response_hash": _response_hash(response),
                    }
                    checks.append(check)
                    if _success_status(response.status_code) and (marker_hit or "admin" in response.text.lower()):
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="role_parameter_privilege_escalation",
                            title="Broken Access Control - Privilege Escalation via Parameter",
                            severity="high",
                            target=mutated["url"],
                            summary=(
                                f"{requester['label']} reached privileged behavior after changing "
                                f"{mutated['parameter']} in an explicit request context."
                            ),
                            confirmed=marker_hit,
                            evidence={**check, "response_excerpt": _body_excerpt(response)},
                        )

            for raw_path in _normalize_string_list(method_override_paths, limit=50):
                override_url = _render_url(base_target, raw_path)
                if not _allowed(scope_allowlist, override_url):
                    continue
                requester = normalized_auth_contexts[0]
                try:
                    response = client.post(
                        override_url,
                        headers={
                            **_request_headers(requester),
                            "X-HTTP-Method-Override": "DELETE",
                        },
                        auth=requester.get("basic_auth"),
                    )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"method override failed for {override_url}: {exc}")
                    continue
                text = response.text.lower()
                check = {
                    "check_type": "method_override",
                    "target": override_url,
                    "auth_label": requester["label"],
                    "status_code": response.status_code,
                    "response_hash": _response_hash(response),
                }
                checks.append(check)
                if _success_status(response.status_code) and any(marker in text for marker in ("deleted", "delete accepted", "override accepted")):
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="method_override_bypass",
                        title="Broken Access Control - Method Override Accepted",
                        severity="high",
                        target=override_url,
                        summary="The endpoint accepted a DELETE method override from a lower-privileged configured account.",
                        confirmed=True,
                        evidence={**check, "response_excerpt": _body_excerpt(response)},
                    )

            admin_candidates = _normalize_string_list(admin_paths, limit=50) or list(DEFAULT_ADMIN_PATHS)
            for raw_path in admin_candidates:
                admin_url = _render_url(base_target, raw_path)
                if not _allowed(scope_allowlist, admin_url):
                    continue
                try:
                    unauth_response = client.get(admin_url, headers=_request_headers(None))
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"admin path exposure failed for {admin_url}: {exc}")
                    continue
                text = unauth_response.text.lower()
                check = {
                    "check_type": "admin_path_exposure",
                    "target": admin_url,
                    "status_code": unauth_response.status_code,
                    "response_hash": _response_hash(unauth_response),
                }
                checks.append(check)
                if _success_status(unauth_response.status_code) and not any(
                    marker in text for marker in ("login", "sign in", "forbidden", "unauthorized")
                ):
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="admin_path_exposed",
                        title="Broken Access Control - Admin Path Exposed",
                        severity="high",
                        target=admin_url,
                        summary="A common administrative path returned successful content without authentication.",
                        confirmed=True,
                        evidence={**check, "response_excerpt": _body_excerpt(unauth_response)},
                    )
                elif _denied_status(unauth_response.status_code):
                    continue

    payload = {
        "tool": "idor-bac",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "auth_context_count": len(normalized_auth_contexts),
            "check_count": len(checks),
            "finding_count": len(findings),
            "confirmed_finding_count": sum(1 for item in findings if item.get("confirmed")),
            "potential_finding_count": sum(1 for item in findings if not item.get("confirmed")),
            "max_id_delta": bounded_delta,
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "credentials_from_configured_contexts": True,
            "max_id_delta": bounded_delta,
            "bruteforce": False,
            "runtime_mutation": False,
            "requires_active_approval": True,
        },
    }
    return RunnerExecution(
        tool="idor-bac",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.idor_bac.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
            "max_id_delta": bounded_delta,
        },
        artifacts=[_json_artifact(IDOR_BAC_ARTIFACT_NAME, payload)],
    )
