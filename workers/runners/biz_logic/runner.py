from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from urllib.parse import urljoin

import httpx as httpx_client

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

BIZ_LOGIC_ARTIFACT_NAME = "biz-logic-results.json"
SUPPORTED_TEST_TYPES = ("idor", "privilege_escalation", "broken_access", "cross_tenant")
DEFAULT_TEST_TYPES = list(SUPPORTED_TEST_TYPES)
MAX_ENUMERATION_BOUND = 100


def _normalize_string_list(value: object, *, limit: int | None = None) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, (str, int)):
            continue
        candidate = str(item).strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
        if limit is not None and len(normalized) >= limit:
            break
    return normalized


def _normalize_test_types(test_types: object) -> list[str]:
    if not isinstance(test_types, list):
        return list(DEFAULT_TEST_TYPES)

    normalized: list[str] = []
    for item in test_types:
        if not isinstance(item, str):
            continue
        candidate = item.strip().lower()
        if candidate in SUPPORTED_TEST_TYPES and candidate not in normalized:
            normalized.append(candidate)
    return normalized or list(DEFAULT_TEST_TYPES)


def _normalize_auth_contexts(auth_contexts: object) -> list[dict[str, Any]]:
    if not isinstance(auth_contexts, list):
        raise ValueError("biz-logic-probe requires at least one authenticated access account")

    normalized: list[dict[str, Any]] = []
    for index, raw_context in enumerate(auth_contexts):
        if not isinstance(raw_context, dict):
            continue
        headers = raw_context.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        normalized_headers = {
            str(key).strip(): str(value).strip()
            for key, value in headers.items()
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
        role = str(raw_context.get("role") or "user").strip()
        username = str(raw_context.get("username") or "").strip()
        tenant = str(raw_context.get("tenant") or raw_context.get("tenant_id") or "").strip()
        marker_tokens = _normalize_string_list(raw_context.get("marker_tokens"), limit=10)
        owned_object_ids = _normalize_string_list(raw_context.get("owned_object_ids"), limit=MAX_ENUMERATION_BOUND)
        normalized.append(
            {
                "label": label or f"Account {index + 1}",
                "role": role or "user",
                "username": username,
                "tenant": tenant,
                "headers": normalized_headers,
                "basic_auth": normalized_basic_auth,
                "marker_tokens": marker_tokens,
                "owned_object_ids": owned_object_ids,
            }
        )

    if not normalized:
        raise ValueError("biz-logic-probe requires at least one authenticated access account")
    return normalized


def _bounded_candidate_ids(candidate_object_ids: object, *, max_object_ids: int) -> list[str]:
    normalized = _normalize_string_list(candidate_object_ids, limit=max_object_ids)
    if normalized:
        return normalized
    return [str(index) for index in range(1, max_object_ids + 1)]


def _render_url(base_target: str, template: str, substitutions: dict[str, str]) -> str:
    rendered = str(template).strip()
    for key, value in substitutions.items():
        rendered = rendered.replace(f"{{{key}}}", value)

    if "://" in rendered:
        return rendered

    base = normalize_http_target(base_target)
    return urljoin(base.rstrip("/") + "/", rendered.lstrip("/"))


def _assert_probe_url_allowed(url: str, scope_allowlist: dict[str, Any]) -> None:
    if not target_value_is_allowed(scope_allowlist, url):
        raise ValueError(f"target outside scope: {url}")


def _auth_request_headers(auth_context: dict[str, Any] | None) -> dict[str, str]:
    if auth_context is None:
        return {"User-Agent": "AegisPT/0.1"}
    return {"User-Agent": "AegisPT/0.1", **dict(auth_context.get("headers") or {})}


def _context_substitutions(
    auth_context: dict[str, Any],
    *,
    candidate_id: str = "",
    subject_context: dict[str, Any] | None = None,
) -> dict[str, str]:
    subject = subject_context or auth_context
    tenant = str(subject.get("tenant") or "").strip() or str(subject.get("label") or "").strip()
    username = str(subject.get("username") or "").strip() or str(subject.get("label") or "").strip()
    return {
        "id": candidate_id,
        "label": str(subject.get("label") or "").strip(),
        "username": username,
        "tenant": tenant,
        "role": str(subject.get("role") or "").strip(),
    }


def _is_success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def _is_admin_role(role: str) -> bool:
    normalized = role.strip().lower()
    return "admin" in normalized or "owner" in normalized or "superuser" in normalized


def _body_markers(auth_context: dict[str, Any]) -> list[str]:
    markers = _normalize_string_list(auth_context.get("marker_tokens"), limit=10)
    for field_name in ("username", "label", "tenant"):
        candidate = str(auth_context.get(field_name) or "").strip()
        if candidate and candidate not in markers:
            markers.append(candidate)
    return markers


def _response_excerpt(response: httpx_client.Response) -> str:
    return response.text[:400].strip().replace("\n", " ")


def _append_finding(
    findings: list[dict[str, Any]],
    seen_keys: set[tuple[str, str, str]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    auth_label: str,
    extra: dict[str, Any] | None = None,
) -> None:
    dedupe_key = (finding_type.strip().lower(), target.strip().lower(), auth_label.strip().lower())
    if dedupe_key in seen_keys:
        return
    seen_keys.add(dedupe_key)
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": target,
            "summary": summary,
            "auth_label": auth_label,
            "methodology_tags": ["business_logic", "authorization", finding_type],
            **(extra or {}),
        }
    )


def execute_biz_logic_probe(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object,
    scope_allowlist: dict[str, Any] | None = None,
    test_types: list[str] | object = None,
    protected_paths: list[str] | object = None,
    admin_paths: list[str] | object = None,
    idor_paths: list[str] | object = None,
    cross_tenant_paths: list[str] | object = None,
    candidate_object_ids: list[str] | object = None,
    max_object_ids: int = 25,
    timeout_seconds: float = 10.0,
    client_factory: Any = httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [normalize_http_target(target) for target in targets]
    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    normalized_test_types = _normalize_test_types(test_types)
    bounded_max_ids = min(max(int(max_object_ids), 1), MAX_ENUMERATION_BOUND)
    bounded_candidate_ids = _bounded_candidate_ids(
        candidate_object_ids,
        max_object_ids=bounded_max_ids,
    )
    normalized_protected_paths = _normalize_string_list(protected_paths, limit=50)
    normalized_admin_paths = _normalize_string_list(admin_paths, limit=50)
    normalized_idor_paths = _normalize_string_list(idor_paths, limit=50)
    normalized_cross_tenant_paths = _normalize_string_list(cross_tenant_paths, limit=50)

    scope_allowlist = scope_allowlist or {}
    probe_records: list[dict[str, Any]] = []
    finding_records: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(
        follow_redirects=True,
        timeout=timeout_seconds,
    ) as client:
        for base_target in normalized_targets:
            target_record = {
                "target": base_target,
                "probes": [],
                "findings": [],
            }

            if "broken_access" in normalized_test_types:
                for path in normalized_protected_paths:
                    auth_context = normalized_auth_contexts[0]
                    url = _render_url(
                        base_target,
                        path,
                        _context_substitutions(auth_context),
                    )
                    _assert_probe_url_allowed(url, scope_allowlist)
                    try:
                        authenticated = client.get(
                            url,
                            headers=_auth_request_headers(auth_context),
                            auth=auth_context.get("basic_auth"),
                        )
                        unauthenticated = client.get(url, headers=_auth_request_headers(None))
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"{url}: {exc}")
                        continue

                    target_record["probes"].append(
                        {
                            "type": "broken_access",
                            "url": url,
                            "auth_label": auth_context["label"],
                            "authenticated_status": authenticated.status_code,
                            "unauthenticated_status": unauthenticated.status_code,
                        }
                    )
                    if _is_success_status(authenticated.status_code) and _is_success_status(
                        unauthenticated.status_code
                    ):
                        _append_finding(
                            finding_records,
                            seen_findings,
                            finding_type="broken_access",
                            title="Broken access control detected",
                            severity="high",
                            target=url,
                            summary=(
                                f"Protected path {url} responded with {unauthenticated.status_code} without authentication "
                                f"after an authenticated baseline by {auth_context['label']}."
                            ),
                            auth_label=auth_context["label"],
                            extra={
                                "evidence": {
                                    "authenticated_status": authenticated.status_code,
                                    "unauthenticated_status": unauthenticated.status_code,
                                }
                            },
                        )

            if "privilege_escalation" in normalized_test_types:
                for auth_context in normalized_auth_contexts:
                    if _is_admin_role(str(auth_context.get("role") or "")):
                        continue
                    for path in normalized_admin_paths:
                        url = _render_url(
                            base_target,
                            path,
                            _context_substitutions(auth_context),
                        )
                        _assert_probe_url_allowed(url, scope_allowlist)
                        try:
                            response = client.get(
                                url,
                                headers=_auth_request_headers(auth_context),
                                auth=auth_context.get("basic_auth"),
                            )
                        except httpx_client.HTTPError as exc:
                            exit_code = 1
                            stderr_lines.append(f"{url}: {exc}")
                            continue

                        target_record["probes"].append(
                            {
                                "type": "privilege_escalation",
                                "url": url,
                                "auth_label": auth_context["label"],
                                "status_code": response.status_code,
                            }
                        )
                        if _is_success_status(response.status_code):
                            _append_finding(
                                finding_records,
                                seen_findings,
                                finding_type="privilege_escalation",
                                title="Privilege escalation detected",
                                severity="high",
                                target=url,
                                summary=(
                                    f"Low-privilege context {auth_context['label']} ({auth_context['role']}) reached "
                                    f"admin path {url} with HTTP {response.status_code}."
                                ),
                                auth_label=auth_context["label"],
                                extra={"evidence": {"status_code": response.status_code}},
                            )

            if "idor" in normalized_test_types:
                for auth_context in normalized_auth_contexts:
                    foreign_contexts = [
                        candidate
                        for candidate in normalized_auth_contexts
                        if candidate["label"] != auth_context["label"]
                    ]
                    foreign_markers = [
                        marker
                        for candidate in foreign_contexts
                        for marker in _body_markers(candidate)
                    ]
                    if not foreign_markers:
                        continue
                    for path in normalized_idor_paths:
                        requested_ids = auth_context["owned_object_ids"] or bounded_candidate_ids
                        for candidate_id in requested_ids[:bounded_max_ids]:
                            url = _render_url(
                                base_target,
                                path,
                                _context_substitutions(auth_context, candidate_id=candidate_id),
                            )
                            _assert_probe_url_allowed(url, scope_allowlist)
                            try:
                                response = client.get(
                                    url,
                                    headers=_auth_request_headers(auth_context),
                                    auth=auth_context.get("basic_auth"),
                                )
                            except httpx_client.HTTPError as exc:
                                exit_code = 1
                                stderr_lines.append(f"{url}: {exc}")
                                continue

                            body_excerpt = _response_excerpt(response)
                            target_record["probes"].append(
                                {
                                    "type": "idor",
                                    "url": url,
                                    "auth_label": auth_context["label"],
                                    "status_code": response.status_code,
                                    "body_sha256": sha256(response.content).hexdigest(),
                                }
                            )
                            matched_marker = next(
                                (
                                    marker
                                    for marker in foreign_markers
                                    if marker and marker.lower() in body_excerpt.lower()
                                ),
                                None,
                            )
                            if _is_success_status(response.status_code) and matched_marker:
                                _append_finding(
                                    finding_records,
                                    seen_findings,
                                    finding_type="idor",
                                    title="Insecure direct object reference detected",
                                    severity="high",
                                    target=url,
                                    summary=(
                                        f"Context {auth_context['label']} retrieved object path {url} and the response body "
                                        f"contained marker {matched_marker!r} from another account."
                                    ),
                                    auth_label=auth_context["label"],
                                    extra={
                                        "evidence": {
                                            "status_code": response.status_code,
                                            "body_excerpt": body_excerpt,
                                        }
                                    },
                                )

            if "cross_tenant" in normalized_test_types and len(normalized_auth_contexts) > 1:
                for auth_context in normalized_auth_contexts:
                    for subject_context in normalized_auth_contexts:
                        if subject_context["label"] == auth_context["label"]:
                            continue
                        for path in normalized_cross_tenant_paths:
                            url = _render_url(
                                base_target,
                                path,
                                _context_substitutions(auth_context, subject_context=subject_context),
                            )
                            _assert_probe_url_allowed(url, scope_allowlist)
                            try:
                                response = client.get(
                                    url,
                                    headers=_auth_request_headers(auth_context),
                                    auth=auth_context.get("basic_auth"),
                                )
                            except httpx_client.HTTPError as exc:
                                exit_code = 1
                                stderr_lines.append(f"{url}: {exc}")
                                continue

                            target_record["probes"].append(
                                {
                                    "type": "cross_tenant",
                                    "url": url,
                                    "auth_label": auth_context["label"],
                                    "subject_label": subject_context["label"],
                                    "status_code": response.status_code,
                                }
                            )
                            if _is_success_status(response.status_code):
                                _append_finding(
                                    finding_records,
                                    seen_findings,
                                    finding_type="cross_tenant",
                                    title="Cross-tenant broken access control detected",
                                    severity="high",
                                    target=url,
                                    summary=(
                                        f"Tenant context {auth_context['label']} accessed path {url} rendered for "
                                        f"{subject_context['label']} with HTTP {response.status_code}."
                                    ),
                                    auth_label=auth_context["label"],
                                    extra={
                                        "evidence": {
                                            "status_code": response.status_code,
                                            "body_excerpt": _response_excerpt(response),
                                        }
                                    },
                                )

            target_record["findings"] = [
                finding for finding in finding_records if finding.get("target", "").startswith(base_target)
            ]
            probe_records.append(target_record)

    artifact_payload = {
        "tool": "biz-logic-probe",
        "status": "ok" if exit_code == 0 else "completed_with_errors",
        "targets": probe_records,
        "summary": {
            "finding_count": len(finding_records),
            "probe_count": sum(len(target.get("probes", [])) for target in probe_records),
            "test_types": normalized_test_types,
            "max_object_ids": bounded_max_ids,
        },
    }
    artifact = EvidenceArtifact(
        name=BIZ_LOGIC_ARTIFACT_NAME,
        content_type="application/json",
        data=json.dumps(artifact_payload, sort_keys=True).encode("utf-8"),
        kind="probe-results",
    )

    return RunnerExecution(
        tool="biz-logic-probe",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": artifact_payload["status"],
            "normalized_targets": normalized_targets,
            "tool_version": f"python-httpx/{httpx_client.__version__}",
            "runner_digest": "workers.biz_logic.runner:v1",
            "finding_count": len(finding_records),
            "probe_count": artifact_payload["summary"]["probe_count"],
            "test_types": normalized_test_types,
            "max_object_ids": bounded_max_ids,
        },
        artifacts=[artifact],
    )
