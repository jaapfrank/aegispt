from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

GRAPHQL_RESULTS_ARTIFACT_NAME = "graphql-probe-results.json"
DEFAULT_ENDPOINT_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/gql")
DEFAULT_IDE_PATHS = ("/graphiql", "/playground")
INJECTION_PAYLOADS = (
    "' OR '1'='1",
    '" OR "1"="1',
    '{"$ne": null}',
)
SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "postgres",
    "sqlite",
    "ora-",
    "odbc",
    "mongodb",
    "bson",
    "sequelize",
    "prisma",
    "syntaxerror",
)
DEPTH_ERROR_MARKERS = ("depth", "complexity", "too deep", "max depth", "maximum depth")
GRAPHQL_HINT_MARKERS = ("graphql", "__typename", "query", "mutation", "errors")


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
    return re.sub(r"\s+", " ", response.text or "").strip()[:700]


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved GraphQL/web scope: {url}")


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


def _candidate_urls(
    targets: list[str],
    scope_allowlist: dict[str, Any] | None,
    *,
    endpoint_paths: list[str] | None = None,
    ide_paths: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    endpoint_candidates: list[str] = []
    ide_candidates: list[str] = []
    seen_endpoints: set[str] = set()
    seen_ide: set[str] = set()
    raw_endpoint_paths = endpoint_paths if endpoint_paths is not None else list(DEFAULT_ENDPOINT_PATHS)
    raw_ide_paths = ide_paths if ide_paths is not None else list(DEFAULT_IDE_PATHS)

    for target in targets:
        parsed = urlparse(target)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        if re.search(r"/(?:graphql|gql)(?:/)?$", parsed.path, flags=re.IGNORECASE):
            candidates = [target]
        else:
            candidates = [urljoin(root, path.lstrip("/")) for path in raw_endpoint_paths]
            if parsed.path and parsed.path != "/":
                candidates.insert(0, target)
        for candidate in candidates:
            if candidate in seen_endpoints or not _allowed(scope_allowlist, candidate):
                continue
            seen_endpoints.add(candidate)
            endpoint_candidates.append(candidate)

        for path in raw_ide_paths:
            candidate = urljoin(root, path.lstrip("/"))
            if candidate in seen_ide or not _allowed(scope_allowlist, candidate):
                continue
            seen_ide.add(candidate)
            ide_candidates.append(candidate)

    return endpoint_candidates, ide_candidates


def _decode_json_response(response: httpx_client.Response) -> dict[str, Any] | list[Any] | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if isinstance(payload, (dict, list)):
        return payload
    return None


def _graphql_post(
    client: httpx_client.Client,
    url: str,
    payload: dict[str, Any] | list[dict[str, Any]],
) -> httpx_client.Response:
    return client.post(
        url,
        json=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AegisPT/graphql-probe bounded validation",
        },
    )


def _looks_like_graphql_response(response: httpx_client.Response) -> bool:
    payload = _decode_json_response(response)
    if isinstance(payload, dict) and ("data" in payload or "errors" in payload):
        return True
    content_type = str(response.headers.get("content-type") or "").lower()
    body = (response.text or "").lower()
    return "graphql" in content_type or any(marker in body for marker in GRAPHQL_HINT_MARKERS)


def _schema_from_payload(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    schema = payload.get("__schema")
    if isinstance(schema, dict):
        return schema
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
        return data["__schema"]
    return None


def _unwrap_type(type_ref: Any) -> dict[str, Any]:
    current = type_ref if isinstance(type_ref, dict) else {}
    wrappers: list[str] = []
    while isinstance(current, dict) and isinstance(current.get("ofType"), dict):
        if current.get("kind"):
            wrappers.append(str(current.get("kind")))
        current = current["ofType"]
    return {
        "kind": str(current.get("kind") or ""),
        "name": str(current.get("name") or ""),
        "wrappers": wrappers,
    }


def _type_index(schema: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    types = schema.get("types") if isinstance(schema, dict) else []
    return {
        str(item.get("name")): item
        for item in types
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    }


def _operation_type_name(schema: dict[str, Any] | None, operation: str = "queryType") -> str | None:
    if not isinstance(schema, dict):
        return None
    value = schema.get(operation)
    if isinstance(value, dict) and value.get("name"):
        return str(value["name"])
    return None


def _fields_for_type(schema: dict[str, Any] | None, type_name: str | None) -> list[dict[str, Any]]:
    if not type_name:
        return []
    type_record = _type_index(schema).get(type_name)
    fields = type_record.get("fields") if isinstance(type_record, dict) else []
    return [field for field in fields if isinstance(field, dict)]


def _schema_map(schema: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    type_count = len(schema.get("types") or [])
    query_type = _operation_type_name(schema, "queryType")
    mutation_type = _operation_type_name(schema, "mutationType")
    query_fields = [
        {
            "name": str(field.get("name") or ""),
            "args": [
                {
                    "name": str(arg.get("name") or ""),
                    "type": _unwrap_type(arg.get("type")),
                }
                for arg in (field.get("args") or [])
                if isinstance(arg, dict)
            ],
            "type": _unwrap_type(field.get("type")),
        }
        for field in _fields_for_type(schema, query_type)
    ]
    mutation_fields = [
        {
            "name": str(field.get("name") or ""),
            "args": [
                {
                    "name": str(arg.get("name") or ""),
                    "type": _unwrap_type(arg.get("type")),
                }
                for arg in (field.get("args") or [])
                if isinstance(arg, dict)
            ],
            "type": _unwrap_type(field.get("type")),
        }
        for field in _fields_for_type(schema, mutation_type)
    ]
    return {
        "type_count": type_count,
        "query_type": query_type,
        "mutation_type": mutation_type,
        "query_fields": query_fields[:100],
        "mutation_fields": mutation_fields[:100],
    }


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
    confirmed: bool = True,
) -> None:
    key = (finding_type, target, str(evidence.get("probe") or evidence.get("field") or evidence.get("path") or ""))
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
            "methodology_tags": [
                "api_security",
                "graphql_security",
                "owasp-api-top-10-2023",
                "graphql-probe-validation",
            ],
            "control_family": "api_security",
            "evidence": evidence,
            "replay_recipe": {
                "tool": "graphql-probe",
                "target": target,
                "scope": "approved-graphql-endpoint-only",
                "depth_probe_max_levels": 20,
                "batch_size": 2,
                "data_extraction_performed": False,
                "authorization_bypass_exploitation": False,
            },
        }
    )


def _introspection_query() -> str:
    return """
    query AegisPTIntrospection {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          fields {
            name
            args { name type { kind name ofType { kind name ofType { kind name } } } }
            type { kind name ofType { kind name ofType { kind name } } }
          }
        }
      }
    }
    """


def _first_query_field_name(schema: dict[str, Any] | None) -> str | None:
    for field in _fields_for_type(schema, _operation_type_name(schema, "queryType")):
        name = str(field.get("name") or "").strip()
        if name and not name.startswith("__"):
            return name
    return None


def _typo_for_field(field: str | None) -> str:
    if not field:
        return "aegisptUnknownField"
    if len(field) <= 3:
        return f"{field}x"
    return field[0] + field[2:]


def _build_depth_query(schema: dict[str, Any] | None, max_depth: int) -> tuple[str, int]:
    depth = min(max(max_depth, 2), 20)
    query_type_name = _operation_type_name(schema, "queryType")
    fields = _fields_for_type(schema, query_type_name)
    field_name: str | None = None
    nested_type: str | None = None
    for field in fields:
        unwrapped = _unwrap_type(field.get("type"))
        if unwrapped["kind"] == "OBJECT" and unwrapped["name"]:
            field_name = str(field.get("name") or "").strip()
            nested_type = unwrapped["name"]
            break
    if not field_name:
        field_name = _first_query_field_name(schema)
    if not field_name:
        return "query AegisPTDepthProbe { __typename }", 1

    chain = [field_name]
    index = _type_index(schema)
    current_type = nested_type
    while current_type and len(chain) < depth:
        child_fields = _fields_for_type(schema, current_type)
        next_field = None
        next_type = None
        for child in child_fields:
            child_name = str(child.get("name") or "").strip()
            unwrapped = _unwrap_type(child.get("type"))
            if child_name and unwrapped["kind"] == "OBJECT" and unwrapped["name"] in index:
                next_field = child_name
                next_type = unwrapped["name"]
                break
        if not next_field:
            break
        chain.append(next_field)
        current_type = next_type

    inner = "__typename"
    for name in reversed(chain):
        inner = f"{name} {{ {inner} }}"
    return f"query AegisPTDepthProbe {{ {inner} }}", len(chain)


def _string_argument_candidates(schema: dict[str, Any] | None, limit: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    query_type = _operation_type_name(schema, "queryType")
    for field in _fields_for_type(schema, query_type):
        field_name = str(field.get("name") or "").strip()
        if not field_name or field_name.startswith("__"):
            continue
        return_type = _unwrap_type(field.get("type"))
        selection = " { __typename }" if return_type["kind"] == "OBJECT" else ""
        for arg in field.get("args") or []:
            if not isinstance(arg, dict):
                continue
            arg_name = str(arg.get("name") or "").strip()
            arg_type = _unwrap_type(arg.get("type"))
            if arg_name and arg_type["name"] in {"String", "ID"}:
                candidates.append(
                    {
                        "field": field_name,
                        "argument": arg_name,
                        "argument_type": arg_type["name"],
                        "selection": selection,
                    }
                )
        if len(candidates) >= limit:
            break
    return candidates[:limit]


def _contains_sql_error(response: httpx_client.Response) -> bool:
    body = (response.text or "").lower()
    return any(marker in body for marker in SQL_ERROR_MARKERS)


def _graphql_errors_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return ""
    return " ".join(
        str(error.get("message") if isinstance(error, dict) else error)
        for error in errors
    )


def execute_graphql_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    endpoint_paths: list[str] | None = None,
    ide_paths: list[str] | None = None,
    max_depth: int = 20,
    max_injection_fields: int = 5,
    timeout_seconds: float = 10.0,
    client_factory: Callable[..., httpx_client.Client] | None = None,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    max_depth = min(max(int(max_depth or 20), 2), 20)
    max_injection_fields = min(max(int(max_injection_fields or 5), 0), 10)

    normalized_targets = _normalize_targets(targets, scope_allowlist)
    endpoint_candidates, ide_candidates = _candidate_urls(
        normalized_targets,
        scope_allowlist,
        endpoint_paths=endpoint_paths,
        ide_paths=ide_paths,
    )

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    discovered_endpoints: list[dict[str, Any]] = []
    schema_maps: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    factory = client_factory or httpx_client.Client
    with factory(timeout=timeout_seconds, follow_redirects=False) as client:
        for ide_url in ide_candidates:
            try:
                response = client.get(
                    ide_url,
                    headers={"User-Agent": "AegisPT/graphql-probe IDE discovery"},
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"GraphQL IDE discovery failed for {ide_url}: {exc}")
                continue
            body = (response.text or "").lower()
            exposed = response.status_code < 400 and (
                "graphiql" in body
                or "graphql playground" in body
                or "apollo sandbox" in body
                or "graphql ide" in body
            )
            checks.append(
                {
                    "check_type": "graphql_ide_discovery",
                    "target": ide_url,
                    "status_code": response.status_code,
                    "exposed": exposed,
                    "response_hash": _response_hash(response),
                }
            )
            if exposed:
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="graphql_ide_exposed",
                    title="GraphQL Playground or IDE Exposed",
                    severity="medium",
                    target=ide_url,
                    summary="A GraphQL IDE or playground interface is reachable in approved scope.",
                    evidence={
                        "probe": "ide-discovery",
                        "status_code": response.status_code,
                        "body_excerpt": _body_excerpt(response),
                    },
                )

        for endpoint_url in endpoint_candidates:
            try:
                detection_response = _graphql_post(
                    client,
                    endpoint_url,
                    {"query": "query AegisPTDetect { __typename }"},
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"GraphQL endpoint detection failed for {endpoint_url}: {exc}")
                continue

            detected = _looks_like_graphql_response(detection_response)
            detection_check = {
                "check_type": "graphql_endpoint_detection",
                "target": endpoint_url,
                "status_code": detection_response.status_code,
                "detected": detected,
                "response_hash": _response_hash(detection_response),
                "body_excerpt": _body_excerpt(detection_response) if detected else "",
            }
            checks.append(detection_check)
            if not detected:
                continue
            discovered_endpoints.append(detection_check)

            schema: dict[str, Any] | None = None
            try:
                introspection_response = _graphql_post(
                    client,
                    endpoint_url,
                    {"query": _introspection_query()},
                )
                introspection_payload = _decode_json_response(introspection_response)
                schema = _schema_from_payload(introspection_payload)
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"GraphQL introspection failed for {endpoint_url}: {exc}")
                introspection_response = None
                introspection_payload = None

            schema_map = _schema_map(schema)
            if schema_map:
                schema_maps.append({"endpoint": endpoint_url, **schema_map})
            checks.append(
                {
                    "check_type": "graphql_introspection",
                    "target": endpoint_url,
                    "status_code": getattr(introspection_response, "status_code", None),
                    "enabled": bool(schema),
                    "schema_map": schema_map,
                    "response_hash": (
                        _response_hash(introspection_response) if introspection_response is not None else None
                    ),
                }
            )
            if schema:
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="graphql_introspection_enabled",
                    title="GraphQL Introspection Enabled - Full Schema Disclosed",
                    severity="medium",
                    target=endpoint_url,
                    summary="The GraphQL endpoint returned a full introspection schema in approved scope.",
                    evidence={
                        "probe": "introspection",
                        "type_count": schema_map.get("type_count"),
                        "query_fields": [field["name"] for field in schema_map.get("query_fields", [])[:20]],
                        "mutation_fields": [field["name"] for field in schema_map.get("mutation_fields", [])[:20]],
                    },
                )

            typo_field = _typo_for_field(_first_query_field_name(schema))
            try:
                suggestion_response = _graphql_post(
                    client,
                    endpoint_url,
                    {"query": f"query AegisPTSuggestion {{ {typo_field} }}"},
                )
                suggestion_payload = _decode_json_response(suggestion_response)
                suggestion_text = _graphql_errors_text(suggestion_payload)
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"GraphQL field suggestion probe failed for {endpoint_url}: {exc}")
                suggestion_response = None
                suggestion_text = ""
            suggestion_leak = bool(re.search(r"did you mean|cannot query field", suggestion_text, re.I))
            checks.append(
                {
                    "check_type": "graphql_field_suggestion",
                    "target": endpoint_url,
                    "probe_field": typo_field,
                    "status_code": getattr(suggestion_response, "status_code", None),
                    "suggestion_leak": suggestion_leak,
                    "error_excerpt": suggestion_text[:500],
                }
            )
            if suggestion_leak:
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="graphql_field_suggestion_leakage",
                    title="GraphQL Field Suggestion Leakage",
                    severity="low",
                    target=endpoint_url,
                    summary="GraphQL validation errors disclose field-name suggestions useful for schema enumeration.",
                    evidence={
                        "probe": "field-suggestion",
                        "field": typo_field,
                        "error_excerpt": suggestion_text[:500],
                    },
                )

            depth_query, actual_depth = _build_depth_query(schema, max_depth)
            if actual_depth > 1:
                try:
                    depth_response = _graphql_post(client, endpoint_url, {"query": depth_query})
                    depth_payload = _decode_json_response(depth_response)
                    depth_errors = _graphql_errors_text(depth_payload)
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"GraphQL depth probe failed for {endpoint_url}: {exc}")
                    depth_response = None
                    depth_errors = ""
                limited = any(marker in depth_errors.lower() for marker in DEPTH_ERROR_MARKERS)
                accepted = (
                    depth_response is not None
                    and depth_response.status_code < 500
                    and not limited
                    and "Cannot query field" not in depth_errors
                )
                checks.append(
                    {
                        "check_type": "graphql_depth_probe",
                        "target": endpoint_url,
                        "requested_depth": actual_depth,
                        "status_code": getattr(depth_response, "status_code", None),
                        "depth_limited": limited,
                        "accepted_without_depth_error": accepted,
                        "error_excerpt": depth_errors[:500],
                    }
                )
                if accepted and actual_depth >= 10:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="graphql_missing_query_depth_limit",
                        title="GraphQL Missing Query Depth Limit",
                        severity="medium",
                        target=endpoint_url,
                        summary="A bounded nested GraphQL query of at least 10 levels was accepted without depth-limit evidence.",
                        evidence={
                            "probe": "depth",
                            "requested_depth": actual_depth,
                            "max_depth_cap": max_depth,
                            "status_code": getattr(depth_response, "status_code", None),
                        },
                    )

            for candidate in _string_argument_candidates(schema, max_injection_fields):
                for payload_value in INJECTION_PAYLOADS:
                    query = (
                        f"query AegisPTInjection($value: {candidate['argument_type']}) "
                        f"{{ {candidate['field']}({candidate['argument']}: $value){candidate['selection']} }}"
                    )
                    try:
                        injection_response = _graphql_post(
                            client,
                            endpoint_url,
                            {"query": query, "variables": {"value": payload_value}},
                        )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(
                            f"GraphQL injection probe failed for {endpoint_url} field {candidate['field']}: {exc}"
                        )
                        continue
                    sql_error = _contains_sql_error(injection_response)
                    checks.append(
                        {
                            "check_type": "graphql_argument_injection",
                            "target": endpoint_url,
                            "field": candidate["field"],
                            "argument": candidate["argument"],
                            "payload_family": "sql-or-nosql-marker",
                            "status_code": injection_response.status_code,
                            "backend_error_signal": sql_error,
                            "response_hash": _response_hash(injection_response),
                        }
                    )
                    if sql_error or injection_response.status_code >= 500:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="graphql_argument_injection_signal",
                            title="GraphQL Argument Injection Error Signal",
                            severity="high",
                            target=endpoint_url,
                            summary="A bounded GraphQL string argument probe produced backend error evidence consistent with injection risk.",
                            evidence={
                                "probe": "argument-injection",
                                "field": candidate["field"],
                                "argument": candidate["argument"],
                                "argument_type": candidate["argument_type"],
                                "payload_family": "sql-or-nosql-marker",
                                "status_code": injection_response.status_code,
                                "body_excerpt": _body_excerpt(injection_response),
                            },
                        )
                        break

            try:
                batch_response = _graphql_post(
                    client,
                    endpoint_url,
                    [
                        {"query": "query AegisPTBatchOne { __typename }"},
                        {"query": "query AegisPTBatchTwo { __typename }"},
                    ],
                )
                batch_payload = _decode_json_response(batch_response)
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"GraphQL batch probe failed for {endpoint_url}: {exc}")
                batch_response = None
                batch_payload = None
            checks.append(
                {
                    "check_type": "graphql_batching_capability",
                    "target": endpoint_url,
                    "batch_size": 2,
                    "status_code": getattr(batch_response, "status_code", None),
                    "batching_accepted": isinstance(batch_payload, list),
                    "rate_limit_bypass_attempted": False,
                }
            )

            auth_candidates = [
                field
                for field in (schema_map.get("query_fields") or [])
                if re.search(r"user|account|admin|profile|tenant|secret", str(field.get("name") or ""), re.I)
            ][:5]
            checks.append(
                {
                    "check_type": "graphql_authorization_bypass_representation",
                    "target": endpoint_url,
                    "candidate_fields": [field.get("name") for field in auth_candidates],
                    "unauthenticated_data_extraction": False,
                    "type_confusion_exploitation": False,
                    "requires_configured_auth_context_future_slice": True,
                }
            )

    payload = {
        "tool": "graphql-probe",
        "targets": normalized_targets,
        "discovered_endpoints": discovered_endpoints,
        "schema_maps": schema_maps,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "candidate_endpoint_count": len(endpoint_candidates),
            "discovered_endpoint_count": len(discovered_endpoints),
            "schema_map_count": len(schema_maps),
            "check_count": len(checks),
            "finding_count": len(findings),
            "introspection_findings": sum(
                1 for item in findings if item.get("type") == "graphql_introspection_enabled"
            ),
            "depth_findings": sum(
                1 for item in findings if item.get("type") == "graphql_missing_query_depth_limit"
            ),
            "suggestion_findings": sum(
                1 for item in findings if item.get("type") == "graphql_field_suggestion_leakage"
            ),
            "injection_findings": sum(
                1 for item in findings if item.get("type") == "graphql_argument_injection_signal"
            ),
        },
        "safety": {
            "scope_enforced": True,
            "approved_graphql_endpoints_only": True,
            "active_tier_requires_approval": True,
            "depth_probe_max_levels": max_depth,
            "batch_probe_size": 2,
            "rate_limit_bypass_attempted": False,
            "unauthenticated_data_extraction": False,
            "authorization_bypass_exploitation": False,
            "runtime_mutation": False,
            "api_assessment_runner_changed": False,
            "zap_configuration_changed": False,
        },
    }
    return RunnerExecution(
        tool="graphql-probe",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.graphql_probe.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(GRAPHQL_RESULTS_ARTIFACT_NAME, payload)],
    )
