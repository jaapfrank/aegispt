from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from urllib.parse import urljoin, urlparse

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

API_ASSESSMENT_RESULTS_ARTIFACT_NAME = "api-assessment-results.json"
API_ASSESSMENT_INVENTORY_ARTIFACT_NAME = "api-assessment-inventory.json"
RUNNER_DIGEST = "workers.api_assessment.runner:v1"

SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
SENSITIVE_SEGMENTS = (
    "admin",
    "billing",
    "credential",
    "identity",
    "internal",
    "invoice",
    "order",
    "payment",
    "reset",
    "token",
    "transfer",
    "user",
    "vehicle",
)
SENSITIVE_PROPERTIES = (
    "api_key",
    "apikey",
    "authorization",
    "creditcard",
    "credential",
    "hash",
    "password",
    "refresh_token",
    "secret",
    "session",
    "ssn",
    "token",
)


@dataclass(slots=True, frozen=True)
class ApiEndpoint:
    method: str
    url: str
    path: str
    source: str
    api_style: str = "rest"
    operation_id: str | None = None
    requires_auth: bool = False
    request_properties: tuple[str, ...] = ()
    response_properties: tuple[str, ...] = ()


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind=kind,
    )


def _as_object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalized_string_list(value: object, *, limit: int = 100) -> list[str]:
    if isinstance(value, str):
        value = [value]
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
        if len(normalized) >= limit:
            break
    return normalized


def _join_url(base_url: str, path: str) -> str:
    normalized_base = normalize_http_target(base_url).rstrip("/") + "/"
    return urljoin(normalized_base, path.lstrip("/"))


def _path_from_url(value: str) -> str:
    parsed = urlparse(value)
    return parsed.path or "/"


def _scope_check_url(value: str) -> str:
    return value.replace("{", "").replace("}", "")


def _allowed_scope_values(scope_allowlist: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("api_base_urls", "urls", "domains", "hosts", "targets"):
        raw_values = scope_allowlist.get(key)
        if isinstance(raw_values, list):
            values.extend(str(item).strip() for item in raw_values if str(item).strip())
    return values


def _endpoint_url_is_allowed(scope_allowlist: dict[str, Any], value: str) -> bool:
    candidate = _scope_check_url(value)
    if target_value_is_allowed(scope_allowlist, candidate):
        return True
    for allowed in _allowed_scope_values(scope_allowlist):
        if candidate == allowed or candidate.startswith(allowed.rstrip("/") + "/"):
            return True
    return False


def _schema_properties(schema: object, *, limit: int = 120) -> tuple[str, ...]:
    properties: list[str] = []
    seen: set[str] = set()

    def walk(node: object) -> None:
        if len(properties) >= limit or not isinstance(node, dict):
            return
        raw_properties = node.get("properties")
        if isinstance(raw_properties, dict):
            for name, child in raw_properties.items():
                normalized = str(name).strip()
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    properties.append(normalized)
                walk(child)
                if len(properties) >= limit:
                    return
        for key in ("items", "allOf", "oneOf", "anyOf"):
            child = node.get(key)
            if isinstance(child, list):
                for item in child:
                    walk(item)
            else:
                walk(child)

    walk(schema)
    return tuple(properties)


def _operation_properties(operation: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    request_properties: list[str] = []
    response_properties: list[str] = []

    request_body = _as_object(operation.get("requestBody"))
    content = _as_object(request_body.get("content"))
    for media in content.values():
        schema = _as_object(media).get("schema")
        request_properties.extend(_schema_properties(schema))

    responses = _as_object(operation.get("responses"))
    for response in responses.values():
        response_content = _as_object(_as_object(response).get("content"))
        for media in response_content.values():
            response_properties.extend(_schema_properties(_as_object(media).get("schema")))

    return tuple(dict.fromkeys(request_properties)), tuple(dict.fromkeys(response_properties))


def _operation_requires_auth(
    *,
    operation: dict[str, Any],
    path_item: dict[str, Any],
    spec: dict[str, Any],
) -> bool:
    if "security" in operation:
        security = operation.get("security")
    elif "security" in path_item:
        security = path_item.get("security")
    else:
        security = spec.get("security")
    return isinstance(security, list) and len(security) > 0


def _parse_openapi_spec(
    *,
    spec: dict[str, Any],
    targets: list[str],
) -> tuple[list[ApiEndpoint], list[str]]:
    if not (spec.get("openapi") or spec.get("swagger")):
        return [], ["unsupported OpenAPI payload: missing openapi/swagger marker"]

    base_urls = list(targets)
    for server in spec.get("servers", []) if isinstance(spec.get("servers"), list) else []:
        if isinstance(server, dict) and isinstance(server.get("url"), str):
            base_urls.append(server["url"])
    if not base_urls:
        base_urls = ["/"]
    base_url = normalize_http_target(base_urls[0]) if base_urls[0] != "/" else "/"

    endpoints: list[ApiEndpoint] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return [], ["unsupported OpenAPI payload: paths must be an object"]

    for raw_path, raw_path_item in paths.items():
        path = str(raw_path or "").strip()
        path_item = _as_object(raw_path_item)
        if not path or not path_item:
            continue
        for method, raw_operation in path_item.items():
            normalized_method = str(method).strip().lower()
            if normalized_method not in SUPPORTED_METHODS:
                continue
            operation = _as_object(raw_operation)
            request_props, response_props = _operation_properties(operation)
            endpoints.append(
                ApiEndpoint(
                    method=normalized_method.upper(),
                    url=_join_url(base_url, path),
                    path=path,
                    source="openapi",
                    operation_id=str(operation.get("operationId") or "").strip() or None,
                    requires_auth=_operation_requires_auth(
                        operation=operation,
                        path_item=path_item,
                        spec=spec,
                    ),
                    request_properties=request_props,
                    response_properties=response_props,
                )
            )
    return endpoints, []


def _postman_url(raw_url: object, *, fallback_base: str) -> str | None:
    if isinstance(raw_url, str) and raw_url.strip():
        return raw_url.strip()
    if not isinstance(raw_url, dict):
        return None
    raw = str(raw_url.get("raw") or "").strip()
    if raw:
        return raw
    path = "/".join(_normalized_string_list(raw_url.get("path"), limit=20))
    if not path:
        return None
    host = ".".join(_normalized_string_list(raw_url.get("host"), limit=10))
    protocol = str(raw_url.get("protocol") or "").strip() or "https"
    if host:
        return f"{protocol}://{host}/{path.lstrip('/')}"
    return _join_url(fallback_base, path)


def _parse_postman_collection(
    *,
    collection: dict[str, Any],
    targets: list[str],
) -> tuple[list[ApiEndpoint], list[str]]:
    if "item" not in collection:
        return [], ["unsupported Postman payload: missing item list"]

    fallback_base = normalize_http_target(targets[0]) if targets else "http://api.local"
    endpoints: list[ApiEndpoint] = []

    def walk(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                walk(item.get("item"))
                continue
            request = item.get("request")
            if isinstance(request, str):
                url = request
                method = "GET"
            else:
                request_obj = _as_object(request)
                url = _postman_url(request_obj.get("url"), fallback_base=fallback_base)
                method = str(request_obj.get("method") or "GET").upper()
            if not url:
                continue
            endpoint_url = normalize_http_target(url) if not url.startswith("/") else _join_url(fallback_base, url)
            endpoints.append(
                ApiEndpoint(
                    method=method,
                    url=endpoint_url,
                    path=_path_from_url(endpoint_url),
                    source="postman",
                    operation_id=str(item.get("name") or "").strip() or None,
                    requires_auth=False,
                )
            )

    walk(collection.get("item"))
    return endpoints, []


def _parse_graphql_introspection(
    *,
    introspection: dict[str, Any],
    targets: list[str],
    endpoint_url: str | None,
    auth_contexts: list[dict[str, Any]],
) -> tuple[list[ApiEndpoint], list[str]]:
    schema = introspection.get("__schema")
    if not isinstance(schema, dict):
        data = introspection.get("data")
        if isinstance(data, dict):
            schema = data.get("__schema")
    if not isinstance(schema, dict):
        return [], ["unsupported GraphQL payload: missing __schema"]

    raw_endpoint = endpoint_url or (targets[0] if targets else "")
    endpoint = normalize_http_target(raw_endpoint or "http://api.local/graphql")
    if _path_from_url(endpoint) in {"", "/"}:
        endpoint = endpoint.rstrip("/") + "/graphql"
    return [
        ApiEndpoint(
            method="POST",
            url=endpoint,
            path=_path_from_url(endpoint),
            source="graphql-introspection",
            api_style="graphql",
            operation_id="GraphQL introspection schema",
            requires_auth=bool(auth_contexts),
        )
    ], []


def _endpoint_record(endpoint: ApiEndpoint) -> dict[str, Any]:
    return {
        "method": endpoint.method,
        "url": endpoint.url,
        "path": endpoint.path,
        "source": endpoint.source,
        "api_style": endpoint.api_style,
        "operation_id": endpoint.operation_id,
        "requires_auth": endpoint.requires_auth,
        "request_properties": list(endpoint.request_properties),
        "response_properties": list(endpoint.response_properties),
    }


def _contains_sensitive(value: str) -> bool:
    lowered = value.strip().lower()
    return any(segment in lowered for segment in SENSITIVE_SEGMENTS)


def _sensitive_properties(properties: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for prop in properties:
        normalized = prop.strip().lower()
        if any(marker in normalized for marker in SENSITIVE_PROPERTIES):
            matches.append(prop)
    return matches


def _add_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    endpoint: ApiEndpoint,
    summary: str,
    tags: list[str],
    evidence: dict[str, Any] | None = None,
) -> None:
    key = (finding_type, f"{endpoint.method} {endpoint.url}".lower())
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": endpoint.url,
            "summary": summary,
            "method": endpoint.method,
            "path": endpoint.path,
            "methodology_tags": ["api_security", "owasp_api_top_10_2023", *tags],
            "evidence": evidence or _endpoint_record(endpoint),
        }
    )


def _analyze_endpoints(
    endpoints: list[ApiEndpoint],
    *,
    auth_contexts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for endpoint in endpoints:
        endpoint_label = f"{endpoint.method} {endpoint.path}"
        checks.append(
            {
                "check": "api_inventory",
                "endpoint": endpoint_label,
                "status": "observed",
                "source": endpoint.source,
            }
        )

        object_route = any(marker in endpoint.path for marker in ("{id}", "{userId}", ":id", "/id/"))
        if object_route and not endpoint.requires_auth:
            _add_finding(
                findings,
                seen,
                finding_type="object_level_authorization",
                title="Object-level authorization missing on API object route",
                severity="high",
                endpoint=endpoint,
                summary=(
                    f"{endpoint_label} exposes an object-style route without declared auth in the supplied API contract."
                ),
                tags=["api1_broken_object_level_authorization"],
            )

        if _contains_sensitive(endpoint.path) and not endpoint.requires_auth and endpoint.method not in {"OPTIONS", "HEAD"}:
            _add_finding(
                findings,
                seen,
                finding_type="unauthenticated_route_exposure",
                title="Sensitive API route is exposed without declared authentication",
                severity="medium",
                endpoint=endpoint,
                summary=(
                    f"{endpoint_label} appears sensitive and has no declared authentication requirement in the supplied API contract."
                ),
                tags=["api5_broken_function_level_authorization", "api8_security_misconfiguration"],
            )

        if endpoint.method in {"PUT", "PATCH", "DELETE"} and not endpoint.requires_auth:
            _add_finding(
                findings,
                seen,
                finding_type="method_tampering",
                title="Unsafe API method is exposed without declared authentication",
                severity="medium",
                endpoint=endpoint,
                summary=(
                    f"{endpoint_label} uses a state-changing method without declared auth; validate method-level authorization before production exposure."
                ),
                tags=["api5_broken_function_level_authorization"],
            )

        exposed_properties = _sensitive_properties(endpoint.response_properties)
        if exposed_properties:
            _add_finding(
                findings,
                seen,
                finding_type="object_property_exposure",
                title="API response schema exposes sensitive object properties",
                severity="high",
                endpoint=endpoint,
                summary=(
                    f"{endpoint_label} response schema includes sensitive properties: {', '.join(exposed_properties[:8])}."
                ),
                tags=["api3_broken_object_property_level_authorization"],
                evidence={**_endpoint_record(endpoint), "sensitive_properties": exposed_properties},
            )

        if endpoint.api_style == "graphql" and endpoint.source == "graphql-introspection" and not auth_contexts:
            _add_finding(
                findings,
                seen,
                finding_type="graphql_schema_exposure",
                title="GraphQL introspection schema is available without auth context",
                severity="medium",
                endpoint=endpoint,
                summary=(
                    "The supplied GraphQL introspection response proves schema visibility without an authenticated context for this run."
                ),
                tags=["api7_server_side_request_forgery", "api8_security_misconfiguration"],
            )

    return checks, findings


def _inventory_payload(endpoints: list[ApiEndpoint]) -> dict[str, Any]:
    hosts: list[str] = []
    seen_hosts: set[str] = set()
    for endpoint in endpoints:
        host = urlparse(endpoint.url).hostname or ""
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            hosts.append(host)
    return {
        "tool": "api-assessment",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "endpoints": [
                {
                    "url": endpoint.url,
                    "methods": [endpoint.method],
                    "status_code": None,
                    "title": endpoint.operation_id,
                    "confidence": 0.82,
                }
                for endpoint in endpoints
            ],
            "api_types": [
                {
                    "type": "graphql" if any(endpoint.api_style == "graphql" for endpoint in endpoints) else "rest",
                    "source": "api-assessment",
                    "confidence": 0.86,
                }
            ],
            "technologies": [
                {
                    "name": "OpenAPI/Postman/GraphQL contract",
                    "vendor": "api-contract",
                    "version": None,
                    "confidence": 0.72,
                }
            ],
            "confidence": 0.84 if endpoints else 0.0,
        },
    }


def execute_api_assessment(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    auth_contexts: list[dict[str, Any]] | object = None,
    openapi_spec: dict[str, Any] | object = None,
    postman_collection: dict[str, Any] | object = None,
    graphql_introspection: dict[str, Any] | object = None,
    graphql_endpoint_url: str | None = None,
    requires_auth_context: bool = False,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [normalize_http_target(target) for target in targets if str(target).strip()]
    scope = scope_allowlist or {}
    for target in normalized_targets:
        if not target_value_is_allowed(scope, target):
            raise ValueError(f"target outside scope: {target}")

    safe_auth_contexts = auth_contexts if isinstance(auth_contexts, list) else []
    if requires_auth_context and not safe_auth_contexts:
        payload = {
            "status": "skipped",
            "reason": "missing_auth_context",
            "targets": normalized_targets,
            "endpoint_inventory": [],
            "checks": [],
            "findings": [],
            "safety": {
                "load_testing": False,
                "volumetric_testing": False,
                "uncontrolled_fuzzing": False,
                "business_process_abuse": False,
            },
        }
        return RunnerExecution(
            tool="api-assessment",
            exit_code=0,
            stdout="API assessment skipped: authenticated API context is required but not available.",
            stderr="",
            metadata={
                "status": "skipped",
                "reason": "missing_auth_context",
                "runner_digest": RUNNER_DIGEST,
                "endpoint_count": 0,
                "finding_count": 0,
            },
            artifacts=[
                _json_artifact(
                    API_ASSESSMENT_RESULTS_ARTIFACT_NAME,
                    payload,
                    kind="api-assessment-results",
                )
            ],
        )

    endpoints: list[ApiEndpoint] = []
    warnings: list[str] = []
    saw_input = False

    if isinstance(openapi_spec, dict) and openapi_spec:
        saw_input = True
        parsed, parse_warnings = _parse_openapi_spec(spec=openapi_spec, targets=normalized_targets)
        endpoints.extend(parsed)
        warnings.extend(parse_warnings)
    elif openapi_spec not in (None, {}, []):
        saw_input = True
        warnings.append("unsupported OpenAPI payload: expected object")

    if isinstance(postman_collection, dict) and postman_collection:
        saw_input = True
        parsed, parse_warnings = _parse_postman_collection(
            collection=postman_collection,
            targets=normalized_targets,
        )
        endpoints.extend(parsed)
        warnings.extend(parse_warnings)
    elif postman_collection not in (None, {}, []):
        saw_input = True
        warnings.append("unsupported Postman payload: expected object")

    if isinstance(graphql_introspection, dict) and graphql_introspection:
        saw_input = True
        parsed, parse_warnings = _parse_graphql_introspection(
            introspection=graphql_introspection,
            targets=normalized_targets,
            endpoint_url=graphql_endpoint_url,
            auth_contexts=safe_auth_contexts,
        )
        endpoints.extend(parsed)
        warnings.extend(parse_warnings)
    elif graphql_introspection not in (None, {}, []):
        saw_input = True
        warnings.append("unsupported GraphQL payload: expected object")

    if not saw_input:
        payload = {
            "status": "skipped",
            "reason": "missing_api_spec",
            "targets": normalized_targets,
            "endpoint_inventory": [],
            "checks": [],
            "findings": [],
            "warnings": [],
            "safety": {
                "load_testing": False,
                "volumetric_testing": False,
                "uncontrolled_fuzzing": False,
                "business_process_abuse": False,
            },
        }
        return RunnerExecution(
            tool="api-assessment",
            exit_code=0,
            stdout="API assessment skipped: no OpenAPI, Postman, or GraphQL input was supplied.",
            stderr="",
            metadata={
                "status": "skipped",
                "reason": "missing_api_spec",
                "runner_digest": RUNNER_DIGEST,
                "endpoint_count": 0,
                "finding_count": 0,
            },
            artifacts=[
                _json_artifact(
                    API_ASSESSMENT_RESULTS_ARTIFACT_NAME,
                    payload,
                    kind="api-assessment-results",
                )
            ],
        )

    if warnings and not endpoints:
        payload = {
            "status": "skipped",
            "reason": "unsupported_schema_format",
            "targets": normalized_targets,
            "endpoint_inventory": [],
            "checks": [],
            "findings": [],
            "warnings": warnings,
            "safety": {
                "load_testing": False,
                "volumetric_testing": False,
                "uncontrolled_fuzzing": False,
                "business_process_abuse": False,
            },
        }
        return RunnerExecution(
            tool="api-assessment",
            exit_code=0,
            stdout="API assessment skipped: supplied API input could not be parsed safely.",
            stderr="\n".join(warnings),
            metadata={
                "status": "skipped",
                "reason": "unsupported_schema_format",
                "runner_digest": RUNNER_DIGEST,
                "endpoint_count": 0,
                "finding_count": 0,
            },
            artifacts=[
                _json_artifact(
                    API_ASSESSMENT_RESULTS_ARTIFACT_NAME,
                    payload,
                    kind="api-assessment-results",
                )
            ],
        )

    for endpoint in endpoints:
        if not _endpoint_url_is_allowed(scope, endpoint.url):
            raise ValueError(f"target outside scope: {endpoint.url}")

    checks, findings = _analyze_endpoints(endpoints, auth_contexts=safe_auth_contexts)
    inventory = _inventory_payload(endpoints)
    payload = {
        "status": "completed",
        "targets": normalized_targets,
        "endpoint_inventory": [_endpoint_record(endpoint) for endpoint in endpoints],
        "checks": checks,
        "findings": findings,
        "warnings": warnings,
        "safety": {
            "load_testing": False,
            "volumetric_testing": False,
            "uncontrolled_fuzzing": False,
            "business_process_abuse": False,
        },
    }
    return RunnerExecution(
        tool="api-assessment",
        exit_code=0,
        stdout=(
            f"API assessment reviewed {len(endpoints)} endpoints and produced "
            f"{len(findings)} evidence-backed finding(s)."
        ),
        stderr="\n".join(warnings),
        metadata={
            "status": "completed",
            "runner_digest": RUNNER_DIGEST,
            "endpoint_count": len(endpoints),
            "finding_count": len(findings),
            "auth_context_count": len(safe_auth_contexts),
        },
        artifacts=[
            _json_artifact(
                API_ASSESSMENT_RESULTS_ARTIFACT_NAME,
                payload,
                kind="api-assessment-results",
            ),
            _json_artifact(
                API_ASSESSMENT_INVENTORY_ARTIFACT_NAME,
                inventory,
                kind="api-assessment-inventory",
            ),
        ],
    )
