from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlparse


_JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "postgresql query failed",
    "pg_query()",
    "ora-00933",
    "ora-01756",
    "sqlite error",
    "sql syntax",
]
_INJECTABLE_PARAMETER_NAMES = {
    "cat",
    "category",
    "filter",
    "id",
    "item",
    "page",
    "product",
    "q",
    "query",
    "search",
    "sort",
    "user",
}
_SERIALIZED_COOKIE_MARKERS = ("rO0", "O%3A", "a%3A", "gAS")


def build_signal_profile(
    *,
    observations: Iterable[dict[str, Any]],
    normalized_inventory: dict[str, Any],
) -> dict[str, Any]:
    """Build evidence-backed technology signals from already collected recon data."""

    signals: list[dict[str, Any]] = []
    seen_signals: set[tuple[str, str, str]] = set()

    def add_signal(key: str, value: Any, *, confidence: float, source: str) -> None:
        if value in (None, ""):
            return
        signal_key = (key, str(value), source)
        if signal_key in seen_signals:
            return
        seen_signals.add(signal_key)
        signals.append(
            {
                "key": key,
                "value": value,
                "confidence": round(max(0.0, min(float(confidence), 1.0)), 3),
                "source": source,
            }
        )

    for observation in observations:
        tool = str(observation.get("tool") or "unknown").strip() or "unknown"
        payload = observation.get("data")
        if not isinstance(payload, dict):
            continue
        _extract_from_payload(payload, tool=tool, add_signal=add_signal)

    for technology in _dict_entries(normalized_inventory.get("technologies")):
        name = str(technology.get("name") or "").strip()
        if not name:
            continue
        source = str(technology.get("source") or "inventory_technology")
        lower_name = name.lower()
        if "wordpress" in lower_name:
            add_signal("wordpress_cms", True, confidence=0.9, source=source)
        if "php" == lower_name or lower_name.startswith("php "):
            add_signal("php_language", "PHP", confidence=0.85, source=source)
        if "spring" in lower_name:
            add_signal("java_spring_indicator", name, confidence=0.85, source=source)
        if "graphql" in lower_name:
            add_signal("graphql_endpoint", True, confidence=0.8, source=source)

    for fingerprint in _dict_entries(normalized_inventory.get("vendor_product_fingerprints")):
        product = str(fingerprint.get("product") or "").strip()
        if not product:
            continue
        source = str(fingerprint.get("source") or "inventory_fingerprint")
        lower_product = product.lower()
        if any(marker in lower_product for marker in ("apache", "nginx", "iis", "tomcat")):
            add_signal("server_header", product, confidence=0.75, source=source)
        if "tomcat" in lower_product:
            add_signal("java_spring_indicator", product, confidence=0.82, source=source)

    return {
        "signals": signals,
        "tech_stack_profile": _summarize_tech_stack(signals),
    }


def _extract_from_payload(
    payload: dict[str, Any],
    *,
    tool: str,
    add_signal,
) -> None:
    existing_profile = payload.get("signal_profile")
    if isinstance(existing_profile, dict):
        for signal in _dict_entries(existing_profile.get("signals")):
            add_signal(
                str(signal.get("key") or "").strip(),
                signal.get("value"),
                confidence=_confidence(signal.get("confidence"), default=0.6),
                source=str(signal.get("source") or "signal_profile"),
            )

    headers = _headers_from_payload(payload)
    body = _string_payload(payload, "body_excerpt", "body", "response_body", "html")
    urls = _urls_from_payload(payload)
    forms = _dict_entries(payload.get("forms"))
    cookies = _cookies_from_payload(payload, headers=headers)

    server = headers.get("server")
    if server:
        add_signal("server_header", server, confidence=0.9, source=f"{tool}_headers")

    powered_by = headers.get("x-powered-by")
    if powered_by and "php" in powered_by.lower():
        add_signal("php_language", "PHP", confidence=0.95, source="response_headers_x_powered_by")

    generator = headers.get("x-generator")
    if generator and "wordpress" in generator.lower():
        add_signal("wordpress_cms", True, confidence=0.95, source="response_headers_generator")

    app_context = headers.get("x-application-context") or headers.get("x-spring-application-context")
    if app_context:
        add_signal("java_spring_indicator", app_context, confidence=0.9, source=f"{tool}_headers")

    content_type = headers.get("content-type") or str(payload.get("content_type") or "")
    if "application/graphql" in content_type.lower():
        add_signal("graphql_endpoint", True, confidence=0.9, source=f"{tool}_headers")

    auth_header = headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(None, 1)[1].strip()
        if _JWT_PATTERN.match(token):
            add_signal("jwt_in_response", True, confidence=0.95, source=f"{tool}_headers")

    if body:
        lower_body = body.lower()
        if "wp-content/" in lower_body or "wp-login.php" in lower_body:
            add_signal("wordpress_cms", True, confidence=0.9, source=f"{tool}_response_body")
        if "name=\"generator\"" in lower_body and "wordpress" in lower_body:
            add_signal("wordpress_cms", True, confidence=0.95, source=f"{tool}_response_body")
        if "graphiql" in lower_body or "__schema" in lower_body:
            add_signal("graphql_endpoint", True, confidence=0.75, source=f"{tool}_response_body")
        for pattern in _SQL_ERROR_PATTERNS:
            if pattern in lower_body:
                add_signal("sql_error_pattern", pattern, confidence=0.9, source=f"{tool}_response_body")

    for url in urls:
        lower_url = url.lower()
        if "wp-content/" in lower_url or "wp-login.php" in lower_url:
            add_signal("wordpress_cms", True, confidence=0.9, source=f"{tool}_url_patterns")
        if "/graphql" in urlparse(url).path.lower():
            add_signal("graphql_endpoint", url, confidence=0.9, source=f"{tool}_url_patterns")
        for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if name.lower() in _INJECTABLE_PARAMETER_NAMES:
                add_signal(
                    "injectable_parameter",
                    f"?{name}=",
                    confidence=0.7,
                    source=f"{tool}_url_patterns",
                )

    for form in forms:
        action = str(form.get("action") or payload.get("final_url") or payload.get("url") or "").strip()
        inputs = _dict_entries(form.get("inputs"))
        input_types = {
            str(item.get("type") or "").strip().lower()
            for item in inputs
            if isinstance(item, dict)
        }
        input_names = {
            str(item.get("name") or "").strip().lower()
            for item in inputs
            if isinstance(item, dict)
        }
        if "password" in input_types:
            add_signal("login_form_found", action or True, confidence=1.0, source=f"{tool}_forms")
        if "file" in input_types:
            add_signal("file_upload_endpoint", action or True, confidence=1.0, source=f"{tool}_forms")
        for name in input_names & _INJECTABLE_PARAMETER_NAMES:
            add_signal("injectable_parameter", name, confidence=0.65, source=f"{tool}_forms")

    for cookie in cookies:
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        value_shape = str(cookie.get("value_shape") or "").strip()
        if name.upper() == "PHPSESSID":
            add_signal("php_language", "PHP", confidence=0.92, source="cookie_analysis")
        if name.upper() == "JSESSIONID":
            add_signal("java_spring_indicator", "JSESSIONID", confidence=0.92, source="cookie_analysis")
        if value_shape == "jwt" or _JWT_PATTERN.match(value):
            add_signal("jwt_in_response", True, confidence=0.9, source="cookie_analysis")
        if value_shape == "serialized" or any(value.startswith(marker) for marker in _SERIALIZED_COOKIE_MARKERS):
            add_signal("serialized_cookie", name or True, confidence=0.85, source="cookie_analysis")


def _summarize_tech_stack(signals: list[dict[str, Any]]) -> dict[str, Any]:
    server = _unique_values(signals, "server_header")
    language = _unique_values(signals, "php_language")
    cms = ["WordPress"] if any(signal["key"] == "wordpress_cms" for signal in signals) else []
    java_indicators = _unique_values(signals, "java_spring_indicator")
    login_forms = _unique_values(signals, "login_form_found")
    file_upload_endpoints = _unique_values(signals, "file_upload_endpoint")
    graphql_endpoints = _unique_values(signals, "graphql_endpoint")
    return {
        "server": server,
        "language": language,
        "cms": cms,
        "jwt_present": any(signal["key"] == "jwt_in_response" for signal in signals),
        "graphql_present": any(signal["key"] == "graphql_endpoint" for signal in signals),
        "java_present": bool(java_indicators),
        "java_indicators": java_indicators,
        "login_forms": login_forms,
        "file_upload_endpoints": file_upload_endpoints,
        "graphql_endpoints": graphql_endpoints,
        "injectable_parameters": _unique_values(signals, "injectable_parameter"),
        "sql_error_patterns": _unique_values(signals, "sql_error_pattern"),
        "serialized_cookie_hints": _unique_values(signals, "serialized_cookie"),
    }


def _unique_values(signals: list[dict[str, Any]], key: str) -> list[Any]:
    values: list[Any] = []
    seen: set[str] = set()
    for signal in signals:
        if signal.get("key") != key:
            continue
        value = signal.get("value")
        marker = str(value)
        if marker in seen:
            continue
        seen.add(marker)
        values.append(value)
    return values


def _headers_from_payload(payload: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key in ("headers", "response_headers"):
        raw_headers = payload.get(key)
        if isinstance(raw_headers, dict):
            for header_name, header_value in raw_headers.items():
                normalized_name = str(header_name).strip().lower()
                if normalized_name and isinstance(header_value, (str, int, float)):
                    headers[normalized_name] = str(header_value).strip()
    for key in ("server", "x_powered_by", "x_generator", "content_type", "authorization"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            headers[key.replace("_", "-")] = value.strip()
    return headers


def _cookies_from_payload(
    payload: dict[str, Any],
    *,
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    cookies = [
        cookie for cookie in _dict_entries(payload.get("cookies")) if str(cookie.get("name") or "").strip()
    ]
    raw_set_cookie = headers.get("set-cookie") or payload.get("set_cookie")
    if isinstance(raw_set_cookie, str) and raw_set_cookie.strip():
        for cookie_header in raw_set_cookie.split(","):
            name, _, value = cookie_header.partition("=")
            if name.strip():
                cookies.append({"name": name.strip(), "value": value.split(";", 1)[0].strip()})
    return cookies


def _urls_from_payload(payload: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for key in ("url", "request_url", "final_url"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            urls.append(value.strip())
    for key in ("urls", "routes", "links"):
        raw_values = payload.get(key)
        if not isinstance(raw_values, list):
            continue
        for item in raw_values:
            if isinstance(item, str) and item.strip():
                urls.append(item.strip())
            elif isinstance(item, dict):
                value = str(item.get("url") or item.get("href") or item.get("path") or "").strip()
                if value:
                    urls.append(value)
    for endpoint in _dict_entries(payload.get("endpoints")):
        url = str(endpoint.get("url") or endpoint.get("endpoint") or "").strip()
        if url:
            urls.append(url)
    return list(dict.fromkeys(urls))


def _string_payload(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _dict_entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _confidence(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
