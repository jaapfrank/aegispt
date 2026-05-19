from __future__ import annotations

import ipaddress
import json
import re
import time
from base64 import b64encode
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

IOT_DEFAULT_CREDS_ARTIFACT_NAME = "iot-default-creds-results.json"
IOT_DEFAULT_CREDS_RUNNER_DIGEST = "workers.iot_default_creds.runner:v1"
DEFAULT_CREDS_PATH = Path(__file__).with_name("default-creds.json")
REDACTED_PASSWORD = "[REDACTED]"
HTTP_MANAGEMENT_PORTS = {80, 81, 443, 5000, 5001, 8000, 8008, 8080, 8081, 8443, 8888, 8123}
LOGIN_MARKERS = (
    "type=\"password\"",
    "type='password'",
    "name=\"password\"",
    "name='password'",
    "login",
    "sign in",
    "signin",
    "authentication",
)
NO_AUTH_NEGATIVE_MARKERS = (
    "unauthorized",
    "forbidden",
    "login",
    "sign in",
    "signin",
    "password",
)


@dataclass(slots=True, frozen=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    final_url: str


HttpClient = Callable[[str, str, dict[str, str], bytes | None, float], HttpResponse]
SleepFunc = Callable[[float], None]
TimeFunc = Callable[[], float]


def load_default_credentials(path: Path | None = None) -> list[dict[str, Any]]:
    source_path = path or DEFAULT_CREDS_PATH
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("default credential database must be a JSON list")
    credentials: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        match_tokens = [
            str(token).strip().lower()
            for token in list(item.get("match_tokens") or [])
            if str(token).strip()
        ]
        username = str(item.get("username") or "").strip()
        password = str(item.get("password") or "")
        no_auth_expected = bool(item.get("no_auth_expected", False))
        if not no_auth_expected and not username:
            continue
        credentials.append(
            {
                "vendor": str(item.get("vendor") or "").strip() or "Generic",
                "model": str(item.get("model") or "").strip() or None,
                "device_type": str(item.get("device_type") or "").strip() or "iot-device",
                "match_tokens": match_tokens,
                "username": username,
                "password": password,
                "no_auth_expected": no_auth_expected,
            }
        )
    return credentials


def _normalized_string_list(values: Iterable[object] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        candidate = str(value or "").strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized


def _scope_networks(values: Iterable[object] | None) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values or []:
        candidate = str(value or "").strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
            continue
        except ValueError:
            pass
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        networks.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))
    return networks


def _scope_values(targets: list[str], scope_allowlist: dict[str, Any]) -> list[str]:
    values = list(targets)
    for key in ("cidrs", "cidr_ranges", "hosts", "ip_addresses", "targets"):
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
    return _normalized_string_list(values)


def _host_in_scope(host: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return any(address in network for network in networks)


def _safe_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 < port <= 65535:
        return port
    return None


def _headers_to_dict(headers: object) -> dict[str, str]:
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(key).lower(): str(value) for key, value in headers.items()}
    return {}


def _default_http_client(
    url: str,
    method: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout_seconds: float,
) -> HttpResponse:
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            body = response.read(524288).decode("utf-8", errors="replace")
            return HttpResponse(
                status_code=int(getattr(response, "status", 0) or 0),
                headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                body=body,
                final_url=str(response.geturl() or url),
            )
    except HTTPError as exc:
        body = exc.read(262144).decode("utf-8", errors="replace")
        return HttpResponse(
            status_code=int(exc.code),
            headers={str(key).lower(): str(value) for key, value in exc.headers.items()},
            body=body,
            final_url=str(exc.geturl() or url),
        )
    except (OSError, URLError) as exc:
        return HttpResponse(
            status_code=0,
            headers={},
            body=str(exc),
            final_url=url,
        )


def _url_from_host_service(host: str, port: int | None, service: str | None = None) -> str:
    service_text = str(service or "").lower()
    scheme = "https" if port == 443 or "https" in service_text else "http"
    if port and port not in {80, 443}:
        return f"{scheme}://{host}:{port}/"
    return f"{scheme}://{host}/"


def _device_metadata_text(device: dict[str, Any]) -> str:
    values: list[str] = []
    for key in (
        "device_type",
        "vendor",
        "manufacturer",
        "model",
        "model_name",
        "product",
        "service",
        "service_type",
        "server",
        "title",
        "name",
    ):
        value = device.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
    txt = device.get("txt")
    if isinstance(txt, dict):
        values.extend(str(value) for value in txt.values() if str(value).strip())
    return " ".join(values).lower()


def _add_device(
    devices: dict[tuple[str, int, str], dict[str, Any]],
    *,
    url: str,
    host: str,
    port: int,
    source: str,
    service: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    parsed = urlparse(url)
    normalized_url = url
    if not parsed.scheme:
        normalized_url = _url_from_host_service(host, port, service)
    key = (host.lower(), port, normalized_url.rstrip("/").lower())
    current = devices.get(key, {})
    merged_metadata = {**current, **(metadata or {})}
    devices[key] = {
        **merged_metadata,
        "url": normalized_url,
        "host": host,
        "port": port,
        "source": source,
        "service": service or merged_metadata.get("service"),
    }


def _devices_from_inventory(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    devices: dict[tuple[str, int, str], dict[str, Any]] = {}
    endpoints = inventory.get("http_endpoints")
    if not isinstance(endpoints, list):
        endpoints = inventory.get("endpoints") if isinstance(inventory.get("endpoints"), list) else []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url") or "").strip()
        parsed = urlparse(url)
        host = str(parsed.hostname or "").strip()
        port = _safe_port(parsed.port or (443 if parsed.scheme == "https" else 80))
        if host and port:
            _add_device(
                devices,
                url=url,
                host=host,
                port=port,
                source=str(endpoint.get("source") or "inventory-endpoint"),
                metadata={"title": endpoint.get("title"), **endpoint},
            )

    for service in inventory.get("services", []) if isinstance(inventory.get("services"), list) else []:
        if not isinstance(service, dict):
            continue
        host = str(service.get("host") or "").strip()
        port = _safe_port(service.get("port"))
        service_name = str(service.get("service") or "").strip().lower()
        if not host or not port:
            continue
        if port not in HTTP_MANAGEMENT_PORTS and "http" not in service_name:
            continue
        _add_device(
            devices,
            url=_url_from_host_service(host, port, service_name),
            host=host,
            port=port,
            source=str(service.get("source") or "inventory-service"),
            service=service_name,
            metadata=service,
        )

    for device in inventory.get("devices", []) if isinstance(inventory.get("devices"), list) else []:
        if not isinstance(device, dict):
            continue
        host = str(device.get("ip") or device.get("host") or "").strip()
        port = _safe_port(device.get("port"))
        url = str(device.get("presentation_url") or device.get("location") or "").strip()
        parsed = urlparse(url)
        host = host or str(parsed.hostname or "").strip()
        port = port or _safe_port(parsed.port or (443 if parsed.scheme == "https" else 80))
        if host and port:
            _add_device(
                devices,
                url=url or _url_from_host_service(host, port, str(device.get("service_type") or "")),
                host=host,
                port=port,
                source=str(device.get("source") or "mdns-ssdp"),
                service=str(device.get("service_type") or ""),
                metadata=device,
            )

    fingerprints = [
        entry
        for entry in inventory.get("vendor_product_fingerprints", [])
        if isinstance(entry, dict)
    ]
    if fingerprints:
        fingerprint_text = " ".join(
            " ".join(str(entry.get(key) or "") for key in ("vendor", "product", "version"))
            for entry in fingerprints
        )
        for device in devices.values():
            device.setdefault("fingerprint_context", fingerprint_text)

    return list(devices.values())


def _devices_from_targets(targets: list[str]) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for target in targets:
        raw = str(target or "").strip()
        if not raw:
            continue
        try:
            ipaddress.ip_network(raw, strict=False)
            if "/" in raw:
                continue
        except ValueError:
            pass
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        host = str(parsed.hostname or raw.split(":", 1)[0]).strip()
        port = _safe_port(parsed.port or (443 if parsed.scheme == "https" else 80))
        if host and port:
            scheme = parsed.scheme if parsed.scheme in {"http", "https"} else None
            url = raw if scheme else _url_from_host_service(host, port)
            devices.append({"url": url, "host": host, "port": port, "source": "explicit-target"})
    return devices


def build_management_targets(
    *,
    targets: list[str],
    inventory: dict[str, Any] | None,
    scope_allowlist: dict[str, Any],
) -> list[dict[str, Any]]:
    source_inventory = inventory if isinstance(inventory, dict) else {}
    devices = [*_devices_from_inventory(source_inventory), *_devices_from_targets(targets)]
    networks = _scope_networks(_scope_values(targets, scope_allowlist))
    deduped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for device in devices:
        host = str(device.get("host") or "").strip()
        port = _safe_port(device.get("port"))
        url = str(device.get("url") or "").strip()
        if not host or port is None or not url or not _host_in_scope(host, networks):
            continue
        key = (host.lower(), port, url.rstrip("/").lower())
        if key not in deduped:
            deduped[key] = device
    return list(deduped.values())


def match_default_credentials(
    device: dict[str, Any],
    credentials: list[dict[str, Any]],
    *,
    max_attempts: int,
) -> list[dict[str, Any]]:
    haystack = " ".join(
        [
            _device_metadata_text(device),
            str(device.get("fingerprint_context") or "").lower(),
            str(device.get("url") or "").lower(),
        ]
    )
    matched: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in credentials:
        tokens = [token for token in list(entry.get("match_tokens") or []) if token]
        device_type = str(entry.get("device_type") or "").lower()
        if not any(token in haystack for token in tokens) and (
            not device_type or device_type not in haystack
        ):
            continue
        key = (
            str(entry.get("vendor") or "").lower(),
            str(entry.get("username") or "").lower(),
            str(entry.get("password") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        matched.append(entry)
        if len([item for item in matched if not item.get("no_auth_expected")]) >= max_attempts:
            break
    return matched


def _looks_like_login(body: str, headers: dict[str, str]) -> bool:
    text = body[:65536].lower()
    if "www-authenticate" in headers:
        return True
    return any(marker in text for marker in LOGIN_MARKERS)


def _is_accessible_without_auth(response: HttpResponse) -> bool:
    if response.status_code not in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
        return False
    if "www-authenticate" in response.headers:
        return False
    text = response.body[:65536].lower()
    return not any(marker in text for marker in NO_AUTH_NEGATIVE_MARKERS)


def _basic_auth_header(username: str, password: str) -> str:
    token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _extract_form_attempt(body: str, base_url: str, username: str, password: str) -> tuple[str, bytes] | None:
    lowered = body.lower()
    if "type=\"password\"" not in lowered and "type='password'" not in lowered:
        return None
    form_match = re.search(r"(?is)<form\b[^>]*>(.*?)</form>", body)
    form_html = form_match.group(0) if form_match else body[:65536]
    action_match = re.search(r"(?is)\baction\s*=\s*['\"]([^'\"]+)['\"]", form_html)
    action = unescape(action_match.group(1).strip()) if action_match else base_url
    username_field = "username"
    password_field = "password"
    user_match = re.search(
        r"(?is)<input\b[^>]*(?:name|id)\s*=\s*['\"]([^'\"]*(?:user|login|email)[^'\"]*)['\"][^>]*>",
        form_html,
    )
    if user_match:
        username_field = unescape(user_match.group(1).strip()) or username_field
    password_match = re.search(
        r"(?is)<input\b[^>]*(?:name|id)\s*=\s*['\"]([^'\"]*pass[^'\"]*)['\"][^>]*>",
        form_html,
    )
    if password_match:
        password_field = unescape(password_match.group(1).strip()) or password_field
    return (
        urljoin(base_url, action),
        urlencode({username_field: username, password_field: password}).encode("utf-8"),
    )


def _credential_accepted(response: HttpResponse) -> bool:
    if response.status_code not in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
        return False
    return not _looks_like_login(response.body, response.headers)


def _redacted_attempt(entry: dict[str, Any], *, result: str, status_code: int, method: str) -> dict[str, Any]:
    return {
        "vendor": entry.get("vendor"),
        "model": entry.get("model"),
        "username": entry.get("username"),
        "password": REDACTED_PASSWORD,
        "password_redacted": True,
        "method": method,
        "result": result,
        "status_code": status_code,
    }


def _build_finding(
    *,
    title: str,
    severity: str,
    target_id: str,
    summary: str,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target_id": target_id,
        "summary": summary,
        "methodology_tags": [
            "iot",
            "default-credentials",
            "active-validation",
            *(tags or []),
        ],
        "ptes_phase": "vulnerability_analysis",
        "nist_phase": "vulnerability_validation",
        "wstg_id": "WSTG-ATHN",
        "control_family": "authentication",
    }


def execute_iot_default_credential_audit(
    *,
    targets: list[str],
    scope_allowlist: dict[str, Any],
    inventory: dict[str, Any] | None = None,
    timeout_seconds: float = 5.0,
    max_attempts_per_host: int = 3,
    rate_limit_per_second: float = 1.0,
    credentials: list[dict[str, Any]] | None = None,
    http_client: HttpClient | None = None,
    sleep_func: SleepFunc = time.sleep,
    time_func: TimeFunc = time.monotonic,
) -> RunnerExecution:
    credentials = credentials if credentials is not None else load_default_credentials()
    http_client = http_client or _default_http_client
    max_attempts = max(1, min(int(max_attempts_per_host or 3), 3))
    rate_limit = max(float(rate_limit_per_second or 1.0), 0.1)
    min_interval = 1.0 / rate_limit
    devices = build_management_targets(
        targets=targets,
        inventory=inventory,
        scope_allowlist=scope_allowlist,
    )
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    last_attempt_at: float | None = None

    for device in devices:
        url = str(device.get("url") or "").strip()
        host = str(device.get("host") or "").strip()
        port = _safe_port(device.get("port")) or 0
        result = {
            "target": host,
            "url": url,
            "port": port,
            "device_type": str(device.get("device_type") or "").strip() or None,
            "metadata_source": str(device.get("source") or "inventory"),
            "matched_credentials": [],
            "attempts": [],
            "no_auth_accessible": False,
            "status": "checked",
        }
        matched = match_default_credentials(device, credentials, max_attempts=max_attempts)
        result["matched_credentials"] = [
            {
                "vendor": entry.get("vendor"),
                "model": entry.get("model"),
                "device_type": entry.get("device_type"),
                "no_auth_expected": bool(entry.get("no_auth_expected", False)),
            }
            for entry in matched
        ]

        initial = http_client(url, "GET", {"User-Agent": "AegisPT-IoT-Audit/1.0"}, None, timeout_seconds)
        known_management_interface = bool(matched)
        if known_management_interface and _is_accessible_without_auth(initial):
            result["no_auth_accessible"] = True
            findings.append(
                _build_finding(
                    title="Management interface accessible without authentication",
                    severity="high",
                    target_id=url,
                    summary=(
                        "A known IoT management interface was reachable without an "
                        "authentication challenge. No credential material was submitted."
                    ),
                    tags=["no-auth"],
                )
            )
            results.append(result)
            continue

        credential_entries = [entry for entry in matched if not entry.get("no_auth_expected")]
        for entry in credential_entries[:max_attempts]:
            now = time_func()
            if last_attempt_at is not None:
                wait_for = min_interval - (now - last_attempt_at)
                if wait_for > 0:
                    sleep_func(wait_for)
                    now = time_func()
            last_attempt_at = now

            username = str(entry.get("username") or "")
            password = str(entry.get("password") or "")
            basic_response = http_client(
                url,
                "GET",
                {
                    "Authorization": _basic_auth_header(username, password),
                    "User-Agent": "AegisPT-IoT-Audit/1.0",
                },
                None,
                timeout_seconds,
            )
            if _credential_accepted(basic_response):
                result["attempts"].append(
                    _redacted_attempt(
                        entry,
                        result="accepted",
                        status_code=basic_response.status_code,
                        method="http-basic",
                    )
                )
                findings.append(
                    _build_finding(
                        title="Default manufacturer credentials accepted",
                        severity="critical",
                        target_id=url,
                        summary=(
                            f"The {entry.get('vendor')} {entry.get('model') or 'device'} "
                            "management interface accepted a manufacturer default credential "
                            f"for username {username!r}; the password is redacted in evidence."
                        ),
                        tags=["default-password"],
                    )
                )
                break

            form_attempt = _extract_form_attempt(initial.body, url, username, password)
            if form_attempt is None:
                result["attempts"].append(
                    _redacted_attempt(
                        entry,
                        result="rejected",
                        status_code=basic_response.status_code,
                        method="http-basic",
                    )
                )
                continue
            form_url, form_body = form_attempt
            form_response = http_client(
                form_url,
                "POST",
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "AegisPT-IoT-Audit/1.0",
                },
                form_body,
                timeout_seconds,
            )
            result["attempts"].append(
                _redacted_attempt(
                    entry,
                    result="accepted" if _credential_accepted(form_response) else "rejected",
                    status_code=form_response.status_code,
                    method="form-post",
                )
            )
            if _credential_accepted(form_response):
                findings.append(
                    _build_finding(
                        title="Default manufacturer credentials accepted",
                        severity="critical",
                        target_id=url,
                        summary=(
                            f"The {entry.get('vendor')} {entry.get('model') or 'device'} "
                            "management interface accepted a manufacturer default credential "
                            f"for username {username!r}; the password is redacted in evidence."
                        ),
                        tags=["default-password", "form-login"],
                    )
                )
                break
        if not matched:
            result["status"] = "no-matching-default-credential-entry"
        results.append(result)

    payload = {
        "tool": "iot-default-creds",
        "targets": results,
        "analysis_findings": findings,
        "metadata": {
            "credential_database_entries": len(credentials),
            "max_attempts_per_host": max_attempts,
            "rate_limit_per_second": rate_limit,
            "raw_credentials_exposed": False,
            "passwords_redacted": True,
        },
    }
    stdout = (
        f"IoT default credential audit checked {len(results)} management interface(s); "
        f"{len(findings)} finding(s) emitted with credential material redacted."
    )
    return RunnerExecution(
        tool="iot-default-creds",
        exit_code=0,
        stdout=stdout,
        stderr="",
        metadata={
            "status": "completed",
            "tool_version": "iot-default-creds-v1",
            "runner_digest": IOT_DEFAULT_CREDS_RUNNER_DIGEST,
        },
        artifacts=[
            EvidenceArtifact(
                name=IOT_DEFAULT_CREDS_ARTIFACT_NAME,
                content_type="application/json",
                data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
                kind="analysis",
            )
        ],
    )
