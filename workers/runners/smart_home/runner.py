from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
import socket
import ssl
import time
from typing import Any, Callable
from urllib.parse import urlparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

SMART_HOME_RESULTS_ARTIFACT_NAME = "smart-home-results.json"
SMART_HOME_RUNNER_DIGEST = "workers.smart_home.runner:v1"

MQTT_PORTS = (1883, 8883)
MQTT_WEBSOCKET_PORT = 9001
HOME_ASSISTANT_PORT = 8123
SUPERVISOR_PORT = 4357
OPENHAB_PORT = 8080
DOMOTICZ_PORT = 8080
NODE_RED_PORT = 1880

SENSITIVE_MQTT_TOPICS = (
    "homeassistant/+/+/state",
    "home/+/+",
    "devices/+",
)
TOKEN_MARKERS = (
    "long-lived access token",
    "access_token",
    "refresh_token",
    "llat_",
    "Authorization",
)


@dataclass(slots=True, frozen=True)
class HttpProbeResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str = ""
    error: str | None = None


MqttProbe = Callable[[str, int, bool, float, float], dict[str, Any]]
HttpGetter = Callable[[str, float], HttpProbeResponse]


def _encode_remaining_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("remaining length must be positive")
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length > 0:
            digit |= 0x80
        encoded.append(digit)
        if length == 0:
            return bytes(encoded)


def _mqtt_string(value: str) -> bytes:
    data = value.encode("utf-8")
    return len(data).to_bytes(2, "big") + data


def build_mqtt_connect_packet(client_id: str = "aegispt-readonly") -> bytes:
    variable_header = _mqtt_string("MQTT") + bytes([4, 0x02]) + (30).to_bytes(2, "big")
    payload = _mqtt_string(client_id)
    remaining = variable_header + payload
    return bytes([0x10]) + _encode_remaining_length(len(remaining)) + remaining


def build_mqtt_subscribe_packet(topic_filter: str = "#", *, packet_id: int = 1) -> bytes:
    payload = _mqtt_string(topic_filter) + bytes([0])
    variable_header = packet_id.to_bytes(2, "big")
    remaining = variable_header + payload
    return bytes([0x82]) + _encode_remaining_length(len(remaining)) + remaining


def _decode_remaining_length(packet: bytes, start: int = 1) -> tuple[int, int]:
    multiplier = 1
    value = 0
    offset = start
    while offset < len(packet):
        digit = packet[offset]
        value += (digit & 127) * multiplier
        offset += 1
        if (digit & 128) == 0:
            return value, offset
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            break
    raise ValueError("invalid MQTT remaining length")


def parse_mqtt_publish_topic(packet: bytes) -> str | None:
    if not packet or packet[0] >> 4 != 3:
        return None
    try:
        _, offset = _decode_remaining_length(packet)
    except ValueError:
        return None
    if offset + 2 > len(packet):
        return None
    topic_length = int.from_bytes(packet[offset : offset + 2], "big")
    topic_start = offset + 2
    topic_end = topic_start + topic_length
    if topic_end > len(packet):
        return None
    return packet[topic_start:topic_end].decode("utf-8", errors="replace").strip() or None


def _socket_mqtt_probe(
    host: str,
    port: int,
    use_tls: bool,
    timeout_seconds: float,
    listen_seconds: float,
) -> dict[str, Any]:
    client_id = f"aegispt-{sha256(f'{host}:{port}'.encode()).hexdigest()[:10]}"
    topics: list[str] = []
    deadline = time.monotonic() + max(float(listen_seconds), 0.5)
    try:
        with socket.create_connection((host, port), timeout=max(timeout_seconds, 1.0)) as raw_socket:
            raw_socket.settimeout(max(timeout_seconds, 1.0))
            if use_tls:
                context = ssl.create_default_context()
                stream = context.wrap_socket(raw_socket, server_hostname=host)
            else:
                stream = raw_socket
            with stream:
                stream.sendall(build_mqtt_connect_packet(client_id))
                response = stream.recv(4)
                accepted = len(response) >= 4 and response[0] == 0x20 and response[3] == 0
                if not accepted:
                    return {
                        "host": host,
                        "port": port,
                        "tls": use_tls,
                        "accepted": False,
                        "reason": f"connack={response.hex() if response else 'empty'}",
                        "topics": [],
                    }
                stream.sendall(build_mqtt_subscribe_packet("#"))
                while time.monotonic() < deadline:
                    try:
                        packet = stream.recv(4096)
                    except socket.timeout:
                        break
                    if not packet:
                        break
                    topic = parse_mqtt_publish_topic(packet)
                    if topic and topic not in topics:
                        topics.append(topic)
                    if len(topics) >= 25:
                        break
                return {
                    "host": host,
                    "port": port,
                    "tls": use_tls,
                    "accepted": True,
                    "topics": topics,
                    "values_redacted": True,
                }
    except OSError as exc:
        return {
            "host": host,
            "port": port,
            "tls": use_tls,
            "accepted": False,
            "reason": str(exc),
            "topics": [],
        }


def _default_http_get(url: str, timeout_seconds: float) -> HttpProbeResponse:
    try:
        with httpx_client.Client(
            follow_redirects=False,
            timeout=max(timeout_seconds, 1.0),
            verify=False,
            headers={"User-Agent": "AegisPT/0.1 smart-home-readonly"},
        ) as client:
            response = client.get(url)
            return HttpProbeResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                body=response.text[:8192],
            )
    except httpx_client.HTTPError as exc:
        return HttpProbeResponse(url=url, status_code=0, headers={}, error=str(exc))


def _redacted_topic_sample(topics: list[str]) -> list[dict[str, str]]:
    return [{"topic": topic, "value": "<redacted>"} for topic in topics[:25]]


def _body_token_markers(body: str) -> list[str]:
    lower_body = body.lower()
    return [marker for marker in TOKEN_MARKERS if marker.lower() in lower_body]


def _host_from_target(target: str) -> str | None:
    value = str(target or "").strip()
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    if "/" in value:
        return None
    if ":" in value and value.count(":") == 1:
        return value.split(":", 1)[0].strip() or None
    return value


def _expand_hosts(
    targets: list[str],
    *,
    inventory: dict[str, Any] | None,
    max_target_hosts: int,
) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()

    def add(host: str | None) -> None:
        normalized = str(host or "").strip().strip("[]")
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        hosts.append(normalized)

    for target in targets:
        value = str(target or "").strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            add(_host_from_target(value))
            continue
        for address in network.hosts():
            add(str(address))
            if len(hosts) >= max_target_hosts:
                return hosts

    if isinstance(inventory, dict):
        for entry in inventory.get("hosts", []):
            if isinstance(entry, dict):
                add(str(entry.get("host") or ""))
            elif isinstance(entry, str):
                add(entry)
            if len(hosts) >= max_target_hosts:
                return hosts
        for entry in inventory.get("services", []):
            if isinstance(entry, dict):
                add(str(entry.get("host") or ""))
            if len(hosts) >= max_target_hosts:
                return hosts
    return hosts[:max_target_hosts]


def _http_probe_record(
    *,
    service: str,
    host: str,
    port: int,
    path: str,
    getter: HttpGetter,
    timeout_seconds: float,
    scheme: str = "http",
) -> dict[str, Any]:
    url = f"{scheme}://{host}:{port}{path}"
    response = getter(url, timeout_seconds)
    token_markers = _body_token_markers(response.body)
    return {
        "service": service,
        "host": host,
        "port": port,
        "path": path,
        "url": url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
        "content_length": len(response.body.encode("utf-8")),
        "body_sha256": sha256(response.body.encode("utf-8")).hexdigest() if response.body else None,
        "token_markers": token_markers,
        "error": response.error,
        "ok": response.status_code > 0,
    }


def _build_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for probe in payload["mqtt"]:
        if not probe.get("accepted"):
            continue
        findings.append(
            {
                "title": "MQTT broker accepts anonymous connections",
                "severity": "critical",
                "target": f"{probe['host']}:{probe['port']}",
                "summary": (
                    "The MQTT broker accepted an anonymous client and allowed a read-only "
                    "subscription attempt. Topic names are recorded with message values redacted."
                ),
                "evidence": {
                    "topics": _redacted_topic_sample(list(probe.get("topics", []))),
                    "values_redacted": True,
                },
            }
        )
    for record in payload["http"]:
        service = record.get("service")
        status = int(record.get("status_code") or 0)
        if service == "home-assistant-api" and record.get("path") == "/api/" and status == 200:
            findings.append(
                {
                    "title": "Home Assistant API accessible without authentication",
                    "severity": "critical",
                    "target": record["url"],
                    "summary": (
                        "Home Assistant returned HTTP 200 for a read-only unauthenticated "
                        "`GET /api/` probe. No control endpoints or automation actions were invoked."
                    ),
                }
            )
        if service == "home-assistant-api" and record.get("path") == "/api/config" and status == 200:
            findings.append(
                {
                    "title": "Home Assistant configuration details accessible without authentication",
                    "severity": "high",
                    "target": record["url"],
                    "summary": (
                        "Home Assistant returned configuration metadata to an unauthenticated "
                        "read-only request. Response values are not stored in the finding."
                    ),
                }
            )
        if service == "home-assistant-frontend" and status == 200:
            findings.append(
                {
                    "title": "Home Assistant frontend asset accessible without authentication",
                    "severity": "medium",
                    "target": record["url"],
                    "summary": "The Home Assistant frontend asset was reachable without authentication.",
                }
            )
        if service == "home-assistant-supervisor" and status in {200, 401, 403}:
            findings.append(
                {
                    "title": "Home Assistant Supervisor API exposed on network",
                    "severity": "high" if status == 200 else "info",
                    "target": record["url"],
                    "summary": (
                        "The Supervisor API port responded to a read-only probe. Confirm that it is "
                        "not reachable from untrusted network segments."
                    ),
                }
            )
        if record.get("token_markers"):
            findings.append(
                {
                    "title": "Token-like marker exposed in smart-home response",
                    "severity": "high",
                    "target": record["url"],
                    "summary": (
                        "A read-only response contained token-like marker names. Values were not "
                        "stored and require manual review."
                    ),
                    "evidence": {"markers": record["token_markers"]},
                }
            )
        if service in {"openhab", "domoticz", "node-red"} and status == 200:
            findings.append(
                {
                    "title": f"{service.replace('-', ' ').title()} interface reachable",
                    "severity": "info",
                    "target": record["url"],
                    "summary": "A smart-home hub interface responded to a safe read-only probe.",
                }
            )
    return findings


def _build_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    def add_host(host: str) -> None:
        if host in seen_hosts:
            return
        seen_hosts.add(host)
        hosts.append({"host": host, "source": "smart-home", "confidence": 0.72})

    for probe in payload["mqtt"]:
        add_host(probe["host"])
        services.append(
            {
                "host": probe["host"],
                "port": probe["port"],
                "protocol": "tcp",
                "service": "mqtts" if probe.get("tls") else "mqtt",
                "confidence": 0.86 if probe.get("accepted") else 0.46,
            }
        )
        fingerprints.append(
            {
                "vendor": None,
                "product": "MQTT broker",
                "version": None,
                "confidence": 0.72 if probe.get("accepted") else 0.4,
            }
        )
    for record in payload["http"]:
        add_host(record["host"])
        services.append(
            {
                "host": record["host"],
                "port": record["port"],
                "protocol": "tcp",
                "service": record["service"],
                "confidence": 0.74 if record.get("ok") else 0.35,
            }
        )
        if record.get("ok"):
            endpoints.append(
                {
                    "url": record["url"],
                    "methods": ["GET"],
                    "status_code": record["status_code"],
                    "title": record["service"],
                    "confidence": 0.72,
                }
            )
            fingerprints.append(
                {
                    "vendor": None,
                    "product": record["service"],
                    "version": None,
                    "confidence": 0.7,
                }
            )
    return {
        "hosts": hosts,
        "services": services,
        "endpoints": endpoints,
        "fingerprints": fingerprints,
        "confidence": 0.72,
    }


def execute_smart_home_audit(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    timeout_seconds: float = 5.0,
    mqtt_listen_seconds: float = 30.0,
    max_target_hosts: int = 128,
    mqtt_probe: MqttProbe | None = None,
    http_getter: HttpGetter | None = None,
) -> RunnerExecution:
    hosts = _expand_hosts(targets, inventory=inventory, max_target_hosts=max_target_hosts)
    mqtt_probe_fn = mqtt_probe or _socket_mqtt_probe
    http_get = http_getter or _default_http_get

    mqtt_results: list[dict[str, Any]] = []
    http_results: list[dict[str, Any]] = []
    for host in hosts:
        for port in MQTT_PORTS:
            mqtt_results.append(
                mqtt_probe_fn(
                    host,
                    port,
                    port == 8883,
                    timeout_seconds,
                    mqtt_listen_seconds,
                )
            )
        http_results.append(
            _http_probe_record(
                service="mqtt-websocket",
                host=host,
                port=MQTT_WEBSOCKET_PORT,
                path="/mqtt",
                getter=http_get,
                timeout_seconds=timeout_seconds,
            )
        )
        for path in ("/api/", "/api/config"):
            http_results.append(
                _http_probe_record(
                    service="home-assistant-api",
                    host=host,
                    port=HOME_ASSISTANT_PORT,
                    path=path,
                    getter=http_get,
                    timeout_seconds=timeout_seconds,
                )
            )
        http_results.append(
            _http_probe_record(
                service="home-assistant-frontend",
                host=host,
                port=HOME_ASSISTANT_PORT,
                path="/frontend_latest/index.html",
                getter=http_get,
                timeout_seconds=timeout_seconds,
            )
        )
        http_results.append(
            _http_probe_record(
                service="home-assistant-supervisor",
                host=host,
                port=SUPERVISOR_PORT,
                path="/supervisor/info",
                getter=http_get,
                timeout_seconds=timeout_seconds,
            )
        )
        for service, port, path in (
            ("openhab", OPENHAB_PORT, "/"),
            ("domoticz", DOMOTICZ_PORT, "/"),
            ("node-red", NODE_RED_PORT, "/"),
        ):
            http_results.append(
                _http_probe_record(
                    service=service,
                    host=host,
                    port=port,
                    path=path,
                    getter=http_get,
                    timeout_seconds=timeout_seconds,
                )
            )

    payload: dict[str, Any] = {
        "targets": targets,
        "scope_allowlist": scope_allowlist or {},
        "hosts": hosts,
        "mqtt": mqtt_results,
        "http": http_results,
        "sensitive_topic_filters": list(SENSITIVE_MQTT_TOPICS),
        "read_only": True,
        "mqtt_publish_performed": False,
        "device_control_performed": False,
    }
    payload["analysis_findings"] = _build_findings(payload)
    payload["inventory"] = _build_inventory(payload)
    artifact_data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")

    accepted_mqtt = [probe for probe in mqtt_results if probe.get("accepted")]
    unauth_ha = [
        record
        for record in http_results
        if record.get("service") == "home-assistant-api"
        and record.get("path") == "/api/"
        and record.get("status_code") == 200
    ]
    return RunnerExecution(
        tool="smart-home",
        exit_code=0,
        stdout=(
            f"Smart-home audit checked {len(hosts)} hosts, "
            f"{len(accepted_mqtt)} anonymous MQTT brokers, "
            f"{len(unauth_ha)} unauthenticated Home Assistant APIs."
        ),
        stderr="",
        metadata={
            "status": "ok",
            "host_count": len(hosts),
            "anonymous_mqtt_count": len(accepted_mqtt),
            "unauthenticated_home_assistant_count": len(unauth_ha),
            "read_only": True,
            "mqtt_publish_performed": False,
            "runner_digest": SMART_HOME_RUNNER_DIGEST,
        },
        artifacts=[
            EvidenceArtifact(
                name=SMART_HOME_RESULTS_ARTIFACT_NAME,
                content_type="application/json",
                data=artifact_data,
                kind="smart-home-audit-results",
            )
        ],
    )
