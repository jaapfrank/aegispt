from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import uuid4
from xml.etree import ElementTree as ET

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

CAMERA_TEST_RESULTS_ARTIFACT_NAME = "camera-test-results.json"
CAMERA_TEST_RUNNER_DIGEST = "workers.camera_test.runner:v1"

ONVIF_MULTICAST_ADDRESS = "239.255.255.250"
ONVIF_MULTICAST_PORT = 3702
RTSP_PORT = 554
RTSP_PATHS = (
    "/live",
    "/cam",
    "/video",
    "/stream",
    "/h264",
    "/channel1",
    "/Streaming/Channels/1",
)
CAMERA_WEB_PORTS = (80, 8080, 443)
CAMERA_SNAPSHOT_PATHS = ("/cgi-bin/viewer/video.jpg", "/snapshot.jpg", "/image.jpg")
DEFAULT_CAMERA_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password"),
    ("root", "root"),
    ("admin", ""),
)


@dataclass(slots=True, frozen=True)
class HttpProbeResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes = b""
    error: str | None = None


WsDiscoveryClient = Callable[[list[str], float], list[dict[str, Any]]]
RtspProbe = Callable[[str, str, float], dict[str, Any]]
HttpGetter = Callable[[str, float], HttpProbeResponse]
HttpPoster = Callable[[str, bytes, float], HttpProbeResponse]
CredentialTester = Callable[[str, tuple[tuple[str, str], ...], float], list[dict[str, Any]]]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def build_ws_discovery_probe(message_id: str | None = None) -> bytes:
    message = message_id or f"uuid:{uuid4()}"
    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
  xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
  xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>{message}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>
  </e:Body>
</e:Envelope>"""
    return envelope.encode("utf-8")


def parse_onvif_probe_matches(xml_payload: bytes | str) -> list[dict[str, Any]]:
    raw = xml_payload.encode("utf-8") if isinstance(xml_payload, str) else xml_payload
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []

    matches: list[dict[str, Any]] = []
    for element in root.iter():
        if _local_name(element.tag) != "probematch":
            continue
        xaddrs: list[str] = []
        scopes: list[str] = []
        endpoint_reference: str | None = None
        for child in element.iter():
            name = _local_name(child.tag)
            text = (child.text or "").strip()
            if name == "xaddrs" and text:
                xaddrs.extend(item for item in text.split() if item.strip())
            elif name == "scopes" and text:
                scopes.extend(item for item in text.split() if item.strip())
            elif name == "address" and text and endpoint_reference is None:
                endpoint_reference = text
        matches.append(
            {
                "xaddrs": xaddrs,
                "scopes": scopes,
                "endpoint_reference": endpoint_reference,
            }
        )
    return matches


def parse_onvif_device_information(xml_payload: bytes | str) -> dict[str, str]:
    raw = xml_payload.encode("utf-8") if isinstance(xml_payload, str) else xml_payload
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}

    fields = {
        "manufacturer": "manufacturer",
        "model": "model",
        "firmwareversion": "firmware_version",
        "serialnumber": "serial_number",
        "hardwareid": "hardware_id",
    }
    info: dict[str, str] = {}
    for element in root.iter():
        key = fields.get(_local_name(element.tag))
        value = (element.text or "").strip()
        if key and value:
            info[key] = value
    return info


def build_get_device_information_envelope() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body><tds:GetDeviceInformation/></s:Body>
</s:Envelope>"""


def _default_ws_discovery(_targets: list[str], timeout_seconds: float) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    deadline = time.monotonic() + max(timeout_seconds, 1.0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(max(min(timeout_seconds, 2.0), 0.5))
        sock.sendto(build_ws_discovery_probe(), (ONVIF_MULTICAST_ADDRESS, ONVIF_MULTICAST_PORT))
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            matches.extend(parse_onvif_probe_matches(data))
    return matches


def _rtsp_status_line(response: bytes) -> tuple[int, str]:
    line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    parts = line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1]), line
    return 0, line


def _rtsp_request(host: str, path: str, method: str, cseq: int, timeout_seconds: float) -> dict[str, Any]:
    uri = f"rtsp://{host}:{RTSP_PORT}{path}"
    request = (
        f"{method} {uri} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        "User-Agent: AegisPT/0.1 camera-readonly\r\n"
        "\r\n"
    ).encode("utf-8")
    try:
        with socket.create_connection((host, RTSP_PORT), timeout=max(timeout_seconds, 1.0)) as stream:
            stream.settimeout(max(timeout_seconds, 1.0))
            stream.sendall(request)
            response = stream.recv(8192)
    except OSError as exc:
        return {"method": method, "status_code": 0, "error": str(exc), "response_sha256": None}
    status_code, status_line = _rtsp_status_line(response)
    return {
        "method": method,
        "status_code": status_code,
        "status_line": status_line,
        "content_length": len(response),
        "response_sha256": sha256(response).hexdigest() if response else None,
    }


def _default_rtsp_probe(host: str, path: str, timeout_seconds: float) -> dict[str, Any]:
    return {
        "host": host,
        "port": RTSP_PORT,
        "path": path,
        "uri": f"rtsp://{host}:{RTSP_PORT}{path}",
        "options": _rtsp_request(host, path, "OPTIONS", 1, timeout_seconds),
        "describe": _rtsp_request(host, path, "DESCRIBE", 2, timeout_seconds),
        "setup_performed": False,
        "play_performed": False,
        "media_captured": False,
    }


def _default_http_get(url: str, timeout_seconds: float) -> HttpProbeResponse:
    try:
        with httpx_client.Client(
            follow_redirects=False,
            timeout=max(timeout_seconds, 1.0),
            verify=False,
            headers={"User-Agent": "AegisPT/0.1 camera-readonly"},
        ) as client:
            response = client.get(url)
            return HttpProbeResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                body=response.content[:524288],
            )
    except httpx_client.HTTPError as exc:
        return HttpProbeResponse(url=url, status_code=0, headers={}, error=str(exc))


def _default_http_post(url: str, body: bytes, timeout_seconds: float) -> HttpProbeResponse:
    try:
        with httpx_client.Client(
            follow_redirects=False,
            timeout=max(timeout_seconds, 1.0),
            verify=False,
            headers={
                "User-Agent": "AegisPT/0.1 camera-readonly",
                "Content-Type": "application/soap+xml; charset=utf-8",
            },
        ) as client:
            response = client.post(url, content=body)
            return HttpProbeResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                body=response.content[:524288],
            )
    except httpx_client.HTTPError as exc:
        return HttpProbeResponse(url=url, status_code=0, headers={}, error=str(exc))


def _default_credential_tester(
    url: str,
    credentials: tuple[tuple[str, str], ...],
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for username, password in credentials:
        for scheme, auth in (
            ("basic", httpx_client.BasicAuth(username, password)),
            ("digest", httpx_client.DigestAuth(username, password)),
        ):
            try:
                with httpx_client.Client(
                    follow_redirects=False,
                    timeout=max(timeout_seconds, 1.0),
                    verify=False,
                    headers={"User-Agent": "AegisPT/0.1 camera-readonly"},
                ) as client:
                    response = client.get(url, auth=auth)
                    status_code = response.status_code
                    accepted = 200 <= status_code < 300
            except httpx_client.HTTPError as exc:
                status_code = 0
                accepted = False
                error = str(exc)
            else:
                error = None
            results.append(
                {
                    "url": url,
                    "auth_scheme": scheme,
                    "username": username,
                    "password_redacted": "[REDACTED]",
                    "status_code": status_code,
                    "accepted": accepted,
                    "error": error,
                }
            )
            if accepted:
                return results
    return results


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
            if not isinstance(entry, dict):
                continue
            port = entry.get("port")
            service = str(entry.get("service") or "").lower()
            if port in {80, 443, 554, 8080} or "rtsp" in service or "camera" in service:
                add(str(entry.get("host") or ""))
            if len(hosts) >= max_target_hosts:
                return hosts
    return hosts[:max_target_hosts]


def _host_from_url(value: str) -> str | None:
    parsed = urlparse(str(value or ""))
    return parsed.hostname


def _onvif_devices_from_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in matches:
        for xaddr in match.get("xaddrs", []):
            url = str(xaddr or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            devices.append(
                {
                    "xaddr": url,
                    "host": _host_from_url(url),
                    "scopes": list(match.get("scopes", [])),
                    "endpoint_reference": match.get("endpoint_reference"),
                }
            )
    return devices


def _probe_onvif_device(
    device: dict[str, Any],
    *,
    getter: HttpGetter,
    poster: HttpPoster,
    timeout_seconds: float,
) -> dict[str, Any]:
    xaddr = str(device.get("xaddr") or "")
    wsdl_url = f"{xaddr}?wsdl" if "?" not in xaddr else xaddr
    response = getter(wsdl_url, timeout_seconds)
    info_response = poster(xaddr, build_get_device_information_envelope(), timeout_seconds)
    info = parse_onvif_device_information(info_response.body) if info_response.body else {}
    return {
        **device,
        "wsdl_url": wsdl_url,
        "wsdl_status_code": response.status_code,
        "wsdl_content_type": response.headers.get("content-type"),
        "wsdl_content_length": len(response.body),
        "wsdl_sha256": sha256(response.body).hexdigest() if response.body else None,
        "get_device_information_status_code": info_response.status_code,
        "get_device_information_content_length": len(info_response.body),
        "get_device_information_sha256": (
            sha256(info_response.body).hexdigest() if info_response.body else None
        ),
        "device_information": info,
        "unauthenticated_wsdl_accessible": response.status_code == 200,
        "unauthenticated_device_information_accessible": info_response.status_code == 200,
        "error": response.error,
        "get_device_information_error": info_response.error,
    }


def _snapshot_record(
    *,
    host: str,
    port: int,
    path: str,
    getter: HttpGetter,
    timeout_seconds: float,
) -> dict[str, Any]:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{path}"
    response = getter(url, timeout_seconds)
    content_type = response.headers.get("content-type", "")
    image_like = response.status_code == 200 and (
        "image/" in content_type.lower() or path.lower().endswith((".jpg", ".jpeg", ".png"))
    )
    return {
        "host": host,
        "port": port,
        "path": path,
        "url": url,
        "status_code": response.status_code,
        "content_type": content_type or None,
        "content_length": len(response.body),
        "body_sha256": sha256(response.body).hexdigest() if response.body else None,
        "unauthenticated_snapshot_accessible": image_like,
        "frame_stored": False,
        "error": response.error,
    }


def _build_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for record in payload.get("rtsp", []):
        describe = record.get("describe") if isinstance(record.get("describe"), dict) else {}
        if int(describe.get("status_code") or 0) == 200:
            findings.append(
                {
                    "title": "RTSP stream describes without authentication",
                    "severity": "critical",
                    "target": record.get("uri"),
                    "summary": (
                        "The camera RTSP endpoint returned 200 to a DESCRIBE request without "
                        "authentication. AegisPT did not perform SETUP, PLAY, streaming, or capture."
                    ),
                    "methodology_tags": ["camera", "rtsp", "unauthenticated-access"],
                    "control_family": "iot-camera",
                    "evidence": {
                        "describe_status_code": describe.get("status_code"),
                        "response_sha256": describe.get("response_sha256"),
                        "play_performed": False,
                    },
                }
            )
    for record in payload.get("snapshots", []):
        if record.get("unauthenticated_snapshot_accessible"):
            findings.append(
                {
                    "title": "Camera snapshot accessible without authentication",
                    "severity": "critical",
                    "target": record.get("url"),
                    "summary": (
                        "A camera snapshot endpoint returned an image-like response without "
                        "authentication. Only content length and hash were stored; no frame was saved."
                    ),
                    "methodology_tags": ["camera", "snapshot", "unauthenticated-access"],
                    "control_family": "iot-camera",
                    "evidence": {
                        "content_type": record.get("content_type"),
                        "content_length": record.get("content_length"),
                        "body_sha256": record.get("body_sha256"),
                        "frame_stored": False,
                    },
                }
            )
    for attempt in payload.get("default_credentials", []):
        if attempt.get("accepted"):
            findings.append(
                {
                    "title": "Camera management interface accepted default credentials",
                    "severity": "critical",
                    "target": attempt.get("url"),
                    "summary": (
                        "A bounded approval-gated camera credential probe succeeded with a default "
                        "username/password pair. The password is redacted in all evidence."
                    ),
                    "methodology_tags": ["camera", "default-credentials"],
                    "control_family": "iot-camera",
                    "evidence": {
                        "auth_scheme": attempt.get("auth_scheme"),
                        "username": attempt.get("username"),
                        "password_redacted": attempt.get("password_redacted"),
                    },
                }
            )
    for device in payload.get("onvif_devices", []):
        if device.get("unauthenticated_wsdl_accessible"):
            findings.append(
                {
                    "title": "ONVIF device service accessible without authentication",
                    "severity": "high",
                    "target": device.get("xaddr"),
                    "summary": (
                        "The ONVIF device service WSDL responded to an unauthenticated read-only "
                        "request. No PTZ, configuration, or control methods were invoked."
                    ),
                    "methodology_tags": ["camera", "onvif", "device-discovery"],
                    "control_family": "iot-camera",
                }
            )
    return findings


def _build_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    def add_host(host: str | None) -> None:
        if not host or host in seen_hosts:
            return
        seen_hosts.add(host)
        hosts.append({"host": host, "source": "camera-test", "device_type": "ip-camera", "confidence": 0.76})

    for host in payload.get("hosts", []):
        add_host(str(host))
    for device in payload.get("onvif_devices", []):
        host = str(device.get("host") or "")
        add_host(host)
        services.append(
            {
                "host": host,
                "port": urlparse(str(device.get("xaddr") or "")).port or 80,
                "protocol": "tcp",
                "service": "onvif-device-service",
                "confidence": 0.84,
            }
        )
        info = device.get("device_information") if isinstance(device.get("device_information"), dict) else {}
        if info:
            fingerprints.append(
                {
                    "vendor": info.get("manufacturer"),
                    "product": info.get("model") or "ONVIF camera",
                    "version": info.get("firmware_version"),
                    "confidence": 0.82,
                }
            )
    for record in payload.get("rtsp", []):
        add_host(str(record.get("host") or ""))
        services.append(
            {
                "host": record.get("host"),
                "port": RTSP_PORT,
                "protocol": "tcp",
                "service": "rtsp",
                "confidence": 0.86 if int(record.get("describe", {}).get("status_code") or 0) else 0.42,
            }
        )
    for record in payload.get("snapshots", []):
        add_host(str(record.get("host") or ""))
        if int(record.get("status_code") or 0) > 0:
            endpoints.append(
                {
                    "url": record.get("url"),
                    "methods": ["GET"],
                    "status_code": record.get("status_code"),
                    "title": "Camera snapshot endpoint",
                    "confidence": 0.78,
                }
            )
    return {
        "hosts": hosts,
        "services": services,
        "endpoints": endpoints,
        "fingerprints": fingerprints,
        "confidence": 0.76,
    }


def execute_camera_test(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    timeout_seconds: float = 5.0,
    max_target_hosts: int = 128,
    max_default_credential_attempts: int = 10,
    ws_discovery_client: WsDiscoveryClient | None = None,
    rtsp_probe: RtspProbe | None = None,
    http_getter: HttpGetter | None = None,
    http_poster: HttpPoster | None = None,
    credential_tester: CredentialTester | None = None,
) -> RunnerExecution:
    hosts = _expand_hosts(targets, inventory=inventory, max_target_hosts=max_target_hosts)
    http_get = http_getter or _default_http_get
    http_post = http_poster or _default_http_post
    rtsp_probe_fn = rtsp_probe or _default_rtsp_probe
    ws_discovery = ws_discovery_client or _default_ws_discovery
    credential_test = credential_tester or _default_credential_tester

    try:
        ws_matches = ws_discovery(hosts, timeout_seconds)
    except OSError as exc:
        ws_matches = [{"error": str(exc), "xaddrs": [], "scopes": []}]
    onvif_devices = [
        _probe_onvif_device(
            device,
            getter=http_get,
            poster=http_post,
            timeout_seconds=timeout_seconds,
        )
        for device in _onvif_devices_from_matches(ws_matches)
    ]
    for device in onvif_devices:
        host = str(device.get("host") or "")
        if host and host not in hosts and len(hosts) < max_target_hosts:
            hosts.append(host)

    rtsp_results: list[dict[str, Any]] = []
    snapshot_results: list[dict[str, Any]] = []
    credential_results: list[dict[str, Any]] = []
    bounded_credentials = DEFAULT_CAMERA_CREDENTIALS[: max(max_default_credential_attempts, 0)]
    for host in hosts:
        for path in RTSP_PATHS:
            rtsp_results.append(rtsp_probe_fn(host, path, timeout_seconds))
        for port in CAMERA_WEB_PORTS:
            for path in CAMERA_SNAPSHOT_PATHS:
                snapshot_results.append(
                    _snapshot_record(
                        host=host,
                        port=port,
                        path=path,
                        getter=http_get,
                        timeout_seconds=timeout_seconds,
                    )
                )
            if bounded_credentials:
                base_url = f"{'https' if port == 443 else 'http'}://{host}:{port}/"
                credential_results.extend(
                    credential_test(base_url, bounded_credentials, timeout_seconds)
                )

    payload: dict[str, Any] = {
        "targets": targets,
        "scope_allowlist": scope_allowlist or {},
        "hosts": hosts,
        "ws_discovery_matches": ws_matches,
        "onvif_devices": onvif_devices,
        "rtsp": rtsp_results,
        "snapshots": snapshot_results,
        "default_credentials": credential_results,
        "read_only": True,
        "onvif_get_device_information_performed": True,
        "onvif_get_device_information_read_only": True,
        "rtsp_methods": ["OPTIONS", "DESCRIBE"],
        "rtsp_setup_performed": False,
        "rtsp_play_performed": False,
        "video_frame_captured": False,
        "video_frame_stored": False,
        "ptz_control_performed": False,
        "configuration_changed": False,
        "default_credential_attempts_bounded": True,
        "max_default_credential_attempts": max_default_credential_attempts,
    }
    payload["analysis_findings"] = _build_findings(payload)
    payload["inventory"] = _build_inventory(payload)

    artifact_data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    critical_count = sum(
        1 for finding in payload["analysis_findings"] if finding.get("severity") == "critical"
    )
    return RunnerExecution(
        tool="camera-test",
        exit_code=0,
        stdout=(
            f"Camera audit checked {len(hosts)} hosts, {len(onvif_devices)} ONVIF devices, "
            f"{critical_count} critical unauthenticated camera exposures."
        ),
        stderr="",
        metadata={
            "status": "ok",
            "host_count": len(hosts),
            "onvif_device_count": len(onvif_devices),
            "finding_count": len(payload["analysis_findings"]),
            "critical_finding_count": critical_count,
            "read_only": True,
            "rtsp_play_performed": False,
            "video_frame_stored": False,
            "runner_digest": CAMERA_TEST_RUNNER_DIGEST,
        },
        artifacts=[
            EvidenceArtifact(
                name=CAMERA_TEST_RESULTS_ARTIFACT_NAME,
                content_type="application/json",
                data=artifact_data,
                kind="camera-test-results",
            )
        ],
    )
