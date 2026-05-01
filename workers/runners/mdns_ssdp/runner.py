from __future__ import annotations

from collections.abc import Callable, Iterable
import ipaddress
import json
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen
from xml.etree import ElementTree as ET

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

MDNS_SSDP_ARTIFACT_NAME = "mdns-ssdp-results.json"
MDNS_SSDP_RUNNER_DIGEST = "workers.mdns_ssdp.runner:v1"

DEFAULT_MDNS_SERVICE_TYPES: tuple[str, ...] = (
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_hue._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_mqtt._tcp.local.",
    "_rtsp._tcp.local.",
    "_daap._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_sonos._tcp.local.",
    "_unifi._tcp.local.",
    "_onvif._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_home-assistant._tcp.local.",
)


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


def _address_in_scope(address: object, networks: list[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return True
    try:
        parsed = ipaddress.ip_address(str(address or "").strip())
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def _scope_values(targets: list[str], scope_allowlist: dict[str, Any]) -> list[str]:
    values = list(targets)
    for key in ("cidrs", "cidr_ranges", "hosts", "ip_addresses"):
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
    return _normalized_string_list(values)


def identify_device_type(
    *,
    service_type: str | None = None,
    port: int | None = None,
    name: str | None = None,
    manufacturer: str | None = None,
    model: str | None = None,
) -> str:
    haystack = " ".join(
        str(value or "").lower() for value in (service_type, name, manufacturer, model)
    )
    if "_hue" in haystack or "philips hue" in haystack or "signify" in haystack:
        return "iot-gateway"
    if "_homekit" in haystack or "_hap" in haystack or "homekit" in haystack:
        return "smart-home-hub"
    if "_home-assistant" in haystack or "home assistant" in haystack or port == 8123:
        return "smart-home-hub"
    if "_mqtt" in haystack or port == 1883:
        return "smart-home-hub"
    if "_rtsp" in haystack or "_onvif" in haystack or "camera" in haystack or port == 554:
        return "ip-camera"
    if "_googlecast" in haystack or "chromecast" in haystack:
        return "consumer-iot"
    if "_airplay" in haystack:
        return "consumer-iot"
    if "_sonos" in haystack or "sonos" in haystack:
        return "consumer-iot"
    if "_unifi" in haystack or "ubiquiti" in haystack:
        return "network-infrastructure"
    if "_ipp" in haystack or "_printer" in haystack or "printer" in haystack:
        return "printer"
    if "upnp" in haystack or "internetgatewaydevice" in haystack:
        return "iot-gateway"
    if "mediaserver" in haystack or "xbox" in haystack or "denon" in haystack or "dishwasher" in haystack:
        return "consumer-iot"
    if service_type and ("_http" in service_type or "_https" in service_type):
        return "consumer-iot"
    return "consumer-iot"


def _txt_to_dict(txt: object) -> dict[str, str]:
    if not txt:
        return {}
    if isinstance(txt, dict):
        return {str(key): str(value) for key, value in txt.items()}
    if isinstance(txt, (list, tuple, set)):
        items = txt
    else:
        items = [txt]
    parsed: dict[str, str] = {}
    for item in items:
        if isinstance(item, bytes):
            item = item.decode("utf-8", errors="replace")
        text = str(item or "").strip()
        if not text:
            continue
        if "=" in text:
            key, value = text.split("=", 1)
            parsed[key.strip()] = value.strip()
        else:
            parsed[text] = ""
    return parsed


def normalize_mdns_record(record: dict[str, Any]) -> dict[str, Any] | None:
    addresses = record.get("addresses")
    if isinstance(addresses, str):
        addresses = [addresses]
    if not isinstance(addresses, list):
        addresses = [record.get("ip") or record.get("address")]
    addresses = _normalized_string_list(addresses)
    if not addresses:
        return None
    port = record.get("port")
    try:
        port = int(port) if port not in {None, ""} else None
    except (TypeError, ValueError):
        port = None
    service_type = str(record.get("service_type") or record.get("type") or "").strip()
    name = str(record.get("name") or record.get("server") or "").strip()
    txt = _txt_to_dict(record.get("txt"))
    device_type = identify_device_type(
        service_type=service_type,
        port=port,
        name=name,
        manufacturer=txt.get("manufacturer") or txt.get("vendor"),
        model=txt.get("model"),
    )
    return {
        "source": "mdns",
        "name": name or None,
        "addresses": addresses,
        "ip": addresses[0],
        "port": port,
        "service_type": service_type or None,
        "txt": txt,
        "device_type": device_type,
    }


def parse_ssdp_response(raw_response: bytes | str) -> dict[str, str]:
    text = (
        raw_response.decode("utf-8", errors="replace")
        if isinstance(raw_response, bytes)
        else str(raw_response)
    )
    headers: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            headers[key] = value
    return headers


def parse_upnp_device_description(xml_text: bytes | str, *, location_url: str) -> dict[str, Any]:
    text = xml_text.decode("utf-8", errors="replace") if isinstance(xml_text, bytes) else str(xml_text)
    root = ET.fromstring(text)

    def find_text(name: str) -> str | None:
        for element in root.iter():
            tag = element.tag.split("}", 1)[-1].lower()
            if tag == name.lower():
                value = str(element.text or "").strip()
                return value or None
        return None

    presentation_url = find_text("presentationURL")
    return {
        "device_type": find_text("deviceType"),
        "friendly_name": find_text("friendlyName"),
        "manufacturer": find_text("manufacturer"),
        "model_name": find_text("modelName"),
        "presentation_url": (
            urljoin(location_url, presentation_url) if presentation_url else None
        ),
    }


def normalize_ssdp_device(
    response_headers: dict[str, str],
    *,
    description: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    location = str(response_headers.get("location") or "").strip()
    parsed_location = urlparse(location)
    host = parsed_location.hostname or ""
    if not host:
        return None
    try:
        port = int(parsed_location.port or (443 if parsed_location.scheme == "https" else 80))
    except ValueError:
        port = None
    description = description if isinstance(description, dict) else {}
    manufacturer = str(description.get("manufacturer") or "").strip() or None
    model = str(description.get("model_name") or "").strip() or None
    friendly_name = str(description.get("friendly_name") or "").strip() or None
    service_type = str(response_headers.get("st") or description.get("device_type") or "upnp").strip()
    return {
        "source": "ssdp",
        "name": friendly_name,
        "addresses": [host],
        "ip": host,
        "port": port,
        "service_type": service_type,
        "device_type": identify_device_type(
            service_type=service_type,
            port=port,
            name=friendly_name,
            manufacturer=manufacturer,
            model=model,
        ),
        "location": location,
        "presentation_url": description.get("presentation_url"),
        "manufacturer": manufacturer,
        "model_name": model,
        "server": response_headers.get("server"),
        "usn": response_headers.get("usn"),
    }


def _dedupe_devices(devices: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, int | None, str], dict[str, Any]] = {}
    for device in devices:
        host = str(device.get("ip") or "").strip().lower()
        service_type = str(device.get("service_type") or "").strip().lower()
        key = (host, device.get("port") if isinstance(device.get("port"), int) else None, service_type)
        if not host or key in deduped:
            continue
        deduped[key] = device
    return list(deduped.values())


def _device_url(device: dict[str, Any]) -> str | None:
    for key in ("presentation_url", "location"):
        value = str(device.get(key) or "").strip()
        if value.startswith(("http://", "https://")):
            return value
    port = device.get("port")
    host = str(device.get("ip") or "").strip()
    service_type = str(device.get("service_type") or "").lower()
    if host and isinstance(port, int) and port > 0:
        scheme = "https" if "https" in service_type or port == 443 else "http"
        return f"{scheme}://{host}:{port}"
    return None


def build_analysis_findings(
    devices: Iterable[dict[str, Any]],
    *,
    expected_networks: list[ipaddress._BaseNetwork],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(title: str, *, target: str, severity: str, summary: str) -> None:
        key = (title.lower(), target.lower())
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "title": title,
                "severity": severity,
                "target_id": target,
                "summary": summary,
                "methodology_tags": ["inventory", "iot", "passive-discovery"],
                "ptes_phase": "intelligence_gathering",
                "nist_phase": "discovery",
                "control_family": "asset-management",
            }
        )

    for device in devices:
        host = str(device.get("ip") or "").strip()
        url = _device_url(device)
        target = url or host or "iot-device"
        txt = device.get("txt") if isinstance(device.get("txt"), dict) else {}
        auth_text = " ".join(
            f"{key}={value}".lower() for key, value in txt.items()
        )
        if any(marker in auth_text for marker in ("auth=false", "auth=0", "noauth", "no-auth")):
            add(
                "IoT management interface advertises no authentication",
                target=target,
                severity="medium",
                summary=(
                    "The advertised mDNS metadata indicates that the IoT or smart-device "
                    "management interface may not require authentication."
                ),
            )
        if url and url.startswith("http://"):
            add(
                "IoT management interface advertised over HTTP",
                target=target,
                severity="low",
                summary=(
                    "Passive mDNS/SSDP discovery observed an IoT or smart-device management "
                    "interface that advertises plain HTTP rather than HTTPS."
                ),
            )
        if host and expected_networks and not _address_in_scope(host, expected_networks):
            add(
                "IoT device advertised outside approved LAN subnet",
                target=host,
                severity="medium",
                summary=(
                    "Passive discovery observed an IoT device address that is outside the "
                    "approved LAN ranges for this run."
                ),
            )
        device_text = " ".join(
            str(device.get(key) or "").lower()
            for key in ("name", "manufacturer", "model_name", "server", "service_type")
        )
        if any(marker in device_text for marker in ("default", "setup", "unconfigured")):
            add(
                "IoT device advertises default or setup identity",
                target=target,
                severity="low",
                summary=(
                    "The advertised device metadata contains default/setup wording, which may "
                    "indicate an unconfigured IoT or smart-home device."
                ),
            )
    return findings


def _inventory_from_devices(devices: list[dict[str, Any]]) -> dict[str, Any]:
    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for device in devices:
        host = str(device.get("ip") or "").strip()
        if not host:
            continue
        if host not in seen_hosts:
            seen_hosts.add(host)
            hosts.append(
                {
                    "host": host,
                    "source": str(device.get("source") or "mdns-ssdp"),
                    "device_type": device.get("device_type") or "consumer-iot",
                    "notes": [
                        f"{device.get('device_type') or 'iot-device'} advertised by {device.get('source') or 'local-discovery'}."
                    ],
                    "confidence": 0.82,
                }
            )
        port = device.get("port")
        service_type = str(device.get("service_type") or "").strip()
        if isinstance(port, int) and port > 0:
            service_name = (
                "https"
                if "https" in service_type.lower() or port == 443
                else "http"
                if "http" in service_type.lower() or port in {80, 8080, 8123}
                else service_type or "iot-service"
            )
            services.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "service": service_name,
                    "product": device.get("model_name") or device.get("device_type"),
                    "version": None,
                    "confidence": 0.8,
                }
            )
        url = _device_url(device)
        if url:
            endpoints.append(
                {
                    "url": url,
                    "methods": ["GET"],
                    "status_code": None,
                    "title": device.get("name") or device.get("manufacturer"),
                    "confidence": 0.72,
                }
            )
        product = str(device.get("model_name") or device.get("device_type") or "").strip()
        vendor = str(device.get("manufacturer") or "").strip() or None
        if product:
            technologies.append(
                {
                    "name": product,
                    "vendor": vendor or "iot",
                    "version": None,
                    "confidence": 0.76,
                }
            )
            fingerprints.append(
                {
                    "vendor": vendor,
                    "product": product,
                    "version": None,
                    "confidence": 0.76,
                }
            )
    return {
        "hosts": hosts,
        "services": services,
        "endpoints": endpoints,
        "technologies": technologies,
        "fingerprints": fingerprints,
        "confidence": 0.82 if hosts else 0.0,
    }


def discover_mdns_services(
    service_types: list[str],
    *,
    timeout_seconds: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        return [], {
            "available": False,
            "backend": "zeroconf",
            "reason": "python zeroconf package is not installed",
        }

    class Listener(ServiceListener):
        def __init__(self) -> None:
            self.records: list[dict[str, Any]] = []

        def add_service(self, zc, service_type: str, name: str) -> None:  # noqa: ANN001
            info = zc.get_service_info(service_type, name, timeout=1000)
            if info is None:
                return
            addresses = []
            for raw_address in getattr(info, "addresses", []) or []:
                try:
                    addresses.append(socket.inet_ntoa(raw_address))
                except OSError:
                    continue
            txt = {}
            for key, value in (getattr(info, "properties", {}) or {}).items():
                key_text = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
                value_text = (
                    value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
                )
                txt[key_text] = value_text
            self.records.append(
                {
                    "name": name,
                    "service_type": service_type,
                    "addresses": addresses,
                    "port": getattr(info, "port", None),
                    "server": getattr(info, "server", None),
                    "txt": txt,
                }
            )

        def remove_service(self, zc, service_type: str, name: str) -> None:  # noqa: ANN001
            return None

        def update_service(self, zc, service_type: str, name: str) -> None:  # noqa: ANN001
            self.add_service(zc, service_type, name)

    zeroconf = Zeroconf()
    listener = Listener()
    try:
        browsers = [ServiceBrowser(zeroconf, service_type, listener) for service_type in service_types]
        time.sleep(max(0.2, min(float(timeout_seconds), 10.0)))
        for browser in browsers:
            browser.cancel()
    finally:
        zeroconf.close()
    return listener.records, {"available": True, "backend": "zeroconf"}


def discover_ssdp_devices(
    *,
    timeout_seconds: float,
    fetch_url: Callable[[str, float], bytes] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    fetch_url = fetch_url or _fetch_url
    request = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode("ascii")
    responses: list[dict[str, str]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(max(0.2, min(float(timeout_seconds), 10.0)))
        sock.sendto(request, ("239.255.255.250", 1900))
        deadline = time.monotonic() + max(0.2, min(float(timeout_seconds), 10.0))
        while time.monotonic() < deadline:
            try:
                data, _address = sock.recvfrom(8192)
            except socket.timeout:
                break
            headers = parse_ssdp_response(data)
            if headers:
                responses.append(headers)
    finally:
        sock.close()

    devices: list[dict[str, Any]] = []
    for headers in responses:
        description = None
        location = str(headers.get("location") or "").strip()
        if location.startswith(("http://", "https://")):
            try:
                description = parse_upnp_device_description(
                    fetch_url(location, 2.0),
                    location_url=location,
                )
            except Exception:
                description = None
        device = normalize_ssdp_device(headers, description=description)
        if device is not None:
            devices.append(device)
    return devices, {"available": True, "response_count": len(responses)}


def _fetch_url(url: str, timeout_seconds: float) -> bytes:
    with urlopen(url, timeout=max(0.5, float(timeout_seconds))) as response:  # noqa: S310
        return response.read(1024 * 1024)


def build_mdns_ssdp_payload(
    *,
    targets: list[str],
    scope_allowlist: dict[str, Any] | None = None,
    mdns_records: list[dict[str, Any]] | None = None,
    ssdp_devices: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    scope_allowlist = scope_allowlist if isinstance(scope_allowlist, dict) else {}
    expected_networks = _scope_networks(_scope_values(targets, scope_allowlist))
    normalized_mdns = [
        device
        for record in (mdns_records or [])
        for device in [normalize_mdns_record(record)]
        if device is not None and _address_in_scope(device.get("ip"), expected_networks)
    ]
    normalized_ssdp = [
        device
        for device in (ssdp_devices or [])
        if isinstance(device, dict) and _address_in_scope(device.get("ip"), expected_networks)
    ]
    devices = _dedupe_devices([*normalized_mdns, *normalized_ssdp])
    return {
        "tool": "mdns-ssdp",
        "kind": "iot-discovery",
        "targets": _normalized_string_list(targets),
        "devices": devices,
        "inventory": _inventory_from_devices(devices),
        "analysis_findings": build_analysis_findings(
            devices,
            expected_networks=expected_networks,
        ),
    }


def execute_mdns_ssdp_discovery(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    service_types: list[str] | None = None,
    timeout_seconds: float = 8.0,
    mdns_enabled: bool = True,
    ssdp_enabled: bool = True,
    mdns_records: list[dict[str, Any]] | None = None,
    ssdp_devices: list[dict[str, Any]] | None = None,
) -> RunnerExecution:
    normalized_targets = _normalized_string_list(targets)
    if not normalized_targets:
        raise ValueError("at least one target is required")

    normalized_service_types = _normalized_string_list(service_types) or list(
        DEFAULT_MDNS_SERVICE_TYPES
    )
    metadata: dict[str, Any] = {
        "status": "ok",
        "normalized_targets": normalized_targets,
        "service_types": normalized_service_types,
        "runner_digest": MDNS_SSDP_RUNNER_DIGEST,
        "timeout_seconds": timeout_seconds,
    }
    discovered_mdns_records = mdns_records or []
    discovered_ssdp_devices = ssdp_devices or []
    if mdns_enabled and mdns_records is None:
        discovered_mdns_records, mdns_metadata = discover_mdns_services(
            normalized_service_types,
            timeout_seconds=timeout_seconds,
        )
        metadata["mdns"] = mdns_metadata
    elif not mdns_enabled:
        metadata["mdns"] = {"available": False, "reason": "disabled by runner params"}
    if ssdp_enabled and ssdp_devices is None:
        discovered_ssdp_devices, ssdp_metadata = discover_ssdp_devices(
            timeout_seconds=timeout_seconds
        )
        metadata["ssdp"] = ssdp_metadata
    elif not ssdp_enabled:
        metadata["ssdp"] = {"available": False, "reason": "disabled by runner params"}

    payload = build_mdns_ssdp_payload(
        targets=normalized_targets,
        scope_allowlist=scope_allowlist,
        mdns_records=discovered_mdns_records,
        ssdp_devices=discovered_ssdp_devices,
    )
    metadata["device_count"] = len(payload["devices"])
    metadata["finding_count"] = len(payload["analysis_findings"])
    artifact = EvidenceArtifact(
        name=MDNS_SSDP_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        kind="iot-discovery-results",
    )
    stdout = (
        f"mDNS/SSDP passive discovery completed: {metadata['device_count']} devices, "
        f"{metadata['finding_count']} findings"
    )
    return RunnerExecution(
        tool="mdns-ssdp",
        exit_code=0,
        stdout=stdout,
        stderr="",
        metadata=metadata,
        artifacts=[artifact],
    )
