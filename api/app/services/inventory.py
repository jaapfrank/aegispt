from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
import json
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from api.app.models import InventorySnapshot


def _bounded_confidence(value: Any, default: float = 0.5) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    return default


def _normalize_str_list(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        item = value.strip()
        if item:
            normalized.append(item)
    return normalized


def wifi_survey_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        payload = {}
    inventory = payload.get("inventory") if isinstance(payload.get("inventory"), dict) else {}
    return {
        "tool": "wifi-survey",
        "kind": "inventory",
        "data": {
            "site": str(payload.get("site") or target_id or "").strip() or None,
            "adapter": str(payload.get("adapter") or "").strip() or None,
            "wireless_access_points": [
                item
                for item in inventory.get("wireless_access_points", [])
                if isinstance(item, dict)
            ],
            "wireless_networks": [
                item for item in inventory.get("wireless_networks", []) if isinstance(item, dict)
            ],
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.6),
        },
    }


def _host_from_value(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc.strip()
    return value.strip()


def nmap_observation_from_xml(
    *,
    xml_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    root = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))

    hosts: list[str] = []
    services: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    script_outputs: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    script_outputs: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    seen_services: set[tuple[str, int, str]] = set()
    seen_endpoints: set[str] = set()

    def add_host(value: str) -> None:
        normalized = value.strip()
        if not normalized or normalized in seen_hosts:
            return
        seen_hosts.add(normalized)
        hosts.append(normalized)

    for host in root.findall("host"):
        state = host.find("status")
        if state is not None and state.get("state") not in {None, "", "up"}:
            continue

        preferred_address = None
        fallback_address = None
        for address in host.findall("address"):
            raw_address = str(address.get("addr") or "").strip()
            if not raw_address:
                continue
            fallback_address = fallback_address or raw_address
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                preferred_address = raw_address
                break
        primary_host = preferred_address or fallback_address
        if primary_host:
            add_host(primary_host)

        for hostname in host.findall("./hostnames/hostname"):
            name = str(hostname.get("name") or "").strip()
            if name:
                add_host(name)

        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            if state_node is not None and state_node.get("state") != "open":
                continue
            try:
                port_number = int(port.get("portid") or 0)
            except ValueError:
                continue
            if port_number <= 0:
                continue
            service_node = port.find("service")
            service_name = str(
                (service_node.get("name") if service_node is not None else None)
                or (service_node.get("product") if service_node is not None else None)
                or "unknown-service"
            ).strip()
            key = (
                (primary_host or target_id or "unknown-host").lower(),
                port_number,
                service_name.lower(),
            )
            if key in seen_services:
                continue
            seen_services.add(key)
            product = (
                str(service_node.get("product") or "").strip() if service_node is not None else ""
            )
            version = (
                str(service_node.get("version") or "").strip() if service_node is not None else ""
            )
            scripts = []
            for script in port.findall("script"):
                script_id = str(script.get("id") or "").strip()
                output = str(script.get("output") or "").strip()
                if not script_id:
                    continue
                script_record = {
                    "host": primary_host or target_id or "unknown-host",
                    "port": port_number,
                    "protocol": str(port.get("protocol") or "tcp"),
                    "id": script_id,
                    "output": output,
                    "confidence": 0.74,
                }
                scripts.append(script_record)
                script_outputs.append(script_record)
            services.append(
                {
                    "host": primary_host or target_id or "unknown-host",
                    "port": port_number,
                    "protocol": str(port.get("protocol") or "tcp"),
                    "service": service_name,
                    "product": product or None,
                    "version": version or None,
                    "scripts": scripts,
                    "confidence": 0.9,
                }
            )
            script_by_id = {script["id"]: script for script in scripts}
            service_lower = service_name.lower()
            if service_lower in {"http", "https", "http-alt", "ssl/http"} or port_number in {
                80,
                81,
                443,
                8008,
                8080,
                8083,
                8443,
            }:
                scheme = "https" if port_number in {443, 8443} or "ssl" in service_lower else "http"
                endpoint_url = f"{scheme}://{primary_host or target_id or 'unknown-host'}:{port_number}/"
                if endpoint_url not in seen_endpoints:
                    seen_endpoints.add(endpoint_url)
                    endpoints.append(
                        {
                            "url": endpoint_url,
                            "methods": ["GET"],
                            "status_code": None,
                            "title": (
                                script_by_id.get("http-title", {}).get("output")
                                if script_by_id.get("http-title")
                                else None
                            ),
                            "confidence": 0.72,
                        }
                    )
            for script_id, technology_name in (
                ("http-server-header", "http-server-header"),
                ("ssl-cert", "tls-certificate"),
                ("snmp-info", "snmp-device-info"),
                ("snmp-sysdescr", "snmp-system-description"),
                ("smb-security-mode", "smb-security-mode"),
                ("ftp-anon", "ftp-anonymous-check"),
                ("upnp-info", "upnp-device-info"),
            ):
                if script_id not in script_by_id:
                    continue
                technologies.append(
                    {
                        "name": technology_name,
                        "vendor": "nmap-nse",
                        "version": None,
                        "evidence": script_by_id[script_id].get("output") or None,
                        "confidence": 0.72,
                    }
                )
            if product:
                fingerprints.append(
                    {
                        "vendor": None,
                        "product": product,
                        "version": version or None,
                        "confidence": 0.82,
                    }
                )

    return {
        "tool": "nmap",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "services": services,
            "endpoints": endpoints,
            "technologies": technologies,
            "fingerprints": fingerprints,
            "script_outputs": script_outputs,
            "confidence": 0.88,
        },
    }


def httpx_observation_from_jsonl(
    *,
    jsonl_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    hosts: list[str] = []
    endpoints: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    seen_endpoints: set[str] = set()

    for raw_line in jsonl_bytes.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        payload = json.loads(line)
        if not isinstance(payload, dict) or not payload.get("ok"):
            continue

        final_url = str(payload.get("final_url") or payload.get("request_url") or "").strip()
        if not final_url:
            continue

        parsed = urlparse(final_url)
        host = str(parsed.hostname or payload.get("input_target") or target_id or "").strip()
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            hosts.append(host)

        if final_url in seen_endpoints:
            continue
        seen_endpoints.add(final_url)

        content_type = str(payload.get("content_type") or "").strip() or None
        endpoints.append(
            {
                "url": final_url,
                "methods": ["GET"],
                "status_code": payload.get("status_code"),
                "title": None,
                "confidence": 0.84,
            }
        )
        if content_type:
            technologies.append(
                {
                    "name": content_type,
                    "vendor": "http-content-type",
                    "version": None,
                    "confidence": 0.55,
                }
            )
            fingerprints.append(
                {
                    "vendor": "http-content-type",
                    "product": content_type,
                    "version": None,
                    "confidence": 0.55,
                }
            )

    return {
        "tool": "httpx",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "endpoints": endpoints,
            "technologies": technologies,
            "fingerprints": fingerprints,
            "confidence": 0.8,
        },
    }


def easm_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("EASM payload must be a JSON object")

    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    seen_services: set[tuple[str, int, str]] = set()
    seen_endpoints: set[str] = set()
    seen_technologies: set[tuple[str, str, str | None]] = set()
    seen_fingerprints: set[tuple[str | None, str, str | None]] = set()

    results = payload.get("results", [])
    if not isinstance(results, list):
        results = []

    for result in results:
        if not isinstance(result, dict):
            continue
        root_domain = str(result.get("root_domain") or target_id or "").strip()
        assets = result.get("assets", [])
        if not isinstance(assets, list):
            continue

        for asset in assets:
            if not isinstance(asset, dict):
                continue
            host = str(asset.get("host") or "").strip()
            if not host:
                continue
            if host.lower() not in seen_hosts:
                seen_hosts.add(host.lower())
                notes = [
                    f"EASM asset discovered from {root_domain}."
                    if root_domain
                    else "EASM asset discovered from the selected root domain."
                ]
                discovery_sources = [
                    str(source).strip()
                    for source in asset.get("discovery_sources", [])
                    if str(source).strip()
                ]
                resolved_ips = [
                    str(address).strip()
                    for address in asset.get("resolved_ips", [])
                    if str(address).strip()
                ]
                if discovery_sources:
                    notes.append(f"Discovery sources: {', '.join(discovery_sources)}.")
                if resolved_ips:
                    notes.append(f"Resolved IPs: {', '.join(resolved_ips)}.")
                hosts.append(
                    {
                        "host": host,
                        "notes": notes,
                        "confidence": _bounded_confidence(asset.get("confidence"), default=0.82),
                    }
                )

            http_endpoints = asset.get("http_endpoints", [])
            if not isinstance(http_endpoints, list):
                continue

            for endpoint in http_endpoints:
                if not isinstance(endpoint, dict):
                    continue
                endpoint_url = str(endpoint.get("url") or "").strip()
                if not endpoint_url or endpoint_url.lower() in seen_endpoints:
                    continue
                seen_endpoints.add(endpoint_url.lower())
                endpoint_confidence = _bounded_confidence(
                    endpoint.get("confidence"), default=0.84
                )
                endpoints.append(
                    {
                        "url": endpoint_url,
                        "methods": ["GET"],
                        "status_code": (
                            endpoint.get("status_code")
                            if isinstance(endpoint.get("status_code"), int)
                            else None
                        ),
                        "title": str(endpoint.get("title") or "") or None,
                        "confidence": endpoint_confidence,
                    }
                )

                parsed_endpoint = urlparse(endpoint_url)
                port = parsed_endpoint.port or (443 if parsed_endpoint.scheme == "https" else 80)
                service_name = "https" if parsed_endpoint.scheme == "https" else "http"
                service_key = (host.lower(), port, service_name)
                if service_key not in seen_services:
                    seen_services.add(service_key)
                    services.append(
                        {
                            "host": host,
                            "port": port,
                            "protocol": "tcp",
                            "service": service_name,
                            "product": str(endpoint.get("server_header") or "") or None,
                            "version": None,
                            "confidence": endpoint_confidence,
                        }
                    )

                server_header = str(endpoint.get("server_header") or "").strip()
                if server_header:
                    technology_key = ("http-server", server_header.lower(), None)
                    if technology_key not in seen_technologies:
                        seen_technologies.add(technology_key)
                        technologies.append(
                            {
                                "name": server_header,
                                "vendor": "http-server",
                                "version": None,
                                "confidence": endpoint_confidence,
                            }
                        )
                    fingerprint_key = ("http-server", server_header.lower(), None)
                    if fingerprint_key not in seen_fingerprints:
                        seen_fingerprints.add(fingerprint_key)
                        fingerprints.append(
                            {
                                "vendor": "http-server",
                                "product": server_header,
                                "version": None,
                                "confidence": endpoint_confidence,
                            }
                        )

                content_type = str(endpoint.get("content_type") or "").strip()
                if content_type:
                    technology_key = ("content-type", content_type.lower(), None)
                    if technology_key not in seen_technologies:
                        seen_technologies.add(technology_key)
                        technologies.append(
                            {
                                "name": content_type,
                                "vendor": "content-type",
                                "version": None,
                                "confidence": 0.62,
                            }
                        )

    return {
        "tool": "easm-discover",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "services": services,
            "endpoints": endpoints,
            "technologies": technologies,
            "fingerprints": fingerprints,
            "confidence": 0.82 if hosts else 0.0,
        },
    }


def external_infrastructure_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("External infrastructure payload must be a JSON object")

    inventory = payload.get("inventory", {})
    if not isinstance(inventory, dict):
        inventory = {}

    return {
        "tool": "external-infra",
        "kind": "inventory",
        "data": {
            "hosts": list(inventory.get("hosts", [])) if isinstance(inventory.get("hosts"), list) else [],
            "services": list(inventory.get("services", [])) if isinstance(inventory.get("services"), list) else [],
            "endpoints": list(inventory.get("endpoints", [])) if isinstance(inventory.get("endpoints"), list) else [],
            "technologies": (
                list(inventory.get("technologies", []))
                if isinstance(inventory.get("technologies"), list)
                else []
            ),
            "fingerprints": (
                list(inventory.get("fingerprints", []))
                if isinstance(inventory.get("fingerprints"), list)
                else []
            ),
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.82),
        },
    }


def mdns_ssdp_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("mDNS/SSDP payload must be a JSON object")

    inventory = payload.get("inventory", {})
    if not isinstance(inventory, dict):
        inventory = {}

    return {
        "tool": "mdns-ssdp",
        "kind": "inventory",
        "data": {
            "hosts": list(inventory.get("hosts", [])) if isinstance(inventory.get("hosts"), list) else [],
            "services": list(inventory.get("services", [])) if isinstance(inventory.get("services"), list) else [],
            "endpoints": list(inventory.get("endpoints", [])) if isinstance(inventory.get("endpoints"), list) else [],
            "technologies": (
                list(inventory.get("technologies", []))
                if isinstance(inventory.get("technologies"), list)
                else []
            ),
            "fingerprints": (
                list(inventory.get("fingerprints", []))
                if isinstance(inventory.get("fingerprints"), list)
                else []
            ),
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.82),
        },
    }


def snmp_enum_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("SNMP enumeration payload must be a JSON object")

    inventory = payload.get("inventory")
    if not isinstance(inventory, dict):
        inventory = {}

    return {
        "tool": "snmp-enum",
        "kind": "inventory",
        "data": {
            "hosts": (
                list(inventory.get("hosts", []))
                if isinstance(inventory.get("hosts"), list)
                else ([target_id] if target_id else [])
            ),
            "services": (
                list(inventory.get("services", []))
                if isinstance(inventory.get("services"), list)
                else []
            ),
            "fingerprints": (
                list(inventory.get("fingerprints", []))
                if isinstance(inventory.get("fingerprints"), list)
                else []
            ),
            "network_interfaces": (
                list(inventory.get("network_interfaces", []))
                if isinstance(inventory.get("network_interfaces"), list)
                else []
            ),
            "arp_table": (
                list(inventory.get("arp_table", []))
                if isinstance(inventory.get("arp_table"), list)
                else []
            ),
            "routes": (
                list(inventory.get("routes", []))
                if isinstance(inventory.get("routes"), list)
                else []
            ),
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.76),
        },
    }


def smart_home_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("Smart-home audit payload must be a JSON object")

    inventory = payload.get("inventory")
    if not isinstance(inventory, dict):
        inventory = {}

    return {
        "tool": "smart-home",
        "kind": "inventory",
        "data": {
            "hosts": (
                list(inventory.get("hosts", []))
                if isinstance(inventory.get("hosts"), list)
                else ([target_id] if target_id else [])
            ),
            "services": (
                list(inventory.get("services", []))
                if isinstance(inventory.get("services"), list)
                else []
            ),
            "endpoints": (
                list(inventory.get("endpoints", []))
                if isinstance(inventory.get("endpoints"), list)
                else []
            ),
            "fingerprints": (
                list(inventory.get("fingerprints", []))
                if isinstance(inventory.get("fingerprints"), list)
                else []
            ),
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.72),
        },
    }


def camera_test_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("Camera audit payload must be a JSON object")

    inventory = payload.get("inventory")
    if not isinstance(inventory, dict):
        inventory = {}

    return {
        "tool": "camera-test",
        "kind": "inventory",
        "data": {
            "hosts": (
                list(inventory.get("hosts", []))
                if isinstance(inventory.get("hosts"), list)
                else ([target_id] if target_id else [])
            ),
            "services": (
                list(inventory.get("services", []))
                if isinstance(inventory.get("services"), list)
                else []
            ),
            "endpoints": (
                list(inventory.get("endpoints", []))
                if isinstance(inventory.get("endpoints"), list)
                else []
            ),
            "fingerprints": (
                list(inventory.get("fingerprints", []))
                if isinstance(inventory.get("fingerprints"), list)
                else []
            ),
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.76),
        },
    }


def ipv6_discovery_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("ipv6 discovery payload must be an object")
    inventory = payload.get("inventory")
    if not isinstance(inventory, dict):
        inventory = {}
    return {
        "tool": "ipv6-discovery",
        "kind": "inventory",
        "data": {
            "hosts": inventory.get("hosts", []),
            "ipv6_addresses": inventory.get("ipv6_addresses", []),
            "ipv6_prefixes": inventory.get("ipv6_prefixes", []),
            "services": inventory.get("services", []),
            "confidence": _bounded_confidence(inventory.get("confidence"), default=0.74),
            "target_id": target_id,
        },
    }


def api_assessment_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("API assessment inventory payload must be a JSON object")

    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}

    return {
        "tool": "api-assessment",
        "kind": "inventory",
        "data": {
            "hosts": list(data.get("hosts", [])) if isinstance(data.get("hosts"), list) else [],
            "endpoints": (
                list(data.get("endpoints", []))
                if isinstance(data.get("endpoints"), list)
                else []
            ),
            "api_types": (
                list(data.get("api_types", []))
                if isinstance(data.get("api_types"), list)
                else []
            ),
            "technologies": (
                list(data.get("technologies", []))
                if isinstance(data.get("technologies"), list)
                else []
            ),
            "confidence": _bounded_confidence(data.get("confidence"), default=0.82),
        },
    }


def mobile_android_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("Mobile Android inventory payload must be a JSON object")

    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}

    mobile_apps = data.get("mobile_apps")
    if not isinstance(mobile_apps, list):
        mobile_apps = []

    return {
        "tool": "mobile-android",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": [],
            "technologies": (
                list(data.get("technologies", []))
                if isinstance(data.get("technologies"), list)
                else []
            ),
            "fingerprints": (
                list(data.get("fingerprints", []))
                if isinstance(data.get("fingerprints"), list)
                else []
            ),
            "mobile_apps": mobile_apps,
            "confidence": _bounded_confidence(data.get("confidence"), default=0.82),
        },
    }


def desktop_client_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("Desktop client inventory payload must be a JSON object")

    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}

    desktop_apps = data.get("desktop_apps")
    if not isinstance(desktop_apps, list):
        desktop_apps = []

    return {
        "tool": "desktop-client",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": (
                list(data.get("endpoints", []))
                if isinstance(data.get("endpoints"), list)
                else []
            ),
            "technologies": (
                list(data.get("technologies", []))
                if isinstance(data.get("technologies"), list)
                else []
            ),
            "fingerprints": (
                list(data.get("fingerprints", []))
                if isinstance(data.get("fingerprints"), list)
                else []
            ),
            "desktop_apps": desktop_apps,
            "confidence": _bounded_confidence(data.get("confidence"), default=0.78),
        },
    }


def cloud_native_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("Cloud-native inventory payload must be a JSON object")

    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}

    return {
        "tool": "cloud-native",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": [],
            "technologies": (
                list(data.get("technologies", []))
                if isinstance(data.get("technologies"), list)
                else []
            ),
            "fingerprints": (
                list(data.get("fingerprints", []))
                if isinstance(data.get("fingerprints"), list)
                else []
            ),
            "kubernetes_clusters": (
                list(data.get("kubernetes_clusters", []))
                if isinstance(data.get("kubernetes_clusters"), list)
                else []
            ),
            "kubernetes_workloads": (
                list(data.get("kubernetes_workloads", []))
                if isinstance(data.get("kubernetes_workloads"), list)
                else []
            ),
            "container_images": (
                list(data.get("container_images", []))
                if isinstance(data.get("container_images"), list)
                else []
            ),
            "confidence": _bounded_confidence(data.get("confidence"), default=0.82),
        },
    }


def cicd_security_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("CI/CD security inventory payload must be a JSON object")

    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}

    return {
        "tool": "cicd-security",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": [],
            "technologies": (
                list(data.get("technologies", []))
                if isinstance(data.get("technologies"), list)
                else []
            ),
            "fingerprints": (
                list(data.get("fingerprints", []))
                if isinstance(data.get("fingerprints"), list)
                else []
            ),
            "repositories": (
                list(data.get("repositories", []))
                if isinstance(data.get("repositories"), list)
                else []
            ),
            "pipeline_configs": (
                list(data.get("pipeline_configs", []))
                if isinstance(data.get("pipeline_configs"), list)
                else []
            ),
            "confidence": _bounded_confidence(data.get("confidence"), default=0.8),
        },
    }


def ldap_enum_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("LDAP enumeration payload must be a JSON object")

    hosts: list[str] = []
    services: list[dict[str, Any]] = []
    identity_subjects: list[dict[str, Any]] = []
    identity_groups: list[dict[str, Any]] = []
    privileged_memberships: list[dict[str, Any]] = []
    auth_mechanisms: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue

        target = str(result.get("target") or target_id or "").strip()
        base_dn = str(result.get("base_dn") or "").strip() or None
        if target and target not in seen_hosts:
            seen_hosts.add(target)
            hosts.append(target)
            services.append(
                {
                    "host": target,
                    "port": 636 if target.startswith("ldaps://") else 389,
                    "protocol": "tcp",
                    "service": "ldap",
                    "product": "LDAP directory",
                    "version": None,
                    "confidence": 0.8,
                }
            )

        auth_mechanisms.append(
            {
                "type": "ldap-directory",
                "location": base_dn or target or None,
                "confidence": 0.82,
            }
        )
        fingerprints.append(
            {
                "vendor": "directory",
                "product": "LDAP directory",
                "version": None,
                "confidence": 0.76,
            }
        )

        for user in result.get("users", []) if isinstance(result.get("users"), list) else []:
            if not isinstance(user, dict):
                continue
            account_name = str(user.get("account_name") or "").strip()
            dn = str(user.get("dn") or "").strip()
            if not account_name and not dn:
                continue
            identity_subjects.append(
                {
                    "account_name": account_name or dn,
                    "principal": str(user.get("user_principal_name") or "") or None,
                    "dn": dn or None,
                    "enabled": (
                        user.get("enabled") if isinstance(user.get("enabled"), bool) else None
                    ),
                    "source": "ldap-enum",
                    "confidence": 0.84,
                }
            )

        for group in result.get("groups", []) if isinstance(result.get("groups"), list) else []:
            if not isinstance(group, dict):
                continue
            name = str(group.get("name") or "").strip()
            dn = str(group.get("dn") or "").strip()
            if not name and not dn:
                continue
            members = group.get("members", [])
            identity_groups.append(
                {
                    "name": name or dn,
                    "dn": dn or None,
                    "member_count": len(members) if isinstance(members, list) else None,
                    "privileged": (
                        group.get("privileged")
                        if isinstance(group.get("privileged"), bool)
                        else False
                    ),
                    "source": "ldap-enum",
                    "confidence": 0.84,
                }
            )

        for membership in (
            result.get("privileged_memberships", [])
            if isinstance(result.get("privileged_memberships"), list)
            else []
        ):
            if not isinstance(membership, dict):
                continue
            privileged_memberships.append(
                {
                    "group": str(membership.get("group") or "").strip(),
                    "member": str(
                        membership.get("account_name") or membership.get("member_dn") or ""
                    ).strip(),
                    "group_dn": str(membership.get("group_dn") or "") or None,
                    "member_dn": str(membership.get("member_dn") or "") or None,
                    "source": "ldap-enum",
                    "confidence": _bounded_confidence(membership.get("confidence"), default=0.78),
                }
            )

    return {
        "tool": "ldap-enum",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "services": services,
            "identity_subjects": identity_subjects,
            "identity_groups": identity_groups,
            "privileged_memberships": privileged_memberships,
            "auth_mechanisms": auth_mechanisms,
            "fingerprints": fingerprints,
            "confidence": 0.82 if identity_subjects or identity_groups else 0.55,
        },
    }


def bloodhound_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("BloodHound results payload must be a JSON object")

    hosts: list[dict[str, Any]] = []
    identity_subjects: list[dict[str, Any]] = []
    identity_groups: list[dict[str, Any]] = []
    privileged_memberships: list[dict[str, Any]] = []
    bloodhound_confirmed_edges: list[dict[str, Any]] = []
    bloodhound_attack_paths: list[dict[str, Any]] = []

    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue
        hosts.extend(
            [
                entry
                for entry in result.get("hosts", [])
                if isinstance(entry, dict) and str(entry.get("host") or "").strip()
            ]
        )
        identity_subjects.extend(
            [
                entry
                for entry in result.get("identity_subjects", [])
                if isinstance(entry, dict)
            ]
        )
        identity_groups.extend(
            [
                entry
                for entry in result.get("identity_groups", [])
                if isinstance(entry, dict)
            ]
        )
        privileged_memberships.extend(
            [
                entry
                for entry in result.get("privileged_memberships", [])
                if isinstance(entry, dict)
            ]
        )
        bloodhound_confirmed_edges.extend(
            [
                entry
                for entry in result.get("bloodhound_confirmed_edges", [])
                if isinstance(entry, dict)
            ]
        )
        bloodhound_attack_paths.extend(
            [
                entry
                for entry in result.get("bloodhound_attack_paths", [])
                if isinstance(entry, dict)
            ]
        )

    return {
        "tool": "bloodhound-collect",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "identity_subjects": identity_subjects,
            "identity_groups": identity_groups,
            "privileged_memberships": privileged_memberships,
            "bloodhound_confirmed_edges": bloodhound_confirmed_edges,
            "bloodhound_attack_paths": bloodhound_attack_paths,
            "auth_mechanisms": [
                {
                    "type": "active-directory-graph",
                    "location": target_id,
                    "source": "bloodhound-collect",
                    "confidence": 0.84,
                }
            ]
            if identity_subjects or identity_groups
            else [],
            "fingerprints": [
                {
                    "vendor": "specterops-compatible",
                    "product": "BloodHound graph collection",
                    "version": None,
                    "confidence": 0.76,
                }
            ]
            if bloodhound_attack_paths or bloodhound_confirmed_edges
            else [],
            "confidence": 0.84 if bloodhound_attack_paths or bloodhound_confirmed_edges else 0.6,
        },
    }


def aws_inventory_observation_from_json(
    *,
    json_bytes: bytes,
    target_id: str | None = None,
) -> dict[str, Any]:
    payload = json.loads(json_bytes.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("AWS inventory payload must be a JSON object")

    hosts: list[str] = []
    cloud_accounts: list[dict[str, Any]] = []
    cloud_regions: list[dict[str, Any]] = []
    cloud_resources: list[dict[str, Any]] = []
    cloud_security_groups: list[dict[str, Any]] = []
    cloud_collection_errors: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    def add_host(value: str | None) -> None:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen_hosts:
            return
        seen_hosts.add(normalized)
        hosts.append(normalized)

    for target in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(target, dict) or target.get("status") not in {"ok", "partial"}:
            continue
        identity = target.get("identity") if isinstance(target.get("identity"), dict) else {}
        account_id = str(identity.get("account_id") or target.get("target") or target_id or "").strip()
        if not account_id:
            continue
        for error in target.get("errors", []) if isinstance(target.get("errors"), list) else []:
            cloud_collection_errors.append(
                {
                    "provider": "aws",
                    "account_id": account_id,
                    "region": None,
                    "service": "aws",
                    "operation": "collect_aws_inventory",
                    "error_code": None,
                    "message": str(error),
                    "source": "aws-inventory",
                    "confidence": 0.82,
                }
            )
        cloud_accounts.append(
            {
                "provider": "aws",
                "account_id": account_id,
                "arn": str(identity.get("arn") or "") or None,
                "source": "aws-inventory",
                "confidence": 0.9,
            }
        )

        for region in target.get("regions", []) if isinstance(target.get("regions"), list) else []:
            if not isinstance(region, dict):
                continue
            region_name = str(region.get("name") or "").strip()
            if region_name:
                cloud_regions.append(
                    {
                        "provider": "aws",
                        "account_id": account_id,
                        "region": region_name,
                        "source": "aws-inventory",
                        "confidence": 0.88,
                    }
                )
            for error in region.get("errors", []) if isinstance(region.get("errors"), list) else []:
                cloud_collection_errors.append(
                    {
                        "provider": "aws",
                        "account_id": account_id,
                        "region": region_name or None,
                        "service": "ec2",
                        "operation": "regional_inventory",
                        "error_code": None,
                        "message": str(error),
                        "source": "aws-inventory",
                        "confidence": 0.82,
                    }
                )

            for vpc in region.get("vpcs", []) if isinstance(region.get("vpcs"), list) else []:
                if not isinstance(vpc, dict):
                    continue
                cloud_resources.append(
                    {
                        "provider": "aws",
                        "account_id": account_id,
                        "region": region_name,
                        "resource_type": "ec2:vpc",
                        "resource_id": str(vpc.get("vpc_id") or ""),
                        "name": str(vpc.get("name") or "") or None,
                        "state": str(vpc.get("state") or "") or None,
                        "metadata": {
                            "cidr_block": vpc.get("cidr_block"),
                            "is_default": vpc.get("is_default"),
                            "tags": vpc.get("tags") if isinstance(vpc.get("tags"), dict) else {},
                        },
                        "source": "aws-inventory",
                        "confidence": 0.86,
                    }
                )

            for subnet in region.get("subnets", []) if isinstance(region.get("subnets"), list) else []:
                if not isinstance(subnet, dict):
                    continue
                cloud_resources.append(
                    {
                        "provider": "aws",
                        "account_id": account_id,
                        "region": region_name,
                        "resource_type": "ec2:subnet",
                        "resource_id": str(subnet.get("subnet_id") or ""),
                        "name": str(subnet.get("name") or "") or None,
                        "state": str(subnet.get("state") or "") or None,
                        "metadata": {
                            "vpc_id": subnet.get("vpc_id"),
                            "cidr_block": subnet.get("cidr_block"),
                            "availability_zone": subnet.get("availability_zone"),
                            "tags": subnet.get("tags") if isinstance(subnet.get("tags"), dict) else {},
                        },
                        "source": "aws-inventory",
                        "confidence": 0.86,
                    }
                )

            for group in (
                region.get("security_groups", [])
                if isinstance(region.get("security_groups"), list)
                else []
            ):
                if not isinstance(group, dict):
                    continue
                ingress_rules = (
                    group.get("ingress_rules")
                    if isinstance(group.get("ingress_rules"), list)
                    else group.get("IpPermissions")
                    if isinstance(group.get("IpPermissions"), list)
                    else []
                )
                egress_rules = (
                    group.get("egress_rules")
                    if isinstance(group.get("egress_rules"), list)
                    else group.get("IpPermissionsEgress")
                    if isinstance(group.get("IpPermissionsEgress"), list)
                    else []
                )
                group_payload = {
                    "provider": "aws",
                    "account_id": account_id,
                    "region": region_name,
                    "group_id": str(group.get("group_id") or ""),
                    "group_name": str(group.get("group_name") or "") or None,
                    "vpc_id": str(group.get("vpc_id") or "") or None,
                    "description": str(group.get("description") or "") or None,
                    "rule_count": group.get("rule_count") if isinstance(group.get("rule_count"), int) else None,
                    "ingress_rules": ingress_rules,
                    "egress_rules": egress_rules,
                    "tags": group.get("tags") if isinstance(group.get("tags"), dict) else {},
                    "source": "aws-inventory",
                    "confidence": 0.84,
                }
                cloud_security_groups.append(group_payload)
                cloud_resources.append(
                    {
                        "provider": "aws",
                        "account_id": account_id,
                        "region": region_name,
                        "resource_type": "ec2:security-group",
                        "resource_id": group_payload["group_id"],
                        "name": group_payload["group_name"],
                        "state": None,
                        "metadata": {
                            "vpc_id": group_payload["vpc_id"],
                            "rule_count": group_payload["rule_count"],
                            "ingress_rules": ingress_rules,
                            "egress_rules": egress_rules,
                            "tags": group_payload["tags"],
                        },
                        "source": "aws-inventory",
                        "confidence": 0.84,
                    }
                )

            for instance in (
                region.get("instances", [])
                if isinstance(region.get("instances"), list)
                else []
            ):
                if not isinstance(instance, dict):
                    continue
                add_host(instance.get("private_dns_name"))
                add_host(instance.get("public_dns_name"))
                add_host(instance.get("private_ip"))
                add_host(instance.get("public_ip"))
                instance_id = str(instance.get("instance_id") or "").strip()
                if instance_id:
                    add_host(instance_id)
                cloud_resources.append(
                    {
                        "provider": "aws",
                        "account_id": account_id,
                        "region": region_name,
                        "resource_type": "ec2:instance",
                        "resource_id": instance_id,
                        "name": str(instance.get("name") or "") or None,
                        "state": str(instance.get("state") or "") or None,
                        "metadata": {
                            "instance_type": instance.get("instance_type"),
                            "private_ip": instance.get("private_ip"),
                            "public_ip": instance.get("public_ip"),
                            "private_dns_name": instance.get("private_dns_name"),
                            "public_dns_name": instance.get("public_dns_name"),
                            "vpc_id": instance.get("vpc_id"),
                            "subnet_id": instance.get("subnet_id"),
                            "security_group_ids": (
                                instance.get("security_group_ids")
                                if isinstance(instance.get("security_group_ids"), list)
                                else []
                            ),
                            "tags": instance.get("tags") if isinstance(instance.get("tags"), dict) else {},
                        },
                        "source": "aws-inventory",
                        "confidence": 0.88,
                    }
                )

    if cloud_resources:
        fingerprints.append(
            {
                "vendor": "AWS",
                "product": "AWS resource inventory",
                "version": None,
                "confidence": 0.8,
            }
        )

    return {
        "tool": "aws-inventory",
        "kind": "inventory",
        "data": {
            "hosts": hosts,
            "cloud_accounts": cloud_accounts,
            "cloud_regions": cloud_regions,
            "cloud_resources": cloud_resources,
            "cloud_security_groups": cloud_security_groups,
            "cloud_collection_errors": cloud_collection_errors,
            "fingerprints": fingerprints,
            "confidence": 0.84 if cloud_accounts else 0.35,
        },
    }


def normalize_inventory_observations(
    *,
    observations: Iterable[dict[str, Any]],
    environment_notes: Iterable[str],
    assumptions: Iterable[str],
) -> dict[str, Any]:
    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []
    script_outputs: list[dict[str, Any]] = []
    auth_mechanisms: list[dict[str, Any]] = []
    identity_subjects: list[dict[str, Any]] = []
    identity_groups: list[dict[str, Any]] = []
    privileged_memberships: list[dict[str, Any]] = []
    bloodhound_confirmed_edges: list[dict[str, Any]] = []
    bloodhound_attack_paths: list[dict[str, Any]] = []
    cloud_accounts: list[dict[str, Any]] = []
    cloud_regions: list[dict[str, Any]] = []
    cloud_resources: list[dict[str, Any]] = []
    cloud_security_groups: list[dict[str, Any]] = []
    cloud_iam_principals: list[dict[str, Any]] = []
    cloud_iam_policies: list[dict[str, Any]] = []
    cloud_iam_attachments: list[dict[str, Any]] = []
    cloud_collection_errors: list[dict[str, Any]] = []
    kubernetes_clusters: list[dict[str, Any]] = []
    kubernetes_workloads: list[dict[str, Any]] = []
    ipv6_addresses: list[dict[str, Any]] = []
    ipv6_prefixes: list[dict[str, Any]] = []
    api_types: list[dict[str, Any]] = []
    wireless_access_points: list[dict[str, Any]] = []
    wireless_networks: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    tls_posture = {
        "protocols": [],
        "issues": [],
        "certificate_subject": None,
        "source": None,
        "confidence": 0.0,
    }

    seen_hosts: set[tuple[str, str]] = set()
    seen_services: set[tuple[str, int, str]] = set()
    seen_endpoints: set[tuple[str, str]] = set()
    seen_technologies: set[tuple[str, str | None, str]] = set()
    seen_script_outputs: set[tuple[str, int, str, str]] = set()
    seen_auth: set[tuple[str, str | None, str]] = set()
    seen_identity_subjects: set[tuple[str, str | None, str]] = set()
    seen_identity_groups: set[tuple[str, str | None, str]] = set()
    seen_privileged_memberships: set[tuple[str, str, str]] = set()
    seen_bloodhound_confirmed_edges: set[tuple[str, str, str]] = set()
    seen_bloodhound_attack_paths: set[str] = set()
    seen_cloud_accounts: set[tuple[str, str, str]] = set()
    seen_cloud_regions: set[tuple[str, str, str, str]] = set()
    seen_cloud_resources: set[tuple[str, str, str, str, str]] = set()
    seen_cloud_security_groups: set[tuple[str, str, str, str]] = set()
    seen_cloud_iam_principals: set[tuple[str, str, str, str, str]] = set()
    seen_cloud_iam_policies: set[tuple[str, str, str, str]] = set()
    seen_cloud_iam_attachments: set[tuple[str, str, str, str]] = set()
    seen_cloud_collection_errors: set[tuple[str, str, str, str, str]] = set()
    seen_kubernetes_clusters: set[tuple[str, str, str, str, str]] = set()
    seen_kubernetes_workloads: set[tuple[str, str, str, str, str, str]] = set()
    seen_ipv6_addresses: set[tuple[str, str]] = set()
    seen_ipv6_prefixes: set[tuple[str, str | None]] = set()
    seen_api: set[tuple[str, str | None, str]] = set()
    seen_wireless_access_points: set[tuple[str, str]] = set()
    seen_wireless_networks: set[tuple[str, str]] = set()
    seen_fingerprints: set[tuple[str | None, str, str]] = set()
    confidence_values: list[float] = []

    def add_host(
        host: str,
        *,
        source: str,
        confidence: float,
        notes: list[str] | None = None,
        device_type: str | None = None,
    ) -> None:
        normalized_host = _host_from_value(host)
        if not normalized_host:
            return
        key = (normalized_host.lower(), source.lower())
        if key in seen_hosts:
            return
        seen_hosts.add(key)
        confidence_values.append(confidence)
        host_record = {
            "host": normalized_host,
            "source": source,
            "confidence": confidence,
            "notes": notes or [],
        }
        if isinstance(device_type, str) and device_type.strip():
            host_record["device_type"] = device_type.strip()
        hosts.append(host_record)

    def add_service(
        *,
        host: str,
        port: Any,
        service: str,
        source: str,
        confidence: float,
        protocol: str = "tcp",
        product: str | None = None,
        version: str | None = None,
    ) -> None:
        if not host or not service:
            return
        try:
            normalized_port = int(port)
        except (TypeError, ValueError):
            return
        key = (host.lower(), normalized_port, service.lower())
        if key in seen_services:
            return
        seen_services.add(key)
        confidence_values.append(confidence)
        services.append(
            {
                "host": host,
                "port": normalized_port,
                "protocol": protocol or "tcp",
                "service": service,
                "product": product,
                "version": version,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_script_output(
        *,
        host: str,
        port: Any,
        script_id: str,
        output: str | None,
        source: str,
        confidence: float,
        protocol: str = "tcp",
    ) -> None:
        normalized_host = host.strip()
        normalized_script_id = script_id.strip()
        if not normalized_host or not normalized_script_id:
            return
        try:
            normalized_port = int(port)
        except (TypeError, ValueError):
            return
        key = (
            normalized_host.lower(),
            normalized_port,
            normalized_script_id.lower(),
            source.lower(),
        )
        if key in seen_script_outputs:
            return
        seen_script_outputs.add(key)
        confidence_values.append(confidence)
        script_outputs.append(
            {
                "host": normalized_host,
                "port": normalized_port,
                "protocol": protocol or "tcp",
                "id": normalized_script_id,
                "output": output or "",
                "source": source,
                "confidence": confidence,
            }
        )

    def add_endpoint(
        *,
        url: str,
        source: str,
        confidence: float,
        methods: list[str] | None = None,
        status_code: Any = None,
        title: str | None = None,
    ) -> None:
        normalized_url = url.strip()
        if not normalized_url:
            return
        key = (normalized_url.lower(), source.lower())
        if key in seen_endpoints:
            return
        seen_endpoints.add(key)
        confidence_values.append(confidence)
        endpoints.append(
            {
                "url": normalized_url,
                "methods": methods or [],
                "status_code": int(status_code) if isinstance(status_code, int) else None,
                "title": title,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_technology(
        *,
        name: str,
        source: str,
        confidence: float,
        vendor: str | None = None,
        version: str | None = None,
    ) -> None:
        normalized_name = name.strip()
        if not normalized_name:
            return
        key = (normalized_name.lower(), vendor, source.lower())
        if key in seen_technologies:
            return
        seen_technologies.add(key)
        confidence_values.append(confidence)
        technologies.append(
            {
                "name": normalized_name,
                "vendor": vendor,
                "version": version,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_auth_mechanism(
        *, auth_type: str, source: str, confidence: float, location: str | None = None
    ) -> None:
        normalized_type = auth_type.strip()
        if not normalized_type:
            return
        key = (normalized_type.lower(), location, source.lower())
        if key in seen_auth:
            return
        seen_auth.add(key)
        confidence_values.append(confidence)
        auth_mechanisms.append(
            {
                "type": normalized_type,
                "location": location,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_identity_subject(
        *,
        account_name: str,
        source: str,
        confidence: float,
        principal: str | None = None,
        dn: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        normalized_account = account_name.strip()
        normalized_principal = (
            principal.strip() if isinstance(principal, str) and principal.strip() else None
        )
        normalized_dn = dn.strip() if isinstance(dn, str) and dn.strip() else None
        if not normalized_account and not normalized_principal and not normalized_dn:
            return
        key = (
            (normalized_account or normalized_principal or normalized_dn).lower(),
            normalized_dn,
            source.lower(),
        )
        if key in seen_identity_subjects:
            return
        seen_identity_subjects.add(key)
        confidence_values.append(confidence)
        identity_subjects.append(
            {
                "account_name": normalized_account or normalized_principal or normalized_dn,
                "principal": normalized_principal,
                "dn": normalized_dn,
                "enabled": enabled,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_identity_group(
        *,
        name: str,
        source: str,
        confidence: float,
        dn: str | None = None,
        member_count: Any = None,
        privileged: bool = False,
    ) -> None:
        normalized_name = name.strip()
        normalized_dn = dn.strip() if isinstance(dn, str) and dn.strip() else None
        if not normalized_name and not normalized_dn:
            return
        key = ((normalized_name or normalized_dn).lower(), normalized_dn, source.lower())
        if key in seen_identity_groups:
            return
        seen_identity_groups.add(key)
        confidence_values.append(confidence)
        identity_groups.append(
            {
                "name": normalized_name or normalized_dn,
                "dn": normalized_dn,
                "member_count": member_count if isinstance(member_count, int) else None,
                "privileged": bool(privileged),
                "source": source,
                "confidence": confidence,
            }
        )

    def add_privileged_membership(
        *,
        group: str,
        member: str,
        source: str,
        confidence: float,
        group_dn: str | None = None,
        member_dn: str | None = None,
    ) -> None:
        normalized_group = group.strip()
        normalized_member = member.strip()
        if not normalized_group or not normalized_member:
            return
        key = (normalized_group.lower(), normalized_member.lower(), source.lower())
        if key in seen_privileged_memberships:
            return
        seen_privileged_memberships.add(key)
        confidence_values.append(confidence)
        privileged_memberships.append(
            {
                "group": normalized_group,
                "member": normalized_member,
                "group_dn": (
                    group_dn.strip() if isinstance(group_dn, str) and group_dn.strip() else None
                ),
                "member_dn": (
                    member_dn.strip() if isinstance(member_dn, str) and member_dn.strip() else None
                ),
                "source": source,
                "confidence": confidence,
            }
        )

    def add_bloodhound_confirmed_edge(
        *,
        edge_payload: dict[str, Any],
        source: str,
        confidence: float,
    ) -> None:
        source_id = str(edge_payload.get("source_id") or "").strip()
        target_id = str(edge_payload.get("target_id") or "").strip()
        relationship = str(edge_payload.get("relationship") or "").strip()
        if not source_id or not target_id or not relationship:
            return
        key = (source_id, target_id, relationship)
        if key in seen_bloodhound_confirmed_edges:
            return
        seen_bloodhound_confirmed_edges.add(key)
        edge_confidence = _bounded_confidence(edge_payload.get("confidence"), default=confidence)
        confidence_values.append(edge_confidence)
        bloodhound_confirmed_edges.append(
            {
                "source_id": source_id,
                "target_id": target_id,
                "source_label": str(edge_payload.get("source_label") or "").strip() or None,
                "target_label": str(edge_payload.get("target_label") or "").strip() or None,
                "source_type": str(edge_payload.get("source_type") or "").strip() or None,
                "target_type": str(edge_payload.get("target_type") or "").strip() or None,
                "relationship": relationship,
                "relationship_label": (
                    str(edge_payload.get("relationship_label") or "").strip() or relationship
                ),
                "rationale": str(edge_payload.get("rationale") or "").strip() or None,
                "source": source,
                "confidence": edge_confidence,
            }
        )

    def add_bloodhound_attack_path(
        *,
        path_payload: dict[str, Any],
        source: str,
        confidence: float,
    ) -> None:
        path_id = str(path_payload.get("path_id") or "").strip()
        if not path_id or path_id in seen_bloodhound_attack_paths:
            return
        seen_bloodhound_attack_paths.add(path_id)
        path_confidence = _bounded_confidence(path_payload.get("confidence"), default=confidence)
        confidence_values.append(path_confidence)
        bloodhound_attack_paths.append(
            {
                "path_id": path_id,
                "finding_title": str(path_payload.get("finding_title") or "").strip() or None,
                "finding_target_id": str(path_payload.get("finding_target_id") or "").strip()
                or None,
                "severity": str(path_payload.get("severity") or "").strip() or None,
                "target_category": str(path_payload.get("target_category") or "").strip() or None,
                "source_label": str(path_payload.get("source_label") or "").strip() or None,
                "source_type": str(path_payload.get("source_type") or "").strip() or None,
                "target_label": str(path_payload.get("target_label") or "").strip() or None,
                "target_type": str(path_payload.get("target_type") or "").strip() or None,
                "node_ids": [
                    str(node_id).strip()
                    for node_id in path_payload.get("node_ids", [])
                    if str(node_id).strip()
                ],
                "node_labels": [
                    str(label).strip()
                    for label in path_payload.get("node_labels", [])
                    if str(label).strip()
                ],
                "edge_chain": [
                    dict(edge)
                    for edge in path_payload.get("edge_chain", [])
                    if isinstance(edge, dict)
                ],
                "summary": str(path_payload.get("summary") or "").strip() or None,
                "source": source,
                "confidence": path_confidence,
            }
        )

    def add_cloud_account(
        *,
        provider: str,
        account_id: str,
        source: str,
        confidence: float,
        arn: str | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        if not normalized_provider or not normalized_account:
            return
        key = (normalized_provider, normalized_account, source.lower())
        if key in seen_cloud_accounts:
            return
        seen_cloud_accounts.add(key)
        confidence_values.append(confidence)
        cloud_accounts.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "arn": arn.strip() if isinstance(arn, str) and arn.strip() else None,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_region(
        *,
        provider: str,
        account_id: str,
        region: str,
        source: str,
        confidence: float,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        normalized_region = region.strip()
        if not normalized_provider or not normalized_account or not normalized_region:
            return
        key = (normalized_provider, normalized_account, normalized_region, source.lower())
        if key in seen_cloud_regions:
            return
        seen_cloud_regions.add(key)
        confidence_values.append(confidence)
        cloud_regions.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "region": normalized_region,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_resource(
        *,
        provider: str,
        account_id: str,
        region: str | None,
        resource_type: str,
        resource_id: str,
        source: str,
        confidence: float,
        name: str | None = None,
        state: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        normalized_region = region.strip() if isinstance(region, str) else ""
        normalized_type = resource_type.strip()
        normalized_id = resource_id.strip()
        if not normalized_provider or not normalized_account or not normalized_type or not normalized_id:
            return
        key = (
            normalized_provider,
            normalized_account,
            normalized_region,
            normalized_type,
            normalized_id,
        )
        if key in seen_cloud_resources:
            return
        seen_cloud_resources.add(key)
        confidence_values.append(confidence)
        cloud_resources.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "region": normalized_region or None,
                "resource_type": normalized_type,
                "resource_id": normalized_id,
                "name": name.strip() if isinstance(name, str) and name.strip() else None,
                "state": state.strip() if isinstance(state, str) and state.strip() else None,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_security_group(
        *,
        provider: str,
        account_id: str,
        region: str | None,
        group_id: str,
        source: str,
        confidence: float,
        group_name: str | None = None,
        vpc_id: str | None = None,
        rule_count: Any = None,
        description: str | None = None,
        ingress_rules: list[dict[str, Any]] | None = None,
        egress_rules: list[dict[str, Any]] | None = None,
        tags: dict[str, Any] | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        normalized_region = region.strip() if isinstance(region, str) else ""
        normalized_group = group_id.strip()
        if not normalized_provider or not normalized_account or not normalized_group:
            return
        key = (normalized_provider, normalized_account, normalized_region, normalized_group)
        if key in seen_cloud_security_groups:
            return
        seen_cloud_security_groups.add(key)
        confidence_values.append(confidence)
        cloud_security_groups.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "region": normalized_region or None,
                "group_id": normalized_group,
                "group_name": (
                    group_name.strip() if isinstance(group_name, str) and group_name.strip() else None
                ),
                "vpc_id": vpc_id.strip() if isinstance(vpc_id, str) and vpc_id.strip() else None,
                "rule_count": rule_count if isinstance(rule_count, int) else None,
                "description": (
                    description.strip()
                    if isinstance(description, str) and description.strip()
                    else None
                ),
                "ingress_rules": ingress_rules if isinstance(ingress_rules, list) else [],
                "egress_rules": egress_rules if isinstance(egress_rules, list) else [],
                "tags": tags if isinstance(tags, dict) else {},
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_iam_principal(
        *,
        provider: str,
        account_id: str,
        principal_type: str,
        principal_id: str,
        source: str,
        confidence: float,
        name: str | None = None,
        arn: str | None = None,
        trust_policy: dict[str, Any] | str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        normalized_type = principal_type.strip().lower() or "unknown"
        normalized_principal = principal_id.strip()
        if not normalized_provider or not normalized_account or not normalized_principal:
            return
        key = (
            normalized_provider,
            normalized_account,
            normalized_type,
            normalized_principal,
            source.lower(),
        )
        if key in seen_cloud_iam_principals:
            return
        seen_cloud_iam_principals.add(key)
        confidence_values.append(confidence)
        cloud_iam_principals.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "principal_type": normalized_type,
                "principal_id": normalized_principal,
                "name": name.strip() if isinstance(name, str) and name.strip() else None,
                "arn": arn.strip() if isinstance(arn, str) and arn.strip() else None,
                "trust_policy": trust_policy if isinstance(trust_policy, (dict, str)) else None,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_iam_policy(
        *,
        provider: str,
        account_id: str,
        policy_id: str,
        source: str,
        confidence: float,
        policy_name: str | None = None,
        arn: str | None = None,
        policy_document: dict[str, Any] | str | None = None,
        attached_to: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        normalized_policy = policy_id.strip()
        if not normalized_provider or not normalized_account or not normalized_policy:
            return
        key = (normalized_provider, normalized_account, normalized_policy, source.lower())
        if key in seen_cloud_iam_policies:
            return
        seen_cloud_iam_policies.add(key)
        confidence_values.append(confidence)
        cloud_iam_policies.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "policy_id": normalized_policy,
                "policy_name": (
                    policy_name.strip()
                    if isinstance(policy_name, str) and policy_name.strip()
                    else None
                ),
                "arn": arn.strip() if isinstance(arn, str) and arn.strip() else None,
                "policy_document": (
                    policy_document if isinstance(policy_document, (dict, str)) else None
                ),
                "attached_to": attached_to if isinstance(attached_to, list) else [],
                "metadata": metadata if isinstance(metadata, dict) else {},
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_iam_attachment(
        *,
        provider: str,
        account_id: str,
        principal_id: str,
        policy_id: str,
        source: str,
        confidence: float,
        relationship: str | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip()
        normalized_principal = principal_id.strip()
        normalized_policy = policy_id.strip()
        if (
            not normalized_provider
            or not normalized_account
            or not normalized_principal
            or not normalized_policy
        ):
            return
        key = (normalized_provider, normalized_account, normalized_principal, normalized_policy)
        if key in seen_cloud_iam_attachments:
            return
        seen_cloud_iam_attachments.add(key)
        confidence_values.append(confidence)
        cloud_iam_attachments.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account,
                "principal_id": normalized_principal,
                "policy_id": normalized_policy,
                "relationship": (
                    relationship.strip()
                    if isinstance(relationship, str) and relationship.strip()
                    else "attached"
                ),
                "source": source,
                "confidence": confidence,
            }
        )

    def add_cloud_collection_error(
        *,
        provider: str,
        source: str,
        confidence: float,
        account_id: str | None = None,
        region: str | None = None,
        service: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
        message: str | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        normalized_account = account_id.strip() if isinstance(account_id, str) else ""
        normalized_region = region.strip() if isinstance(region, str) else ""
        normalized_service = service.strip() if isinstance(service, str) else ""
        normalized_operation = operation.strip() if isinstance(operation, str) else ""
        normalized_message = message.strip() if isinstance(message, str) else ""
        if not normalized_provider or not normalized_message:
            return
        key = (
            normalized_provider,
            normalized_account,
            normalized_region,
            normalized_operation,
            normalized_message,
        )
        if key in seen_cloud_collection_errors:
            return
        seen_cloud_collection_errors.add(key)
        confidence_values.append(confidence)
        cloud_collection_errors.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account or None,
                "region": normalized_region or None,
                "service": normalized_service or None,
                "operation": normalized_operation or None,
                "error_code": (
                    error_code.strip()
                    if isinstance(error_code, str) and error_code.strip()
                    else None
                ),
                "message": normalized_message,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_kubernetes_cluster(
        *,
        cluster_id: str,
        source: str,
        confidence: float,
        provider: str = "kubernetes",
        account_id: str | None = None,
        region: str | None = None,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower() or "kubernetes"
        normalized_account = account_id.strip() if isinstance(account_id, str) else ""
        normalized_region = region.strip() if isinstance(region, str) else ""
        normalized_cluster = cluster_id.strip()
        if not normalized_cluster:
            return
        key = (
            normalized_provider,
            normalized_account,
            normalized_region,
            normalized_cluster,
            source.lower(),
        )
        if key in seen_kubernetes_clusters:
            return
        seen_kubernetes_clusters.add(key)
        confidence_values.append(confidence)
        kubernetes_clusters.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account or None,
                "region": normalized_region or None,
                "cluster_id": normalized_cluster,
                "name": name.strip() if isinstance(name, str) and name.strip() else None,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "source": source,
                "confidence": confidence,
            }
        )

    def add_kubernetes_workload(
        *,
        cluster_id: str,
        namespace: str,
        name: str,
        source: str,
        confidence: float,
        kind: str | None = None,
        provider: str = "kubernetes",
        account_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower() or "kubernetes"
        normalized_account = account_id.strip() if isinstance(account_id, str) else ""
        normalized_cluster = cluster_id.strip()
        normalized_namespace = namespace.strip() or "default"
        normalized_name = name.strip()
        normalized_kind = kind.strip() if isinstance(kind, str) and kind.strip() else "workload"
        if not normalized_cluster or not normalized_name:
            return
        key = (
            normalized_provider,
            normalized_account,
            normalized_cluster,
            normalized_namespace,
            normalized_kind.lower(),
            normalized_name,
        )
        if key in seen_kubernetes_workloads:
            return
        seen_kubernetes_workloads.add(key)
        confidence_values.append(confidence)
        kubernetes_workloads.append(
            {
                "provider": normalized_provider,
                "account_id": normalized_account or None,
                "cluster_id": normalized_cluster,
                "namespace": normalized_namespace,
                "kind": normalized_kind,
                "name": normalized_name,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "source": source,
                "confidence": confidence,
            }
        )

    def add_api_type(
        *, api_type: str, source: str, confidence: float, base_url: str | None = None
    ) -> None:
        normalized_type = api_type.strip()
        if not normalized_type:
            return
        key = (normalized_type.lower(), base_url, source.lower())
        if key in seen_api:
            return
        seen_api.add(key)
        confidence_values.append(confidence)
        api_types.append(
            {
                "type": normalized_type,
                "base_url": base_url,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_fingerprint(
        *,
        product: str,
        source: str,
        confidence: float,
        vendor: str | None = None,
        version: str | None = None,
    ) -> None:
        normalized_product = product.strip()
        if not normalized_product:
            return
        key = (vendor, normalized_product.lower(), source.lower())
        if key in seen_fingerprints:
            return
        seen_fingerprints.add(key)
        confidence_values.append(confidence)
        fingerprints.append(
            {
                "vendor": vendor,
                "product": normalized_product,
                "version": version,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_wireless_access_point(
        *,
        ap: dict[str, Any],
        source: str,
        confidence: float,
    ) -> None:
        bssid = str(ap.get("bssid") or "").strip().lower()
        if not bssid:
            return
        key = (bssid, source.lower())
        if key in seen_wireless_access_points:
            return
        seen_wireless_access_points.add(key)
        ap_confidence = _bounded_confidence(ap.get("confidence"), default=confidence)
        confidence_values.append(ap_confidence)
        wireless_access_points.append(
            {
                "ssid": str(ap.get("ssid") or "<hidden>").strip() or "<hidden>",
                "bssid": bssid,
                "site": str(ap.get("site") or "").strip() or None,
                "adapter": str(ap.get("adapter") or "").strip() or None,
                "channel": str(ap.get("channel") or "").strip() or None,
                "band": str(ap.get("band") or "").strip() or None,
                "encryption": str(ap.get("encryption") or "unknown").strip() or "unknown",
                "auth_mode": str(ap.get("auth_mode") or "unknown").strip() or "unknown",
                "cipher": str(ap.get("cipher") or "").strip() or None,
                "pmf": str(ap.get("pmf") or "unknown").strip() or "unknown",
                "wps": bool(ap.get("wps")),
                "signal_dbm": ap.get("signal_dbm") if isinstance(ap.get("signal_dbm"), int) else None,
                "observed_at": str(ap.get("observed_at") or "").strip() or None,
                "sources": _normalize_str_list(ap.get("sources")) or [source],
                "source": source,
                "confidence": ap_confidence,
            }
        )

    def add_wireless_network(
        *,
        network: dict[str, Any],
        source: str,
        confidence: float,
    ) -> None:
        ssid = str(network.get("ssid") or "").strip()
        if not ssid:
            return
        key = (ssid.lower(), source.lower())
        if key in seen_wireless_networks:
            return
        seen_wireless_networks.add(key)
        network_confidence = _bounded_confidence(network.get("confidence"), default=confidence)
        confidence_values.append(network_confidence)
        wireless_networks.append(
            {
                "ssid": ssid,
                "bssid_count": int(network.get("bssid_count") or 0),
                "bssids": _normalize_str_list(network.get("bssids")),
                "channels": _normalize_str_list(network.get("channels")),
                "encryption": str(network.get("encryption") or "unknown").strip() or "unknown",
                "auth_modes": _normalize_str_list(network.get("auth_modes")),
                "wps": bool(network.get("wps")),
                "pmf": _normalize_str_list(network.get("pmf")),
                "source": source,
                "confidence": network_confidence,
            }
        )

    def add_ipv6_address(
        *,
        address: str,
        source: str,
        confidence: float,
        interface: str | None = None,
        mac: str | None = None,
        address_type: str | None = None,
        router: bool | None = None,
        reachable: bool | None = None,
    ) -> None:
        normalized_address = address.strip()
        if not normalized_address or ":" not in normalized_address:
            return
        key = (normalized_address.lower(), source.lower())
        if key in seen_ipv6_addresses:
            return
        seen_ipv6_addresses.add(key)
        confidence_values.append(confidence)
        ipv6_addresses.append(
            {
                "address": normalized_address,
                "interface": interface,
                "mac": mac,
                "address_type": address_type,
                "router": router if isinstance(router, bool) else None,
                "reachable": reachable if isinstance(reachable, bool) else None,
                "source": source,
                "confidence": confidence,
            }
        )

    def add_ipv6_prefix(
        *,
        prefix: str,
        source: str,
        confidence: float,
        interface: str | None = None,
    ) -> None:
        normalized_prefix = prefix.strip()
        if not normalized_prefix or ":" not in normalized_prefix or "/" not in normalized_prefix:
            return
        key = (normalized_prefix.lower(), interface)
        if key in seen_ipv6_prefixes:
            return
        seen_ipv6_prefixes.add(key)
        confidence_values.append(confidence)
        ipv6_prefixes.append(
            {
                "prefix": normalized_prefix,
                "interface": interface,
                "source": source,
                "confidence": confidence,
            }
        )

    for observation in observations:
        source = str(observation.get("tool") or "unknown").strip() or "unknown"
        payload = observation.get("data")
        if not isinstance(payload, dict):
            continue

        confidence = _bounded_confidence(payload.get("confidence"), default=0.6)

        direct_host = str(payload.get("host") or payload.get("hostname") or "").strip()
        if direct_host:
            add_host(direct_host, source=source, confidence=confidence)

        for ap_entry in (
            payload.get("wireless_access_points", [])
            if isinstance(payload.get("wireless_access_points"), list)
            else []
        ):
            if isinstance(ap_entry, dict):
                add_wireless_access_point(
                    ap=ap_entry,
                    source=source,
                    confidence=confidence,
                )

        for network_entry in (
            payload.get("wireless_networks", [])
            if isinstance(payload.get("wireless_networks"), list)
            else []
        ):
            if isinstance(network_entry, dict):
                add_wireless_network(
                    network=network_entry,
                    source=source,
                    confidence=confidence,
                )

        host_entries = payload.get("hosts", [])
        if isinstance(host_entries, list):
            for host_entry in host_entries:
                if isinstance(host_entry, dict):
                    add_host(
                        str(host_entry.get("host") or host_entry.get("name") or ""),
                        source=source,
                        confidence=_bounded_confidence(
                            host_entry.get("confidence"), default=confidence
                        ),
                        notes=_normalize_str_list(host_entry.get("notes")),
                        device_type=(
                            str(host_entry.get("device_type") or "").strip()
                            if isinstance(host_entry.get("device_type"), str)
                            else None
                        ),
                    )
                elif isinstance(host_entry, str):
                    add_host(host_entry, source=source, confidence=confidence)
                    if ":" in host_entry:
                        add_ipv6_address(
                            address=host_entry,
                            source=source,
                            confidence=confidence,
                        )
        for ipv6_entry in (
            payload.get("ipv6_addresses", [])
            if isinstance(payload.get("ipv6_addresses"), list)
            else []
        ):
            if isinstance(ipv6_entry, str):
                add_ipv6_address(
                    address=ipv6_entry,
                    source=source,
                    confidence=confidence,
                )
                continue
            if not isinstance(ipv6_entry, dict):
                continue
            add_ipv6_address(
                address=str(ipv6_entry.get("address") or ipv6_entry.get("host") or ""),
                interface=str(ipv6_entry.get("interface") or "") or None,
                mac=str(ipv6_entry.get("mac") or "") or None,
                address_type=str(ipv6_entry.get("address_type") or "") or None,
                router=ipv6_entry.get("router"),
                reachable=ipv6_entry.get("reachable"),
                source=source,
                confidence=_bounded_confidence(ipv6_entry.get("confidence"), default=confidence),
            )
        for prefix_entry in (
            payload.get("ipv6_prefixes", [])
            if isinstance(payload.get("ipv6_prefixes"), list)
            else []
        ):
            if isinstance(prefix_entry, str):
                add_ipv6_prefix(prefix=prefix_entry, source=source, confidence=confidence)
                continue
            if not isinstance(prefix_entry, dict):
                continue
            add_ipv6_prefix(
                prefix=str(prefix_entry.get("prefix") or ""),
                interface=str(prefix_entry.get("interface") or "") or None,
                source=source,
                confidence=_bounded_confidence(prefix_entry.get("confidence"), default=confidence),
            )
        for url in _normalize_str_list(payload.get("urls")):
            add_host(url, source=source, confidence=confidence)
            add_endpoint(url=url, source=source, confidence=confidence)

        for port_entry in (
            payload.get("ports", []) if isinstance(payload.get("ports"), list) else []
        ):
            if isinstance(port_entry, int):
                add_service(
                    host=direct_host or "unknown-host",
                    port=port_entry,
                    service=str(payload.get("service") or "unknown-service"),
                    source=source,
                    confidence=confidence,
                )
                continue
            if not isinstance(port_entry, dict):
                continue
            service_host = str(port_entry.get("host") or direct_host or "unknown-host").strip()
            add_host(service_host, source=source, confidence=confidence)
            add_service(
                host=service_host,
                port=port_entry.get("port"),
                protocol=str(port_entry.get("protocol") or "tcp"),
                service=str(
                    port_entry.get("service") or port_entry.get("name") or "unknown-service"
                ),
                product=str(port_entry.get("product") or "") or None,
                version=str(port_entry.get("version") or "") or None,
                source=source,
                confidence=_bounded_confidence(port_entry.get("confidence"), default=confidence),
            )
            if port_entry.get("product"):
                add_fingerprint(
                    product=str(port_entry["product"]),
                    version=str(port_entry.get("version") or "") or None,
                    source=source,
                    confidence=_bounded_confidence(
                        port_entry.get("confidence"), default=confidence
                    ),
                )

        for service_entry in (
            payload.get("services", []) if isinstance(payload.get("services"), list) else []
        ):
            if not isinstance(service_entry, dict):
                continue
            service_host = str(service_entry.get("host") or direct_host or "unknown-host").strip()
            add_host(service_host, source=source, confidence=confidence)
            add_service(
                host=service_host,
                port=service_entry.get("port"),
                protocol=str(service_entry.get("protocol") or "tcp"),
                service=str(
                    service_entry.get("service") or service_entry.get("name") or "unknown-service"
                ),
                product=str(service_entry.get("product") or "") or None,
                version=str(service_entry.get("version") or "") or None,
                source=source,
                confidence=_bounded_confidence(service_entry.get("confidence"), default=confidence),
            )
            for script_entry in (
                service_entry.get("scripts", [])
                if isinstance(service_entry.get("scripts"), list)
                else []
            ):
                if not isinstance(script_entry, dict):
                    continue
                add_script_output(
                    host=str(script_entry.get("host") or service_host),
                    port=script_entry.get("port", service_entry.get("port")),
                    protocol=str(script_entry.get("protocol") or service_entry.get("protocol") or "tcp"),
                    script_id=str(script_entry.get("id") or ""),
                    output=str(script_entry.get("output") or ""),
                    source=source,
                    confidence=_bounded_confidence(
                        script_entry.get("confidence"), default=confidence
                    ),
                )

        for script_entry in (
            payload.get("script_outputs", [])
            if isinstance(payload.get("script_outputs"), list)
            else []
        ):
            if not isinstance(script_entry, dict):
                continue
            add_script_output(
                host=str(script_entry.get("host") or direct_host or "unknown-host"),
                port=script_entry.get("port"),
                protocol=str(script_entry.get("protocol") or "tcp"),
                script_id=str(script_entry.get("id") or ""),
                output=str(script_entry.get("output") or ""),
                source=source,
                confidence=_bounded_confidence(script_entry.get("confidence"), default=confidence),
            )

        for endpoint_entry in (
            payload.get("endpoints", []) if isinstance(payload.get("endpoints"), list) else []
        ):
            if isinstance(endpoint_entry, str):
                add_endpoint(url=endpoint_entry, source=source, confidence=confidence)
                add_host(endpoint_entry, source=source, confidence=confidence)
                continue
            if not isinstance(endpoint_entry, dict):
                continue
            endpoint_url = str(
                endpoint_entry.get("url") or endpoint_entry.get("endpoint") or ""
            ).strip()
            if not endpoint_url:
                continue
            add_endpoint(
                url=endpoint_url,
                source=source,
                confidence=_bounded_confidence(
                    endpoint_entry.get("confidence"), default=confidence
                ),
                methods=_normalize_str_list(endpoint_entry.get("methods")),
                status_code=endpoint_entry.get("status_code"),
                title=str(endpoint_entry.get("title") or "") or None,
            )
            add_host(endpoint_url, source=source, confidence=confidence)

        for technology_entry in (
            payload.get("technologies", []) if isinstance(payload.get("technologies"), list) else []
        ):
            if isinstance(technology_entry, str):
                add_technology(name=technology_entry, source=source, confidence=confidence)
                continue
            if not isinstance(technology_entry, dict):
                continue
            add_technology(
                name=str(technology_entry.get("name") or technology_entry.get("technology") or ""),
                vendor=str(technology_entry.get("vendor") or "") or None,
                version=str(technology_entry.get("version") or "") or None,
                source=source,
                confidence=_bounded_confidence(
                    technology_entry.get("confidence"), default=confidence
                ),
            )

        for framework in _normalize_str_list(payload.get("frameworks")):
            add_technology(name=framework, source=source, confidence=confidence)

        for auth_entry in (
            payload.get("auth_mechanisms", [])
            if isinstance(payload.get("auth_mechanisms"), list)
            else []
        ):
            if isinstance(auth_entry, str):
                add_auth_mechanism(auth_type=auth_entry, source=source, confidence=confidence)
                continue
            if not isinstance(auth_entry, dict):
                continue
            add_auth_mechanism(
                auth_type=str(auth_entry.get("type") or auth_entry.get("mechanism") or ""),
                location=str(auth_entry.get("location") or "") or None,
                source=source,
                confidence=_bounded_confidence(auth_entry.get("confidence"), default=confidence),
            )

        subject_entries = payload.get("identity_subjects", payload.get("users", []))
        for subject_entry in subject_entries if isinstance(subject_entries, list) else []:
            if isinstance(subject_entry, str):
                add_identity_subject(
                    account_name=subject_entry, source=source, confidence=confidence
                )
                continue
            if not isinstance(subject_entry, dict):
                continue
            add_identity_subject(
                account_name=str(
                    subject_entry.get("account_name")
                    or subject_entry.get("principal")
                    or subject_entry.get("user_principal_name")
                    or ""
                ),
                principal=str(
                    subject_entry.get("principal") or subject_entry.get("user_principal_name") or ""
                )
                or None,
                dn=str(subject_entry.get("dn") or "") or None,
                enabled=(
                    subject_entry.get("enabled")
                    if isinstance(subject_entry.get("enabled"), bool)
                    else None
                ),
                source=source,
                confidence=_bounded_confidence(subject_entry.get("confidence"), default=confidence),
            )

        group_entries = payload.get("identity_groups", payload.get("groups", []))
        for group_entry in group_entries if isinstance(group_entries, list) else []:
            if isinstance(group_entry, str):
                add_identity_group(name=group_entry, source=source, confidence=confidence)
                continue
            if not isinstance(group_entry, dict):
                continue
            add_identity_group(
                name=str(group_entry.get("name") or group_entry.get("group") or ""),
                dn=str(group_entry.get("dn") or "") or None,
                member_count=group_entry.get("member_count"),
                privileged=bool(group_entry.get("privileged")),
                source=source,
                confidence=_bounded_confidence(group_entry.get("confidence"), default=confidence),
            )

        membership_entries = payload.get("privileged_memberships", [])
        for membership_entry in membership_entries if isinstance(membership_entries, list) else []:
            if not isinstance(membership_entry, dict):
                continue
            add_privileged_membership(
                group=str(membership_entry.get("group") or ""),
                member=str(
                    membership_entry.get("member") or membership_entry.get("account_name") or ""
                ),
                group_dn=str(membership_entry.get("group_dn") or "") or None,
                member_dn=str(membership_entry.get("member_dn") or "") or None,
                source=source,
                confidence=_bounded_confidence(
                    membership_entry.get("confidence"), default=confidence
                ),
            )

        confirmed_edge_entries = payload.get("bloodhound_confirmed_edges", [])
        for edge_entry in confirmed_edge_entries if isinstance(confirmed_edge_entries, list) else []:
            if not isinstance(edge_entry, dict):
                continue
            add_bloodhound_confirmed_edge(
                edge_payload=edge_entry,
                source=source,
                confidence=confidence,
            )

        attack_path_entries = payload.get("bloodhound_attack_paths", [])
        for attack_path_entry in attack_path_entries if isinstance(attack_path_entries, list) else []:
            if not isinstance(attack_path_entry, dict):
                continue
            add_bloodhound_attack_path(
                path_payload=attack_path_entry,
                source=source,
                confidence=confidence,
            )

        for account_entry in (
            payload.get("cloud_accounts", [])
            if isinstance(payload.get("cloud_accounts"), list)
            else []
        ):
            if not isinstance(account_entry, dict):
                continue
            add_cloud_account(
                provider=str(account_entry.get("provider") or "aws"),
                account_id=str(account_entry.get("account_id") or ""),
                arn=str(account_entry.get("arn") or "") or None,
                source=source,
                confidence=_bounded_confidence(account_entry.get("confidence"), default=confidence),
            )

        for region_entry in (
            payload.get("cloud_regions", [])
            if isinstance(payload.get("cloud_regions"), list)
            else []
        ):
            if not isinstance(region_entry, dict):
                continue
            add_cloud_region(
                provider=str(region_entry.get("provider") or "aws"),
                account_id=str(region_entry.get("account_id") or ""),
                region=str(region_entry.get("region") or ""),
                source=source,
                confidence=_bounded_confidence(region_entry.get("confidence"), default=confidence),
            )

        for resource_entry in (
            payload.get("cloud_resources", [])
            if isinstance(payload.get("cloud_resources"), list)
            else []
        ):
            if not isinstance(resource_entry, dict):
                continue
            add_cloud_resource(
                provider=str(resource_entry.get("provider") or "aws"),
                account_id=str(resource_entry.get("account_id") or ""),
                region=str(resource_entry.get("region") or "") or None,
                resource_type=str(resource_entry.get("resource_type") or ""),
                resource_id=str(resource_entry.get("resource_id") or ""),
                name=str(resource_entry.get("name") or "") or None,
                state=str(resource_entry.get("state") or "") or None,
                metadata=(
                    resource_entry.get("metadata")
                    if isinstance(resource_entry.get("metadata"), dict)
                    else {}
                ),
                source=source,
                confidence=_bounded_confidence(resource_entry.get("confidence"), default=confidence),
            )

        for group_entry in (
            payload.get("cloud_security_groups", [])
            if isinstance(payload.get("cloud_security_groups"), list)
            else []
        ):
            if not isinstance(group_entry, dict):
                continue
            add_cloud_security_group(
                provider=str(group_entry.get("provider") or "aws"),
                account_id=str(group_entry.get("account_id") or ""),
                region=str(group_entry.get("region") or "") or None,
                group_id=str(group_entry.get("group_id") or ""),
                group_name=str(group_entry.get("group_name") or "") or None,
                vpc_id=str(group_entry.get("vpc_id") or "") or None,
                rule_count=group_entry.get("rule_count"),
                description=str(group_entry.get("description") or "") or None,
                ingress_rules=(
                    group_entry.get("ingress_rules")
                    if isinstance(group_entry.get("ingress_rules"), list)
                    else []
                ),
                egress_rules=(
                    group_entry.get("egress_rules")
                    if isinstance(group_entry.get("egress_rules"), list)
                    else []
                ),
                tags=group_entry.get("tags") if isinstance(group_entry.get("tags"), dict) else {},
                source=source,
                confidence=_bounded_confidence(group_entry.get("confidence"), default=confidence),
            )

        principal_entries = payload.get("cloud_iam_principals", payload.get("iam_principals", []))
        for principal_entry in principal_entries if isinstance(principal_entries, list) else []:
            if not isinstance(principal_entry, dict):
                continue
            add_cloud_iam_principal(
                provider=str(principal_entry.get("provider") or "aws"),
                account_id=str(principal_entry.get("account_id") or ""),
                principal_type=str(
                    principal_entry.get("principal_type")
                    or principal_entry.get("type")
                    or "unknown"
                ),
                principal_id=str(
                    principal_entry.get("principal_id")
                    or principal_entry.get("arn")
                    or principal_entry.get("name")
                    or ""
                ),
                name=str(principal_entry.get("name") or "") or None,
                arn=str(principal_entry.get("arn") or "") or None,
                trust_policy=(
                    principal_entry.get("trust_policy")
                    if isinstance(principal_entry.get("trust_policy"), (dict, str))
                    else principal_entry.get("assume_role_policy_document")
                    if isinstance(principal_entry.get("assume_role_policy_document"), (dict, str))
                    else None
                ),
                metadata=(
                    principal_entry.get("metadata")
                    if isinstance(principal_entry.get("metadata"), dict)
                    else {}
                ),
                source=source,
                confidence=_bounded_confidence(
                    principal_entry.get("confidence"), default=confidence
                ),
            )

        policy_entries = payload.get("cloud_iam_policies", payload.get("iam_policies", []))
        for policy_entry in policy_entries if isinstance(policy_entries, list) else []:
            if not isinstance(policy_entry, dict):
                continue
            add_cloud_iam_policy(
                provider=str(policy_entry.get("provider") or "aws"),
                account_id=str(policy_entry.get("account_id") or ""),
                policy_id=str(
                    policy_entry.get("policy_id")
                    or policy_entry.get("arn")
                    or policy_entry.get("policy_name")
                    or policy_entry.get("name")
                    or ""
                ),
                policy_name=str(
                    policy_entry.get("policy_name") or policy_entry.get("name") or ""
                )
                or None,
                arn=str(policy_entry.get("arn") or "") or None,
                policy_document=(
                    policy_entry.get("policy_document")
                    if isinstance(policy_entry.get("policy_document"), (dict, str))
                    else policy_entry.get("document")
                    if isinstance(policy_entry.get("document"), (dict, str))
                    else None
                ),
                attached_to=(
                    policy_entry.get("attached_to")
                    if isinstance(policy_entry.get("attached_to"), list)
                    else []
                ),
                metadata=(
                    policy_entry.get("metadata")
                    if isinstance(policy_entry.get("metadata"), dict)
                    else {}
                ),
                source=source,
                confidence=_bounded_confidence(policy_entry.get("confidence"), default=confidence),
            )

        attachment_entries = payload.get(
            "cloud_iam_attachments", payload.get("iam_attachments", [])
        )
        for attachment_entry in attachment_entries if isinstance(attachment_entries, list) else []:
            if not isinstance(attachment_entry, dict):
                continue
            add_cloud_iam_attachment(
                provider=str(attachment_entry.get("provider") or "aws"),
                account_id=str(attachment_entry.get("account_id") or ""),
                principal_id=str(attachment_entry.get("principal_id") or ""),
                policy_id=str(attachment_entry.get("policy_id") or ""),
                relationship=str(attachment_entry.get("relationship") or "") or None,
                source=source,
                confidence=_bounded_confidence(
                    attachment_entry.get("confidence"), default=confidence
                ),
            )

        error_entries = payload.get("cloud_collection_errors", [])
        for error_entry in error_entries if isinstance(error_entries, list) else []:
            if not isinstance(error_entry, dict):
                continue
            add_cloud_collection_error(
                provider=str(error_entry.get("provider") or "aws"),
                account_id=str(error_entry.get("account_id") or "") or None,
                region=str(error_entry.get("region") or "") or None,
                service=str(error_entry.get("service") or "") or None,
                operation=str(error_entry.get("operation") or "") or None,
                error_code=str(error_entry.get("error_code") or "") or None,
                message=str(error_entry.get("message") or error_entry.get("error") or "") or None,
                source=source,
                confidence=_bounded_confidence(error_entry.get("confidence"), default=confidence),
            )

        cluster_entries = payload.get("kubernetes_clusters", [])
        for cluster_entry in cluster_entries if isinstance(cluster_entries, list) else []:
            if not isinstance(cluster_entry, dict):
                continue
            cluster_metadata = (
                cluster_entry.get("metadata") if isinstance(cluster_entry.get("metadata"), dict) else {}
            )
            for key, value in cluster_entry.items():
                if key not in {
                    "provider",
                    "account_id",
                    "region",
                    "cluster_id",
                    "name",
                    "metadata",
                    "source",
                    "confidence",
                }:
                    cluster_metadata.setdefault(key, value)
            add_kubernetes_cluster(
                provider=str(cluster_entry.get("provider") or "kubernetes"),
                account_id=str(cluster_entry.get("account_id") or "") or None,
                region=str(cluster_entry.get("region") or "") or None,
                cluster_id=str(cluster_entry.get("cluster_id") or cluster_entry.get("name") or ""),
                name=str(cluster_entry.get("name") or "") or None,
                metadata=cluster_metadata,
                source=source,
                confidence=_bounded_confidence(cluster_entry.get("confidence"), default=confidence),
            )

        workload_entries = payload.get("kubernetes_workloads", [])
        for workload_entry in workload_entries if isinstance(workload_entries, list) else []:
            if not isinstance(workload_entry, dict):
                continue
            workload_metadata = (
                workload_entry.get("metadata")
                if isinstance(workload_entry.get("metadata"), dict)
                else {}
            )
            for key, value in workload_entry.items():
                if key not in {
                    "provider",
                    "account_id",
                    "cluster_id",
                    "namespace",
                    "kind",
                    "name",
                    "metadata",
                    "source",
                    "confidence",
                }:
                    workload_metadata.setdefault(key, value)
            add_kubernetes_workload(
                provider=str(workload_entry.get("provider") or "kubernetes"),
                account_id=str(workload_entry.get("account_id") or "") or None,
                cluster_id=str(workload_entry.get("cluster_id") or ""),
                namespace=str(workload_entry.get("namespace") or "default"),
                kind=str(workload_entry.get("kind") or "") or None,
                name=str(workload_entry.get("name") or ""),
                metadata=workload_metadata,
                source=source,
                confidence=_bounded_confidence(workload_entry.get("confidence"), default=confidence),
            )

        for api_entry in (
            payload.get("api_types", []) if isinstance(payload.get("api_types"), list) else []
        ):
            if isinstance(api_entry, str):
                add_api_type(api_type=api_entry, source=source, confidence=confidence)
                continue
            if not isinstance(api_entry, dict):
                continue
            add_api_type(
                api_type=str(api_entry.get("type") or api_entry.get("api_type") or ""),
                base_url=str(api_entry.get("base_url") or "") or None,
                source=source,
                confidence=_bounded_confidence(api_entry.get("confidence"), default=confidence),
            )

        if payload.get("graphql") is True:
            add_api_type(api_type="graphql", source=source, confidence=confidence)
        if payload.get("openapi") is True:
            add_api_type(api_type="rest", source=source, confidence=confidence)

        tls_entry = payload.get("tls") or payload.get("tls_summary")
        if isinstance(tls_entry, dict):
            tls_posture["protocols"] = sorted(
                {
                    *tls_posture["protocols"],
                    *_normalize_str_list(tls_entry.get("protocols")),
                }
            )
            tls_posture["issues"] = sorted(
                {
                    *tls_posture["issues"],
                    *_normalize_str_list(tls_entry.get("issues")),
                }
            )
            certificate_subject = str(tls_entry.get("certificate_subject") or "").strip()
            if certificate_subject:
                tls_posture["certificate_subject"] = certificate_subject
            tls_posture["source"] = source
            tls_posture["confidence"] = max(
                _bounded_confidence(tls_posture["confidence"], default=0.0),
                _bounded_confidence(tls_entry.get("confidence"), default=confidence),
            )

        for fingerprint_entry in (
            payload.get("fingerprints", []) if isinstance(payload.get("fingerprints"), list) else []
        ):
            if isinstance(fingerprint_entry, str):
                add_fingerprint(product=fingerprint_entry, source=source, confidence=confidence)
                continue
            if not isinstance(fingerprint_entry, dict):
                continue
            add_fingerprint(
                vendor=str(fingerprint_entry.get("vendor") or "") or None,
                product=str(
                    fingerprint_entry.get("product") or fingerprint_entry.get("name") or ""
                ),
                version=str(fingerprint_entry.get("version") or "") or None,
                source=source,
                confidence=_bounded_confidence(
                    fingerprint_entry.get("confidence"), default=confidence
                ),
            )

    inventory_confidence = (
        round(
            sum(confidence_values) / len(confidence_values),
            3,
        )
        if confidence_values
        else 0.0
    )

    return {
        "hosts": hosts,
        "services": services,
        "http_endpoints": endpoints,
        "technologies": technologies,
        "script_outputs": script_outputs,
        "auth_mechanisms": auth_mechanisms,
        "identity_subjects": identity_subjects,
        "identity_groups": identity_groups,
        "privileged_memberships": privileged_memberships,
        "bloodhound_confirmed_edges": bloodhound_confirmed_edges,
        "bloodhound_attack_paths": bloodhound_attack_paths,
        "cloud_accounts": cloud_accounts,
        "cloud_regions": cloud_regions,
        "cloud_resources": cloud_resources,
        "cloud_security_groups": cloud_security_groups,
        "cloud_iam_principals": cloud_iam_principals,
        "cloud_iam_policies": cloud_iam_policies,
        "cloud_iam_attachments": cloud_iam_attachments,
        "cloud_collection_errors": cloud_collection_errors,
        "kubernetes_clusters": kubernetes_clusters,
        "kubernetes_workloads": kubernetes_workloads,
        "ipv6_addresses": ipv6_addresses,
        "ipv6_prefixes": ipv6_prefixes,
        "api_types": api_types,
        "wireless_access_points": wireless_access_points,
        "wireless_networks": wireless_networks,
        "tls_posture": tls_posture,
        "vendor_product_fingerprints": fingerprints,
        "environment_notes": list(dict.fromkeys(_normalize_str_list(list(environment_notes)))),
        "assumptions": list(dict.fromkeys(_normalize_str_list(list(assumptions)))),
        "confidence_score": inventory_confidence,
    }


def inventory_summary_from_normalized(normalized_inventory: dict[str, Any]) -> dict[str, Any]:
    fingerprints = normalized_inventory.get("vendor_product_fingerprints", [])
    tls_posture = normalized_inventory.get("tls_posture", {})
    device_types = sorted(
        {
            str(host.get("device_type")).strip()
            for host in normalized_inventory.get("hosts", [])
            if isinstance(host, dict) and str(host.get("device_type") or "").strip()
        }
    )
    return {
        "host_count": len(normalized_inventory.get("hosts", [])),
        "service_count": len(normalized_inventory.get("services", [])),
        "endpoint_count": len(normalized_inventory.get("http_endpoints", [])),
        "technology_count": len(normalized_inventory.get("technologies", [])),
        "auth_mechanism_count": len(normalized_inventory.get("auth_mechanisms", [])),
        "identity_subject_count": len(normalized_inventory.get("identity_subjects", [])),
        "identity_group_count": len(normalized_inventory.get("identity_groups", [])),
        "privileged_membership_count": len(normalized_inventory.get("privileged_memberships", [])),
        "bloodhound_confirmed_edge_count": len(
            normalized_inventory.get("bloodhound_confirmed_edges", [])
        ),
        "bloodhound_attack_path_count": len(normalized_inventory.get("bloodhound_attack_paths", [])),
        "cloud_account_count": len(normalized_inventory.get("cloud_accounts", [])),
        "cloud_region_count": len(normalized_inventory.get("cloud_regions", [])),
        "cloud_resource_count": len(normalized_inventory.get("cloud_resources", [])),
        "cloud_security_group_count": len(normalized_inventory.get("cloud_security_groups", [])),
        "cloud_iam_principal_count": len(normalized_inventory.get("cloud_iam_principals", [])),
        "cloud_iam_policy_count": len(normalized_inventory.get("cloud_iam_policies", [])),
        "cloud_collection_error_count": len(normalized_inventory.get("cloud_collection_errors", [])),
        "kubernetes_cluster_count": len(normalized_inventory.get("kubernetes_clusters", [])),
        "kubernetes_workload_count": len(normalized_inventory.get("kubernetes_workloads", [])),
        "ipv6_address_count": len(normalized_inventory.get("ipv6_addresses", [])),
        "ipv6_prefix_count": len(normalized_inventory.get("ipv6_prefixes", [])),
        "api_type_count": len(normalized_inventory.get("api_types", [])),
        "wireless_access_point_count": len(
            normalized_inventory.get("wireless_access_points", [])
        ),
        "wireless_network_count": len(normalized_inventory.get("wireless_networks", [])),
        "device_type_count": len(device_types),
        "device_types": device_types,
        "tls_issue_count": len(
            tls_posture.get("issues", []) if isinstance(tls_posture, dict) else []
        ),
        "vendor_product_count": len(fingerprints),
        "detected_products": sorted(
            {
                str(fingerprint.get("product")).strip()
                for fingerprint in fingerprints
                if isinstance(fingerprint, dict) and str(fingerprint.get("product") or "").strip()
            }
        ),
        "detected_vendors": sorted(
            {
                str(fingerprint.get("vendor")).strip()
                for fingerprint in fingerprints
                if isinstance(fingerprint, dict) and str(fingerprint.get("vendor") or "").strip()
            }
        ),
        "confidence_score": float(normalized_inventory.get("confidence_score") or 0.0),
    }


def inventory_summary_for_snapshot(snapshot: InventorySnapshot) -> dict[str, Any]:
    return inventory_summary_from_normalized(snapshot.normalized_inventory_json)


def observation_from_normalized_inventory(
    normalized_inventory: dict[str, Any],
    *,
    source: str = "inventory-aggregate",
) -> dict[str, Any]:
    tls_posture = normalized_inventory.get("tls_posture", {})
    return {
        "tool": source,
        "kind": "inventory",
        "data": {
            "hosts": [
                str(entry.get("host") or "").strip()
                for entry in normalized_inventory.get("hosts", [])
                if isinstance(entry, dict) and str(entry.get("host") or "").strip()
            ],
            "services": [
                entry
                for entry in normalized_inventory.get("services", [])
                if isinstance(entry, dict)
            ],
            "endpoints": [
                entry
                for entry in normalized_inventory.get("http_endpoints", [])
                if isinstance(entry, dict)
            ],
            "technologies": [
                entry
                for entry in normalized_inventory.get("technologies", [])
                if isinstance(entry, dict)
            ],
            "ipv6_addresses": [
                entry
                for entry in normalized_inventory.get("ipv6_addresses", [])
                if isinstance(entry, dict)
            ],
            "ipv6_prefixes": [
                entry
                for entry in normalized_inventory.get("ipv6_prefixes", [])
                if isinstance(entry, dict)
            ],
            "auth_mechanisms": [
                entry
                for entry in normalized_inventory.get("auth_mechanisms", [])
                if isinstance(entry, dict)
            ],
            "identity_subjects": [
                entry
                for entry in normalized_inventory.get("identity_subjects", [])
                if isinstance(entry, dict)
            ],
            "identity_groups": [
                entry
                for entry in normalized_inventory.get("identity_groups", [])
                if isinstance(entry, dict)
            ],
            "privileged_memberships": [
                entry
                for entry in normalized_inventory.get("privileged_memberships", [])
                if isinstance(entry, dict)
            ],
            "bloodhound_confirmed_edges": [
                entry
                for entry in normalized_inventory.get("bloodhound_confirmed_edges", [])
                if isinstance(entry, dict)
            ],
            "bloodhound_attack_paths": [
                entry
                for entry in normalized_inventory.get("bloodhound_attack_paths", [])
                if isinstance(entry, dict)
            ],
            "cloud_accounts": [
                entry
                for entry in normalized_inventory.get("cloud_accounts", [])
                if isinstance(entry, dict)
            ],
            "cloud_regions": [
                entry
                for entry in normalized_inventory.get("cloud_regions", [])
                if isinstance(entry, dict)
            ],
            "cloud_resources": [
                entry
                for entry in normalized_inventory.get("cloud_resources", [])
                if isinstance(entry, dict)
            ],
            "cloud_security_groups": [
                entry
                for entry in normalized_inventory.get("cloud_security_groups", [])
                if isinstance(entry, dict)
            ],
            "cloud_iam_principals": [
                entry
                for entry in normalized_inventory.get("cloud_iam_principals", [])
                if isinstance(entry, dict)
            ],
            "cloud_iam_policies": [
                entry
                for entry in normalized_inventory.get("cloud_iam_policies", [])
                if isinstance(entry, dict)
            ],
            "cloud_iam_attachments": [
                entry
                for entry in normalized_inventory.get("cloud_iam_attachments", [])
                if isinstance(entry, dict)
            ],
            "cloud_collection_errors": [
                entry
                for entry in normalized_inventory.get("cloud_collection_errors", [])
                if isinstance(entry, dict)
            ],
            "kubernetes_clusters": [
                entry
                for entry in normalized_inventory.get("kubernetes_clusters", [])
                if isinstance(entry, dict)
            ],
            "kubernetes_workloads": [
                entry
                for entry in normalized_inventory.get("kubernetes_workloads", [])
                if isinstance(entry, dict)
            ],
            "api_types": [
                entry
                for entry in normalized_inventory.get("api_types", [])
                if isinstance(entry, dict)
            ],
            "wireless_access_points": [
                entry
                for entry in normalized_inventory.get("wireless_access_points", [])
                if isinstance(entry, dict)
            ],
            "wireless_networks": [
                entry
                for entry in normalized_inventory.get("wireless_networks", [])
                if isinstance(entry, dict)
            ],
            "tls_summary": tls_posture if isinstance(tls_posture, dict) else {},
            "fingerprints": [
                entry
                for entry in normalized_inventory.get("vendor_product_fingerprints", [])
                if isinstance(entry, dict)
            ],
            "confidence": float(normalized_inventory.get("confidence_score") or 0.0),
        },
    }


def aggregate_inventory_snapshots(snapshots: Iterable[InventorySnapshot]) -> dict[str, Any] | None:
    snapshot_list = [snapshot for snapshot in snapshots if snapshot is not None]
    if not snapshot_list:
        return None

    observations = [
        observation_from_normalized_inventory(
            snapshot.normalized_inventory_json or {},
            source=(
                snapshot.source_tools_json[0]
                if snapshot.source_tools_json
                else "inventory-aggregate"
            ),
        )
        for snapshot in snapshot_list
    ]
    environment_notes = [
        note
        for snapshot in snapshot_list
        for note in (snapshot.environment_notes_json or [])
        if isinstance(note, str) and note.strip()
    ]
    assumptions = [
        note
        for snapshot in snapshot_list
        for note in (snapshot.assumptions_json or [])
        if isinstance(note, str) and note.strip()
    ]
    normalized = normalize_inventory_observations(
        observations=observations,
        environment_notes=environment_notes,
        assumptions=assumptions,
    )
    return {
        "normalized_inventory_json": normalized,
        "summary_json": inventory_summary_from_normalized(normalized),
        "source_tools_json": list(
            dict.fromkeys(
                tool
                for snapshot in snapshot_list
                for tool in (snapshot.source_tools_json or [])
                if isinstance(tool, str) and tool.strip()
            )
        ),
        "environment_notes_json": environment_notes,
        "assumptions_json": assumptions,
        "confidence_score": float(normalized.get("confidence_score") or 0.0),
    }


def create_inventory_snapshot_record(
    *,
    engagement_id,
    requested_by: str,
    source_tools: Iterable[str],
    observations: Iterable[dict[str, Any]],
    environment_notes: Iterable[str] = (),
    assumptions: Iterable[str] = (),
    raw_inputs_json: dict[str, Any] | None = None,
) -> InventorySnapshot:
    observation_list = list(observations)
    normalized = normalize_inventory_observations(
        observations=observation_list,
        environment_notes=environment_notes,
        assumptions=assumptions,
    )
    summary = inventory_summary_from_normalized(normalized)
    timestamp = datetime.now(tz=UTC)
    return InventorySnapshot(
        engagement_id=engagement_id,
        requested_by=requested_by,
        status="completed",
        source_tools_json=list(
            dict.fromkeys([tool for tool in source_tools if isinstance(tool, str) and tool.strip()])
        ),
        raw_inputs_json=raw_inputs_json or {"observations": observation_list},
        normalized_inventory_json=normalized,
        summary_json=summary,
        environment_notes_json=list(environment_notes),
        assumptions_json=list(assumptions),
        confidence_score=float(normalized.get("confidence_score") or 0.0),
        created_at=timestamp,
        updated_at=timestamp,
    )
