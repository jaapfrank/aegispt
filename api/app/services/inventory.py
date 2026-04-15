from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

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


def _host_from_value(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc.strip()
    return value.strip()


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
    auth_mechanisms: list[dict[str, Any]] = []
    api_types: list[dict[str, Any]] = []
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
    seen_auth: set[tuple[str, str | None, str]] = set()
    seen_api: set[tuple[str, str | None, str]] = set()
    seen_fingerprints: set[tuple[str | None, str, str]] = set()
    confidence_values: list[float] = []

    def add_host(host: str, *, source: str, confidence: float, notes: list[str] | None = None) -> None:
        normalized_host = _host_from_value(host)
        if not normalized_host:
            return
        key = (normalized_host.lower(), source.lower())
        if key in seen_hosts:
            return
        seen_hosts.add(key)
        confidence_values.append(confidence)
        hosts.append(
            {
                "host": normalized_host,
                "source": source,
                "confidence": confidence,
                "notes": notes or [],
            }
        )

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

    def add_auth_mechanism(*, auth_type: str, source: str, confidence: float, location: str | None = None) -> None:
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

    def add_api_type(*, api_type: str, source: str, confidence: float, base_url: str | None = None) -> None:
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

    for observation in observations:
        source = str(observation.get("tool") or "unknown").strip() or "unknown"
        payload = observation.get("data")
        if not isinstance(payload, dict):
            continue

        confidence = _bounded_confidence(payload.get("confidence"), default=0.6)

        direct_host = str(payload.get("host") or payload.get("hostname") or "").strip()
        if direct_host:
            add_host(direct_host, source=source, confidence=confidence)

        for host in _normalize_str_list(payload.get("hosts")):
            add_host(host, source=source, confidence=confidence)
        for url in _normalize_str_list(payload.get("urls")):
            add_host(url, source=source, confidence=confidence)
            add_endpoint(url=url, source=source, confidence=confidence)

        for port_entry in payload.get("ports", []) if isinstance(payload.get("ports"), list) else []:
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
                service=str(port_entry.get("service") or port_entry.get("name") or "unknown-service"),
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
                    confidence=_bounded_confidence(port_entry.get("confidence"), default=confidence),
                )

        for service_entry in payload.get("services", []) if isinstance(payload.get("services"), list) else []:
            if not isinstance(service_entry, dict):
                continue
            service_host = str(service_entry.get("host") or direct_host or "unknown-host").strip()
            add_host(service_host, source=source, confidence=confidence)
            add_service(
                host=service_host,
                port=service_entry.get("port"),
                protocol=str(service_entry.get("protocol") or "tcp"),
                service=str(service_entry.get("service") or service_entry.get("name") or "unknown-service"),
                product=str(service_entry.get("product") or "") or None,
                version=str(service_entry.get("version") or "") or None,
                source=source,
                confidence=_bounded_confidence(service_entry.get("confidence"), default=confidence),
            )

        for endpoint_entry in payload.get("endpoints", []) if isinstance(payload.get("endpoints"), list) else []:
            if isinstance(endpoint_entry, str):
                add_endpoint(url=endpoint_entry, source=source, confidence=confidence)
                add_host(endpoint_entry, source=source, confidence=confidence)
                continue
            if not isinstance(endpoint_entry, dict):
                continue
            endpoint_url = str(endpoint_entry.get("url") or endpoint_entry.get("endpoint") or "").strip()
            if not endpoint_url:
                continue
            add_endpoint(
                url=endpoint_url,
                source=source,
                confidence=_bounded_confidence(endpoint_entry.get("confidence"), default=confidence),
                methods=_normalize_str_list(endpoint_entry.get("methods")),
                status_code=endpoint_entry.get("status_code"),
                title=str(endpoint_entry.get("title") or "") or None,
            )
            add_host(endpoint_url, source=source, confidence=confidence)

        for technology_entry in payload.get("technologies", []) if isinstance(payload.get("technologies"), list) else []:
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
                confidence=_bounded_confidence(technology_entry.get("confidence"), default=confidence),
            )

        for framework in _normalize_str_list(payload.get("frameworks")):
            add_technology(name=framework, source=source, confidence=confidence)

        for auth_entry in payload.get("auth_mechanisms", []) if isinstance(payload.get("auth_mechanisms"), list) else []:
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

        for api_entry in payload.get("api_types", []) if isinstance(payload.get("api_types"), list) else []:
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

        for fingerprint_entry in payload.get("fingerprints", []) if isinstance(payload.get("fingerprints"), list) else []:
            if isinstance(fingerprint_entry, str):
                add_fingerprint(product=fingerprint_entry, source=source, confidence=confidence)
                continue
            if not isinstance(fingerprint_entry, dict):
                continue
            add_fingerprint(
                vendor=str(fingerprint_entry.get("vendor") or "") or None,
                product=str(fingerprint_entry.get("product") or fingerprint_entry.get("name") or ""),
                version=str(fingerprint_entry.get("version") or "") or None,
                source=source,
                confidence=_bounded_confidence(fingerprint_entry.get("confidence"), default=confidence),
            )

    inventory_confidence = round(
        sum(confidence_values) / len(confidence_values),
        3,
    ) if confidence_values else 0.0

    return {
        "hosts": hosts,
        "services": services,
        "http_endpoints": endpoints,
        "technologies": technologies,
        "auth_mechanisms": auth_mechanisms,
        "api_types": api_types,
        "tls_posture": tls_posture,
        "vendor_product_fingerprints": fingerprints,
        "environment_notes": list(dict.fromkeys(_normalize_str_list(list(environment_notes)))),
        "assumptions": list(dict.fromkeys(_normalize_str_list(list(assumptions)))),
        "confidence_score": inventory_confidence,
    }


def inventory_summary_from_normalized(normalized_inventory: dict[str, Any]) -> dict[str, Any]:
    fingerprints = normalized_inventory.get("vendor_product_fingerprints", [])
    tls_posture = normalized_inventory.get("tls_posture", {})
    return {
        "host_count": len(normalized_inventory.get("hosts", [])),
        "service_count": len(normalized_inventory.get("services", [])),
        "endpoint_count": len(normalized_inventory.get("http_endpoints", [])),
        "technology_count": len(normalized_inventory.get("technologies", [])),
        "auth_mechanism_count": len(normalized_inventory.get("auth_mechanisms", [])),
        "api_type_count": len(normalized_inventory.get("api_types", [])),
        "tls_issue_count": len(tls_posture.get("issues", []) if isinstance(tls_posture, dict) else []),
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

