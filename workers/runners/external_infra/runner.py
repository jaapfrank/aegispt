from __future__ import annotations

import json
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

from api.app.services.inventory import httpx_observation_from_jsonl, nmap_observation_from_xml
from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.easm.runner import (
    EASM_RESULTS_ARTIFACT_NAME,
    execute_easm_discovery,
    normalize_root_domain,
)
from workers.runners.httpx.runner import execute_httpx_probe
from workers.runners.netexec.runner import NETEXEC_RESULTS_ARTIFACT_NAME, execute_netexec_smb
from workers.runners.nmap.runner import execute_nmap_scan
from workers.runners.nuclei.runner import (
    INFRASTRUCTURE_NUCLEI_TEMPLATE,
    INFRASTRUCTURE_TEMPLATE_FILENAME,
    INFRASTRUCTURE_TEMPLATE_ID,
    INFRASTRUCTURE_TEMPLATE_SOURCE,
    execute_nuclei_scan,
)
from workers.runners.ssh_audit.runner import execute_ssh_audit

EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME = "external-infra-results.json"

_HTTP_PORTS = {80, 81, 443, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443}
_MANAGEMENT_PORTS = {22, 23, 3389, 5900, 5901, 5985, 5986, 8443, 9443, 1194, 1723}
_DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9042, 9200, 27017}
_SSH_PORTS = {22, 2222}
_SMB_PORTS = {139, 445}
_HTTPS_PORTS = {443, 8443, 9443}
_DATABASE_SERVICE_MARKERS = (
    "mysql",
    "mssql",
    "ms-sql",
    "postgres",
    "postgresql",
    "mongodb",
    "mongo",
    "redis",
    "oracle",
    "elasticsearch",
    "cassandra",
)
_MANAGEMENT_SERVICE_MARKERS = (
    "rdp",
    "ms-wbt-server",
    "winrm",
    "vnc",
    "telnet",
    "ssh",
    "vpn",
    "fortinet",
    "citrix",
)


def _normalize_mode(mode: str | None) -> str:
    normalized = str(mode or "passive").strip().lower()
    if normalized not in {"passive", "active"}:
        raise ValueError("mode must be passive or active")
    return normalized


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _is_cidr(value: str) -> bool:
    try:
        ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _target_kind(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError("target must not be blank")
    parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
    if parsed.scheme and parsed.hostname:
        return "url"
    if _is_cidr(normalized):
        return "cidr"
    if _is_ip(normalized):
        return "host"
    if parsed.hostname and "." in parsed.hostname:
        return "domain"
    if "." in normalized:
        return "domain"
    return "target"


def _normalize_explicit_targets(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, str]]:
    normalized_scope = scope_allowlist or {}
    normalized_targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_target in targets:
        candidate = str(raw_target or "").strip()
        if not candidate or candidate in seen:
            continue
        if not target_value_is_allowed(normalized_scope, candidate):
            raise ValueError(f"target outside scope: {candidate}")
        seen.add(candidate)
        normalized_targets.append({"kind": _target_kind(candidate), "value": candidate})
    if not normalized_targets:
        raise ValueError("at least one target is required")
    return normalized_targets


def _domain_targets(targets: list[dict[str, str]]) -> list[str]:
    discovered: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if target["kind"] not in {"domain", "url", "target"}:
            continue
        try:
            root_domain = normalize_root_domain(target["value"])
        except ValueError:
            continue
        if root_domain in seen:
            continue
        seen.add(root_domain)
        discovered.append(root_domain)
    return discovered


def _parse_json_artifact(artifact: EvidenceArtifact) -> dict[str, Any]:
    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    return payload if isinstance(payload, dict) else {}


def _extract_easm_details(execution: RunnerExecution) -> tuple[dict[str, Any], list[str], list[str], list[str]]:
    artifact = next(
        (artifact for artifact in execution.artifacts if artifact.name == EASM_RESULTS_ARTIFACT_NAME),
        None,
    )
    if artifact is None or not artifact.data:
        return {}, [], [], []
    payload = _parse_json_artifact(artifact)
    discovered_hosts: list[str] = []
    discovered_ips: list[str] = []
    discovered_http_targets: list[str] = []
    seen_hosts: set[str] = set()
    seen_ips: set[str] = set()
    seen_http_targets: set[str] = set()
    for result in payload.get("results", []) if isinstance(payload.get("results"), list) else []:
        if not isinstance(result, dict):
            continue
        for asset in result.get("assets", []) if isinstance(result.get("assets"), list) else []:
            if not isinstance(asset, dict):
                continue
            host = str(asset.get("host") or "").strip()
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                discovered_hosts.append(host)
            for address in asset.get("resolved_ips", []) if isinstance(asset.get("resolved_ips"), list) else []:
                value = str(address or "").strip()
                if value and value not in seen_ips:
                    seen_ips.add(value)
                    discovered_ips.append(value)
            for endpoint in asset.get("http_endpoints", []) if isinstance(asset.get("http_endpoints"), list) else []:
                if not isinstance(endpoint, dict):
                    continue
                url = str(endpoint.get("url") or "").strip()
                if url and url not in seen_http_targets:
                    seen_http_targets.add(url)
                    discovered_http_targets.append(url)
    return payload, discovered_hosts, discovered_ips, discovered_http_targets


def _dedupe_preserve(values: list[str]) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        results.append(candidate)
    return results


def _build_scan_targets(explicit_targets: list[dict[str, str]], derived_ips: list[str], derived_hosts: list[str]) -> list[str]:
    targets: list[str] = []
    fallback_domains: list[str] = []
    for target in explicit_targets:
        if target["kind"] in {"host", "cidr"}:
            targets.append(target["value"])
        elif target["kind"] in {"domain", "url", "target"}:
            try:
                fallback_domains.append(normalize_root_domain(target["value"]))
            except ValueError:
                fallback_domains.append(target["value"])
    if derived_ips:
        targets.extend(derived_ips)
    if derived_hosts and not derived_ips:
        targets.extend(derived_hosts)
    if not targets:
        targets.extend(fallback_domains)
    return _dedupe_preserve(targets)


def _is_http_service(service: dict[str, Any]) -> bool:
    name = str(service.get("service") or "").strip().lower()
    port = int(service.get("port") or 0)
    return (
        "http" in name
        or "ssl/http" in name
        or "https" in name
        or port in _HTTP_PORTS
    )


def _http_targets_from_services(services: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for service in services:
        if not _is_http_service(service):
            continue
        host = str(service.get("host") or "").strip()
        port = int(service.get("port") or 0)
        if not host or port <= 0:
            continue
        name = str(service.get("service") or "").strip().lower()
        scheme = "https" if "https" in name or "ssl" in name or port in _HTTPS_PORTS else "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            targets.append(f"{scheme}://{host}")
        else:
            targets.append(f"{scheme}://{host}:{port}")
    return _dedupe_preserve(targets)


def _hosts_for_port(services: list[dict[str, Any]], ports: set[int], service_markers: tuple[str, ...] = ()) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for service in services:
        host = str(service.get("host") or "").strip()
        port = int(service.get("port") or 0)
        name = str(service.get("service") or "").strip().lower()
        if not host or port <= 0:
            continue
        if port not in ports and not any(marker in name for marker in service_markers):
            continue
        signature = (host, port)
        if signature in seen:
            continue
        seen.add(signature)
        results.append(signature)
    return results


def _service_finding(
    *,
    title: str,
    severity: str,
    target_id: str,
    summary: str,
    methodology_tags: list[str],
    control_family: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target_id": target_id,
        "summary": summary,
        "methodology_tags": methodology_tags,
        "ptes_phase": "vulnerability_analysis",
        "nist_phase": "discovery",
        "control_family": control_family,
    }


def _derive_service_findings(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for service in services:
        host = str(service.get("host") or "").strip()
        port = int(service.get("port") or 0)
        name = str(service.get("service") or "").strip().lower()
        product = str(service.get("product") or "").strip()
        if not host or port <= 0:
            continue
        target_id = f"{host}:{port}"
        if port in _DATABASE_PORTS or any(marker in name for marker in _DATABASE_SERVICE_MARKERS):
            title = f"Externally exposed database service on {target_id}"
            key = (title.lower(), target_id.lower())
            if key not in seen:
                seen.add(key)
                findings.append(
                    _service_finding(
                        title=title,
                        severity="high",
                        target_id=target_id,
                        summary=(
                            f"Nmap service detection identified a database-facing service ({product or name or 'database'}) "
                            f"exposed on {target_id} from the outside-attacker perspective."
                        ),
                        methodology_tags=["owasp-wstg", "WSTG-INFO", "information_gathering", "database"],
                        control_family="information_gathering",
                    )
                )
        if port in _MANAGEMENT_PORTS or any(marker in name for marker in _MANAGEMENT_SERVICE_MARKERS):
            title = f"Externally exposed management service on {target_id}"
            key = (title.lower(), target_id.lower())
            if key not in seen:
                seen.add(key)
                findings.append(
                    _service_finding(
                        title=title,
                        severity="medium" if port in {22, 443, 8443, 9443} else "high",
                        target_id=target_id,
                        summary=(
                            f"Nmap service detection identified a remote administration or management surface "
                            f"({product or name or 'management service'}) on {target_id}."
                        ),
                        methodology_tags=["owasp-wstg", "WSTG-CONFIG", "configuration", "management-surface"],
                        control_family="configuration",
                    )
                )
    return findings


def _extract_nuclei_findings(artifact: EvidenceArtifact) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in artifact.data.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        result = json.loads(line)
        if not isinstance(result, dict):
            continue
        info = result.get("info", {})
        severity = str(info.get("severity") or "medium").strip().lower() if isinstance(info, dict) else "medium"
        title = str(info.get("name") or result.get("template-id") or "Infrastructure nuclei finding").strip()
        target_id = str(result.get("matched-at") or "").strip() or "unknown-target"
        findings.append(
            {
                "title": title,
                "severity": severity if severity in {"critical", "high", "medium", "low", "info"} else "medium",
                "target_id": target_id,
                "summary": str(result.get("matcher-name") or result.get("template-id") or title).strip(),
                "methodology_tags": ["owasp-wstg", "WSTG-CONFIG", "configuration", "nuclei"],
                "ptes_phase": "vulnerability_analysis",
                "nist_phase": "discovery",
                "control_family": "configuration",
            }
        )
    return findings


def _merge_findings(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for finding in group:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or "").strip()
            target_id = str(finding.get("target_id") or "").strip()
            if not title or not target_id:
                continue
            signature = (title.lower(), target_id.lower())
            if signature in seen:
                continue
            seen.add(signature)
            merged.append(finding)
    return merged


def _parse_netexec_findings(execution: RunnerExecution) -> list[dict[str, Any]]:
    artifact = next(
        (artifact for artifact in execution.artifacts if artifact.name == NETEXEC_RESULTS_ARTIFACT_NAME),
        None,
    )
    if artifact is None or not artifact.data:
        return []
    payload = _parse_json_artifact(artifact)
    findings: list[dict[str, Any]] = []
    for target in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(target, dict):
            continue
        for finding in target.get("analysis_findings", []) if isinstance(target.get("analysis_findings"), list) else []:
            if isinstance(finding, dict):
                findings.append(finding)
    return findings


def _build_inventory(
    *,
    easm_payload: dict[str, Any],
    nmap_observation: dict[str, Any],
    httpx_observation: dict[str, Any],
) -> dict[str, Any]:
    hosts: list[Any] = []
    seen_hosts: set[str] = set()

    def add_host(host_value: Any) -> None:
        if isinstance(host_value, dict):
            host_name = str(host_value.get("host") or "").strip()
            if not host_name:
                return
            signature = host_name.lower()
            if signature in seen_hosts:
                return
            seen_hosts.add(signature)
            hosts.append(host_value)
            return
        host_name = str(host_value or "").strip()
        if not host_name:
            return
        signature = host_name.lower()
        if signature in seen_hosts:
            return
        seen_hosts.add(signature)
        hosts.append(host_name)

    for result in easm_payload.get("results", []) if isinstance(easm_payload.get("results"), list) else []:
        if not isinstance(result, dict):
            continue
        for asset in result.get("assets", []) if isinstance(result.get("assets"), list) else []:
            if isinstance(asset, dict):
                add_host({"host": str(asset.get("host") or "").strip(), "notes": asset.get("discovery_sources", []), "confidence": asset.get("confidence", 0.82)})
    for host in nmap_observation.get("data", {}).get("hosts", []) if isinstance(nmap_observation.get("data"), dict) else []:
        add_host(host)
    for host in httpx_observation.get("data", {}).get("hosts", []) if isinstance(httpx_observation.get("data"), dict) else []:
        add_host(host)

    return {
        "hosts": hosts,
        "services": list(nmap_observation.get("data", {}).get("services", [])) if isinstance(nmap_observation.get("data"), dict) else [],
        "endpoints": list(httpx_observation.get("data", {}).get("endpoints", [])) if isinstance(httpx_observation.get("data"), dict) else [],
        "technologies": list(httpx_observation.get("data", {}).get("technologies", [])) if isinstance(httpx_observation.get("data"), dict) else [],
        "fingerprints": [
            *(
                list(nmap_observation.get("data", {}).get("fingerprints", []))
                if isinstance(nmap_observation.get("data"), dict)
                else []
            ),
            *(
                list(httpx_observation.get("data", {}).get("fingerprints", []))
                if isinstance(httpx_observation.get("data"), dict)
                else []
            ),
        ],
        "confidence": 0.86,
    }


def execute_external_infra_assessment(
    targets: list[str],
    *,
    mode: str = "passive",
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = 15.0,
    rate_limit: int = 1,
    nmap_binary: str = "nmap",
    nuclei_binary: str = "nuclei",
    netexec_binary: str = "nxc",
    ssh_audit_binary: str = "ssh-audit",
    include_passive_smb: bool = True,
    execute_easm=execute_easm_discovery,
    execute_nmap=execute_nmap_scan,
    execute_httpx=execute_httpx_probe,
    execute_nuclei=execute_nuclei_scan,
    execute_netexec=execute_netexec_smb,
    execute_ssh=execute_ssh_audit,
) -> RunnerExecution:
    normalized_mode = _normalize_mode(mode)
    explicit_targets = _normalize_explicit_targets(targets, scope_allowlist=scope_allowlist)
    domain_targets = _domain_targets(explicit_targets)

    warnings: list[str] = []
    artifacts: list[EvidenceArtifact] = []
    easm_payload: dict[str, Any] = {}
    derived_hosts: list[str] = []
    derived_ips: list[str] = []
    derived_http_targets: list[str] = []

    if domain_targets:
        easm_execution = execute_easm(
            targets=domain_targets,
            scope_allowlist=scope_allowlist,
            timeout_seconds=timeout_seconds,
        )
        artifacts.extend(easm_execution.artifacts)
        if easm_execution.stderr:
            warnings.append(easm_execution.stderr.strip())
        if easm_execution.exit_code == 0:
            easm_payload, derived_hosts, derived_ips, derived_http_targets = _extract_easm_details(
                easm_execution
            )

    scan_targets = _build_scan_targets(explicit_targets, derived_ips, derived_hosts)
    if not scan_targets:
        raise ValueError("external infrastructure assessment requires at least one scan target")

    nmap_execution = execute_nmap(
        targets=scan_targets,
        binary=nmap_binary,
        discovery_only=False,
        service_detection=True,
        skip_discovery=True,
        full_port_scan=True,
    )
    artifacts.extend(nmap_execution.artifacts)
    if nmap_execution.stderr:
        warnings.append(nmap_execution.stderr.strip())
    if nmap_execution.exit_code != 0:
        result_payload = {
            "mode": normalized_mode,
            "status": "failed",
            "requested_targets": [target["value"] for target in explicit_targets],
            "scan_targets": scan_targets,
            "inventory": {"hosts": [], "services": [], "endpoints": [], "technologies": [], "fingerprints": [], "confidence": 0.0},
            "analysis_findings": [],
            "warnings": warnings,
        }
        artifacts.append(
            EvidenceArtifact(
                name=EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME,
                content_type="application/json",
                data=(json.dumps(result_payload, sort_keys=True) + "\n").encode("utf-8"),
                kind="external-infra-results",
            )
        )
        return RunnerExecution(
            tool="external-infra",
            exit_code=nmap_execution.exit_code,
            stdout=nmap_execution.stdout,
            stderr="\n".join(warnings),
            metadata={
                "status": "failed",
                "mode": normalized_mode,
                "requested_target_count": len(explicit_targets),
                "scan_target_count": len(scan_targets),
                "runner_digest": "workers.external_infra.runner:v1",
            },
            artifacts=artifacts,
        )

    nmap_artifact = next(
        (artifact for artifact in nmap_execution.artifacts if artifact.name == "nmap-results.xml"),
        None,
    )
    nmap_observation = (
        nmap_observation_from_xml(xml_bytes=nmap_artifact.data, target_id=scan_targets[0])
        if nmap_artifact is not None and nmap_artifact.data
        else {"data": {"hosts": [], "services": [], "fingerprints": []}}
    )
    services = (
        list(nmap_observation.get("data", {}).get("services", []))
        if isinstance(nmap_observation.get("data"), dict)
        else []
    )

    http_targets = _dedupe_preserve([*derived_http_targets, *_http_targets_from_services(services)])
    httpx_observation = {"data": {"hosts": [], "endpoints": [], "technologies": [], "fingerprints": []}}
    if http_targets:
        httpx_execution = execute_httpx(
            targets=http_targets,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
        )
        artifacts.extend(httpx_execution.artifacts)
        if httpx_execution.stderr:
            warnings.append(httpx_execution.stderr.strip())
        httpx_artifact = next(
            (artifact for artifact in httpx_execution.artifacts if artifact.name == "httpx-results.jsonl"),
            None,
        )
        if httpx_artifact is not None and httpx_artifact.data:
            httpx_observation = httpx_observation_from_jsonl(
                jsonl_bytes=httpx_artifact.data,
                target_id=http_targets[0],
            )

    ssh_findings: list[dict[str, Any]] = []
    ssh_results: list[dict[str, Any]] = []
    for host, port in _hosts_for_port(services, _SSH_PORTS, ("ssh",)):
        ssh_execution = execute_ssh(
            host=host,
            port=port,
            binary=ssh_audit_binary,
            timeout_seconds=timeout_seconds,
        )
        artifacts.extend(ssh_execution.artifacts)
        if ssh_execution.stderr:
            warnings.append(ssh_execution.stderr.strip())
        for artifact in ssh_execution.artifacts:
            if artifact.name.startswith("ssh-audit-") and artifact.data:
                payload = _parse_json_artifact(artifact)
                ssh_results.append(payload)
                ssh_findings.extend(
                    payload.get("analysis_findings", [])
                    if isinstance(payload.get("analysis_findings"), list)
                    else []
                )

    smb_findings: list[dict[str, Any]] = []
    smb_summary: dict[str, Any] | None = None
    smb_targets = [host for host, _port in _hosts_for_port(services, _SMB_PORTS, ("microsoft-ds", "netbios-ssn", "smb"))]
    if include_passive_smb and smb_targets:
        smb_scope = dict(scope_allowlist or {})
        smb_scope["hosts"] = _dedupe_preserve(
            list(smb_scope.get("hosts", [])) + smb_targets + derived_ips
        )
        smb_execution = execute_netexec(
            targets=smb_targets,
            mode="passive",
            binary=netexec_binary,
            scope_allowlist=smb_scope,
            timeout_seconds=max(timeout_seconds, 30.0),
        )
        artifacts.extend(smb_execution.artifacts)
        if smb_execution.stderr:
            warnings.append(smb_execution.stderr.strip())
        smb_findings.extend(_parse_netexec_findings(smb_execution))
        smb_summary = {
            "status": smb_execution.metadata.get("status"),
            "target_count": len(smb_targets),
            "finding_count": len(smb_findings),
        }

    nuclei_findings: list[dict[str, Any]] = []
    nuclei_summary: dict[str, Any] | None = None
    if normalized_mode == "active" and http_targets:
        nuclei_execution = execute_nuclei(
            targets=http_targets,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            binary=nuclei_binary,
            template_body=INFRASTRUCTURE_NUCLEI_TEMPLATE,
            template_id=INFRASTRUCTURE_TEMPLATE_ID,
            template_source=INFRASTRUCTURE_TEMPLATE_SOURCE,
            template_filename=INFRASTRUCTURE_TEMPLATE_FILENAME,
        )
        artifacts.extend(nuclei_execution.artifacts)
        if nuclei_execution.stderr:
            warnings.append(nuclei_execution.stderr.strip())
        nuclei_artifact = next(
            (artifact for artifact in nuclei_execution.artifacts if artifact.name == "nuclei-results.jsonl"),
            None,
        )
        if nuclei_artifact is not None and nuclei_artifact.data:
            nuclei_findings.extend(_extract_nuclei_findings(nuclei_artifact))
        nuclei_summary = {
            "status": nuclei_execution.metadata.get("status"),
            "target_count": len(http_targets),
            "finding_count": len(nuclei_findings),
            "template_id": nuclei_execution.metadata.get("template_id"),
        }

    service_findings = _derive_service_findings(services)
    analysis_findings = _merge_findings(service_findings, ssh_findings, smb_findings, nuclei_findings)
    inventory = _build_inventory(
        easm_payload=easm_payload,
        nmap_observation=nmap_observation,
        httpx_observation=httpx_observation,
    )
    status = "completed_with_errors" if warnings else "ok"
    result_payload = {
        "mode": normalized_mode,
        "status": status,
        "requested_targets": [target["value"] for target in explicit_targets],
        "domain_targets": domain_targets,
        "scan_targets": scan_targets,
        "easm": {
            "domain_count": len(domain_targets),
            "discovered_host_count": len(derived_hosts),
            "derived_ip_count": len(derived_ips),
            "discovered_http_target_count": len(derived_http_targets),
            "summary": easm_payload.get("summary", {}) if easm_payload else {},
        },
        "http_followup_targets": http_targets,
        "ssh_audit_targets": [result.get("host") for result in ssh_results if isinstance(result, dict)],
        "inventory": inventory,
        "analysis_findings": analysis_findings,
        "substeps": {
            "nmap": {
                "status": nmap_execution.metadata.get("status"),
                "scan_target_count": len(scan_targets),
                "service_count": len(services),
            },
            "httpx": {
                "status": "ok" if http_targets else "skipped",
                "target_count": len(http_targets),
            },
            "ssh_audit": {
                "status": "ok" if ssh_results else "skipped",
                "target_count": len(ssh_results),
                "finding_count": len(ssh_findings),
            },
            "smb": smb_summary or {"status": "skipped", "target_count": 0, "finding_count": 0},
            "nuclei": nuclei_summary or {"status": "skipped", "target_count": 0, "finding_count": 0},
        },
        "warnings": warnings,
    }
    artifacts.append(
        EvidenceArtifact(
            name=EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=(json.dumps(result_payload, sort_keys=True) + "\n").encode("utf-8"),
            kind="external-infra-results",
        )
    )
    return RunnerExecution(
        tool="external-infra",
        exit_code=0,
        stdout=json.dumps({"status": status, "scan_targets": scan_targets}, sort_keys=True),
        stderr="\n".join(warnings),
        metadata={
            "status": status,
            "mode": normalized_mode,
            "requested_target_count": len(explicit_targets),
            "scan_target_count": len(scan_targets),
            "service_count": len(services),
            "finding_count": len(analysis_findings),
            "runner_digest": "workers.external_infra.runner:v1",
        },
        artifacts=artifacts,
    )
