from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Finding, Run, RunDrift, TargetContextDocument
from api.app.services.audit import write_audit_event
from api.app.services.exposure_score import CLOSED_FINDING_STATUSES, SEVERITY_WEIGHTS

DRIFT_ELIGIBLE_RUN_STATUSES = {"completed", "completed_with_errors"}
CONTINUOUS_EXPOSURE_DRIFT_VERSION = "2026-05-08.1"


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _finding_fingerprint(finding: Finding) -> tuple[str, str]:
    return (
        str(finding.title or "").strip().lower(),
        str(finding.target_id or "").strip().lower(),
    )


def _open_finding_fingerprints(findings: list[Finding]) -> set[tuple[str, str]]:
    return {
        _finding_fingerprint(finding)
        for finding in findings
        if str(finding.status or "").strip().lower() not in CLOSED_FINDING_STATUSES
    }


def _exposure_for_findings(findings: list[Finding]) -> float:
    weight = 0.0
    for finding in findings:
        if str(finding.status or "").strip().lower() in CLOSED_FINDING_STATUSES:
            continue
        severity = str(finding.severity or "unknown").strip().lower()
        weight += float(SEVERITY_WEIGHTS.get(severity, 0.0))
    return min(100.0, round((weight / 40.0) * 100.0, 1))


def _load_run_for_drift(session: Session, run_id: UUID) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.findings),
            selectinload(Run.profile),
            selectinload(Run.drift_summary),
            selectinload(Run.source_inventory_snapshot),
            selectinload(Run.context_documents),
        )
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )


def _previous_completed_run(session: Session, run: Run) -> Run | None:
    if run.profile_id is None:
        return None
    return session.scalar(
        select(Run)
        .options(selectinload(Run.findings), selectinload(Run.profile))
        .where(
            Run.id != run.id,
            Run.engagement_id == run.engagement_id,
            Run.profile_id == run.profile_id,
            Run.deleted_at.is_(None),
            Run.status.in_(DRIFT_ELIGIBLE_RUN_STATUSES),
            Run.created_at <= run.created_at,
        )
        .options(
            selectinload(Run.findings),
            selectinload(Run.profile),
            selectinload(Run.source_inventory_snapshot),
            selectinload(Run.context_documents),
        )
        .order_by(Run.created_at.desc(), Run.updated_at.desc(), Run.id.desc())
        .limit(1)
    )


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _string(value: object) -> str:
    return str(value or "").strip()


def _lower_key(value: object) -> str:
    return _string(value).lower()


def _latest_context_document(run: Run) -> TargetContextDocument | None:
    documents = list(run.context_documents or [])
    if not documents:
        return None
    return sorted(
        documents,
        key=lambda document: (
            document.updated_at or datetime.min.replace(tzinfo=UTC),
            document.created_at or datetime.min.replace(tzinfo=UTC),
            document.parent_context_document_id is not None,
            document.id.hex,
        ),
        reverse=True,
    )[0]


def _inventory(run: Run) -> dict[str, Any]:
    snapshot = run.source_inventory_snapshot
    if snapshot is None or not isinstance(snapshot.normalized_inventory_json, dict):
        return {}
    return dict(snapshot.normalized_inventory_json or {})


def _inventory_snapshot_ref(run: Run) -> dict[str, str] | None:
    snapshot = run.source_inventory_snapshot
    if snapshot is None:
        return None
    return {
        "type": "inventory_snapshot",
        "id": str(snapshot.id),
        "evidence_ref": "inventory_snapshot.normalized_inventory_json",
    }


def _service_from_parts(
    *,
    host: object = "",
    port: object = "",
    protocol: object = "tcp",
    service: object = "",
    evidence_ref: str,
) -> dict[str, Any] | None:
    port_text = _string(port)
    if not port_text:
        return None
    host_text = _string(host) or "*"
    protocol_text = _string(protocol).lower() or "tcp"
    service_text = _string(service)
    return {
        "key": f"{host_text.lower()}:{port_text}/{protocol_text}",
        "host": host_text,
        "port": port_text,
        "protocol": protocol_text,
        "service": service_text,
        "evidence_ref": evidence_ref,
    }


def _extract_services(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    services: dict[str, dict[str, Any]] = {}

    def add(service: dict[str, Any] | None) -> None:
        if service is not None:
            services[service["key"]] = service

    for entry in _as_list(inventory.get("services")):
        if not isinstance(entry, dict):
            continue
        add(
            _service_from_parts(
                host=entry.get("host") or entry.get("hostname") or entry.get("ip"),
                port=entry.get("port"),
                protocol=entry.get("protocol") or entry.get("transport") or "tcp",
                service=entry.get("service") or entry.get("name") or entry.get("product"),
                evidence_ref="inventory_snapshot.normalized_inventory_json.services",
            )
        )

    for host_entry in _as_list(inventory.get("hosts")):
        if isinstance(host_entry, str):
            continue
        if not isinstance(host_entry, dict):
            continue
        host = (
            host_entry.get("host")
            or host_entry.get("hostname")
            or host_entry.get("ip")
            or host_entry.get("name")
        )
        for port_entry in _as_list(host_entry.get("ports")):
            if isinstance(port_entry, dict):
                add(
                    _service_from_parts(
                        host=host,
                        port=port_entry.get("port") or port_entry.get("number"),
                        protocol=port_entry.get("protocol") or port_entry.get("transport") or "tcp",
                        service=port_entry.get("service") or port_entry.get("name") or port_entry.get("product"),
                        evidence_ref="inventory_snapshot.normalized_inventory_json.hosts.ports",
                    )
                )
            else:
                add(
                    _service_from_parts(
                        host=host,
                        port=port_entry,
                        protocol="tcp",
                        evidence_ref="inventory_snapshot.normalized_inventory_json.hosts.ports",
                    )
                )
        for service_entry in _as_list(host_entry.get("services")):
            if not isinstance(service_entry, dict):
                continue
            add(
                _service_from_parts(
                    host=host,
                    port=service_entry.get("port"),
                    protocol=service_entry.get("protocol") or service_entry.get("transport") or "tcp",
                    service=service_entry.get("service") or service_entry.get("name") or service_entry.get("product"),
                    evidence_ref="inventory_snapshot.normalized_inventory_json.hosts.services",
                )
            )

    return services


def _extract_endpoints(inventory: dict[str, Any], context: TargetContextDocument | None) -> dict[str, dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}

    def add(value: object, evidence_ref: str) -> None:
        if isinstance(value, dict):
            endpoint = _string(value.get("url") or value.get("endpoint") or value.get("target"))
        else:
            endpoint = _string(value)
        if endpoint:
            endpoints[endpoint.lower()] = {"endpoint": endpoint, "evidence_ref": evidence_ref}

    for key in ("urls", "endpoints", "api_endpoints", "graphql_endpoints"):
        for value in _as_list(inventory.get(key)):
            add(value, f"inventory_snapshot.normalized_inventory_json.{key}")

    stack = _as_dict(inventory.get("tech_stack_profile"))
    for key, value in stack.items():
        if key.endswith("_endpoints") or key in {"endpoints", "urls"}:
            for endpoint in _as_list(value):
                add(endpoint, f"inventory_snapshot.normalized_inventory_json.tech_stack_profile.{key}")

    profile = _as_dict(inventory.get("signal_profile"))
    for signal in _as_list(profile.get("signals")):
        if not isinstance(signal, dict):
            continue
        key = _lower_key(signal.get("key"))
        if "endpoint" in key or key in {"url", "api"}:
            add(signal.get("value") or signal.get("url"), "inventory_snapshot.normalized_inventory_json.signal_profile.signals")

    if context is not None:
        for endpoint in list(context.endpoints_discovered_json or []):
            add(endpoint, "target_context_documents.endpoints_discovered_json")

    return endpoints


def _technology_from_dict(entry: dict[str, Any], evidence_ref: str) -> dict[str, Any] | None:
    name = _string(
        entry.get("name")
        or entry.get("technology")
        or entry.get("product")
        or entry.get("framework")
        or entry.get("library")
    )
    if not name:
        return None
    version = _string(entry.get("version") or entry.get("detected_version") or entry.get("product_version"))
    return {"key": name.lower(), "name": name, "version": version, "evidence_ref": evidence_ref}


def _extract_technologies(
    inventory: dict[str, Any],
    context: TargetContextDocument | None,
) -> dict[str, dict[str, Any]]:
    technologies: dict[str, dict[str, Any]] = {}

    def add(value: object, evidence_ref: str) -> None:
        technology: dict[str, Any] | None
        if isinstance(value, dict):
            technology = _technology_from_dict(value, evidence_ref)
        else:
            name = _string(value)
            technology = (
                {"key": name.lower(), "name": name, "version": "", "evidence_ref": evidence_ref}
                if name
                else None
            )
        if technology is not None:
            current = technologies.get(technology["key"])
            if current is None or (not current.get("version") and technology.get("version")):
                technologies[technology["key"]] = technology

    stack = _as_dict(inventory.get("tech_stack_profile"))
    for key in ("technologies", "frameworks", "libraries", "products", "languages"):
        for value in _as_list(stack.get(key)):
            add(value, f"inventory_snapshot.normalized_inventory_json.tech_stack_profile.{key}")
    for key, value in stack.items():
        if key in {"technologies", "frameworks", "libraries", "products", "languages"}:
            continue
        if key.endswith("_frameworks") or key.endswith("_libraries"):
            for item in _as_list(value):
                add(item, f"inventory_snapshot.normalized_inventory_json.tech_stack_profile.{key}")

    for value in _as_list(inventory.get("fingerprints")):
        add(value, "inventory_snapshot.normalized_inventory_json.fingerprints")
    for value in _as_list(inventory.get("technologies")):
        add(value, "inventory_snapshot.normalized_inventory_json.technologies")

    profile = _as_dict(inventory.get("signal_profile"))
    for signal in _as_list(profile.get("signals")):
        if not isinstance(signal, dict):
            continue
        key = _lower_key(signal.get("key"))
        if key.endswith("_technology") or key.endswith("_framework") or "cms" in key:
            add(
                {
                    "name": signal.get("product") or signal.get("technology") or signal.get("value") or signal.get("key"),
                    "version": signal.get("version"),
                },
                "inventory_snapshot.normalized_inventory_json.signal_profile.signals",
            )

    if context is not None:
        for technology in list(context.technologies_detected_json or []):
            add(technology, "target_context_documents.technologies_detected_json")

    return technologies


def _version_tuple(version: str) -> tuple[int, ...] | None:
    parts = [int(part) for part in re.findall(r"\d+", version or "")]
    return tuple(parts) if parts else None


def _version_direction(previous: str, current: str) -> str:
    previous_tuple = _version_tuple(previous)
    current_tuple = _version_tuple(current)
    if previous_tuple is None or current_tuple is None or previous_tuple == current_tuple:
        return "changed"
    return "downgraded" if current_tuple < previous_tuple else "upgraded"


def _finding_payloads_by_fingerprint(findings: list[Finding]) -> dict[tuple[str, str], dict[str, Any]]:
    payloads: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if str(finding.status or "").strip().lower() in CLOSED_FINDING_STATUSES:
            continue
        key = _finding_fingerprint(finding)
        payloads[key] = {
            "finding_id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "target_id": finding.target_id,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
        }
    return payloads


def _diff_payloads(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return (
        [current[key] for key in sorted(set(current) - set(previous))],
        [previous[key] for key in sorted(set(previous) - set(current))],
    )


def _technology_drift(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    added, removed = _diff_payloads(current, previous)
    changes: list[dict[str, Any]] = []
    for key in sorted(set(current) & set(previous)):
        current_version = _string(current[key].get("version"))
        previous_version = _string(previous[key].get("version"))
        if current_version and previous_version and current_version != previous_version:
            changes.append(
                {
                    "technology": current[key].get("name") or previous[key].get("name") or key,
                    "previous_version": previous_version,
                    "current_version": current_version,
                    "direction": _version_direction(previous_version, current_version),
                    "previous_evidence_ref": previous[key].get("evidence_ref"),
                    "current_evidence_ref": current[key].get("evidence_ref"),
                }
            )
    return {
        "added": added,
        "removed": removed,
        "version_changes": changes,
        "downgraded": [change for change in changes if change["direction"] == "downgraded"],
    }


def _context_drift(
    current: TargetContextDocument | None,
    previous: TargetContextDocument | None,
) -> dict[str, Any]:
    if current is None and previous is None:
        return {"status": "no_context_documents"}
    if previous is None:
        return {
            "status": "new_context_document",
            "current_context_document_id": str(current.id) if current is not None else None,
        }
    if current is None:
        return {
            "status": "context_document_removed",
            "previous_context_document_id": str(previous.id),
        }

    def as_set(values: list[Any] | None) -> set[str]:
        return {_string(value).lower() for value in list(values or []) if _string(value)}

    current_endpoints = as_set(current.endpoints_discovered_json)
    previous_endpoints = as_set(previous.endpoints_discovered_json)
    current_technologies = as_set(current.technologies_detected_json)
    previous_technologies = as_set(previous.technologies_detected_json)
    current_tools = as_set(current.recommended_tools_json)
    previous_tools = as_set(previous.recommended_tools_json)
    return {
        "status": "compared",
        "current_context_document_id": str(current.id),
        "previous_context_document_id": str(previous.id),
        "new_endpoints": sorted(current_endpoints - previous_endpoints),
        "removed_endpoints": sorted(previous_endpoints - current_endpoints),
        "new_technologies": sorted(current_technologies - previous_technologies),
        "removed_technologies": sorted(previous_technologies - current_technologies),
        "new_recommended_tools": sorted(current_tools - previous_tools),
        "removed_recommended_tools": sorted(previous_tools - current_tools),
        "summary_changed": _string(current.context_summary) != _string(previous.context_summary),
        "evidence_ref": "target_context_documents",
    }


def _operator_alerts(
    *,
    new_findings: list[dict[str, Any]],
    resolved_findings: list[dict[str, Any]],
    new_services: list[dict[str, Any]],
    tech_drift: dict[str, Any],
    context_drift: dict[str, Any],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for service in new_services:
        alerts.append(
            {
                "type": "new_surface_service",
                "severity": "medium",
                "title": f"New exposed service observed on {service['host']}:{service['port']}",
                "message": "Potential shadow IT or unauthorized exposure drift; validate ownership and intended change.",
                "evidence_ref": service.get("evidence_ref"),
                "service": service,
            }
        )
    for change in tech_drift.get("downgraded", []):
        alerts.append(
            {
                "type": "technology_downgrade",
                "severity": "high",
                "title": f"{change['technology']} version moved backward",
                "message": "Potential patch regression; verify the deployment history and exposure score impact.",
                "evidence_ref": change.get("current_evidence_ref"),
                "technology_change": change,
            }
        )
    for finding in new_findings:
        alerts.append(
            {
                "type": "new_finding",
                "severity": finding.get("severity") or "unknown",
                "title": f"New open finding: {finding.get('title')}",
                "message": "New evidence-backed finding is present in the current run.",
                "evidence_ref": finding.get("evidence_ref"),
                "finding_id": finding.get("finding_id"),
            }
        )
    for finding in resolved_findings:
        alerts.append(
            {
                "type": "resolved_finding",
                "severity": "info",
                "title": f"Previously open finding no longer observed: {finding.get('title')}",
                "message": "Resolution signal is based on finding fingerprint absence in the current run.",
                "evidence_ref": finding.get("evidence_ref"),
                "finding_id": finding.get("finding_id"),
            }
        )
    if context_drift.get("status") == "compared" and context_drift.get("new_endpoints"):
        alerts.append(
            {
                "type": "context_endpoint_drift",
                "severity": "medium",
                "title": "Target context contains newly observed endpoints",
                "message": "Review target context drift before expanding assessment depth.",
                "evidence_ref": context_drift.get("evidence_ref"),
                "new_endpoints": context_drift.get("new_endpoints", []),
            }
        )
    return alerts


def _build_continuous_exposure_drift_report_for_runs(
    *,
    run: Run,
    previous: Run,
    computed_at: datetime,
) -> dict[str, Any]:
    current_findings = _finding_payloads_by_fingerprint(list(run.findings or []))
    previous_findings = _finding_payloads_by_fingerprint(list(previous.findings or []))
    new_findings = [current_findings[key] for key in sorted(set(current_findings) - set(previous_findings))]
    resolved_findings = [previous_findings[key] for key in sorted(set(previous_findings) - set(current_findings))]

    current_inventory = _inventory(run)
    previous_inventory = _inventory(previous)
    current_context = _latest_context_document(run)
    previous_context = _latest_context_document(previous)
    current_services = _extract_services(current_inventory)
    previous_services = _extract_services(previous_inventory)
    new_services, removed_services = _diff_payloads(current_services, previous_services)
    current_endpoints = _extract_endpoints(current_inventory, current_context)
    previous_endpoints = _extract_endpoints(previous_inventory, previous_context)
    new_endpoints, removed_endpoints = _diff_payloads(current_endpoints, previous_endpoints)
    tech_drift = _technology_drift(
        _extract_technologies(current_inventory, current_context),
        _extract_technologies(previous_inventory, previous_context),
    )
    context_drift = _context_drift(current_context, previous_context)
    current_exposure = _exposure_for_findings(list(run.findings or []))
    previous_exposure = _exposure_for_findings(list(previous.findings or []))
    alerts = _operator_alerts(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        new_services=new_services,
        tech_drift=tech_drift,
        context_drift=context_drift,
    )
    previous_inventory_ref = _inventory_snapshot_ref(previous)
    current_inventory_ref = _inventory_snapshot_ref(run)
    evidence_refs = [ref for ref in [previous_inventory_ref, current_inventory_ref] if ref is not None]
    if previous_context is not None:
        evidence_refs.append(
            {
                "type": "target_context_document",
                "id": str(previous_context.id),
                "evidence_ref": "target_context_documents.previous",
            }
        )
    if current_context is not None:
        evidence_refs.append(
            {
                "type": "target_context_document",
                "id": str(current_context.id),
                "evidence_ref": "target_context_documents.current",
            }
        )
    for finding in new_findings + resolved_findings:
        evidence_refs.append(
            {
                "type": "finding",
                "id": finding["finding_id"],
                "evidence_ref": finding.get("evidence_ref") or "findings",
            }
        )

    return {
        "version": CONTINUOUS_EXPOSURE_DRIFT_VERSION,
        "status": "ready",
        "run_id": str(run.id),
        "previous_run_id": str(previous.id),
        "computed_at": computed_at.isoformat(),
        "summary": {
            "new_finding_count": len(new_findings),
            "resolved_finding_count": len(resolved_findings),
            "exposure_delta": round(current_exposure - previous_exposure, 1),
            "new_service_count": len(new_services),
            "removed_service_count": len(removed_services),
            "new_endpoint_count": len(new_endpoints),
            "removed_endpoint_count": len(removed_endpoints),
            "technology_downgrade_count": len(tech_drift["downgraded"]),
            "operator_alert_count": len(alerts),
        },
        "finding_drift": {
            "new_open_findings": new_findings,
            "resolved_open_findings": resolved_findings,
            "evidence_ref": "findings",
        },
        "surface_drift": {
            "new_services": new_services,
            "removed_services": removed_services,
            "new_endpoints": new_endpoints,
            "removed_endpoints": removed_endpoints,
        },
        "technology_drift": tech_drift,
        "context_drift": context_drift,
        "operator_alerts": alerts,
        "soc_alerts": alerts,
        "evidence_refs": evidence_refs,
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "creates_tasks": False,
            "runner_registry_bypassed": False,
            "approval_gates_bypassed": False,
            "scope_expansion_performed": False,
            "live_target_actions_performed": False,
        },
    }


def build_continuous_exposure_drift_report(
    session: Session,
    *,
    run_id: UUID,
    computed_at: datetime | None = None,
) -> dict[str, Any]:
    session.flush()
    run = _load_run_for_drift(session, run_id)
    if run is None:
        raise ValueError(f"run not found: {run_id}")
    previous = _previous_completed_run(session, run)
    if previous is None:
        return {
            "version": CONTINUOUS_EXPOSURE_DRIFT_VERSION,
            "status": "no_previous_run",
            "run_id": str(run.id),
            "previous_run_id": None,
            "computed_at": (computed_at or _utc_now()).isoformat(),
            "summary": {
                "new_finding_count": 0,
                "resolved_finding_count": 0,
                "exposure_delta": 0.0,
                "new_service_count": 0,
                "removed_service_count": 0,
                "new_endpoint_count": 0,
                "removed_endpoint_count": 0,
                "technology_downgrade_count": 0,
                "operator_alert_count": 0,
            },
            "finding_drift": {"new_open_findings": [], "resolved_open_findings": [], "evidence_ref": "findings"},
            "surface_drift": {"new_services": [], "removed_services": [], "new_endpoints": [], "removed_endpoints": []},
            "technology_drift": {"added": [], "removed": [], "version_changes": [], "downgraded": []},
            "context_drift": {"status": "not_compared"},
            "operator_alerts": [],
            "soc_alerts": [],
            "evidence_refs": [],
            "execution_contract": {
                "analysis_only": True,
                "dispatches_work_directly": False,
                "creates_tasks": False,
                "runner_registry_bypassed": False,
                "approval_gates_bypassed": False,
                "scope_expansion_performed": False,
                "live_target_actions_performed": False,
            },
        }
    return _build_continuous_exposure_drift_report_for_runs(
        run=run,
        previous=previous,
        computed_at=computed_at or _utc_now(),
    )


def compute_run_drift(
    session: Session,
    *,
    run_id: UUID,
    actor: str = "system:drift",
    computed_at: datetime | None = None,
) -> RunDrift | None:
    session.flush()
    run = _load_run_for_drift(session, run_id)
    if run is None or str(run.status or "").lower() not in DRIFT_ELIGIBLE_RUN_STATUSES:
        return None

    previous = _previous_completed_run(session, run)
    if previous is None:
        return None

    drift_computed_at = computed_at or _utc_now()
    current_open = _open_finding_fingerprints(list(run.findings or []))
    previous_open = _open_finding_fingerprints(list(previous.findings or []))
    current_exposure = _exposure_for_findings(list(run.findings or []))
    previous_exposure = _exposure_for_findings(list(previous.findings or []))

    drift = run.drift_summary
    if drift is None:
        drift = RunDrift(run_id=run.id, previous_run_id=previous.id, computed_at=drift_computed_at)
        session.add(drift)

    drift.previous_run_id = previous.id
    drift.new_finding_count = len(current_open - previous_open)
    drift.resolved_finding_count = len(previous_open - current_open)
    drift.exposure_delta = round(current_exposure - previous_exposure, 1)
    drift.computed_at = drift_computed_at

    report = _build_continuous_exposure_drift_report_for_runs(
        run=run,
        previous=previous,
        computed_at=drift_computed_at,
    )
    configuration = dict(run.configuration_json or {})
    configuration["continuous_exposure_drift"] = report
    run.configuration_json = configuration
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="run.drift_computed",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "previous_run_id": str(previous.id),
            "new_finding_count": drift.new_finding_count,
            "resolved_finding_count": drift.resolved_finding_count,
            "exposure_delta": drift.exposure_delta,
            "new_service_count": report["summary"]["new_service_count"],
            "new_endpoint_count": report["summary"]["new_endpoint_count"],
            "technology_downgrade_count": report["summary"]["technology_downgrade_count"],
            "operator_alert_count": report["summary"]["operator_alert_count"],
            "continuous_exposure_drift_version": CONTINUOUS_EXPOSURE_DRIFT_VERSION,
        },
    )
    return drift
