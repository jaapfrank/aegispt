from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_network
import subprocess
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.orm.attributes import flag_modified

from api.app.config import Settings
from api.app.models import (
    AssessmentChain,
    Engagement,
    Finding,
    InventorySnapshot,
    Run,
    RunProfile,
    Scope,
    SecretRef,
    Task,
)
from api.app.services.ai_enrichment import store_agent_reasoning_record
from api.app.services.audit import write_audit_event
from api.app.services.runs import (
    dispatch_queued_run_tasks,
    finding_context_for_runner,
    latest_scope_query,
    load_run,
    queue_run_tasks,
)
from workers.runners.metasploit.module_allowlist import resolve_allowlisted_module

HASH_BUNDLE_SECRET_KINDS = {
    "ntlmv2_hash_bundle",
    "kerberoast_tgs_hash_bundle",
    "asrep_hash_bundle",
}
PASSWORD_SECRET_KINDS = {"password"}
PHASE_TIER_RANK = {
    "passive": 0,
    "active": 1,
    "intrusive-credential": 2,
    "intrusive-exploitation": 3,
}
CHAIN_AUTHORIZATION_TIER_RANK = {
    "passive": 0,
    "active": 1,
    "full": 3,
}
TERMINAL_CHAIN_STATUSES = {
    "completed",
    "completed_with_gaps",
    "blocked",
    "rejected",
    "halted",
    "cancelled",
}

HOST_FOLLOW_UP_PROFILES = {
    "passive-network-service-enumeration",
    "passive-lan-infrastructure-audit",
    "passive-lan-nse-full",
    "passive-lan-snmp-enum",
    "passive-lan-smart-home-audit",
    "active-lan-camera-audit",
    "active-lan-default-creds-audit",
    "passive-lan-segmentation-check",
    "passive-lan-ipv6-discovery",
    "passive-identity-ldap-enum",
    "passive-lan-smb-enum",
    "active-ad-bloodhound",
    "active-ad-kerberoast",
    "active-ad-asreproast",
    "intrusive-ad-password-spray",
    "intrusive-lan-smb-auth",
    "intrusive-impacket-remote-exec",
    "intrusive-impacket-secretsdump",
    "intrusive-impacket-dcsync",
}

CHAIN_CRITICAL_FAILURE_PROFILES = {
    "passive-network-discovery",
}


@dataclass(frozen=True, slots=True)
class AssessmentChainPhaseDefinition:
    key: str
    label: str
    tier: str
    requires_approval: bool
    profiles: tuple[str, ...]
    never_auto_start: bool = False


@dataclass(frozen=True, slots=True)
class AssessmentChainDefinition:
    mode: str
    label: str
    phases: tuple[AssessmentChainPhaseDefinition, ...]
    phase_preapproval_allowed: bool = True


ASSESSMENT_CHAIN_DEFINITIONS: dict[str, AssessmentChainDefinition] = {
    "FULL-INTERNAL-LAN": AssessmentChainDefinition(
        mode="FULL-INTERNAL-LAN",
        label="Full Internal LAN",
        phases=(
            AssessmentChainPhaseDefinition(
                key="passive-discovery",
                label="Phase 1 · Passive Discovery",
                tier="passive",
                requires_approval=False,
                profiles=(
                    "passive-network-discovery",
                    "passive-lan-iot-discovery",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="active-enrichment",
                label="Phase 2 · Active Enrichment",
                tier="active",
                requires_approval=True,
                profiles=(
                    "passive-network-service-enumeration",
                    "passive-lan-infrastructure-audit",
                    "passive-lan-smb-enum",
                    "passive-identity-ldap-enum",
                    "passive-web-baseline",
                    "passive-web-nuclei-audit",
                    "active-ad-bloodhound",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="intrusive-credential",
                label="Phase 3 · Intrusive Credential Validation",
                tier="intrusive-credential",
                requires_approval=True,
                profiles=(
                    "intrusive-lan-credential-capture",
                    "active-ad-kerberoast",
                    "active-ad-asreproast",
                    "active-offline-hash-crack",
                    "intrusive-lan-smb-auth",
                    "intrusive-ad-password-spray",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="intrusive-exploitation",
                label="Phase 4 · Intrusive Exploitation",
                tier="intrusive-exploitation",
                requires_approval=True,
                never_auto_start=True,
                profiles=(
                    "intrusive-exploitation",
                    "intrusive-impacket-remote-exec",
                    "intrusive-impacket-secretsdump",
                    "intrusive-impacket-dcsync",
                ),
            ),
        ),
    ),
    "FULL-LAN-IOT": AssessmentChainDefinition(
        mode="FULL-LAN-IOT",
        label="Full LAN + IoT",
        phase_preapproval_allowed=False,
        phases=(
            AssessmentChainPhaseDefinition(
                key="iot-discovery",
                label="Phase 1 · Discovery",
                tier="passive",
                requires_approval=False,
                profiles=(
                    "passive-network-discovery",
                    "passive-lan-iot-discovery",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="iot-enumeration",
                label="Phase 2 · Enumeration",
                tier="active",
                requires_approval=True,
                profiles=(
                    "passive-network-service-enumeration",
                    "passive-lan-nse-full",
                    "passive-lan-snmp-enum",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="iot-service-analysis",
                label="Phase 3 · Service Analysis",
                tier="active",
                requires_approval=True,
                profiles=(
                    "passive-lan-smart-home-audit",
                    "active-lan-camera-audit",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="iot-credential-testing",
                label="Phase 4 · Credential Testing",
                tier="active",
                requires_approval=True,
                profiles=(
                    "active-lan-default-creds-audit",
                    "passive-lan-smb-enum",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="iot-segmentation",
                label="Phase 5 · Segmentation",
                tier="active",
                requires_approval=True,
                profiles=(
                    "passive-lan-segmentation-check",
                    "passive-lan-ipv6-discovery",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="iot-intrusive",
                label="Phase 6 · Optional Intrusive",
                tier="intrusive-credential",
                requires_approval=True,
                never_auto_start=True,
                profiles=(
                    "passive-lan-infrastructure-audit",
                    "intrusive-lan-credential-capture",
                ),
            ),
        ),
    ),
    "FULL-EXTERNAL-WEB": AssessmentChainDefinition(
        mode="FULL-EXTERNAL-WEB",
        label="Full External Web",
        phases=(
            AssessmentChainPhaseDefinition(
                key="passive-surface",
                label="Phase 1 · Passive Surface Mapping",
                tier="passive",
                requires_approval=False,
                profiles=(
                    "passive-easm-discovery",
                    "passive-web-baseline",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="active-web-validation",
                label="Phase 2 · Active Web Validation",
                tier="active",
                requires_approval=True,
                profiles=(
                    "passive-web-nuclei-audit",
                    "active-web-safe",
                    "passive-web-burp",
                    "active-business-logic",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="intrusive-confirmation",
                label="Phase 3 · Intrusive Confirmation",
                tier="intrusive-exploitation",
                requires_approval=True,
                never_auto_start=True,
                profiles=(
                    "active-llm-application-probe",
                    "intrusive-exploitation",
                ),
            ),
        ),
    ),
    "FULL-AD-ASSESSMENT": AssessmentChainDefinition(
        mode="FULL-AD-ASSESSMENT",
        label="Full AD Assessment",
        phases=(
            AssessmentChainPhaseDefinition(
                key="directory-baseline",
                label="Phase 1 · Directory Baseline",
                tier="passive",
                requires_approval=False,
                profiles=(
                    "passive-identity-ldap-enum",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="directory-enumeration",
                label="Phase 2 · Directory Enumeration",
                tier="active",
                requires_approval=True,
                profiles=(
                    "active-ad-bloodhound",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="credential-impact",
                label="Phase 3 · Credential Impact",
                tier="intrusive-credential",
                requires_approval=True,
                profiles=(
                    "active-ad-kerberoast",
                    "active-ad-asreproast",
                    "active-offline-hash-crack",
                    "intrusive-ad-password-spray",
                ),
            ),
            AssessmentChainPhaseDefinition(
                key="lateral-confirmation",
                label="Phase 4 · Lateral Confirmation",
                tier="intrusive-exploitation",
                requires_approval=True,
                never_auto_start=True,
                profiles=(
                    "intrusive-lan-smb-auth",
                    "intrusive-impacket-remote-exec",
                    "intrusive-impacket-secretsdump",
                    "intrusive-impacket-dcsync",
                ),
            ),
        ),
    ),
}


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _uuid_or_none(value: object) -> UUID | None:
    if value in {None, ""}:
        return None
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def normalize_assessment_mode(value: str) -> str:
    normalized = str(value or "").strip().upper()
    if normalized not in ASSESSMENT_CHAIN_DEFINITIONS:
        raise ValueError("unsupported assessment mode")
    return normalized


def normalize_chain_authorization_level(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in CHAIN_AUTHORIZATION_TIER_RANK:
        return "passive"
    return normalized


def _chain_authorization_from_configuration(configuration_json: dict[str, Any] | None) -> dict[str, Any]:
    payload = configuration_json if isinstance(configuration_json, dict) else {}
    assessment_mode = payload.get("assessment_mode")
    if not isinstance(assessment_mode, dict):
        return {
            "level": "passive",
            "confirmed_scope": "",
            "confirmation_target": "",
            "typed_scope_confirmation": "",
        }
    return {
        "level": normalize_chain_authorization_level(assessment_mode.get("authorization_level")),
        "confirmed_scope": str(assessment_mode.get("confirmed_scope") or "").strip(),
        "confirmation_target": str(assessment_mode.get("confirmation_target") or "").strip(),
        "typed_scope_confirmation": str(assessment_mode.get("typed_scope_confirmation") or "").strip(),
    }


def _normalized_scope_confirmation(value: object) -> str:
    return str(value or "").strip().rstrip("/").lower()


def _validate_chain_authorization(
    configuration_json: dict[str, Any] | None,
) -> dict[str, Any]:
    authorization = _chain_authorization_from_configuration(configuration_json)
    if authorization["level"] != "full":
        return authorization
    expected = _normalized_scope_confirmation(authorization["confirmation_target"])
    actual = _normalized_scope_confirmation(authorization["typed_scope_confirmation"])
    if not expected or actual != expected:
        raise ValueError("full authorization requires typed target confirmation")
    if not authorization["confirmed_scope"]:
        raise ValueError("full authorization requires confirmed scope context")
    return authorization


def _authorized_phase_tier_rank(chain: AssessmentChain) -> int:
    metadata = dict(chain.metadata_json or {})
    authorization = metadata.get("authorization")
    if not isinstance(authorization, dict):
        return CHAIN_AUTHORIZATION_TIER_RANK["passive"]
    return CHAIN_AUTHORIZATION_TIER_RANK.get(
        normalize_chain_authorization_level(authorization.get("level")),
        CHAIN_AUTHORIZATION_TIER_RANK["passive"],
    )


def _phase_is_pre_authorized(chain: AssessmentChain, phase: dict[str, Any] | None) -> bool:
    if not isinstance(phase, dict):
        return False
    return _phase_rank(phase) <= _authorized_phase_tier_rank(chain)


def _apply_chain_phase_preapproval(chain: AssessmentChain, phase: dict[str, Any]) -> bool:
    if not isinstance(phase, dict) or not bool(phase.get("requires_approval")):
        return False
    metadata = dict(chain.metadata_json or {})
    if metadata.get("phase_preapproval_allowed") is False:
        return False
    if phase.get("approved_at") or not _phase_is_pre_authorized(chain, phase):
        return False
    authorization = metadata.get("authorization")
    if not isinstance(authorization, dict):
        return False
    phase["approved_by"] = str(authorization.get("actor") or chain.created_by or "operator")
    phase["approved_at"] = str(authorization.get("confirmed_at") or _now().isoformat())
    phase["status"] = "active"
    return True


def _phase_states_for_definition(definition: AssessmentChainDefinition) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for index, phase in enumerate(definition.phases):
        states.append(
            {
                "key": phase.key,
                "label": phase.label,
                "tier": phase.tier,
                "status": "active" if index == 0 and not phase.requires_approval else "pending",
                "requires_approval": phase.requires_approval,
                "never_auto_start": phase.never_auto_start,
                "approved_by": None,
                "approved_at": None,
                "started_at": None,
                "completed_at": None,
                "steps": [
                    {
                        "profile_name": profile_name,
                        "status": "pending",
                        "run_id": None,
                        "skip_reason": None,
                    }
                    for profile_name in phase.profiles
                ],
            }
        )
    return states


def _phase_rank(phase: dict[str, Any]) -> int:
    return PHASE_TIER_RANK.get(str(phase.get("tier") or "").strip().lower(), 0)


def _current_phase(phases: list[dict[str, Any]], phase_index: int) -> dict[str, Any] | None:
    if phase_index < 0 or phase_index >= len(phases):
        return None
    return phases[phase_index]


def _run_ids_for_chain(session: Session, chain: AssessmentChain) -> set[str]:
    return {
        str(run_id)
        for run_id in session.scalars(
            select(Run.id).where(Run.assessment_chain_id == chain.id)
        ).all()
    }


def _chain_inventory_snapshots(
    session: Session,
    chain: AssessmentChain,
) -> list[InventorySnapshot]:
    run_ids = _run_ids_for_chain(session, chain)
    if not run_ids:
        return []

    snapshots = session.scalars(
        select(InventorySnapshot)
        .where(InventorySnapshot.engagement_id == chain.engagement_id)
        .order_by(InventorySnapshot.created_at.desc(), InventorySnapshot.id.desc())
    ).all()
    matching: list[InventorySnapshot] = []
    for snapshot in snapshots:
        raw_inputs = snapshot.raw_inputs_json if isinstance(snapshot.raw_inputs_json, dict) else {}
        if str(raw_inputs.get("run_id") or "") in run_ids:
            matching.append(snapshot)
    return matching


def _latest_chain_inventory_snapshot(
    session: Session,
    chain: AssessmentChain,
) -> InventorySnapshot | None:
    snapshots = _chain_inventory_snapshots(session, chain)
    return snapshots[0] if snapshots else None


def _append_unique(values: list[str], value: object) -> None:
    candidate = str(value or "").strip()
    if not candidate or candidate in values:
        return
    values.append(candidate)


def _hosts_from_inventory_snapshot(snapshot: InventorySnapshot | None) -> list[str]:
    if snapshot is None:
        return []
    normalized_inventory = (
        snapshot.normalized_inventory_json
        if isinstance(snapshot.normalized_inventory_json, dict)
        else {}
    )
    hosts: list[str] = []
    for entry in normalized_inventory.get("hosts") or []:
        if not isinstance(entry, dict):
            continue
        _append_unique(hosts, entry.get("host"))
    for entry in normalized_inventory.get("services") or []:
        if not isinstance(entry, dict):
            continue
        _append_unique(hosts, entry.get("host"))
    return hosts


def _hosts_from_inventory_snapshots(snapshots: list[InventorySnapshot]) -> list[str]:
    hosts: list[str] = []
    for snapshot in reversed(snapshots):
        for host in _hosts_from_inventory_snapshot(snapshot):
            _append_unique(hosts, host)
    return hosts


def _urls_from_inventory_snapshot(snapshot: InventorySnapshot | None) -> list[str]:
    if snapshot is None:
        return []
    normalized_inventory = (
        snapshot.normalized_inventory_json
        if isinstance(snapshot.normalized_inventory_json, dict)
        else {}
    )
    urls: list[str] = []
    for entry in normalized_inventory.get("http_endpoints") or []:
        if not isinstance(entry, dict):
            continue
        _append_unique(urls, entry.get("url"))
    return urls


def _urls_from_inventory_snapshots(snapshots: list[InventorySnapshot]) -> list[str]:
    urls: list[str] = []
    for snapshot in reversed(snapshots):
        for url in _urls_from_inventory_snapshot(snapshot):
            _append_unique(urls, url)
    return urls


def _service_entry_port(entry: dict[str, Any]) -> int | None:
    for key in ("port", "port_id", "portid"):
        value = entry.get(key)
        if isinstance(value, int):
            return value
        try:
            return int(str(value or "").strip())
        except ValueError:
            continue
    return None


def _ldap_hosts_from_inventory_snapshots(snapshots: list[InventorySnapshot]) -> list[str]:
    hosts: list[str] = []
    for snapshot in reversed(snapshots):
        normalized_inventory = (
            snapshot.normalized_inventory_json
            if isinstance(snapshot.normalized_inventory_json, dict)
            else {}
        )
        for entry in normalized_inventory.get("services") or []:
            if not isinstance(entry, dict):
                continue
            service_text = " ".join(
                str(entry.get(key) or "").lower()
                for key in ("name", "service", "product", "banner")
            )
            port = _service_entry_port(entry)
            if port not in {389, 636, 3268, 3269} and "ldap" not in service_text:
                continue
            _append_unique(hosts, entry.get("host"))
    return hosts


def _phase_has_skipped_steps(phase: dict[str, Any] | None) -> bool:
    if not isinstance(phase, dict):
        return False
    return any(
        str(step.get("status") or "").lower() == "skipped"
        for step in (phase.get("steps") if isinstance(phase.get("steps"), list) else [])
        if isinstance(step, dict)
    )


def _chain_has_skipped_steps(phases: list[dict[str, Any]]) -> bool:
    return any(_phase_has_skipped_steps(phase) for phase in phases)


def _completed_phase_status(phase: dict[str, Any]) -> str:
    return "completed_with_gaps" if _phase_has_skipped_steps(phase) else "completed"


def _set_follow_up_targets(
    configuration: dict[str, Any],
    *,
    hosts: list[str] | None = None,
    urls: list[str] | None = None,
    domains: list[str] | None = None,
) -> None:
    targets: dict[str, Any] = {}
    if hosts:
        targets["hosts"] = hosts
        targets["ip_addresses"] = hosts
    if urls:
        targets["urls"] = urls
    if domains:
        targets["domains"] = domains
    configuration["targets"] = targets


def _domain_targets_from_configuration(configuration: dict[str, Any]) -> list[str]:
    targets = configuration.get("targets")
    if not isinstance(targets, dict):
        return []
    domains: list[str] = []
    for key in ("ad_domains", "domains"):
        values = targets.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            _append_unique(domains, value)
    return domains


def _domain_to_base_dn(value: str) -> str:
    return ",".join(f"DC={label}" for label in str(value or "").split(".") if label)


def _int_at_least(value: object, minimum: int) -> int:
    try:
        return max(int(value or 0), minimum)
    except (TypeError, ValueError):
        return minimum


def _float_at_least(value: object, minimum: float) -> float:
    try:
        return max(float(value or 0), minimum)
    except (TypeError, ValueError):
        return minimum


def _apply_deep_lan_service_enumeration_defaults(configuration: dict[str, Any]) -> None:
    if str(configuration.get("assessment_type") or "").strip().lower() not in {
        "internal range / lan",
        "internal lan",
    }:
        return
    if str(configuration.get("test_profile") or "").strip().lower() != "deep":
        return

    nmap = dict(configuration.get("nmap") or {})
    nmap["discovery_only"] = False
    nmap["service_detection"] = True
    nmap["skip_discovery"] = True
    nmap["top_ports"] = _int_at_least(nmap.get("top_ports"), 1000)
    nmap["version_intensity"] = _int_at_least(nmap.get("version_intensity"), 5)
    nmap["timing_template"] = str(nmap.get("timing_template") or "T3")
    nmap["max_retries"] = _int_at_least(nmap.get("max_retries"), 2)
    nmap["host_timeout_seconds"] = _float_at_least(nmap.get("host_timeout_seconds"), 90.0)
    nmap["timeout_seconds"] = _float_at_least(nmap.get("timeout_seconds"), 180.0)
    configuration["nmap"] = nmap


def _configuration_has_host_targets(configuration: dict[str, Any]) -> bool:
    targets = configuration.get("targets")
    if not isinstance(targets, dict):
        return False
    for key in ("hosts", "ip_addresses", "directory_hosts", "ldap_hosts"):
        values = targets.get(key)
        if isinstance(values, list) and any(str(value or "").strip() for value in values):
            return True
    return False


def _cidr_targets_from_configuration(configuration: dict[str, Any]) -> list[str]:
    targets = configuration.get("targets")
    if not isinstance(targets, dict):
        return []
    cidrs: list[str] = []
    for key in ("cidr_ranges", "cidrs"):
        values = targets.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            candidate = str(value or "").strip()
            if candidate and candidate not in cidrs:
                cidrs.append(candidate)
    return cidrs


def _route_probe_ip_for_cidr(cidr: str) -> str | None:
    try:
        network = ip_network(str(cidr or "").strip(), strict=False)
    except ValueError:
        return None
    if network.num_addresses <= 1:
        return str(network.network_address)
    return str(next(network.hosts(), network.network_address))


def _route_interface_for_target(target: str) -> str | None:
    probe_ip = _route_probe_ip_for_cidr(target) or str(target or "").strip()
    if not probe_ip:
        return None
    try:
        result = subprocess.run(
            ["ip", "route", "get", probe_ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=2.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    parts = (result.stdout or "").split()
    for index, part in enumerate(parts[:-1]):
        if part == "dev":
            interface = parts[index + 1].strip()
            return interface or None
    return None


def _ensure_responder_interface(configuration: dict[str, Any]) -> None:
    responder = configuration.get("responder")
    if not isinstance(responder, dict):
        responder = {}
    if str(responder.get("interface") or "").strip():
        configuration["responder"] = responder
        return
    for cidr in _cidr_targets_from_configuration(configuration):
        interface = _route_interface_for_target(cidr)
        if interface:
            responder["interface"] = interface
            responder.setdefault("interface_source", "route-auto-detected")
            configuration["responder"] = responder
            return
    raise ValueError(
        "intrusive-lan-credential-capture requires responder.interface or a routable approved CIDR for interface auto-detection"
    )


def _chain_secret_refs(
    session: Session,
    chain: AssessmentChain,
    *,
    secret_kinds: set[str],
) -> list[SecretRef]:
    run_ids = _run_ids_for_chain(session, chain)
    if not run_ids:
        return []

    refs = session.scalars(
        select(SecretRef)
        .where(
            SecretRef.engagement_id == chain.engagement_id,
            SecretRef.secret_kind.in_(sorted(secret_kinds)),
        )
        .order_by(SecretRef.created_at.desc(), SecretRef.id.desc())
    ).all()
    matching: list[SecretRef] = []
    for ref in refs:
        metadata = ref.metadata_json if isinstance(ref.metadata_json, dict) else {}
        if str(metadata.get("run_id") or "") in run_ids:
            matching.append(ref)
    return matching


def _latest_allowlisted_finding(session: Session, chain: AssessmentChain) -> Finding | None:
    findings = session.scalars(
        select(Finding)
        .join(Run, Finding.run_id == Run.id)
        .where(Run.assessment_chain_id == chain.id)
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    ).all()
    for finding in findings:
        try:
            resolve_allowlisted_module(finding_context_for_runner(finding))
        except ValueError:
            continue
        return finding
    return None


def _phase_step_run_configuration(
    session: Session,
    chain: AssessmentChain,
    *,
    phase_key: str,
    step_index: int,
    profile_name: str,
) -> tuple[dict[str, Any], UUID | None]:
    configuration = copy.deepcopy(chain.configuration_json or {})
    latest_snapshot = _latest_chain_inventory_snapshot(session, chain)
    chain_snapshots = _chain_inventory_snapshots(session, chain)
    latest_hash_refs = _chain_secret_refs(
        session,
        chain,
        secret_kinds=HASH_BUNDLE_SECRET_KINDS,
    )
    latest_password_refs = _chain_secret_refs(
        session,
        chain,
        secret_kinds=PASSWORD_SECRET_KINDS,
    )
    allowlisted_finding = _latest_allowlisted_finding(session, chain)

    assessment_metadata = dict(configuration.get("assessment_mode") or {})
    assessment_metadata.update(
        {
            "enabled": True,
            "mode": chain.assessment_mode,
            "phase_key": phase_key,
            "step_index": step_index,
            "chain_id": str(chain.id),
            "auto_advance_on_phase_complete": bool(chain.auto_advance_on_phase_complete),
        }
    )
    configuration["assessment_mode"] = assessment_metadata

    source_inventory_snapshot_id = latest_snapshot.id if latest_snapshot is not None else None

    if profile_name == "passive-identity-ldap-enum":
        ldap_hosts = _ldap_hosts_from_inventory_snapshots(chain_snapshots)
        domain_targets = _domain_targets_from_configuration(configuration)
        if ldap_hosts:
            _set_follow_up_targets(configuration, hosts=ldap_hosts)
            if domain_targets:
                ldap = dict(configuration.get("ldap") or {})
                ldap.setdefault("base_dn", _domain_to_base_dn(domain_targets[0]))
                configuration["ldap"] = ldap
        elif domain_targets:
            _set_follow_up_targets(configuration, domains=domain_targets)
        else:
            raise ValueError(
                "passive-identity-ldap-enum requires a discovered LDAP service or AD domain target"
            )
    elif profile_name in HOST_FOLLOW_UP_PROFILES:
        discovered_hosts = _hosts_from_inventory_snapshots(chain_snapshots)
        if discovered_hosts:
            _set_follow_up_targets(configuration, hosts=discovered_hosts)
        elif not _configuration_has_host_targets(configuration):
            raise ValueError(
                f"{profile_name} requires discovered host inventory from an earlier chain step"
            )
    elif profile_name in {
        "passive-web-baseline",
        "passive-web-nuclei-audit",
    }:
        discovered_urls = _urls_from_inventory_snapshots(chain_snapshots)
        discovered_hosts = _hosts_from_inventory_snapshots(chain_snapshots)
        if discovered_urls:
            _set_follow_up_targets(configuration, urls=discovered_urls)
        elif discovered_hosts:
            _set_follow_up_targets(configuration, hosts=discovered_hosts)
        else:
            raise ValueError(
                f"{profile_name} requires discovered web targets or hosts from an earlier chain step"
            )

    if profile_name == "passive-network-service-enumeration":
        _apply_deep_lan_service_enumeration_defaults(configuration)

    if profile_name in {
        "active-ad-kerberoast",
        "active-ad-asreproast",
        "active-offline-hash-crack",
        "intrusive-ad-password-spray",
    }:
        if latest_snapshot is None:
            raise ValueError(
                "assessment chain has no inventory snapshot for credential-attack chaining"
            )

    if profile_name == "intrusive-lan-credential-capture":
        _ensure_responder_interface(configuration)
    elif profile_name == "active-offline-hash-crack":
        if not latest_hash_refs:
            raise ValueError("assessment chain has no protected hash bundles to crack yet")
        credential_attacks = dict(configuration.get("credential_attacks") or {})
        credential_attacks["hash_sources"] = [
            {
                "label": ref.display_label or f"Chain hash {index}",
                "secret_ref": ref.vault_pointer,
            }
            for index, ref in enumerate(latest_hash_refs[:5], start=1)
        ]
        configuration["credential_attacks"] = credential_attacks
    elif profile_name == "intrusive-ad-password-spray":
        if not latest_password_refs:
            raise ValueError(
                "assessment chain has no protected password candidates for spraying yet"
            )
        if latest_snapshot is None:
            raise ValueError("assessment chain has no inventory snapshot for spraying context")
        snapshot_inputs = (
            latest_snapshot.raw_inputs_json
            if isinstance(latest_snapshot.raw_inputs_json, dict)
            else {}
        )
        attack_context = (
            snapshot_inputs.get("credential_attack_context")
            if isinstance(snapshot_inputs.get("credential_attack_context"), dict)
            else {}
        )
        password_policy = (
            attack_context.get("password_policy")
            if isinstance(attack_context.get("password_policy"), dict)
            else {}
        )
        lockout_threshold = password_policy.get("lockout_threshold")
        candidate_accounts = []
        for key in ("kerberoastable_accounts", "asrep_roastable_accounts"):
            values = attack_context.get(key)
            if not isinstance(values, list):
                continue
            for row in values:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("account_name") or row.get("user_principal_name") or "").strip()
                if name and name not in candidate_accounts:
                    candidate_accounts.append(name)
        credential_attacks = dict(configuration.get("credential_attacks") or {})
        credential_attacks["password_candidates"] = [
            {
                "label": ref.display_label or f"Recovered password {index}",
                "password_ref": ref.vault_pointer,
            }
            for index, ref in enumerate(latest_password_refs[:5], start=1)
        ]
        if candidate_accounts:
            credential_attacks["spray_accounts"] = candidate_accounts[:25]
        if isinstance(lockout_threshold, int):
            credential_attacks["lockout_threshold_confirmed"] = lockout_threshold
            credential_attacks["attempts_per_window"] = max(
                1,
                min(
                    int(credential_attacks.get("attempts_per_window") or 1),
                    max(lockout_threshold - 1, 1),
                ),
            )
        configuration["credential_attacks"] = credential_attacks
    elif profile_name == "intrusive-exploitation":
        if allowlisted_finding is None:
            raise ValueError(
                "assessment chain has no allowlisted finding for exploitation confirmation yet"
            )
        _set_follow_up_targets(configuration, hosts=[allowlisted_finding.target_id])
        metasploit = dict(configuration.get("metasploit") or {})
        metasploit["finding_id"] = str(allowlisted_finding.id)
        configuration["metasploit"] = metasploit

    return configuration, source_inventory_snapshot_id


def _serialize_assessment_chain(chain: AssessmentChain) -> dict[str, Any]:
    phases = list(chain.phases_json or [])
    current_phase = _current_phase(phases, chain.current_phase_index)
    completed_phases = sum(
        1 for phase in phases if phase.get("status") in {"completed", "completed_with_gaps"}
    )
    operator_state = _assessment_chain_operator_state(chain, phases)
    return {
        "id": str(chain.id),
        "engagement_id": str(chain.engagement_id),
        "assessment_mode": chain.assessment_mode,
        "status": chain.status,
        "current_phase_index": chain.current_phase_index,
        "current_step_index": chain.current_step_index,
        "current_phase_key": current_phase.get("key") if current_phase else None,
        "current_run_id": str(chain.current_run_id) if chain.current_run_id else None,
        "last_completed_run_id": (
            str(chain.last_completed_run_id) if chain.last_completed_run_id else None
        ),
        "auto_advance_on_phase_complete": bool(chain.auto_advance_on_phase_complete),
        "halt_requested": bool(chain.halt_requested),
        "completed_phase_count": completed_phases,
        "phase_count": len(phases),
        "phases": copy.deepcopy(phases),
        "operator_state": operator_state,
        "created_at": chain.created_at.isoformat(),
        "updated_at": chain.updated_at.isoformat(),
    }


def build_assessment_chain_summary(chain: AssessmentChain | None) -> dict[str, Any]:
    if chain is None:
        return {}
    return _serialize_assessment_chain(chain)


def load_assessment_chain(session: Session, chain_id: UUID) -> AssessmentChain | None:
    return session.scalar(
        select(AssessmentChain)
        .options(
            selectinload(AssessmentChain.engagement),
            selectinload(AssessmentChain.current_run).selectinload(Run.profile),
            selectinload(AssessmentChain.last_completed_run).selectinload(Run.profile),
            selectinload(AssessmentChain.runs).selectinload(Run.profile),
        )
        .where(AssessmentChain.id == chain_id)
    )


def _store_chain_phases(chain: AssessmentChain, phases: list[dict[str, Any]]) -> None:
    chain.phases_json = phases
    flag_modified(chain, "phases_json")


def _chain_blocker_type(reason: str, *, default: str = "runtime_gap") -> str:
    normalized = reason.lower()
    if "profile" in normalized and "not available" in normalized:
        return "profile_unavailable"
    if "no in-scope targets" in normalized or "no eligible target" in normalized:
        return "no_in_scope_targets"
    if "credential" in normalized or "password" in normalized or "hash" in normalized or "access account" in normalized:
        return "missing_credentials"
    if "allowlisted finding" in normalized or "exploitation confirmation" in normalized:
        return "missing_exploitation_evidence"
    if "domain" in normalized or "ldap" in normalized or "ad_" in normalized or "ad " in normalized:
        return "missing_identity_context"
    if "inventory" in normalized or "discovered" in normalized or "service" in normalized or "web target" in normalized:
        return "missing_inventory_evidence"
    if "failed" in normalized or "did not complete" in normalized:
        return "runner_failure"
    return default


def _chain_safe_next_action(blocker_type: str, *, blocked: bool = False) -> str:
    if blocker_type == "profile_unavailable":
        return "Keep the remaining approved chain running; add or deploy this run profile before relaunching this coverage."
    if blocker_type == "no_in_scope_targets":
        return "Continue with the remaining planned checks; add matching in-scope targets in a new mission if this coverage is required."
    if blocker_type == "missing_credentials":
        return "Continue without credentialed checks, or add approved secret references and relaunch this tier."
    if blocker_type == "missing_exploitation_evidence":
        return "Continue without exploitation; only relaunch exploitation after an allowlisted finding and explicit scope confirmation exist."
    if blocker_type == "missing_identity_context":
        return "Continue with non-identity checks, or add AD/domain context and relaunch the identity tier."
    if blocker_type == "missing_inventory_evidence":
        return "Continue with remaining checks; review discovery evidence or rerun discovery if inventory should exist."
    if blocker_type == "runner_failure" and blocked:
        return "Review the failed run output, then use Review Failure & Continue only if the remaining planned checks are still safe."
    if blocker_type == "runner_failure":
        return "AegisPT recorded this as a non-blocking chain gap and continued with the remaining safe planned checks."
    return "Review the evidence and continue only when the remaining planned checks still match the approved scope."


def _annotate_chain_step_gap(
    step: dict[str, Any],
    *,
    reason: str,
    blocked: bool = False,
    decision: str | None = None,
) -> None:
    blocker_type = _chain_blocker_type(reason)
    step["skip_reason"] = reason
    step["blocker_type"] = blocker_type
    step["prerequisite"] = reason
    step["evidence"] = reason
    step["safe_next_action"] = _chain_safe_next_action(blocker_type, blocked=blocked)
    if decision:
        step["operator_next_action"] = decision


def _clear_chain_step_gap(step: dict[str, Any]) -> None:
    step["skip_reason"] = None
    for key in (
        "blocker_type",
        "prerequisite",
        "evidence",
        "safe_next_action",
        "operator_next_action",
    ):
        step.pop(key, None)


def _assessment_chain_operator_state(
    chain: AssessmentChain,
    phases: list[dict[str, Any]],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for phase_index, phase in enumerate(phases):
        for step_index, step in enumerate(phase.get("steps") if isinstance(phase.get("steps"), list) else []):
            if not isinstance(step, dict):
                continue
            status = str(step.get("status") or "pending").lower()
            rows.append(
                {
                    "phase_index": phase_index,
                    "step_index": step_index,
                    "phase_key": phase.get("key"),
                    "phase_label": phase.get("label"),
                    "profile_name": step.get("profile_name"),
                    "status": status,
                    "run_id": step.get("run_id"),
                    "reason": step.get("skip_reason") or step.get("evidence"),
                    "safe_next_action": step.get("safe_next_action"),
                }
            )
    active = next((row for row in rows if row["status"] == "running"), None)
    failed = next((row for row in rows if row["status"] == "failed"), None)
    pending = next((row for row in rows if row["status"] in {"pending", "queued"}), None)
    skipped = [row for row in rows if row["status"] == "skipped"]
    status = str(chain.status or "unknown").lower()
    if status == "blocked" and failed:
        safe_action = _chain_safe_next_action("runner_failure", blocked=True)
        primary_action = "Review Failure & Continue"
        now = failed
    elif active:
        safe_action = "Follow the active run in Mission Control or Live Agents; no extra dispatch action is required."
        primary_action = "Monitor Running Check"
        now = active
    elif status == "pending_phase_approval":
        safe_action = "Approve the next phase only if the displayed scope, tier, and prerequisites still match the authorization."
        primary_action = "Approve Next Phase"
        now = pending
    elif status == "completed_with_gaps":
        safe_action = "Review skipped checks and relaunch only the missing coverage with the required prerequisites."
        primary_action = "Review Gaps"
        now = skipped[0] if skipped else None
    elif status == "active" and pending:
        safe_action = "AegisPT will queue the next runnable check automatically once the current boundary clears."
        primary_action = "Wait For Chain"
        now = pending
    else:
        safe_action = "Review the chain plan and selected run state before taking action."
        primary_action = "Review Chain"
        now = active or pending or failed
    return {
        "status": status,
        "now": now,
        "next": pending,
        "primary_action": primary_action,
        "safe_next_action": safe_action,
        "skipped_count": len(skipped),
        "failed_count": len([row for row in rows if row["status"] == "failed"]),
        "running_count": len([row for row in rows if row["status"] == "running"]),
        "pending_count": len([row for row in rows if row["status"] in {"pending", "queued"}]),
    }


def _queue_chain_run(
    session: Session,
    *,
    chain: AssessmentChain,
    run: Run,
):
    scope = session.scalar(latest_scope_query(chain.engagement_id))
    if scope is None:
        raise ValueError("engagement scope missing during assessment-chain activation")
    return queue_run_tasks(session, run, scope, run.profile)


def _latest_run_failure_text(run: Run) -> str:
    snippets: list[str] = []
    for task in run.tasks or []:
        task_status = str(task.status or "").lower()
        if task_status not in {"failed", "cancelled"}:
            continue
        snippets.append(f"{task.tool} on {task.target_id} ended {task_status}")
        executions = sorted(
            task.executions or [],
            key=lambda execution: execution.created_at,
            reverse=True,
        )
        for execution in executions[:1]:
            stderr = str(execution.stderr_text or "").strip()
            stdout = str(execution.stdout_text or "").strip()
            detail = stderr or stdout
            if detail:
                snippets.append(detail[:500])
    return " | ".join(snippets)[:1200]


def _failed_chain_run_is_recoverable(
    *,
    phase: dict[str, Any],
    profile_name: str,
) -> bool:
    normalized_profile = str(profile_name or "").strip()
    if normalized_profile in CHAIN_CRITICAL_FAILURE_PROFILES:
        return False
    phase_key = str(phase.get("key") or "").strip()
    if phase_key == "passive-discovery":
        return False
    return True


def _record_recoverable_chain_failure_triage(
    session: Session,
    *,
    run: Run,
    step: dict[str, Any],
    phase: dict[str, Any],
    actor: str,
    reason: str,
) -> None:
    task = next((item for item in run.tasks or [] if str(item.status or "").lower() == "failed"), None)
    failure_text = _latest_run_failure_text(run)
    fallback_profile = run.profile.name if run.profile is not None else ""
    profile_name = str(step.get("profile_name") or fallback_profile).strip()
    observation = {
        "type": "chain_runtime_triage",
        "kind": "chain",
        "title": "Runner failure triaged",
        "summary": reason,
        "profile_name": profile_name,
        "phase_key": str(phase.get("key") or ""),
        "run_id": str(run.id),
    }
    if failure_text:
        observation["diagnostic"] = failure_text
    store_agent_reasoning_record(
        session=session,
        run=run,
        task=task,
        reasoning_type="chain_runtime_failure_triage",
        status="recorded",
        provider="deterministic-runtime-triage",
        confidence_score=0.91,
        context_snapshot={
            "run_id": str(run.id),
            "profile_name": profile_name,
            "run_status": run.status,
            "phase_key": str(phase.get("key") or ""),
            "step_status": step.get("status"),
            "failure_text": failure_text,
        },
        observations=[observation],
        hypotheses=[
            {
                "summary": "The runner failed after the chain had enough context to continue other planned checks.",
                "confidence": 0.91,
            }
        ],
        proposals=[],
        metadata={
            "auto_continue_applied": True,
            "reviewed_by": actor,
            "safe_action": "mark_step_skipped_and_continue_chain",
        },
    )


def _launch_next_chain_run(
    session: Session,
    *,
    chain: AssessmentChain,
    actor: str,
) -> Run | None:
    phases = copy.deepcopy(chain.phases_json or [])

    while True:
        phase = _current_phase(phases, chain.current_phase_index)
        if phase is None:
            chain.status = "completed_with_gaps" if _chain_has_skipped_steps(phases) else "completed"
            chain.current_run_id = None
            _store_chain_phases(chain, phases)
            return None

        if bool(chain.halt_requested):
            chain.status = "halted"
            chain.current_run_id = None
            _store_chain_phases(chain, phases)
            return None

        if phase.get("completed_at"):
            chain.current_phase_index += 1
            chain.current_step_index = 0
            continue

        if bool(phase.get("requires_approval")) and not phase.get("approved_at"):
            _apply_chain_phase_preapproval(chain, phase)
        if bool(phase.get("requires_approval")) and not phase.get("approved_at"):
            phase["status"] = "pending_approval"
            chain.status = "pending_phase_approval"
            chain.current_run_id = None
            _store_chain_phases(chain, phases)
            return None

        phase["status"] = "active"
        phase.setdefault("started_at", _now().isoformat())
        steps = phase.get("steps") if isinstance(phase.get("steps"), list) else []

        if chain.current_step_index >= len(steps):
            phase["status"] = _completed_phase_status(phase)
            phase["completed_at"] = _now().isoformat()
            chain.current_phase_index += 1
            chain.current_step_index = 0
            chain.current_run_id = None
            _store_chain_phases(chain, phases)
            continue

        step = steps[chain.current_step_index]
        if not isinstance(step, dict):
            chain.current_step_index += 1
            _store_chain_phases(chain, phases)
            continue
        if step.get("status") in {"completed", "skipped"}:
            chain.current_step_index += 1
            _store_chain_phases(chain, phases)
            continue

        profile_name = str(step.get("profile_name") or "").strip()
        profile = session.scalar(select(RunProfile).where(RunProfile.name == profile_name))
        if profile is None:
            step["status"] = "skipped"
            _annotate_chain_step_gap(
                step,
                reason=f"run profile {profile_name} is not available",
            )
            chain.current_step_index += 1
            _store_chain_phases(chain, phases)
            continue

        try:
            configuration_json, source_inventory_snapshot_id = _phase_step_run_configuration(
                session,
                chain,
                phase_key=str(phase.get("key") or ""),
                step_index=chain.current_step_index,
                profile_name=profile_name,
            )
            run = Run(
                engagement_id=chain.engagement_id,
                assessment_chain_id=chain.id,
                profile_id=profile.id,
                profile=profile,
                source_inventory_snapshot_id=source_inventory_snapshot_id,
                requested_by=actor,
                status="requested",
                configuration_json=configuration_json,
                autonomous_mode=False,
                autonomous_intrusive_allowed=False,
                created_at=_now(),
                updated_at=_now(),
            )
            session.add(run)
            session.flush()
            queued_tasks = _queue_chain_run(
                session,
                chain=chain,
                run=run,
            )
            if not queued_tasks:
                session.delete(run)
                session.flush()
                step["status"] = "skipped"
                _annotate_chain_step_gap(
                    step,
                    reason=f"{profile_name} had no in-scope targets to queue",
                )
                chain.current_step_index += 1
                _store_chain_phases(chain, phases)
                continue
        except ValueError as exc:
            step["status"] = "skipped"
            _annotate_chain_step_gap(step, reason=str(exc))
            chain.current_step_index += 1
            _store_chain_phases(chain, phases)
            continue

        step["status"] = "running"
        step["run_id"] = str(run.id)
        _clear_chain_step_gap(step)
        phase["status"] = "active"
        chain.current_run_id = run.id
        chain.status = "active"
        chain.metadata_json = {
            **dict(chain.metadata_json or {}),
            "last_dispatch_mode": "pending_chain_dispatch",
            "last_launched_profile": profile_name,
        }
        _store_chain_phases(chain, phases)
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_chain.run_launched",
            object_type="assessment_chain",
            object_id=str(chain.id),
            metadata={
                "run_id": str(run.id),
                "profile_name": profile_name,
                "phase_key": str(phase.get("key") or ""),
                "step_index": chain.current_step_index,
                "dispatch_mode": "pending_chain_dispatch",
            },
        )
        return run


def create_assessment_chain_launch(
    session: Session,
    *,
    engagement: Engagement,
    actor: str,
    settings: Settings,
    assessment_mode: str,
    auto_advance_on_phase_complete: bool,
    configuration_json: dict[str, Any],
) -> Run:
    normalized_mode = normalize_assessment_mode(assessment_mode)
    definition = ASSESSMENT_CHAIN_DEFINITIONS[normalized_mode]
    authorization = _validate_chain_authorization(configuration_json)
    effective_auto_advance = bool(auto_advance_on_phase_complete) or authorization["level"] in {
        "active",
        "full",
    }
    confirmed_at = _now().isoformat()
    chain = AssessmentChain(
        engagement_id=engagement.id,
        assessment_mode=definition.mode,
        status="active",
        current_phase_index=0,
        current_step_index=0,
        auto_advance_on_phase_complete=effective_auto_advance,
        halt_requested=False,
        created_by=actor,
        phases_json=_phase_states_for_definition(definition),
        configuration_json=copy.deepcopy(configuration_json or {}),
        metadata_json={
            "label": definition.label,
            "phase_preapproval_allowed": definition.phase_preapproval_allowed,
            "authorization": {
                "level": authorization["level"],
                "actor": actor,
                "confirmed_at": confirmed_at,
                "confirmed_scope": authorization["confirmed_scope"],
                "confirmation_target": authorization["confirmation_target"],
                "typed_scope_confirmation": authorization["typed_scope_confirmation"]
                if authorization["level"] == "full"
                else "",
            },
        },
    )
    session.add(chain)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_chain.created",
        object_type="assessment_chain",
        object_id=str(chain.id),
        metadata={
            "engagement_id": str(engagement.id),
            "assessment_mode": chain.assessment_mode,
            "auto_advance_on_phase_complete": bool(chain.auto_advance_on_phase_complete),
        },
    )

    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_chain.authorization_confirmed",
        object_type="assessment_chain",
        object_id=str(chain.id),
        metadata={
            "engagement_id": str(engagement.id),
            "assessment_mode": chain.assessment_mode,
            "authorization_level": authorization["level"],
            "confirmed_scope": authorization["confirmed_scope"],
            "confirmation_target": authorization["confirmation_target"],
            "typed_scope_confirmation": authorization["typed_scope_confirmation"]
            if authorization["level"] == "full"
            else None,
        },
    )

    launched_run = _launch_next_chain_run(
        session,
        chain=chain,
        actor=actor,
    )
    session.flush()
    if chain.current_run_id is not None:
        hydrated_run = load_run(session, chain.current_run_id)
        if hydrated_run is not None:
            return hydrated_run
    if launched_run is not None:
        hydrated_run = load_run(session, launched_run.id)
        if hydrated_run is not None:
            return hydrated_run
    if chain.last_completed_run_id is not None:
        hydrated_run = load_run(session, chain.last_completed_run_id)
        if hydrated_run is not None:
            return hydrated_run
    raise ValueError("assessment chain did not produce a launchable run")


def dispatch_assessment_chain_current_run(
    session: Session,
    *,
    chain_id: UUID,
    actor: str,
    settings: Settings,
    background_tasks=None,
) -> str | None:
    chain = load_assessment_chain(session, chain_id)
    if chain is None or chain.current_run_id is None:
        return None
    run = load_run(session, chain.current_run_id)
    if run is None:
        return None
    try:
        dispatch_mode, _ = dispatch_queued_run_tasks(
            session,
            run=run,
            actor=actor,
            settings=settings,
            background_tasks=background_tasks,
        )
    except ValueError as exc:
        if str(exc) != "run has no queued tasks to dispatch":
            raise
        return None
    chain.metadata_json = {
        **dict(chain.metadata_json or {}),
        "last_dispatch_mode": dispatch_mode,
    }
    return dispatch_mode


def approve_assessment_chain_phase(
    session: Session,
    *,
    chain: AssessmentChain,
    phase_key: str,
    actor: str,
    settings: Settings,
    decision: str = "approved",
) -> AssessmentChain:
    if chain.status in TERMINAL_CHAIN_STATUSES:
        raise ValueError("assessment chain is already terminal")
    phases = copy.deepcopy(chain.phases_json or [])
    phase = _current_phase(phases, chain.current_phase_index)
    if phase is None:
        raise ValueError("assessment chain has no pending phase")
    if str(phase.get("key") or "") != str(phase_key or "").strip():
        raise ValueError("assessment chain is not waiting on that phase")
    if not bool(phase.get("requires_approval")):
        raise ValueError("current phase does not require approval")

    if decision == "rejected":
        phase["status"] = "rejected"
        phase["approved_by"] = actor
        phase["approved_at"] = _now().isoformat()
        chain.status = "rejected"
        chain.current_run_id = None
        _store_chain_phases(chain, phases)
        return chain

    phase["approved_by"] = actor
    phase["approved_at"] = _now().isoformat()
    phase["status"] = "active"
    chain.status = "active"
    chain.halt_requested = False
    _store_chain_phases(chain, phases)
    _launch_next_chain_run(
        session,
        chain=chain,
        actor=actor,
    )
    return chain


def halt_assessment_chain_at_boundary(
    session: Session,
    *,
    chain: AssessmentChain,
    actor: str,
) -> AssessmentChain:
    if chain.status in TERMINAL_CHAIN_STATUSES:
        return chain
    if chain.current_run_id is not None:
        raise ValueError("assessment chain can only halt at a phase boundary")
    chain.halt_requested = True
    chain.status = "halted"
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_chain.halted",
        object_type="assessment_chain",
        object_id=str(chain.id),
        metadata={
            "engagement_id": str(chain.engagement_id),
            "assessment_mode": chain.assessment_mode,
        },
    )
    return chain


def continue_assessment_chain_after_blocked_step(
    session: Session,
    *,
    chain: AssessmentChain,
    actor: str,
    settings: Settings,
) -> AssessmentChain:
    if chain.status != "blocked":
        raise ValueError("assessment chain is not blocked")

    phases = copy.deepcopy(chain.phases_json or [])
    phase = _current_phase(phases, chain.current_phase_index)
    if phase is None:
        raise ValueError("assessment chain has no current blocked phase")

    steps = phase.get("steps") if isinstance(phase.get("steps"), list) else []
    failed_index = next(
        (
            index
            for index, step in enumerate(steps)
            if str(step.get("status") or "").lower() == "failed"
        ),
        None,
    )
    if failed_index is None:
        raise ValueError("blocked assessment chain has no failed runner to review")

    failed_step = steps[failed_index]
    failed_step["status"] = "skipped"
    _annotate_chain_step_gap(
        failed_step,
        reason="Operator reviewed the failed runner and continued the assessment chain.",
        decision="Continue remaining planned checks after operator review.",
    )
    failed_step["reviewed_by"] = actor
    failed_step["reviewed_at"] = _now().isoformat()
    failed_step["review_decision"] = "continue_after_failure"

    phase["status"] = "active"
    chain.status = "active"
    chain.current_run_id = None
    chain.current_step_index = max(chain.current_step_index, failed_index + 1)
    chain.metadata_json = {
        **dict(chain.metadata_json or {}),
        "last_blocked_runner_review": {
            "phase_key": str(phase.get("key") or ""),
            "step_index": failed_index,
            "profile_name": str(failed_step.get("profile_name") or ""),
            "failed_run_id": str(failed_step.get("run_id") or ""),
            "reviewed_by": actor,
            "reviewed_at": failed_step["reviewed_at"],
        },
    }
    _store_chain_phases(chain, phases)
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_chain.blocked_step_continued",
        object_type="assessment_chain",
        object_id=str(chain.id),
        metadata={
            "engagement_id": str(chain.engagement_id),
            "assessment_mode": chain.assessment_mode,
            "phase_key": str(phase.get("key") or ""),
            "step_index": failed_index,
            "profile_name": str(failed_step.get("profile_name") or ""),
            "failed_run_id": str(failed_step.get("run_id") or ""),
        },
    )
    _launch_next_chain_run(
        session,
        chain=chain,
        actor=actor,
    )
    return chain


def auto_continue_recoverable_blocked_assessment_chain(
    session: Session,
    *,
    chain: AssessmentChain,
    actor: str,
    settings: Settings,
) -> AssessmentChain:
    if chain.status != "blocked":
        return chain

    phases = copy.deepcopy(chain.phases_json or [])
    phase = _current_phase(phases, chain.current_phase_index)
    if phase is None:
        return chain

    steps = phase.get("steps") if isinstance(phase.get("steps"), list) else []
    failed_index = next(
        (
            index
            for index, step in enumerate(steps)
            if str(step.get("status") or "").lower() == "failed"
        ),
        None,
    )
    if failed_index is None:
        return chain

    failed_step = steps[failed_index]
    profile_name = str(failed_step.get("profile_name") or "").strip()
    if not _failed_chain_run_is_recoverable(phase=phase, profile_name=profile_name):
        return chain

    failed_run_id = _uuid_or_none(failed_step.get("run_id"))
    failed_run = (
        session.scalar(
            select(Run)
            .options(
                selectinload(Run.profile),
                selectinload(Run.tasks).selectinload(Task.executions),
            )
            .where(Run.id == failed_run_id, Run.deleted_at.is_(None))
        )
        if failed_run_id is not None
        else None
    )
    reason = (
        f"{profile_name or 'Runner'} did not complete cleanly; AegisPT recorded this "
        "as a non-blocking chain gap and continued with the remaining planned checks."
    )
    failed_step["status"] = "skipped"
    _annotate_chain_step_gap(failed_step, reason=reason)
    failed_step["reviewed_by"] = "system:auto-triage"
    failed_step["reviewed_at"] = _now().isoformat()
    failed_step["review_decision"] = "auto_continue_after_recoverable_failure"
    if failed_run_id is not None:
        failed_step["failed_run_id"] = str(failed_run_id)
    failed_step["failure_triage"] = {
        "provider": "deterministic-runtime-triage",
        "reason": reason,
        "critical_failure": False,
    }
    if failed_run is not None:
        _record_recoverable_chain_failure_triage(
            session,
            run=failed_run,
            step=failed_step,
            phase=phase,
            actor=actor,
            reason=reason,
        )

    phase["status"] = "active"
    chain.status = "active"
    chain.current_run_id = None
    chain.current_step_index = max(chain.current_step_index, failed_index + 1)
    _store_chain_phases(chain, phases)
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_chain.recoverable_step_auto_continued",
        object_type="assessment_chain",
        object_id=str(chain.id),
        metadata={
            "engagement_id": str(chain.engagement_id),
            "assessment_mode": chain.assessment_mode,
            "phase_key": str(phase.get("key") or ""),
            "step_index": failed_index,
            "profile_name": profile_name,
            "failed_run_id": str(failed_run_id) if failed_run_id else None,
        },
    )
    _launch_next_chain_run(
        session,
        chain=chain,
        actor=actor,
    )
    return chain


def advance_assessment_chain_for_completed_run(
    session: Session,
    *,
    run_id: UUID,
    actor: str,
    settings: Settings,
) -> AssessmentChain | None:
    run = session.scalar(
        select(Run)
        .options(
            selectinload(Run.profile),
            selectinload(Run.assessment_chain),
            selectinload(Run.tasks).selectinload(Task.executions),
        )
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )
    if run is None or run.assessment_chain is None:
        return None

    chain = load_assessment_chain(session, run.assessment_chain.id)
    if chain is None or chain.status in TERMINAL_CHAIN_STATUSES:
        return chain

    phases = copy.deepcopy(chain.phases_json or [])
    phase = _current_phase(phases, chain.current_phase_index)
    if phase is None:
        chain.status = "completed"
        chain.current_run_id = None
        _store_chain_phases(chain, phases)
        return chain

    steps = phase.get("steps") if isinstance(phase.get("steps"), list) else []
    matched_step_index = None
    for index, step in enumerate(steps):
        if str(step.get("run_id") or "") == str(run.id):
            matched_step_index = index
            break
    if matched_step_index is None:
        return chain

    step = steps[matched_step_index]
    chain.current_run_id = None
    chain.last_completed_run_id = run.id

    if run.status == "completed":
        step["status"] = "completed"
        phase["status"] = "active"
        chain.current_step_index = matched_step_index + 1
    elif run.status in {"cancelled", "cancelling"}:
        step["status"] = "cancelled"
        phase["status"] = "cancelled"
        chain.status = "cancelled"
        _store_chain_phases(chain, phases)
        return chain
    else:
        profile_name = str(step.get("profile_name") or (run.profile.name if run.profile else "")).strip()
        if _failed_chain_run_is_recoverable(phase=phase, profile_name=profile_name):
            reason = (
                f"{profile_name or 'Runner'} did not complete cleanly; AegisPT recorded this "
                "as a non-blocking chain gap and continued with the remaining planned checks."
            )
            step["status"] = "skipped"
            _annotate_chain_step_gap(step, reason=reason)
            step["reviewed_by"] = "system:auto-triage"
            step["reviewed_at"] = _now().isoformat()
            step["review_decision"] = "auto_continue_after_recoverable_failure"
            step["failed_run_id"] = str(run.id)
            step["failure_triage"] = {
                "provider": "deterministic-runtime-triage",
                "reason": reason,
                "critical_failure": False,
            }
            _record_recoverable_chain_failure_triage(
                session,
                run=run,
                step=step,
                phase=phase,
                actor=actor,
                reason=reason,
            )
            phase["status"] = "active"
            chain.current_step_index = matched_step_index + 1
        else:
            step["status"] = "failed"
            _annotate_chain_step_gap(
                step,
                reason=(
                    f"{profile_name or 'Runner'} did not complete cleanly and is a critical "
                    "chain boundary that requires operator review."
                ),
                blocked=True,
                decision="Review failed run evidence, then continue only if remaining checks are safe.",
            )
            phase["status"] = "blocked"
            chain.status = "blocked"
            _store_chain_phases(chain, phases)
            return chain

    if chain.current_step_index >= len(steps):
        phase["status"] = _completed_phase_status(phase)
        phase["completed_at"] = _now().isoformat()
        next_phase_index = chain.current_phase_index + 1
        next_phase = _current_phase(phases, next_phase_index)
        if next_phase is None:
            chain.status = "completed_with_gaps" if _chain_has_skipped_steps(phases) else "completed"
            chain.current_phase_index = next_phase_index
            chain.current_step_index = 0
            _store_chain_phases(chain, phases)
            return chain

        chain.current_phase_index = next_phase_index
        chain.current_step_index = 0
        next_phase_requires_approval = bool(next_phase.get("requires_approval"))
        previous_rank = _phase_rank(phase)
        next_rank = _phase_rank(next_phase)
        next_phase_pre_authorized = _phase_is_pre_authorized(chain, next_phase)
        if (
            (bool(next_phase.get("never_auto_start")) and not next_phase_pre_authorized)
            or (next_phase_requires_approval and not next_phase_pre_authorized)
            or not bool(chain.auto_advance_on_phase_complete)
            or (next_rank > previous_rank and not next_phase_pre_authorized)
        ):
            next_phase["status"] = "pending_approval"
            chain.status = "pending_phase_approval"
            _store_chain_phases(chain, phases)
            return chain

    _store_chain_phases(chain, phases)
    _launch_next_chain_run(
        session,
        chain=chain,
        actor=actor,
    )
    return chain
