from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace

from api.app.config import get_settings
from api.app.methodology import derive_finding_methodology
from api.app.models import EvidenceArtifact as EvidenceArtifactRecord
from api.app.models import Finding, Task
from api.app.services.ai_enrichment import enrich_finding_async
from api.app.services.audit import write_audit_event
from api.app.services.finding_quality import finding_quality_view
from api.app.services.finding_sla import apply_finding_sla
from workers.runners.api_assessment.runner import API_ASSESSMENT_RESULTS_ARTIFACT_NAME
from workers.runners.auth_flow.runner import AUTH_FLOW_RESULTS_ARTIFACT_NAME
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.biz_logic.runner import BIZ_LOGIC_ARTIFACT_NAME
from workers.runners.bloodhound.runner import BLOODHOUND_RESULTS_ARTIFACT_NAME
from workers.runners.burp.runner import BURP_RESULTS_ARTIFACT_NAME
from workers.runners.c2_ingest.runner import C2_INGEST_RESULTS_ARTIFACT_NAME
from workers.runners.camera_test.runner import CAMERA_TEST_RESULTS_ARTIFACT_NAME
from workers.runners.cicd_security.runner import CICD_SECURITY_RESULTS_ARTIFACT_NAME
from workers.runners.client_state.runner import CLIENT_STATE_RESULTS_ARTIFACT_NAME
from workers.runners.cloud_native.runner import CLOUD_NATIVE_RESULTS_ARTIFACT_NAME
from workers.runners.credential_attacks.runner import (
    CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME,
)
from workers.runners.crypto_audit.runner import CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME
from workers.runners.deserialization_probe.runner import DESERIALIZATION_RESULTS_ARTIFACT_NAME
from workers.runners.desktop_client.runner import DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME
from workers.runners.external_infra.runner import EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME
from workers.runners.graphql_command_injection.runner import (
    GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME,
)
from workers.runners.graphql_probe.runner import GRAPHQL_RESULTS_ARTIFACT_NAME
from workers.runners.headers_security.runner import HEADERS_SECURITY_RESULTS_ARTIFACT_NAME
from workers.runners.http_smuggling.runner import HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME
from workers.runners.idor_bac.runner import IDOR_BAC_ARTIFACT_NAME
from workers.runners.impacket.runner import IMPACKET_RESULTS_ARTIFACT_NAME
from workers.runners.iot_default_creds.runner import IOT_DEFAULT_CREDS_ARTIFACT_NAME
from workers.runners.ipv6_discovery.runner import IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME
from workers.runners.ldap_enum.runner import LDAP_ENUM_ARTIFACT_NAME
from workers.runners.leak_check.runner import LEAK_CHECK_RESULTS_ARTIFACT_NAME
from workers.runners.llm_probe import LLM_PROBE_ARTIFACT_NAME
from workers.runners.logging_probe.runner import LOGGING_PROBE_RESULTS_ARTIFACT_NAME
from workers.runners.malware_sim.runner import MALWARE_SIM_RESULTS_ARTIFACT_NAME
from workers.runners.mdns_ssdp.runner import MDNS_SSDP_ARTIFACT_NAME
from workers.runners.metasploit.runner import METASPLOIT_RESULTS_ARTIFACT_NAME
from workers.runners.mobile_android.runner import MOBILE_ANDROID_RESULTS_ARTIFACT_NAME
from workers.runners.netexec.runner import NETEXEC_RESULTS_ARTIFACT_NAME
from workers.runners.network_capture.runner import NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME
from workers.runners.network_segmentation.runner import NETWORK_SEGMENTATION_ARTIFACT_NAME
from workers.runners.oauth_probe.runner import OAUTH_PROBE_RESULTS_ARTIFACT_NAME
from workers.runners.playwright_web.runner import PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME
from workers.runners.priv_esc_linux.runner import PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME
from workers.runners.responder.runner import RESPONDER_RESULTS_ARTIFACT_NAME
from workers.runners.semgrep.runner import normalize_semgrep_rule_id
from workers.runners.session_security.runner import SESSION_SECURITY_RESULTS_ARTIFACT_NAME
from workers.runners.smart_home.runner import SMART_HOME_RESULTS_ARTIFACT_NAME
from workers.runners.smart_web_probe.runner import SMART_PROBE_RESULTS_ARTIFACT_NAME
from workers.runners.snmp_enum.runner import SNMP_ENUM_RESULTS_ARTIFACT_NAME
from workers.runners.social_campaign.runner import SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME
from workers.runners.ssh_brute.runner import SSH_BRUTE_RESULTS_ARTIFACT_NAME
from workers.runners.ssrf_probe.runner import SSRF_RESULTS_ARTIFACT_NAME
from workers.runners.ssti_probe.runner import SSTI_RESULTS_ARTIFACT_NAME
from workers.runners.waf_detect.runner import WAF_DETECT_RESULTS_ARTIFACT_NAME
from workers.runners.web_depth.runner import (
    CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME,
    EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME,
    JWT_RESULTS_ARTIFACT_NAME,
    NIKTO_RESULTS_ARTIFACT_NAME,
    SQLMAP_RESULTS_ARTIFACT_NAME,
    VULN_COMPONENTS_RESULTS_ARTIFACT_NAME,
    XXE_RESULTS_ARTIFACT_NAME,
)
from workers.runners.wifi_survey.runner import WIFI_SURVEY_RESULTS_ARTIFACT_NAME
from workers.runners.xss_extended.runner import XSS_EXTENDED_RESULTS_ARTIFACT_NAME
from workers.runners.xss_proof.runner import XSS_PROOF_RESULTS_ARTIFACT_NAME


@dataclass(slots=True, frozen=True)
class NormalizedFinding:
    title: str
    severity: str
    target_id: str
    evidence_ref: str
    summary: str | None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    methodology_tags: tuple[str, ...] = ()
    ptes_phase: str | None = None
    nist_phase: str | None = None
    wstg_id: str | None = None
    wstg_version: str | None = None
    asvs_reference: str | None = None
    control_family: str | None = None
    finding_origin: str = "standard"
    source_pack_id: uuid.UUID | None = None
    source_pack_artifact_id: uuid.UUID | None = None
    source_inventory_snapshot_id: uuid.UUID | None = None
    source_relevance_decision_id: uuid.UUID | None = None
    source_pack_version: str | None = None
    replay_recipe_json: dict | None = None


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def normalize_severity(raw_severity: str | None) -> str:
    normalized = (raw_severity or "").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(normalized, "unknown")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, SEVERITY_ORDER["unknown"])


def finding_signature(*, title: str, target_id: str) -> tuple[str, str]:
    return (title.strip().lower(), target_id.strip().lower())


def _uuid_or_none(value: object) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return uuid.UUID(value.strip())
        except ValueError:
            return None
    return None


def _parse_cvss_score(*values: object) -> float | None:
    for value in values:
        if value is None:
            continue
        try:
            score = float(str(value).strip())
        except (TypeError, ValueError):
            continue
        if 0.0 <= score <= 10.0:
            return score
    return None


def _parse_cvss_vector(*values: object) -> str | None:
    for value in values:
        if not isinstance(value, str):
            continue
        vector = value.strip()
        if vector:
            return vector[:64]
    return None


def merge_finding(existing: Finding, incoming: NormalizedFinding) -> bool:
    changed = False

    if severity_rank(incoming.severity) < severity_rank(existing.severity):
        existing.severity = incoming.severity
        changed = True
    if existing.evidence_ref != incoming.evidence_ref:
        existing.evidence_ref = incoming.evidence_ref
        changed = True
    if incoming.summary and existing.summary != incoming.summary:
        existing.summary = incoming.summary
        changed = True
    existing_tags = [
        tag for tag in (existing.methodology_tags or []) if isinstance(tag, str) and tag.strip()
    ]
    incoming_tags = [
        tag for tag in incoming.methodology_tags if isinstance(tag, str) and tag.strip()
    ]
    merged_tags = list(dict.fromkeys([*existing_tags, *incoming_tags]))
    if merged_tags != existing_tags:
        existing.methodology_tags = merged_tags
        changed = True
    for field_name in (
        "ptes_phase",
        "nist_phase",
        "wstg_id",
        "wstg_version",
        "asvs_reference",
        "control_family",
        "source_pack_version",
    ):
        existing_value = getattr(existing, field_name)
        incoming_value = getattr(incoming, field_name)
        if incoming_value and not existing_value:
            setattr(existing, field_name, incoming_value)
            changed = True
    for field_name in (
        "source_pack_id",
        "source_pack_artifact_id",
        "source_inventory_snapshot_id",
        "source_relevance_decision_id",
    ):
        existing_value = getattr(existing, field_name)
        incoming_value = getattr(incoming, field_name)
        if incoming_value is not None and existing_value is None:
            setattr(existing, field_name, incoming_value)
            changed = True
    if incoming.finding_origin == "adaptive_pack" and existing.finding_origin != "adaptive_pack":
        existing.finding_origin = incoming.finding_origin
        changed = True
    if existing.status == "resolved":
        existing.status = "reopened"
        changed = True
    if incoming.replay_recipe_json and not existing.replay_recipe_json:
        existing.replay_recipe_json = dict(incoming.replay_recipe_json)
        changed = True
    if incoming.cvss_score is not None and existing.cvss_score != incoming.cvss_score:
        existing.cvss_score = incoming.cvss_score
        changed = True
    if incoming.cvss_vector and existing.cvss_vector != incoming.cvss_vector:
        existing.cvss_vector = incoming.cvss_vector
        changed = True

    return changed


def enrich_finding_with_methodology(*, finding: NormalizedFinding, task: Task) -> NormalizedFinding:
    pack_context = task.params_json.get("capability_pack", {})
    if not isinstance(pack_context, dict):
        pack_context = {}
    methodology = derive_finding_methodology(
        title=finding.title,
        summary=finding.summary,
        tool=task.tool,
        run_class=str(task.params_json.get("run_class") or ""),
    )
    pack_tags = [
        tag
        for tag in pack_context.get("methodology_tags", [])
        if isinstance(tag, str) and tag.strip()
    ]
    derived_tags = [
        tag
        for tag in methodology.get("methodology_tags", [])
        if isinstance(tag, str) and tag.strip()
    ]
    artifact_refs = pack_context.get("artifact_refs", [])
    first_artifact_id = None
    if isinstance(artifact_refs, list):
        for artifact_ref in artifact_refs:
            if not isinstance(artifact_ref, dict):
                continue
            first_artifact_id = _uuid_or_none(artifact_ref.get("artifact_id"))
            if first_artifact_id is not None:
                break
    enriched = replace(
        finding,
        methodology_tags=tuple(
            dict.fromkeys([*finding.methodology_tags, *pack_tags, *derived_tags])
        ),
        ptes_phase=finding.ptes_phase or (str(methodology.get("ptes_phase") or "") or None),
        nist_phase=finding.nist_phase or (str(methodology.get("nist_phase") or "") or None),
        wstg_id=finding.wstg_id or (str(methodology.get("wstg_id") or "") or None),
        wstg_version=finding.wstg_version or (str(methodology.get("wstg_version") or "") or None),
        asvs_reference=finding.asvs_reference
        or (str(methodology.get("asvs_reference") or "") or None),
        control_family=finding.control_family
        or (str(methodology.get("control_family") or "") or None),
        finding_origin="adaptive_pack" if pack_context.get("pack_id") else finding.finding_origin,
        source_pack_id=_uuid_or_none(pack_context.get("pack_id")),
        source_pack_artifact_id=first_artifact_id,
        source_inventory_snapshot_id=_uuid_or_none(
            pack_context.get("source_inventory_snapshot_id")
        ),
        source_relevance_decision_id=_uuid_or_none(pack_context.get("relevance_decision_id")),
        source_pack_version=str(pack_context.get("version") or "") or None,
    )
    quality = finding_quality_view(enriched)
    quality_tags = tuple(str(tag) for tag in quality["owasp"].get("tags", []) if str(tag).strip())
    return replace(
        enriched,
        cvss_score=(
            enriched.cvss_score if enriched.cvss_score is not None else quality["cvss"]["score"]
        ),
        cvss_vector=enriched.cvss_vector or quality["cvss"].get("vector"),
        methodology_tags=tuple(dict.fromkeys([*enriched.methodology_tags, *quality_tags])),
    )


def _scope_allowlist_for_task(task: Task) -> list[str]:
    run = getattr(task, "run", None)
    engagement = getattr(run, "engagement", None)
    scopes = list(getattr(engagement, "scopes", []) or [])
    scopes.sort(key=lambda item: (item.created_at, item.id.hex), reverse=True)
    for scope in scopes:
        allowlist = getattr(scope, "allowlist_json", None)
        if isinstance(allowlist, list):
            return [str(item) for item in allowlist]
        if isinstance(allowlist, dict):
            values: list[str] = []
            for key in ("cidr_ranges", "hosts", "urls", "ip_addresses", "targets"):
                raw_items = allowlist.get(key)
                if isinstance(raw_items, list):
                    values.extend(str(item) for item in raw_items if str(item).strip())
            if values:
                return values
    configuration = getattr(run, "configuration_json", {}) if run is not None else {}
    if isinstance(configuration, dict):
        targets = configuration.get("targets")
        if isinstance(targets, dict):
            values: list[str] = []
            for key in ("cidr_ranges", "hosts", "urls", "ip_addresses", "targets"):
                raw_items = targets.get(key)
                if isinstance(raw_items, list):
                    values.extend(str(item) for item in raw_items if str(item).strip())
            if values:
                return values
    return []


def _expected_match_pattern(finding: NormalizedFinding) -> str:
    for value in (finding.title, finding.target_id, finding.summary or ""):
        normalized = str(value or "").strip()
        if normalized:
            return normalized
    return "finding evidence match"


def build_replay_recipe(
    *,
    task: Task,
    finding: NormalizedFinding,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> dict[str, object]:
    execution = getattr(artifact_record, "execution", None)
    return {
        "tool": task.tool,
        "tool_version": getattr(execution, "tool_version", None) or "unknown",
        "target": finding.target_id or task.target_id,
        "params_json": dict(task.params_json or {}),
        "scope_allowlist": _scope_allowlist_for_task(task),
        "expected_match_pattern": _expected_match_pattern(finding),
        "artifact": {
            "id": str(artifact_record.id),
            "name": artifact.name,
            "uri": artifact_record.uri,
            "sha256": artifact_record.sha256,
        },
    }


def extract_findings(
    *,
    task: Task,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if task.tool == "nuclei":
        return extract_nuclei_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "burp":
        return extract_burp_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "zap":
        return extract_zap_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "semgrep":
        return extract_semgrep_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "ldap-enum":
        return extract_ldap_enum_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "bloodhound-collect":
        return extract_bloodhound_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "credential-attacks":
        return extract_credential_attack_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "external-infra":
        return extract_external_infra_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "mdns-ssdp":
        return extract_mdns_ssdp_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "iot-default-creds":
        return extract_iot_default_credential_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "network-segmentation":
        return extract_network_segmentation_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "network-capture":
        return extract_network_capture_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "snmp-enum":
        return extract_snmp_enum_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "smart-home":
        return extract_smart_home_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "camera-test":
        return extract_camera_test_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "ipv6-discovery":
        return extract_ipv6_discovery_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "impacket-lateral":
        return extract_impacket_lateral_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "metasploit":
        return extract_metasploit_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "netexec":
        return extract_netexec_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "llm-probe":
        return extract_llm_probe_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "biz-logic-probe":
        return extract_biz_logic_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "api-assessment":
        return extract_api_assessment_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "mobile-android":
        return extract_mobile_android_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "cloud-native":
        return extract_cloud_native_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "cicd-security":
        return extract_cicd_security_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "desktop-client":
        return extract_desktop_client_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "playwright-web":
        return extract_playwright_web_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "responder":
        return extract_responder_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "wifi-survey":
        return extract_wifi_survey_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool in {
        "content-discovery",
        "nikto",
        "sqlmap",
        "external-osint",
        "xxe-probe",
        "jwt-probe",
        "vuln-components",
        "idor-bac",
        "client-state",
        "headers-security",
        "graphql-command-injection",
        "graphql-probe",
        "ssti-probe",
        "http-smuggling",
        "oauth-probe",
        "logging-probe",
        "xss-extended",
        "xss-proof",
        "smart-web-probe",
        "ssrf-probe",
        "deserialization-probe",
        "session-security",
        "social-campaign",
        "auth-flow",
        "c2-ingest",
        "malware-sim",
        "leak-check",
        "priv-esc-linux",
        "crypto-audit",
        "ssh-brute",
        "waf-detect",
    }:
        return extract_standard_json_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
            accepted_artifact_names={
                CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME,
                NIKTO_RESULTS_ARTIFACT_NAME,
                SQLMAP_RESULTS_ARTIFACT_NAME,
                EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME,
                XXE_RESULTS_ARTIFACT_NAME,
                JWT_RESULTS_ARTIFACT_NAME,
                VULN_COMPONENTS_RESULTS_ARTIFACT_NAME,
                IDOR_BAC_ARTIFACT_NAME,
                CLIENT_STATE_RESULTS_ARTIFACT_NAME,
                HEADERS_SECURITY_RESULTS_ARTIFACT_NAME,
                GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME,
                GRAPHQL_RESULTS_ARTIFACT_NAME,
                SSTI_RESULTS_ARTIFACT_NAME,
                HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME,
                OAUTH_PROBE_RESULTS_ARTIFACT_NAME,
                LOGGING_PROBE_RESULTS_ARTIFACT_NAME,
                XSS_EXTENDED_RESULTS_ARTIFACT_NAME,
                XSS_PROOF_RESULTS_ARTIFACT_NAME,
                SMART_PROBE_RESULTS_ARTIFACT_NAME,
                SSRF_RESULTS_ARTIFACT_NAME,
                DESERIALIZATION_RESULTS_ARTIFACT_NAME,
                SESSION_SECURITY_RESULTS_ARTIFACT_NAME,
                SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME,
                AUTH_FLOW_RESULTS_ARTIFACT_NAME,
                C2_INGEST_RESULTS_ARTIFACT_NAME,
                MALWARE_SIM_RESULTS_ARTIFACT_NAME,
                LEAK_CHECK_RESULTS_ARTIFACT_NAME,
                PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME,
                CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME,
                SSH_BRUTE_RESULTS_ARTIFACT_NAME,
                WAF_DETECT_RESULTS_ARTIFACT_NAME,
            },
            default_title=f"{task.tool} finding",
        )

    return []


def extract_standard_json_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
    accepted_artifact_names: set[str],
    default_title: str,
) -> list[NormalizedFinding]:
    if artifact.name not in accepted_artifact_names:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = payload.get("analysis_findings", [])
    if not isinstance(raw_findings, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or default_title).strip() or default_title
        matched_target = (
            str(item.get("target") or item.get("target_id") or target_id).strip() or target_id
        )
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_wifi_survey_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != WIFI_SURVEY_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_finding in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(raw_finding, dict):
            continue
        title = str(raw_finding.get("title") or "WiFi survey finding").strip()
        finding_target = str(raw_finding.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), finding_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        methodology_tags = tuple(
            str(tag).strip()
            for tag in list(raw_finding.get("methodology_tags") or ["wireless", "wifi"])
            if str(tag).strip()
        )
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                target_id=finding_target,
                evidence_ref=artifact_record.uri,
                summary=str(raw_finding.get("summary") or "").strip()
                or f"WiFi passive survey reported {title}.",
                methodology_tags=methodology_tags,
                ptes_phase=str(raw_finding.get("ptes_phase") or "") or None,
                nist_phase=str(raw_finding.get("nist_phase") or "") or None,
                control_family=str(raw_finding.get("control_family") or "") or None,
            )
        )
    return findings


def extract_api_assessment_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != API_ASSESSMENT_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_finding in (
        payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
    ):
        if not isinstance(raw_finding, dict):
            continue
        title = str(raw_finding.get("title") or "API assessment finding").strip()
        finding_target = str(raw_finding.get("target") or target_id).strip() or target_id
        dedupe_key = (title.lower(), finding_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        summary = str(raw_finding.get("summary") or "").strip()
        methodology_tags = tuple(
            str(tag).strip()
            for tag in list(raw_finding.get("methodology_tags") or [])
            if str(tag).strip()
        )
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                target_id=finding_target,
                evidence_ref=artifact_record.uri,
                summary=summary or f"API assessment reported {title}.",
                methodology_tags=methodology_tags,
            )
        )
    return findings


def extract_mobile_android_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != MOBILE_ANDROID_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_finding in (
        payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
    ):
        if not isinstance(raw_finding, dict):
            continue
        title = str(raw_finding.get("title") or "Android mobile finding").strip()
        finding_target = str(raw_finding.get("target") or target_id).strip() or target_id
        dedupe_key = (title.lower(), finding_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        summary = str(raw_finding.get("summary") or "").strip()
        methodology_tags = tuple(
            str(tag).strip()
            for tag in list(raw_finding.get("methodology_tags") or [])
            if str(tag).strip()
        )
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                target_id=finding_target,
                evidence_ref=artifact_record.uri,
                summary=summary or f"Android mobile static review reported {title}.",
                methodology_tags=methodology_tags,
            )
        )
    return findings


def extract_cloud_native_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != CLOUD_NATIVE_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_finding in (
        payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
    ):
        if not isinstance(raw_finding, dict):
            continue
        title = str(raw_finding.get("title") or "Cloud-native finding").strip()
        finding_target = str(raw_finding.get("target") or target_id).strip() or target_id
        dedupe_key = (title.lower(), finding_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        summary = str(raw_finding.get("summary") or "").strip()
        methodology_tags = tuple(
            str(tag).strip()
            for tag in list(raw_finding.get("methodology_tags") or [])
            if str(tag).strip()
        )
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                target_id=finding_target,
                evidence_ref=artifact_record.uri,
                summary=summary or f"Cloud-native static/read-only review reported {title}.",
                methodology_tags=methodology_tags,
            )
        )
    return findings


def extract_cicd_security_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != CICD_SECURITY_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_finding in (
        payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
    ):
        if not isinstance(raw_finding, dict):
            continue
        title = str(raw_finding.get("title") or "CI/CD security finding").strip()
        finding_target = str(raw_finding.get("target") or target_id).strip() or target_id
        dedupe_key = (title.lower(), finding_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        summary = str(raw_finding.get("summary") or "").strip()
        methodology_tags = tuple(
            str(tag).strip()
            for tag in list(raw_finding.get("methodology_tags") or [])
            if str(tag).strip()
        )
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                target_id=finding_target,
                evidence_ref=artifact_record.uri,
                summary=summary or f"CI/CD static/read-only review reported {title}.",
                methodology_tags=methodology_tags,
            )
        )
    return findings


def extract_desktop_client_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_finding in (
        payload.get("findings", []) if isinstance(payload.get("findings"), list) else []
    ):
        if not isinstance(raw_finding, dict):
            continue
        title = str(raw_finding.get("title") or "Desktop client finding").strip()
        finding_target = str(raw_finding.get("target") or target_id).strip() or target_id
        dedupe_key = (title.lower(), finding_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        summary = str(raw_finding.get("summary") or "").strip()
        methodology_tags = tuple(
            str(tag).strip()
            for tag in list(raw_finding.get("methodology_tags") or [])
            if str(tag).strip()
        )
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                target_id=finding_target,
                evidence_ref=artifact_record.uri,
                summary=summary or f"Desktop/thick-client static review reported {title}.",
                methodology_tags=methodology_tags,
            )
        )
    return findings


def extract_playwright_web_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for target_result in (
        payload.get("targets", []) if isinstance(payload.get("targets"), list) else []
    ):
        if not isinstance(target_result, dict):
            continue
        matched_target = (
            str(target_result.get("final_url") or target_result.get("url") or target_id).strip()
            or target_id
        )
        for raw_finding in (
            target_result.get("findings", [])
            if isinstance(target_result.get("findings"), list)
            else []
        ):
            if not isinstance(raw_finding, dict):
                continue
            title = str(raw_finding.get("title") or "Browser workflow finding").strip()
            finding_target = str(raw_finding.get("target") or matched_target).strip() or target_id
            dedupe_key = (title.lower(), finding_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            summary = str(raw_finding.get("summary") or "").strip()
            methodology_tags = tuple(
                str(tag).strip()
                for tag in list(raw_finding.get("methodology_tags") or [])
                if str(tag).strip()
            )
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(raw_finding.get("severity") or "info")),
                    target_id=finding_target,
                    evidence_ref=artifact_record.uri,
                    summary=summary or f"Browser validation reported {title}.",
                    methodology_tags=methodology_tags,
                )
            )
    return findings


def extract_nuclei_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != "nuclei-results.jsonl":
        return []

    findings: list[NormalizedFinding] = []
    for raw_line in artifact.data.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        result = json.loads(line)
        if not isinstance(result, dict):
            continue

        info = result.get("info", {})
        classification = info.get("classification", {}) if isinstance(info, dict) else {}
        if not isinstance(classification, dict):
            classification = {}
        template_id = str(result.get("template-id") or "unknown-template").strip()
        severity = normalize_severity(info.get("severity") if isinstance(info, dict) else None)
        title = str(
            info.get("name")
            if isinstance(info, dict) and info.get("name")
            else f"Nuclei: {template_id}"
        ).strip()
        matched_at = str(result.get("matched-at") or target_id).strip()
        summary = f"Template {template_id} matched at {matched_at}."

        findings.append(
            NormalizedFinding(
                title=title,
                severity=severity,
                target_id=matched_at or target_id,
                evidence_ref=artifact_record.uri,
                summary=summary,
                cvss_score=_parse_cvss_score(
                    classification.get("cvss-score"),
                    classification.get("cvss_score"),
                    info.get("cvss-score") if isinstance(info, dict) else None,
                    info.get("cvss_score") if isinstance(info, dict) else None,
                    result.get("cvss-score"),
                    result.get("cvss_score"),
                ),
                cvss_vector=_parse_cvss_vector(
                    classification.get("cvss-metrics"),
                    classification.get("cvss_metrics"),
                    classification.get("cvss-vector"),
                    classification.get("cvss_vector"),
                    info.get("cvss-metrics") if isinstance(info, dict) else None,
                    info.get("cvss_vector") if isinstance(info, dict) else None,
                ),
            )
        )

    return findings


def extract_zap_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != "zap-results.json":
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, ...]] = set()

    for result in results:
        if not isinstance(result, dict):
            continue
        alerts = result.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            title = str(alert.get("alert") or "ZAP Alert").strip()
            matched_target = (
                str(alert.get("url") or result.get("target") or target_id).strip() or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            severity = normalize_severity(str(alert.get("risk") or "info"))
            cvss_score = _parse_cvss_score(
                alert.get("cvss_score"),
                alert.get("cvss-score"),
                alert.get("cvss"),
                alert.get("risk_score"),
                alert.get("riskScore"),
                alert.get("riskcode"),
                alert.get("riskCode"),
            )
            description = str(alert.get("description") or "").strip()
            summary = description or f"ZAP reported {title} for {matched_target}."

            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=summary,
                    cvss_score=cvss_score,
                    cvss_vector=_parse_cvss_vector(
                        alert.get("cvss_vector"),
                        alert.get("cvss-vector"),
                    ),
                )
            )

    return findings


def extract_burp_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != BURP_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()

    for result in results:
        if not isinstance(result, dict):
            continue
        issues = result.get("issues", [])
        if not isinstance(issues, list):
            continue

        for issue in issues:
            if not isinstance(issue, dict):
                continue
            title = str(
                issue.get("name") or issue.get("title") or issue.get("issue_name") or "Burp Issue"
            ).strip()
            matched_target = (
                str(
                    issue.get("url") or issue.get("path") or result.get("target") or target_id
                ).strip()
                or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            severity = normalize_severity(
                str(issue.get("severity") or issue.get("issue_severity") or "info")
            )
            summary = str(
                issue.get("description")
                or issue.get("issue_background")
                or issue.get("detail")
                or ""
            ).strip()
            if not summary:
                summary = f"Burp reported {title} for {matched_target}."

            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=summary,
                )
            )

    return findings


def extract_semgrep_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != "semgrep-results.json":
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    runs = payload.get("runs", [])
    if not isinstance(runs, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    severity_mapping = {
        "error": "high",
        "warning": "medium",
        "info": "info",
        "inventory": "info",
    }

    for run_payload in runs:
        if not isinstance(run_payload, dict):
            continue
        results = run_payload.get("results", [])
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue

            check_id = normalize_semgrep_rule_id(str(result.get("check_id") or "semgrep-rule"))
            path = str(result.get("path") or target_id).strip() or target_id
            extra = result.get("extra", {})
            severity_raw = ""
            message = ""
            if isinstance(extra, dict):
                severity_raw = str(extra.get("severity") or "").strip().lower()
                message = str(extra.get("message") or "").strip()

            severity = severity_mapping.get(severity_raw, normalize_severity(severity_raw))
            title = message or f"Semgrep: {check_id}"
            dedupe_key = (title.lower(), path.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            start = result.get("start", {})
            line = None
            if isinstance(start, dict):
                line = start.get("line")
            line_suffix = f":{line}" if isinstance(line, int) else ""
            summary = f"Semgrep rule {check_id} matched at {path}{line_suffix}."

            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    target_id=path,
                    evidence_ref=artifact_record.uri,
                    summary=summary,
                )
            )

    return findings


def extract_ldap_enum_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != LDAP_ENUM_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue

        matched_target = str(result.get("target") or target_id).strip() or target_id
        base_dn = str(result.get("base_dn") or "").strip()
        context = f" for {base_dn}" if base_dn else f" on {matched_target}"
        privileged_memberships = result.get("privileged_memberships", [])
        spn_accounts = result.get("spn_accounts", [])
        asrep_accounts = result.get("asrep_roastable_accounts", [])
        password_policy = result.get("password_policy", {})

        if isinstance(privileged_memberships, list) and privileged_memberships:
            findings.append(
                NormalizedFinding(
                    title="Privileged directory memberships observed",
                    severity="info",
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=(
                        f"LDAP read-only enumeration observed {len(privileged_memberships)} direct privileged "
                        f"group membership signal(s){context}."
                    ),
                    methodology_tags=("identity_management", "authorization", "ldap-enum"),
                )
            )

        if isinstance(spn_accounts, list) and spn_accounts:
            findings.append(
                NormalizedFinding(
                    title="Kerberoastable account indicators observed",
                    severity="medium",
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=(
                        f"LDAP read-only enumeration observed {len(spn_accounts)} enabled account(s) with "
                        f"service principal names{context}. No Kerberoasting or ticket request was performed."
                    ),
                    methodology_tags=("identity_management", "authentication", "ldap-enum"),
                )
            )

        if isinstance(asrep_accounts, list) and asrep_accounts:
            findings.append(
                NormalizedFinding(
                    title="AS-REP roastable account indicators observed",
                    severity="high",
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=(
                        f"LDAP read-only enumeration observed {len(asrep_accounts)} enabled account(s) that do "
                        f"not require Kerberos pre-authentication{context}. No AS-REP request or cracking was performed."
                    ),
                    methodology_tags=("identity_management", "authentication", "ldap-enum"),
                )
            )

        if isinstance(password_policy, dict):
            weak_policy_signals: list[str] = []
            min_length = password_policy.get("min_length")
            if isinstance(min_length, int) and min_length < 12:
                weak_policy_signals.append(f"minimum length {min_length}")
            if password_policy.get("complexity_enabled") is False:
                weak_policy_signals.append("complexity disabled")
            lockout_threshold = password_policy.get("lockout_threshold")
            if isinstance(lockout_threshold, int) and lockout_threshold <= 0:
                weak_policy_signals.append("no lockout threshold")
            if weak_policy_signals:
                findings.append(
                    NormalizedFinding(
                        title="Weak password policy signals observed",
                        severity="medium",
                        target_id=matched_target,
                        evidence_ref=artifact_record.uri,
                        summary=(
                            "LDAP read-only enumeration observed password policy signal(s): "
                            f"{', '.join(weak_policy_signals)}{context}."
                        ),
                        methodology_tags=("identity_management", "authentication", "ldap-enum"),
                    )
                )

    return findings


def extract_bloodhound_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != BLOODHOUND_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue
        for item in (
            result.get("analysis_findings", [])
            if isinstance(result.get("analysis_findings"), list)
            else []
        ):
            if not isinstance(item, dict):
                continue
            findings.append(
                NormalizedFinding(
                    title=str(item.get("title") or "BloodHound analysis signal").strip(),
                    severity=normalize_severity(str(item.get("severity") or "medium")),
                    target_id=str(item.get("target_id") or target_id).strip() or target_id,
                    evidence_ref=artifact_record.uri,
                    summary=str(item.get("summary") or "").strip() or None,
                    methodology_tags=tuple(
                        tag
                        for tag in item.get("methodology_tags", [])
                        if isinstance(tag, str) and tag.strip()
                    ),
                    ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                    nist_phase=str(item.get("nist_phase") or "").strip() or None,
                    wstg_id=str(item.get("wstg_id") or "").strip() or None,
                    control_family=str(item.get("control_family") or "").strip() or None,
                )
            )
    return findings


def extract_netexec_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != NETEXEC_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue
        raw_findings = result.get("analysis_findings", [])
        if not isinstance(raw_findings, list):
            continue
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "NetExec SMB signal").strip()
            matched_target = (
                str(item.get("target_id") or result.get("target") or target_id).strip() or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(item.get("severity") or "medium")),
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=str(item.get("summary") or "").strip() or None,
                    methodology_tags=tuple(
                        tag
                        for tag in item.get("methodology_tags", [])
                        if isinstance(tag, str) and tag.strip()
                    ),
                    ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                    nist_phase=str(item.get("nist_phase") or "").strip() or None,
                    wstg_id=str(item.get("wstg_id") or "").strip() or None,
                    control_family=str(item.get("control_family") or "").strip() or None,
                )
            )
    return findings


def extract_metasploit_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != METASPLOIT_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") != "ok":
            continue
        raw_findings = result.get("analysis_findings", [])
        if not isinstance(raw_findings, list):
            continue
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "Confirmed RCE").strip()
            matched_target = (
                str(item.get("target_id") or result.get("target") or target_id).strip() or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(item.get("severity") or "critical")),
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=str(item.get("summary") or "").strip() or None,
                    methodology_tags=tuple(
                        tag
                        for tag in item.get("methodology_tags", [])
                        if isinstance(tag, str) and tag.strip()
                    ),
                    ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                    nist_phase=str(item.get("nist_phase") or "").strip() or None,
                    wstg_id=str(item.get("wstg_id") or "").strip() or None,
                    control_family=str(item.get("control_family") or "").strip() or None,
                )
            )
    return findings


def extract_external_infra_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "External infrastructure signal").strip()
        matched_target = str(item.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "medium")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_mdns_ssdp_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != MDNS_SSDP_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "IoT discovery signal").strip()
        matched_target = str(item.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_impacket_lateral_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != IMPACKET_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue
        raw_findings = result.get("analysis_findings", [])
        if not isinstance(raw_findings, list):
            continue
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "Impacket lateral movement signal").strip()
            matched_target = (
                str(item.get("target_id") or result.get("target") or target_id).strip() or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(item.get("severity") or "high")),
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=str(item.get("summary") or "").strip() or None,
                    methodology_tags=tuple(
                        tag
                        for tag in item.get("methodology_tags", [])
                        if isinstance(tag, str) and tag.strip()
                    ),
                    ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                    nist_phase=str(item.get("nist_phase") or "").strip() or None,
                    control_family=str(item.get("control_family") or "").strip() or None,
                )
            )
    return findings


def extract_credential_attack_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue
        raw_findings = result.get("analysis_findings", [])
        if not isinstance(raw_findings, list):
            continue
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "Credential attack signal").strip()
            matched_target = (
                str(item.get("target_id") or result.get("target") or target_id).strip() or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(item.get("severity") or "medium")),
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=str(item.get("summary") or "").strip() or None,
                    methodology_tags=tuple(
                        tag
                        for tag in item.get("methodology_tags", [])
                        if isinstance(tag, str) and tag.strip()
                    ),
                )
            )
    return findings


def extract_iot_default_credential_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != IOT_DEFAULT_CREDS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "IoT default credential signal").strip()
        matched_target = str(item.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "high")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_network_segmentation_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != NETWORK_SEGMENTATION_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "Network segmentation signal").strip()
        matched_target = str(item.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_network_capture_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "Network capture signal").strip()
        matched_target = str(item.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_snmp_enum_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != SNMP_ENUM_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "SNMP enumeration signal").strip()
        matched_target = str(item.get("target_id") or target_id).strip() or target_id
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    tag
                    for tag in item.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                ),
                ptes_phase=str(item.get("ptes_phase") or "").strip() or None,
                nist_phase=str(item.get("nist_phase") or "").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "").strip() or None,
            )
        )
    return findings


def extract_smart_home_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != SMART_HOME_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "Smart-home exposure signal").strip()
        matched_target = (
            str(item.get("target") or item.get("target_id") or target_id).strip() or target_id
        )
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    dict.fromkeys(
                        [
                            "smart-home",
                            *[
                                tag
                                for tag in item.get("methodology_tags", [])
                                if isinstance(tag, str) and tag.strip()
                            ],
                        ]
                    )
                ),
                ptes_phase=str(item.get("ptes_phase") or "intelligence_gathering").strip() or None,
                nist_phase=str(item.get("nist_phase") or "Discovery").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "iot-smart-home").strip() or None,
            )
        )
    return findings


def extract_camera_test_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != CAMERA_TEST_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "Camera audit exposure signal").strip()
        matched_target = (
            str(item.get("target") or item.get("target_id") or target_id).strip() or target_id
        )
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=tuple(
                    dict.fromkeys(
                        [
                            "camera",
                            *[
                                tag
                                for tag in item.get("methodology_tags", [])
                                if isinstance(tag, str) and tag.strip()
                            ],
                        ]
                    )
                ),
                ptes_phase=str(item.get("ptes_phase") or "intelligence_gathering").strip() or None,
                nist_phase=str(item.get("nist_phase") or "Discovery").strip() or None,
                wstg_id=str(item.get("wstg_id") or "").strip() or None,
                control_family=str(item.get("control_family") or "iot-camera").strip() or None,
            )
        )
    return findings


def extract_ipv6_discovery_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for item in (
        payload.get("analysis_findings", [])
        if isinstance(payload.get("analysis_findings"), list)
        else []
    ):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "IPv6 discovery signal").strip()
        matched_target = (
            str(item.get("target") or item.get("target_id") or target_id).strip() or target_id
        )
        dedupe_key = (title.lower(), matched_target.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity=normalize_severity(str(item.get("severity") or "info")),
                target_id=matched_target,
                evidence_ref=artifact_record.uri,
                summary=str(item.get("summary") or "").strip() or None,
                methodology_tags=("ipv6", "network-discovery"),
                ptes_phase="intelligence_gathering",
                nist_phase="Discovery",
                control_family="network-exposure",
            )
        )
    return findings


def extract_llm_probe_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != LLM_PROBE_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    for result in payload.get("targets", []) if isinstance(payload.get("targets"), list) else []:
        if not isinstance(result, dict):
            continue
        matched_target = str(result.get("target") or target_id).strip() or target_id
        for finding in (
            result.get("findings", []) if isinstance(result.get("findings"), list) else []
        ):
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or "LLM application safety signal").strip()
            category = str(finding.get("category") or "llm_probe").strip()
            summary = str(finding.get("summary") or "").strip()
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(finding.get("severity") or "info")),
                    target_id=str(finding.get("target_id") or matched_target).strip()
                    or matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=summary or f"LLM probe reported a {category.replace('_', ' ')} signal.",
                    methodology_tags=(
                        "llm_application_testing",
                        category,
                        "bounded_probe",
                    ),
                    finding_origin="standard",
                )
            )

    return findings


def extract_biz_logic_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != BIZ_LOGIC_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    targets = payload.get("targets", [])
    if not isinstance(targets, list):
        return []

    for target_payload in targets:
        if not isinstance(target_payload, dict):
            continue
        raw_findings = target_payload.get("findings", [])
        if not isinstance(raw_findings, list):
            continue
        for raw_finding in raw_findings:
            if not isinstance(raw_finding, dict):
                continue
            title = str(raw_finding.get("title") or "Business logic issue detected").strip()
            matched_target = (
                str(raw_finding.get("target") or target_payload.get("target") or target_id).strip()
                or target_id
            )
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=normalize_severity(str(raw_finding.get("severity") or "medium")),
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=str(raw_finding.get("summary") or "").strip() or None,
                    methodology_tags=tuple(
                        tag
                        for tag in raw_finding.get("methodology_tags", [])
                        if isinstance(tag, str) and tag.strip()
                    ),
                )
            )

    return findings


def extract_responder_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != RESPONDER_RESULTS_ARTIFACT_NAME:
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    captures = payload.get("captures", [])
    if not isinstance(captures, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    for raw_capture in captures:
        if not isinstance(raw_capture, dict):
            continue
        host = str(raw_capture.get("host") or target_id).strip() or target_id
        username = str(raw_capture.get("username") or "unknown").strip() or "unknown"
        domain = str(raw_capture.get("domain") or "").strip()
        title = "Captured NTLMv2 credential hash via Responder poisoning"
        dedupe_key = (title.lower(), host.lower(), username.lower(), domain.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        findings.append(
            NormalizedFinding(
                title=title,
                severity="high",
                target_id=host,
                evidence_ref=artifact_record.uri,
                summary=(
                    f"Responder captured NTLMv2 material for {username}"
                    f"{'@' + domain if domain else ''} from {host}; protected credential material remains encrypted outside the visible artifact trail."
                ),
                methodology_tags=(
                    "credential_access",
                    "responder",
                    "llmnr_poisoning",
                    "ntlmv2",
                    "T1557.001",
                    "owasp-wstg",
                ),
                ptes_phase="exploitation",
                nist_phase="credential_access",
                wstg_id="WSTG-ATHN",
                control_family="authentication",
            )
        )

    return findings


def store_findings(
    *,
    session,
    task: Task,
    artifact_pairs: list[tuple[EvidenceArtifact, EvidenceArtifactRecord]],
) -> list[Finding]:
    if task.run_id is None:
        return []

    existing_findings = {
        finding_signature(title=finding.title, target_id=finding.target_id): finding
        for finding in task.run.findings
    }
    created_findings: list[Finding] = []
    for artifact, artifact_record in artifact_pairs:
        for extracted_finding in extract_findings(
            task=task, artifact=artifact, artifact_record=artifact_record
        ):
            extracted_finding = replace(
                extracted_finding,
                replay_recipe_json=build_replay_recipe(
                    task=task,
                    finding=extracted_finding,
                    artifact=artifact,
                    artifact_record=artifact_record,
                ),
            )
            finding = enrich_finding_with_methodology(finding=extracted_finding, task=task)
            signature = finding_signature(title=finding.title, target_id=finding.target_id)
            existing = existing_findings.get(signature)
            if existing is not None:
                previous_status = existing.status
                merge_finding(existing, finding)
                if previous_status != existing.status:
                    write_audit_event(
                        session=session,
                        actor=f"runner:{task.tool}",
                        action="finding.status_changed",
                        object_type="finding",
                        object_id=str(existing.id),
                        metadata={
                            "old_status": previous_status,
                            "new_status": existing.status,
                            "reason": "Existing finding reopened by new evidence.",
                            "task_id": str(task.id),
                            "run_id": str(task.run_id) if task.run_id else None,
                        },
                    )
                _store_optional_ai_enrichment(session=session, finding=existing)
                continue

            created_finding = Finding(
                run_id=task.run_id,
                source_pack_id=finding.source_pack_id,
                source_pack_artifact_id=finding.source_pack_artifact_id,
                source_inventory_snapshot_id=finding.source_inventory_snapshot_id,
                source_relevance_decision_id=finding.source_relevance_decision_id,
                source_pack_version=finding.source_pack_version,
                finding_origin=finding.finding_origin,
                title=finding.title,
                severity=finding.severity,
                target_id=finding.target_id,
                evidence_ref=finding.evidence_ref,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                summary=finding.summary,
                replay_recipe_json=dict(finding.replay_recipe_json or {}),
                methodology_tags=list(finding.methodology_tags),
                ptes_phase=finding.ptes_phase,
                nist_phase=finding.nist_phase,
                wstg_id=finding.wstg_id,
                wstg_version=finding.wstg_version,
                asvs_reference=finding.asvs_reference,
                control_family=finding.control_family,
                status="open",
            )
            apply_finding_sla(session, created_finding, settings=get_settings())
            session.add(created_finding)
            session.flush()
            write_audit_event(
                session=session,
                actor=f"runner:{task.tool}",
                action="finding.created",
                object_type="finding",
                object_id=str(created_finding.id),
                metadata={
                    "run_id": str(task.run_id) if task.run_id else None,
                    "task_id": str(task.id),
                    "title": created_finding.title,
                    "severity": created_finding.severity,
                    "target_id": created_finding.target_id,
                    "cvss_score": created_finding.cvss_score,
                    "cvss_vector": created_finding.cvss_vector,
                },
            )
            existing_findings[signature] = created_finding
            _store_optional_ai_enrichment(session=session, finding=created_finding)
            created_findings.append(created_finding)

    return created_findings


def _store_optional_ai_enrichment(*, session, finding: Finding) -> None:
    try:
        enrich_finding_async(finding.id, session, settings=get_settings())
    except Exception:
        # Finding creation remains the source of truth; enrichment must never block it.
        return
