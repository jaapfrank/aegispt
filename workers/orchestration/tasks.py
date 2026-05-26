from __future__ import annotations

import json
import logging
import os
import shlex
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID

import dramatiq

from api.app.observability import traced  # backlog-407 — tracing-only decorator

logger = logging.getLogger(__name__)
from dramatiq.brokers.redis import RedisBroker
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from api.app.config import get_settings
from api.app.models import EvidenceArtifact as EvidenceArtifactRecord
from api.app.models import (
    Finding,
    InventorySnapshot,
    Run,
    Scope,
    SecretRef,
    TargetContextDocument,
    Task,
    ToolExecution,
)
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.services.ai_agent import run_post_task_analysis_for_task
from api.app.services.ai_planner import (
    PHASE0_LAYER_NAME,
    generate_pivot_contexts_for_run,
    latest_context_document,
)
from api.app.services.ai_shell_safety import (
    AiShellSafetyError,
    ai_shell_command_preview,
    normalize_ai_shell_params,
)
from api.app.services.artifact_storage import (
    artifact_storage_config_from_settings,
    store_artifact_bytes_with_fallback,
)
from api.app.services.assessment_chain import (
    advance_assessment_chain_for_completed_run,
    dispatch_assessment_chain_current_run,
)
from api.app.services.assessment_loop import advance_assessment_loop
from api.app.services.audit import write_audit_event
from api.app.services.cve_sync import suggest_watchlist_from_inventory_snapshot
from api.app.services.evidence_integrity import apply_artifact_integrity_metadata
from api.app.services.exposure_score import record_exposure_score
from api.app.services.finding_chains import link_pivot_chain_findings
from api.app.services.finding_validator import (
    dispatch_validation_runs,
    finalize_validation_for_task,
    is_validation_task,
    mark_validation_running,
    queue_automatic_validations,
)
from api.app.services.inventory import (
    api_assessment_observation_from_json,
    aws_inventory_observation_from_json,
    bloodhound_observation_from_json,
    camera_test_observation_from_json,
    cicd_security_observation_from_json,
    cloud_native_observation_from_json,
    create_inventory_snapshot_record,
    desktop_client_observation_from_json,
    easm_observation_from_json,
    external_infrastructure_observation_from_json,
    httpx_observation_from_jsonl,
    ipv6_discovery_observation_from_json,
    ldap_enum_observation_from_json,
    mdns_ssdp_observation_from_json,
    mobile_android_observation_from_json,
    network_capture_observation_from_json,
    nmap_observation_from_xml,
    smart_home_observation_from_json,
    snmp_enum_observation_from_json,
    wifi_survey_observation_from_json,
)
from api.app.services.notification_delivery import (
    deliver_critical_finding_notifications,
    deliver_phase_approval_needed_notifications,
    deliver_run_completion_notifications,
)
from api.app.services.on_demand_cve_intel import maybe_refresh_after_discovery_task
from api.app.services.redaction import redact_artifact_bytes, redact_text
from api.app.services.run_credential_vault import (
    clear_run_credential_vault_if_terminal,
    inject_run_credential_vault_into_task,
    run_uses_ai_loop,
    store_run_credential_vault_secret,
)
from api.app.services.run_drift import compute_run_drift
from api.app.services.runner_registry import runner_capability_registry
from api.app.services.runs import latest_scope_query, target_is_allowed
from api.app.services.secrets import (
    direct_secret_storage_backend,
    encrypt_secret_value,
    load_secret_value,
    public_secret_binding,
)
from api.app.services.settings import effective_runtime_settings_for_task
from api.app.services.siem_push import (
    deliver_critical_findings_to_configured_siems,
    deliver_run_completion_to_configured_siems,
)
from api.app.services.soft_delete import purge_expired_soft_deleted_runs
from api.app.services.task_dispatch import dispatch_task_batch, supported_execution_tools
from workers.orchestration.findings import store_findings
from workers.orchestration.runtime import session_scope
from workers.runners.ai_pentest_agent.runner import execute_ai_pentest_agent
from workers.runners.ai_shell.runner import execute_ai_shell_command
from workers.runners.api_assessment.runner import (
    API_ASSESSMENT_INVENTORY_ARTIFACT_NAME,
    execute_api_assessment,
)
from workers.runners.auth_flow.runner import execute_auth_flow_analysis
from workers.runners.recon_deliverable.runner import execute_recon_deliverable
from workers.runners.code_exec_attack.runner import execute_code_exec_attack
from workers.runners.pre_recon_source.runner import execute_pre_recon_source
from workers.runners.pre_recon_cpg.runner import execute_pre_recon_cpg
from workers.runners.aws_inventory.runner import execute_aws_inventory
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution, RunnerRequest
from workers.runners.base.stdout_stream import (
    append_task_stdout,
    mark_task_stdout_completed,
    mark_task_stdout_unavailable,
    reset_task_stdout_stream,
)
from workers.runners.biz_logic.runner import execute_biz_logic_probe
from workers.runners.bloodhound.runner import execute_bloodhound_collect
from workers.runners.burp.runner import execute_burp_scan
from workers.runners.c2_ingest.runner import execute_c2_ingest
from workers.runners.camera_test.runner import (
    CAMERA_TEST_RESULTS_ARTIFACT_NAME,
    execute_camera_test,
)
from workers.runners.cicd_security.runner import (
    CICD_SECURITY_INVENTORY_ARTIFACT_NAME,
    execute_cicd_security_assessment,
)
from workers.runners.client_state.runner import execute_client_state_analysis
from workers.runners.cloud_native.runner import (
    CLOUD_NATIVE_INVENTORY_ARTIFACT_NAME,
    execute_cloud_native_assessment,
)
from workers.runners.cookie_tamper_probe.runner import execute_cookie_tamper_probe
from workers.runners.credential_attacks.runner import execute_credential_attacks
from workers.runners.crypto_audit.runner import execute_crypto_audit
from workers.runners.deserialization_probe.runner import execute_deserialization_probe
from workers.runners.desktop_client.runner import (
    DESKTOP_CLIENT_INVENTORY_ARTIFACT_NAME,
    execute_desktop_client_assessment,
)
from workers.runners.easm.runner import execute_easm_discovery
from workers.runners.exec_plan.runner import execute_exec_plan
from workers.runners.external_infra.runner import execute_external_infra_assessment
from workers.runners.file_upload_probe.runner import execute_file_upload_probe
from workers.runners.graphql_command_injection.runner import execute_graphql_command_injection
from workers.runners.graphql_probe.runner import execute_graphql_probe
from workers.runners.headers_security.runner import execute_headers_security_analysis
from workers.runners.http_smuggling.runner import execute_http_smuggling_probe
from workers.runners.httpx.runner import execute_httpx_probe
from workers.runners.idor_bac.runner import execute_idor_bac_probe
from workers.runners.impacket.runner import execute_impacket_lateral
from workers.runners.info_disclosure_probe.runner import execute_info_disclosure_probe
from workers.runners.iot_default_creds.runner import execute_iot_default_credential_audit
from workers.runners.ipv6_discovery.runner import (
    IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME,
    execute_ipv6_discovery,
)
from workers.runners.lan_intel.runner import execute_lan_intel
from workers.runners.ldap_enum.runner import execute_ldap_enum
from workers.runners.leak_check.runner import execute_leak_check_review
from workers.runners.llm_probe import execute_llm_probe
from workers.runners.logging_probe.runner import execute_logging_probe
from workers.runners.malware_sim.runner import execute_malware_simulation_review
from workers.runners.mdns_ssdp.runner import (
    MDNS_SSDP_ARTIFACT_NAME,
    execute_mdns_ssdp_discovery,
)
from workers.runners.metasploit.runner import execute_metasploit_exploit
from workers.runners.mobile_android.runner import (
    MOBILE_ANDROID_INVENTORY_ARTIFACT_NAME,
    execute_mobile_android_static,
)
from workers.runners.netexec.runner import execute_netexec_smb
from workers.runners.network_capture.runner import (
    NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME,
    execute_network_capture_assessment,
)
from workers.runners.network_segmentation.runner import execute_network_segmentation_assessment
from workers.runners.nmap.runner import execute_nmap_scan
from workers.runners.nuclei.runner import execute_nuclei_scan
from workers.runners.oauth_probe.runner import execute_oauth_probe
from workers.runners.param_pollution_probe.runner import execute_param_pollution_probe
from workers.runners.playwright_web.runner import execute_playwright_web_validation
from workers.runners.priv_esc_linux.runner import execute_priv_esc_linux
from workers.runners.responder.runner import execute_responder_capture
from workers.runners.semgrep.runner import execute_semgrep_scan
from workers.runners.session_security.runner import execute_session_security_analysis
from workers.runners.smart_home.runner import (
    SMART_HOME_RESULTS_ARTIFACT_NAME,
    execute_smart_home_audit,
)
from workers.runners.smart_web_probe.runner import execute_smart_web_probe
from workers.runners.snmp_enum.runner import (
    SNMP_ENUM_RESULTS_ARTIFACT_NAME,
    execute_snmp_enumeration,
)
from workers.runners.social_campaign.runner import execute_social_campaign_review
from workers.runners.ssh_brute.runner import execute_ssh_brute_force
from workers.runners.ssrf_probe.runner import execute_ssrf_probe
from workers.runners.ssti_probe.runner import execute_ssti_probe
from workers.runners.stored_xss_probe.runner import execute_stored_xss_probe
from workers.runners.target_intel.runner import execute_target_intel
from workers.runners.waf_detect.runner import execute_waf_detection
from workers.runners.web_depth.runner import (
    execute_content_discovery,
    execute_external_osint_recon,
    execute_jwt_probe,
    execute_nikto_scan,
    execute_sqlmap_confirmation,
    execute_vuln_components_scan,
    execute_xxe_probe,
)
from workers.runners.wifi_survey.runner import (
    WIFI_SURVEY_RESULTS_ARTIFACT_NAME,
    execute_wifi_survey,
)
from workers.runners.xss_extended.runner import execute_xss_extended_scan
from workers.runners.xss_proof.runner import execute_xss_proof
from workers.runners.zap.runner import execute_zap_scan

redis_broker = RedisBroker(url=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
dramatiq.set_broker(redis_broker)

SUPPORTED_TOOLS = {
    "ai-shell",
    "api-assessment",
    "auth-flow",
    "recon-deliverable",  # Phase 2 of landscape-plan 2026-05-22 — Shannon-style attack surface map
    "code-exec-attack",   # Phase B 2026-05-22 — AI-emitted Python exploit script with scope-guarded httpx
    "pre-recon-source",   # Phase 4 2026-05-22 — Shannon-style white-box source audit (opt-in per run)
    "pre-recon-cpg",      # M3 beat-shannon-pro 2026-05-23 — Joern CPG dataflow scan
    "aws-inventory",
    "bloodhound-collect",
    "biz-logic-probe",
    # Burp Suite Pro removed 2026-05-21: operator declined to license the
    # proprietary $399+/yr product. OWASP ZAP is the free-OSS replacement
    # (still in this set as "zap"). The workers/runners/burp module is
    # retained for future re-enablement; SUPPORTED_TOOLS gates picker access.
    "c2-ingest",
    "camera-test",
    "cicd-security",
    "client-state",
    "cloud-native",
    "content-discovery",
    "desktop-client",
    "deserialization-probe",
    "credential-attacks",
    "crypto-audit",
    "easm-discover",
    "external-osint",
    "external-infra",
    "graphql-command-injection",
    "graphql-probe",
    "headers-security",
    "http-smuggling",
    "httpx",
    "idor-bac",
    "impacket-lateral",
    "iot-default-creds",
    "ipv6-discovery",
    "jwt-probe",
    "ldap-enum",
    "leak-check",
    "llm-probe",
    "logging-probe",
    "info-disclosure-probe",
    "param-pollution-probe",
    "stored-xss-probe",
    "cookie-tamper-probe",
    "file-upload-probe",
    "malware-sim",
    "metasploit",
    "mdns-ssdp",
    "mobile-android",
    "network-capture",
    "network-segmentation",
    "nmap",
    "netexec",
    "nikto",
    "nuclei",
    "oauth-probe",
    "playwright-web",
    "priv-esc-linux",
    "responder",
    "semgrep",
    "session-security",
    "smart-home",
    "social-campaign",
    "ssh-brute",
    "ssti-probe",
    "ssrf-probe",
    "snmp-enum",
    "sqlmap",
    "vuln-components",
    "waf-detect",
    "wifi-survey",
    "xss-extended",
    "xss-proof",
    "smart-web-probe",
    "ai-pentest-agent",
    "target-intel",
    "lan-intel",
    "xxe-probe",
    "zap",
    "exec-plan",
    "exploit-developer-agent",
}


@dataclass(slots=True)
class StoredExecutionResult:
    created_finding_ids: list[UUID]


@traced("runner.dispatch")  # backlog-407: tracing-only, no behavior change
def dispatch_runner(request: RunnerRequest) -> RunnerExecution:
    rate_limit = int(request.params.get("limits", {}).get("max_rps", 2))
    timeout_seconds = float(request.params.get("timeout_seconds", 10.0))
    limits = (
        request.params.get("limits", {})
        if isinstance(request.params.get("limits", {}), dict)
        else {}
    )

    if request.tool == "httpx":
        return execute_httpx_probe(
            targets=request.targets,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "aws-inventory":
        regions = request.params.get("regions", limits.get("regions"))
        return execute_aws_inventory(
            targets=request.targets,
            regions=(
                [
                    str(region).strip()
                    for region in regions
                    if isinstance(region, str) and str(region).strip()
                ]
                if isinstance(regions, list)
                else None
            ),
            access_key_id_env=(
                request.params.get("access_key_id_env")
                if isinstance(request.params.get("access_key_id_env"), str)
                else None
            ),
            secret_access_key_env=(
                request.params.get("secret_access_key_env")
                if isinstance(request.params.get("secret_access_key_env"), str)
                else None
            ),
            session_token_env=(
                request.params.get("session_token_env")
                if isinstance(request.params.get("session_token_env"), str)
                else None
            ),
        )
    if request.tool == "api-assessment":
        return execute_api_assessment(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            auth_contexts=request.params.get("auth_contexts", []),
            openapi_spec=request.params.get("openapi_spec"),
            postman_collection=request.params.get("postman_collection"),
            graphql_introspection=request.params.get("graphql_introspection"),
            graphql_endpoint_url=(
                request.params.get("graphql_endpoint_url")
                if isinstance(request.params.get("graphql_endpoint_url"), str)
                else None
            ),
            requires_auth_context=bool(request.params.get("requires_auth_context", False)),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "mobile-android":
        return execute_mobile_android_static(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            apk_path=(
                request.params.get("apk_path")
                if isinstance(request.params.get("apk_path"), str)
                else None
            ),
            proxy_metadata=request.params.get("proxy_metadata"),
            dynamic_prerequisites=request.params.get("dynamic_prerequisites"),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "cloud-native":
        return execute_cloud_native_assessment(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            manifest_paths=(
                request.params.get("manifest_paths")
                if isinstance(request.params.get("manifest_paths"), list)
                else None
            ),
            manifests=request.params.get("manifests"),
            image_metadata=request.params.get("image_metadata"),
            cluster_posture=request.params.get("cluster_posture"),
            provider=(
                request.params.get("provider")
                if isinstance(request.params.get("provider"), str)
                else "kubernetes"
            ),
            cluster_id=(
                request.params.get("cluster_id")
                if isinstance(request.params.get("cluster_id"), str)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "cicd-security":
        return execute_cicd_security_assessment(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            pipeline_paths=(
                request.params.get("pipeline_paths")
                if isinstance(request.params.get("pipeline_paths"), list)
                else None
            ),
            pipeline_configs=request.params.get("pipeline_configs"),
            repository_metadata=request.params.get("repository_metadata"),
            pipeline_type=(
                request.params.get("pipeline_type")
                if isinstance(request.params.get("pipeline_type"), str)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "desktop-client":
        return execute_desktop_client_assessment(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            artifact_paths=(
                request.params.get("artifact_paths")
                if isinstance(request.params.get("artifact_paths"), list)
                else None
            ),
            helper_urls=(
                request.params.get("helper_urls")
                if isinstance(request.params.get("helper_urls"), list)
                else None
            ),
            desktop_metadata=(
                request.params.get("desktop_metadata")
                if isinstance(request.params.get("desktop_metadata"), dict)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "biz-logic-probe":
        return execute_biz_logic_probe(
            targets=request.targets,
            auth_contexts=request.params.get("auth_contexts", []),
            scope_allowlist=request.scope_allowlist,
            test_types=request.params.get("test_types"),
            protected_paths=request.params.get("protected_paths"),
            admin_paths=request.params.get("admin_paths"),
            idor_paths=request.params.get("idor_paths"),
            cross_tenant_paths=request.params.get("cross_tenant_paths"),
            candidate_object_ids=request.params.get("candidate_object_ids"),
            max_object_ids=(
                request.params.get("max_object_ids")
                if isinstance(request.params.get("max_object_ids"), int)
                else 25
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "idor-bac":
        # Build auth_contexts: start with vault-injected contexts,
        # then add discovered_users as marker-only contexts so _foreign_marker
        # can detect their data in responses even without their credentials.
        idor_auth_contexts = list(request.params.get("auth_contexts") or [])
        discovered = request.params.get("discovered_users") or []
        if isinstance(discovered, list):
            existing_users = {
                str(ctx.get("username") or "").lower()
                for ctx in idor_auth_contexts
                if isinstance(ctx, dict)
            }
            for other_user in discovered:
                user_str = str(other_user or "").strip()
                if user_str and user_str.lower() not in existing_users:
                    idor_auth_contexts.append({
                        "label": f"Discovered user: {user_str}",
                        "username": user_str,
                        "role": "discovered-other-user",
                        "marker_tokens": [user_str],
                        "headers": {},
                    })

        return execute_idor_bac_probe(
            targets=request.targets,
            auth_contexts=idor_auth_contexts,
            scope_allowlist=request.scope_allowlist,
            evidence_records=(
                request.params.get("evidence_records")
                if isinstance(request.params.get("evidence_records"), list)
                else []
            ),
            request_contexts=(
                request.params.get("request_contexts")
                if isinstance(request.params.get("request_contexts"), list)
                else []
            ),
            admin_paths=(
                request.params.get("admin_paths")
                if isinstance(request.params.get("admin_paths"), list)
                else None
            ),
            candidate_paths=(
                request.params.get("candidate_paths")
                if isinstance(request.params.get("candidate_paths"), list)
                else []
            ),
            candidate_object_ids=(
                list(request.params.get("candidate_object_ids") or [])
                + [str(u) for u in (request.params.get("discovered_users") or []) if u]
            ),
            method_override_paths=(
                request.params.get("method_override_paths")
                if isinstance(request.params.get("method_override_paths"), list)
                else []
            ),
            max_id_delta=(
                request.params.get("max_id_delta")
                if isinstance(request.params.get("max_id_delta"), int)
                else 20
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "client-state":
        return execute_client_state_analysis(
            targets=request.targets,
            auth_contexts=request.params.get("auth_contexts", []),
            scope_allowlist=request.scope_allowlist,
            form_contexts=(
                request.params.get("form_contexts")
                if isinstance(request.params.get("form_contexts"), list)
                else []
            ),
            cookie_contexts=(
                request.params.get("cookie_contexts")
                if isinstance(request.params.get("cookie_contexts"), list)
                else []
            ),
            request_contexts=(
                request.params.get("request_contexts")
                if isinstance(request.params.get("request_contexts"), list)
                else []
            ),
            price_contexts=(
                request.params.get("price_contexts")
                if isinstance(request.params.get("price_contexts"), list)
                else []
            ),
            workflow_contexts=(
                request.params.get("workflow_contexts")
                if isinstance(request.params.get("workflow_contexts"), list)
                else []
            ),
            gruyere_contexts=(
                request.params.get("gruyere_contexts")
                if isinstance(request.params.get("gruyere_contexts"), list)
                else []
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "headers-security":
        return execute_headers_security_analysis(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            attacker_origin=(
                request.params.get("attacker_origin")
                if isinstance(request.params.get("attacker_origin"), str)
                else "https://evil.example.com"
            ),
            additional_origins=(
                request.params.get("additional_origins")
                if isinstance(request.params.get("additional_origins"), list)
                else []
            ),
            redirect_paths=(
                request.params.get("redirect_paths")
                if isinstance(request.params.get("redirect_paths"), list)
                else []
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "graphql-probe":
        return execute_graphql_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            endpoint_paths=(
                request.params.get("endpoint_paths")
                if isinstance(request.params.get("endpoint_paths"), list)
                else None
            ),
            ide_paths=(
                request.params.get("ide_paths")
                if isinstance(request.params.get("ide_paths"), list)
                else None
            ),
            max_depth=(
                request.params.get("max_depth")
                if isinstance(request.params.get("max_depth"), int)
                else 20
            ),
            max_injection_fields=(
                request.params.get("max_injection_fields")
                if isinstance(request.params.get("max_injection_fields"), int)
                else 5
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "graphql-command-injection":
        return execute_graphql_command_injection(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            endpoint_path=(
                request.params.get("endpoint_path")
                if isinstance(request.params.get("endpoint_path"), str)
                else "/graphql"
            ),
            command=(
                request.params.get("command")
                if isinstance(request.params.get("command"), str)
                else None
            ),
            allowed_commands=(
                request.params.get("allowed_commands")
                if isinstance(request.params.get("allowed_commands"), list)
                else None
            ),
            intrusive_authorized=bool(request.params.get("intrusive_authorized", False)),
            allow_command_injection_proof=bool(
                request.params.get("allow_command_injection_proof", False)
            ),
            kill_switch_enabled=execution_kill_switch_enabled(),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "ssti-probe":
        return execute_ssti_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            parameter_names=(
                request.params.get("parameter_names")
                if isinstance(request.params.get("parameter_names"), list)
                else None
            ),
            candidate_paths=(
                request.params.get("candidate_paths")
                if isinstance(request.params.get("candidate_paths"), list)
                else None
            ),
            stored_form_contexts=(
                request.params.get("stored_form_contexts")
                if isinstance(request.params.get("stored_form_contexts"), list)
                else []
            ),
            gruyere_contexts=(
                request.params.get("gruyere_contexts")
                if isinstance(request.params.get("gruyere_contexts"), list)
                else []
            ),
            max_parameters=(
                request.params.get("max_parameters")
                if isinstance(request.params.get("max_parameters"), int)
                else 12
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "http-smuggling":
        return execute_http_smuggling_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            proxy_evidence=(
                request.params.get("proxy_evidence")
                if isinstance(request.params.get("proxy_evidence"), list)
                else []
            ),
            timing_threshold_seconds=(
                float(request.params.get("timing_threshold_seconds"))
                if isinstance(request.params.get("timing_threshold_seconds"), (int, float))
                else 4.5
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "oauth-probe":
        return execute_oauth_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            authorization_urls=(
                request.params.get("authorization_urls")
                if isinstance(request.params.get("authorization_urls"), list)
                else []
            ),
            login_paths=(
                request.params.get("login_paths")
                if isinstance(request.params.get("login_paths"), list)
                else []
            ),
            well_known_paths=(
                request.params.get("well_known_paths")
                if isinstance(request.params.get("well_known_paths"), list)
                else []
            ),
            script_paths=(
                request.params.get("script_paths")
                if isinstance(request.params.get("script_paths"), list)
                else []
            ),
            token_evidence=(
                request.params.get("token_evidence")
                if isinstance(request.params.get("token_evidence"), list)
                else []
            ),
            client_id=(
                request.params.get("client_id")
                if isinstance(request.params.get("client_id"), str)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    # #338 — extract stack-hints once for all 5 stack-aware probes so we
    # don't repeat the request.params.get(...) call site noise. None /
    # missing → probes use their baseline catalog.
    _stack_hints = request.params.get("stack_hints") if isinstance(request.params, dict) else None
    _attack_candidates = (
        request.params.get("attack_candidates") if isinstance(request.params, dict) else None
    )
    if request.tool == "info-disclosure-probe":
        return execute_info_disclosure_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            stack_hints=_stack_hints,
            attack_candidates=_attack_candidates,
        )
    if request.tool == "param-pollution-probe":
        return execute_param_pollution_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            stack_hints=_stack_hints,
            attack_candidates=_attack_candidates,
        )
    if request.tool == "stored-xss-probe":
        return execute_stored_xss_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            stack_hints=_stack_hints,
            attack_candidates=_attack_candidates,
        )
    if request.tool == "cookie-tamper-probe":
        return execute_cookie_tamper_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            stack_hints=_stack_hints,
            attack_candidates=_attack_candidates,
        )
    if request.tool == "file-upload-probe":
        return execute_file_upload_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            stack_hints=_stack_hints,
            attack_candidates=_attack_candidates,
        )
    if request.tool == "logging-probe":
        return execute_logging_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            admin_paths=(
                request.params.get("admin_paths")
                if isinstance(request.params.get("admin_paths"), list)
                else None
            ),
            actuator_paths=(
                request.params.get("actuator_paths")
                if isinstance(request.params.get("actuator_paths"), list)
                else None
            ),
            debug_paths=(
                request.params.get("debug_paths")
                if isinstance(request.params.get("debug_paths"), list)
                else None
            ),
            error_paths=(
                request.params.get("error_paths")
                if isinstance(request.params.get("error_paths"), list)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "ssh-brute":
        return execute_ssh_brute_force(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            service_targets=(
                request.params.get("service_targets")
                if isinstance(request.params.get("service_targets"), list)
                else None
            ),
            discovered_services=(
                request.params.get("discovered_services")
                if isinstance(request.params.get("discovered_services"), list)
                else None
            ),
            usernames=(
                request.params.get("usernames")
                if isinstance(request.params.get("usernames"), list)
                else None
            ),
            password_candidates=(
                request.params.get("password_candidates")
                if isinstance(request.params.get("password_candidates"), list)
                else None
            ),
            max_usernames=(
                request.params.get("max_usernames")
                if isinstance(request.params.get("max_usernames"), int)
                else 10
            ),
            max_custom_passwords=(
                request.params.get("max_custom_passwords")
                if isinstance(request.params.get("max_custom_passwords"), int)
                else 50
            ),
            max_attempts_per_service=(
                request.params.get("max_attempts_per_service")
                if isinstance(request.params.get("max_attempts_per_service"), int)
                else 200
            ),
            rate_limit_per_second=(
                float(request.params.get("rate_limit_per_second"))
                if isinstance(request.params.get("rate_limit_per_second"), (int, float))
                else 5.0
            ),
            lockout_stop_threshold=(
                request.params.get("lockout_stop_threshold")
                if isinstance(request.params.get("lockout_stop_threshold"), int)
                else 3
            ),
            timeout_seconds=timeout_seconds,
            hydra_binary=os.getenv("HYDRA_BINARY", "hydra"),
            kill_switch_check=execution_kill_switch_enabled,
        )
    if request.tool == "bloodhound-collect":
        return execute_bloodhound_collect(
            targets=request.targets,
            auth_contexts=request.params.get("auth_contexts", []),
            scope_allowlist=request.scope_allowlist,
            binary=os.getenv("BLOODHOUND_PYTHON_BINARY", "bloodhound-python"),
            domain=(
                request.params.get("domain")
                if isinstance(request.params.get("domain"), str)
                else None
            ),
            domain_controller=(
                request.params.get("domain_controller")
                if isinstance(request.params.get("domain_controller"), str)
                else None
            ),
            nameserver=(
                request.params.get("nameserver")
                if isinstance(request.params.get("nameserver"), str)
                else None
            ),
            collection_methods=(
                request.params.get("collection_methods")
                if isinstance(request.params.get("collection_methods"), list)
                else None
            ),
            dns_tcp=bool(request.params.get("dns_tcp", False)),
            use_ldaps=bool(request.params.get("use_ldaps", False)),
            timeout_seconds=timeout_seconds,
            kill_switch_check=execution_kill_switch_enabled,
        )
    if request.tool == "burp":
        settings = get_settings()
        return execute_burp_scan(
            targets=request.targets,
            base_url=settings.burp_api_url or "",
            api_key=settings.burp_api_key,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            named_scan_configurations=(
                request.params.get("named_scan_configurations")
                if isinstance(request.params.get("named_scan_configurations"), list)
                else None
            ),
            scan_definition=(
                request.params.get("scan_definition")
                if isinstance(request.params.get("scan_definition"), dict)
                else None
            ),
            scope_allowlist=request.scope_allowlist,
        )
    if request.tool == "c2-ingest":
        c2_export = (
            request.params.get("c2_export")
            or request.params.get("session_export")
            or request.params.get("mythic_export")
            or request.params.get("sliver_export")
        )
        return execute_c2_ingest(
            targets=request.targets,
            c2_export=c2_export if isinstance(c2_export, dict) else None,
            framework=(
                str(request.params.get("framework"))
                if isinstance(request.params.get("framework"), str)
                else None
            ),
            command_execution_requested=bool(
                request.params.get("command_execution_requested")
                or request.params.get("execute_command")
                or request.params.get("run_command")
            ),
            session_mutation_requested=bool(
                request.params.get("session_mutation_requested")
                or request.params.get("mutate_session")
            ),
        )
    if request.tool == "credential-attacks":
        return execute_credential_attacks(
            targets=request.targets,
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "kerberoast"
            ),
            auth_contexts=request.params.get("auth_contexts", []),
            candidate_accounts=request.params.get("candidate_accounts", []),
            hash_inputs=request.params.get("hash_sources", []),
            password_candidates=request.params.get("password_candidates", []),
            configured_domain=(
                request.params.get("domain")
                if isinstance(request.params.get("domain"), str)
                else None
            ),
            domain_controller=(
                request.params.get("domain_controller")
                if isinstance(request.params.get("domain_controller"), str)
                else None
            ),
            wordlist_path=(
                request.params.get("wordlist_path")
                if isinstance(request.params.get("wordlist_path"), str)
                else None
            ),
            attempts_per_window=(
                request.params.get("attempts_per_window")
                if isinstance(request.params.get("attempts_per_window"), int)
                else 1
            ),
            window_minutes=(
                request.params.get("window_minutes")
                if isinstance(request.params.get("window_minutes"), int)
                else 30
            ),
            lockout_threshold=(
                request.params.get("lockout_threshold")
                if isinstance(request.params.get("lockout_threshold"), int)
                else None
            ),
            getuserspns_binary=os.getenv("IMPACKET_GETUSERSPNS_BINARY", "GetUserSPNs.py"),
            getnpusers_binary=os.getenv("IMPACKET_GETNPUSERS_BINARY", "GetNPUsers.py"),
            hashcat_binary=os.getenv("HASHCAT_BINARY", "hashcat"),
            spray_binary=os.getenv("KERBRUTE_BINARY", "kerbrute"),
            timeout_seconds=timeout_seconds,
            kill_switch_check=execution_kill_switch_enabled,
        )
    if request.tool == "easm-discover":
        return execute_easm_discovery(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            subfinder_binary=os.getenv("SUBFINDER_BINARY", "subfinder"),
            crtsh_base_url=os.getenv("EASM_CRTSH_BASE_URL", "https://crt.sh/"),
            dns_wordlist_path=os.getenv("EASM_DNS_WORDLIST_PATH") or None,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "crypto-audit":
        return execute_crypto_audit(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else limits.get("mode", "passive")
            ),
            timeout_seconds=timeout_seconds,
            testssl_binary=os.getenv("TESTSSL_BINARY", "testssl.sh"),
            ssh_audit_binary=os.getenv("SSH_AUDIT_BINARY", "ssh-audit"),
            tls_targets=(
                request.params.get("tls_targets")
                if isinstance(request.params.get("tls_targets"), list)
                else None
            ),
            ssh_targets=(
                request.params.get("ssh_targets")
                if isinstance(request.params.get("ssh_targets"), list)
                else None
            ),
            token_evidence=(
                request.params.get("token_evidence")
                if isinstance(request.params.get("token_evidence"), list)
                else None
            ),
            testssl_results=request.params.get("testssl_results"),
            ssh_audit_results=request.params.get("ssh_audit_results"),
            http_headers_by_target=(
                request.params.get("http_headers_by_target")
                if isinstance(request.params.get("http_headers_by_target"), dict)
                else None
            ),
        )
    if request.tool == "ai-shell":
        ai_shell_control = (
            request.params.get("ai_shell")
            if isinstance(request.params.get("ai_shell"), dict)
            else {}
        )

        def ai_shell_kill_switch() -> bool:
            return bool(
                request.params.get("ai_shell_disabled")
                or ai_shell_control.get("enabled") is False
                or ai_shell_control.get("kill_switch") is True
            )

        return execute_ai_shell_command(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            command=(
                request.params.get("command")
                if isinstance(request.params.get("command"), str)
                else None
            ),
            via=str(request.params.get("via") or "ssh"),
            credentials_ref=(
                request.params.get("credentials_ref")
                if isinstance(request.params.get("credentials_ref"), str)
                else None
            ),
            username=(
                request.params.get("username")
                if isinstance(request.params.get("username"), str)
                else None
            ),
            ssh_port=(
                int(request.params["ssh_port"])
                if isinstance(request.params.get("ssh_port"), int)
                else None
            ),
            output_cap_chars=int(request.params.get("output_cap_chars") or 8000),
            timeout_seconds=timeout_seconds,
            kill_switch_check=ai_shell_kill_switch,
        )
    if request.tool == "external-infra":
        return execute_external_infra_assessment(
            targets=request.targets,
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "passive"
            ),
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            rate_limit=rate_limit,
            nmap_binary=os.getenv("NMAP_BINARY", "nmap"),
            nuclei_binary=os.getenv("NUCLEI_BINARY", "nuclei"),
            netexec_binary=os.getenv("NETEXEC_BINARY", "nxc"),
            ssh_audit_binary=os.getenv("SSH_AUDIT_BINARY", "ssh-audit"),
            include_passive_smb=bool(request.params.get("include_passive_smb", True)),
        )
    if request.tool == "mdns-ssdp":
        return execute_mdns_ssdp_discovery(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            service_types=(
                request.params.get("service_types")
                if isinstance(request.params.get("service_types"), list)
                else None
            ),
            timeout_seconds=timeout_seconds,
            mdns_enabled=bool(request.params.get("mdns_enabled", True)),
            ssdp_enabled=bool(request.params.get("ssdp_enabled", True)),
        )
    if request.tool == "wifi-survey":
        return execute_wifi_survey(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            site=(
                request.params.get("site") if isinstance(request.params.get("site"), str) else None
            ),
            adapter=(
                request.params.get("adapter")
                if isinstance(request.params.get("adapter"), str)
                else None
            ),
            approved_ssids=(
                request.params.get("approved_ssids")
                if isinstance(request.params.get("approved_ssids"), list)
                else None
            ),
            approved_bssids=(
                request.params.get("approved_bssids")
                if isinstance(request.params.get("approved_bssids"), list)
                else None
            ),
            excluded_ssids=(
                request.params.get("excluded_ssids")
                if isinstance(request.params.get("excluded_ssids"), list)
                else None
            ),
            excluded_bssids=(
                request.params.get("excluded_bssids")
                if isinstance(request.params.get("excluded_bssids"), list)
                else None
            ),
            iw_scan_text=(
                request.params.get("fixture_iw_scan_text")
                if isinstance(request.params.get("fixture_iw_scan_text"), str)
                else None
            ),
            airodump_csv_text=(
                request.params.get("fixture_airodump_csv_text")
                if isinstance(request.params.get("fixture_airodump_csv_text"), str)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "iot-default-creds":
        return execute_iot_default_credential_audit(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            timeout_seconds=timeout_seconds,
            max_attempts_per_host=(
                request.params.get("max_attempts_per_host")
                if isinstance(request.params.get("max_attempts_per_host"), int)
                else 3
            ),
            rate_limit_per_second=(
                float(request.params.get("rate_limit_per_second"))
                if isinstance(request.params.get("rate_limit_per_second"), (int, float))
                else 1.0
            ),
        )
    if request.tool == "network-segmentation":
        return execute_network_segmentation_assessment(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "passive"
            ),
            timeout_seconds=timeout_seconds,
            reachability_ports=(
                [
                    int(port)
                    for port in request.params.get("reachability_ports", [])
                    if isinstance(port, int)
                ]
                if isinstance(request.params.get("reachability_ports"), list)
                else None
            ),
            vlan_probe_count=(
                int(request.params.get("vlan_probe_count"))
                if isinstance(request.params.get("vlan_probe_count"), int)
                else 10
            ),
            native_vlan=(
                int(request.params.get("native_vlan"))
                if isinstance(request.params.get("native_vlan"), int)
                else 1
            ),
            target_vlan=(
                int(request.params.get("target_vlan"))
                if isinstance(request.params.get("target_vlan"), int)
                else 2
            ),
            vlan_interface=(
                request.params.get("vlan_interface")
                if isinstance(request.params.get("vlan_interface"), str)
                else None
            ),
            vlan_target_ip=(
                request.params.get("vlan_target_ip")
                if isinstance(request.params.get("vlan_target_ip"), str)
                else None
            ),
        )
    if request.tool == "network-capture":
        return execute_network_capture_assessment(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "passive"
            ),
            interface=(
                request.params.get("interface")
                if isinstance(request.params.get("interface"), str)
                else None
            ),
            capture_seconds=(
                int(request.params.get("capture_seconds"))
                if isinstance(request.params.get("capture_seconds"), int)
                else 60
            ),
            packet_limit=(
                int(request.params.get("packet_limit"))
                if isinstance(request.params.get("packet_limit"), int)
                else 10000
            ),
            packet_text=(
                request.params.get("fixture_packet_text")
                if isinstance(request.params.get("fixture_packet_text"), str)
                else None
            ),
            ip_neigh_text=(
                request.params.get("fixture_ip_neigh_text")
                if isinstance(request.params.get("fixture_ip_neigh_text"), str)
                else None
            ),
            arp_probe_text=(
                request.params.get("fixture_arp_probe_text")
                if isinstance(request.params.get("fixture_arp_probe_text"), str)
                else None
            ),
            arp_table=(
                request.params.get("arp_table")
                if isinstance(request.params.get("arp_table"), list)
                else None
            ),
            arp_probe_enabled=bool(request.params.get("arp_probe_enabled", True)),
            arp_probe_count=(
                int(request.params.get("arp_probe_count"))
                if isinstance(request.params.get("arp_probe_count"), int)
                else 1
            ),
            gateway_ip=(
                request.params.get("gateway_ip")
                if isinstance(request.params.get("gateway_ip"), str)
                else None
            ),
            expected_gateway_mac=(
                request.params.get("expected_gateway_mac")
                if isinstance(request.params.get("expected_gateway_mac"), str)
                else None
            ),
            arp_spoof_proof_requested=bool(
                request.params.get("arp_spoof_proof_requested")
                or request.params.get("arp_spoof_enabled")
            ),
            allow_arp_spoof_proof=bool(request.params.get("allow_arp_spoof_proof")),
            intrusive_authorized=bool(request.params.get("intrusive_authorized")),
            arp_spoof_duration_seconds=(
                int(request.params.get("arp_spoof_duration_seconds"))
                if isinstance(request.params.get("arp_spoof_duration_seconds"), int)
                else 10
            ),
            arp_spoof_target=(
                request.params.get("arp_spoof_target")
                if isinstance(request.params.get("arp_spoof_target"), str)
                else None
            ),
            tcpdump_binary=os.getenv("TCPDUMP_BINARY", "tcpdump"),
            ip_binary=os.getenv("IP_BINARY", "ip"),
            arping_binary=os.getenv("ARPING_BINARY", "arping"),
            arpspoof_binary=os.getenv("ARPSPOOF_BINARY", "arpspoof"),
        )
    if request.tool == "snmp-enum":
        return execute_snmp_enumeration(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            communities=(
                request.params.get("community_strings")
                if isinstance(request.params.get("community_strings"), list)
                else None
            ),
            ports=(
                request.params.get("ports")
                if isinstance(request.params.get("ports"), (int, list, tuple, str))
                else None
            ),
            timeout_seconds=timeout_seconds,
            max_target_hosts=(
                int(request.params.get("max_target_hosts"))
                if isinstance(request.params.get("max_target_hosts"), int)
                else 256
            ),
        )
    if request.tool == "smart-home":
        return execute_smart_home_audit(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            timeout_seconds=timeout_seconds,
            mqtt_listen_seconds=(
                float(request.params.get("mqtt_listen_seconds"))
                if isinstance(request.params.get("mqtt_listen_seconds"), (int, float))
                else 30.0
            ),
            max_target_hosts=(
                int(request.params.get("max_target_hosts"))
                if isinstance(request.params.get("max_target_hosts"), int)
                else 128
            ),
        )
    if request.tool == "social-campaign":
        campaign_export = (
            request.params.get("campaign_export")
            or request.params.get("imported_campaign")
            or request.params.get("gophish_campaign")
        )
        return execute_social_campaign_review(
            targets=request.targets,
            campaign_export=campaign_export if isinstance(campaign_export, dict) else None,
            approved_recipient_domains=(
                request.params.get("approved_recipient_domains")
                if isinstance(request.params.get("approved_recipient_domains"), list)
                else None
            ),
            launch_requested=bool(request.params.get("launch_requested", False)),
            operator_approved=bool(request.params.get("operator_approved", False)),
        )
    if request.tool == "camera-test":
        return execute_camera_test(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            timeout_seconds=timeout_seconds,
            max_target_hosts=(
                int(request.params.get("max_target_hosts"))
                if isinstance(request.params.get("max_target_hosts"), int)
                else 128
            ),
            max_default_credential_attempts=(
                int(request.params.get("max_default_credential_attempts"))
                if isinstance(request.params.get("max_default_credential_attempts"), int)
                else 10
            ),
        )
    if request.tool == "ipv6-discovery":
        return execute_ipv6_discovery(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            interface=(
                request.params.get("interface")
                if isinstance(request.params.get("interface"), str)
                else None
            ),
            timeout_seconds=timeout_seconds,
            max_discovered_hosts=(
                int(request.params.get("max_discovered_hosts"))
                if isinstance(request.params.get("max_discovered_hosts"), int)
                else 128
            ),
            run_nmap=bool(request.params.get("run_nmap", True)),
            ports=(
                request.params.get("ports")
                if isinstance(request.params.get("ports"), (list, str, tuple))
                else None
            ),
            ip_binary=os.getenv("IP_BINARY", "ip"),
            ping_binary=os.getenv("PING_BINARY", "ping"),
            nmap_binary=os.getenv("NMAP_BINARY", "nmap"),
        )
    if request.tool == "nmap":
        return execute_nmap_scan(
            targets=request.targets,
            binary=os.getenv("NMAP_BINARY", "nmap"),
            discovery_only=bool(
                request.params.get("discovery_only", limits.get("discovery_only", True))
            ),
            service_detection=bool(
                request.params.get("service_detection", limits.get("service_detection", False))
            ),
            skip_discovery=bool(
                request.params.get("skip_discovery", limits.get("skip_discovery", False))
            ),
            top_ports=(
                request.params.get("top_ports")
                if isinstance(request.params.get("top_ports"), int)
                else (
                    limits.get("top_ports")
                    if "ports" not in request.params
                    and isinstance(limits.get("top_ports"), int)
                    and request.params.get("top_ports") is None
                    else None
                )
            ),
            ports=(
                request.params.get("ports")
                if isinstance(request.params.get("ports"), (list, str, tuple))
                else (
                    limits.get("ports")
                    if request.params.get("top_ports") is None
                    and not bool(request.params.get("full_port_scan", False))
                    and isinstance(limits.get("ports"), (list, str, tuple))
                    else None
                )
            ),
            scripts=(
                request.params.get("scripts")
                if isinstance(request.params.get("scripts"), list)
                else limits.get("scripts") if isinstance(limits.get("scripts"), list) else None
            ),
            script_args=(
                request.params.get("script_args")
                if isinstance(request.params.get("script_args"), dict)
                else (
                    limits.get("script_args")
                    if isinstance(limits.get("script_args"), dict)
                    else None
                )
            ),
            version_intensity=(
                request.params.get("version_intensity", limits.get("version_intensity"))
                if isinstance(
                    request.params.get("version_intensity", limits.get("version_intensity")), int
                )
                else None
            ),
            timing_template=(
                request.params.get("timing_template", limits.get("timing_template"))
                if isinstance(
                    request.params.get("timing_template", limits.get("timing_template")), str
                )
                else None
            ),
            max_retries=(
                request.params.get("max_retries", limits.get("max_retries"))
                if isinstance(request.params.get("max_retries", limits.get("max_retries")), int)
                else None
            ),
            host_timeout_seconds=(
                request.params.get("host_timeout_seconds", limits.get("host_timeout_seconds"))
                if isinstance(
                    request.params.get("host_timeout_seconds", limits.get("host_timeout_seconds")),
                    (int, float),
                )
                else None
            ),
            ipv6=bool(request.params.get("ipv6", limits.get("ipv6", False))),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "netexec":
        return execute_netexec_smb(
            targets=request.targets,
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "passive"
            ),
            auth_contexts=request.params.get("auth_contexts", []),
            binary=os.getenv("NETEXEC_BINARY", "nxc"),
            sensitive_patterns=(
                request.params.get("sensitive_patterns")
                if isinstance(request.params.get("sensitive_patterns"), list)
                else None
            ),
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
            kill_switch_check=execution_kill_switch_enabled,
        )
    if request.tool == "priv-esc-linux":
        return execute_priv_esc_linux(
            targets=request.targets,
            auth_contexts=request.params.get("auth_contexts", []),
            scope_allowlist=request.scope_allowlist,
            ssh_binary=os.getenv("PRIV_ESC_LINUX_SSH_BINARY", "ssh"),
            sshpass_binary=os.getenv("PRIV_ESC_LINUX_SSHPASS_BINARY", "sshpass"),
            ssh_port=(
                request.params.get("ssh_port")
                if isinstance(request.params.get("ssh_port"), int)
                else 22
            ),
            timeout_seconds=timeout_seconds,
            kill_switch_check=execution_kill_switch_enabled,
        )
    if request.tool == "nuclei":
        return execute_nuclei_scan(
            targets=request.targets,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            binary=os.getenv("NUCLEI_BINARY", "nuclei"),
            template_body=(
                request.params.get("template_body")
                if isinstance(request.params.get("template_body"), str)
                else None
            )
            or None,
            template_id=(
                request.params.get("template_id")
                if isinstance(request.params.get("template_id"), str)
                else None
            )
            or None,
            template_source=(
                request.params.get("template_source")
                if isinstance(request.params.get("template_source"), str)
                else None
            )
            or None,
            template_filename=(
                request.params.get("template_filename")
                if isinstance(request.params.get("template_filename"), str)
                else None
            )
            or None,
            rce_template_selection=bool(request.params.get("rce_template_selection", False)),
            service_evidence=(
                request.params.get("service_evidence")
                if isinstance(request.params.get("service_evidence"), list)
                else None
            ),
            inventory=(
                request.params.get("inventory")
                if isinstance(request.params.get("inventory"), dict)
                else None
            ),
            requested_template_ids=(
                [
                    str(item).strip()
                    for item in request.params.get("requested_template_ids", [])
                    if str(item).strip()
                ]
                if isinstance(request.params.get("requested_template_ids"), list)
                else None
            ),
            oob_enabled=bool(request.params.get("oob_enabled", False)),
            interactsh_server=(
                request.params.get("interactsh_server")
                if isinstance(request.params.get("interactsh_server"), str)
                else None
            ),
            update_templates=bool(request.params.get("update_templates", False)),
            template_update_approved=bool(request.params.get("template_update_approved", False)),
            template_update_dir=(
                request.params.get("template_update_dir")
                if isinstance(request.params.get("template_update_dir"), str)
                else None
            ),
        )
    if request.tool == "playwright-web":
        return execute_playwright_web_validation(
            targets=request.targets,
            auth_contexts=request.params.get("auth_contexts", []),
            scope_allowlist=request.scope_allowlist,
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "passive"
            ),
            requires_auth_context=bool(request.params.get("requires_auth_context", False)),
            proof_marker=(
                request.params.get("proof_marker")
                if isinstance(request.params.get("proof_marker"), str)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "responder":
        return execute_responder_capture(
            targets=request.targets,
            interface=(
                request.params.get("interface")
                if isinstance(request.params.get("interface"), str)
                else ""
            ),
            duration_minutes=request.params.get("duration_minutes"),
            binary=os.getenv("RESPONDER_BINARY", "responder"),
            scope_allowlist=request.scope_allowlist,
        )
    if request.tool == "ldap-enum":
        page_size = request.params.get("page_size", limits.get("page_size", 500))
        return execute_ldap_enum(
            targets=request.targets,
            base_dn=(
                request.params.get("base_dn")
                if isinstance(request.params.get("base_dn"), str)
                else None
            ),
            bind_dn=(
                request.params.get("bind_dn")
                if isinstance(request.params.get("bind_dn"), str)
                else None
            ),
            password_env=(
                request.params.get("password_env")
                if isinstance(request.params.get("password_env"), str)
                else None
            ),
            use_ssl=bool(request.params.get("use_ssl", limits.get("use_ssl", False))),
            timeout_seconds=timeout_seconds,
            page_size=page_size if isinstance(page_size, int) else 500,
        )
    if request.tool == "leak-check":
        leak_export = (
            request.params.get("leak_export")
            or request.params.get("leak_records")
            or request.params.get("lookup_results")
        )
        return execute_leak_check_review(
            targets=request.targets,
            leak_export=leak_export if isinstance(leak_export, dict) else None,
            credential_attack_auto_queue_requested=bool(
                request.params.get("credential_attack_auto_queue_requested")
                or request.params.get("auto_queue_credential_attack")
                or request.params.get("auto_queue_spray")
            ),
            login_attempt_requested=bool(
                request.params.get("login_attempt_requested")
                or request.params.get("perform_login_attempts")
            ),
        )
    if request.tool == "llm-probe":
        max_tokens = request.params.get("max_tokens", limits.get("max_tokens", 96))
        max_probes = request.params.get("max_probes", limits.get("max_probes"))
        return execute_llm_probe(
            targets=request.targets,
            provider_mode=(
                request.params.get("provider_mode")
                if isinstance(request.params.get("provider_mode"), str)
                else "http"
            ),
            deterministic_profile=(
                request.params.get("deterministic_profile")
                if isinstance(request.params.get("deterministic_profile"), str)
                else "safe"
            ),
            api_key_env=(
                request.params.get("api_key_env")
                if isinstance(request.params.get("api_key_env"), str)
                else None
            ),
            bearer_token_env=(
                request.params.get("bearer_token_env")
                if isinstance(request.params.get("bearer_token_env"), str)
                else None
            ),
            model=(
                request.params.get("model")
                if isinstance(request.params.get("model"), str)
                else None
            ),
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens if isinstance(max_tokens, int) else 96,
            max_probes=max_probes if isinstance(max_probes, int) else None,
        )
    if request.tool == "malware-sim":
        telemetry_export = (
            request.params.get("telemetry_export")
            or request.params.get("simulation_export")
            or request.params.get("lab_telemetry")
        )
        return execute_malware_simulation_review(
            targets=request.targets,
            telemetry_export=telemetry_export if isinstance(telemetry_export, dict) else None,
            deploy_payload_requested=bool(
                request.params.get("deploy_payload_requested")
                or request.params.get("deploy_payload")
            ),
            live_execution_requested=bool(
                request.params.get("live_execution_requested")
                or request.params.get("live_execution")
            ),
            external_beacon_requested=bool(
                request.params.get("external_beacon_requested")
                or request.params.get("external_beacon")
            ),
        )
    if request.tool == "impacket-lateral":
        return execute_impacket_lateral(
            targets=request.targets,
            mode=(
                request.params.get("mode")
                if isinstance(request.params.get("mode"), str)
                else "remote_exec"
            ),
            auth_contexts=request.params.get("auth_contexts", []),
            remote_exec_method=(
                request.params.get("remote_exec_method")
                if isinstance(request.params.get("remote_exec_method"), str)
                else "psexec"
            ),
            scope_allowlist=request.scope_allowlist,
            secretsdump_binary=os.getenv("IMPACKET_SECRETSDUMP_BINARY", "secretsdump.py"),
            psexec_binary=os.getenv("IMPACKET_PSEXEC_BINARY", "psexec.py"),
            wmiexec_binary=os.getenv("IMPACKET_WMIEXEC_BINARY", "wmiexec.py"),
            timeout_seconds=timeout_seconds,
            kill_switch_check=execution_kill_switch_enabled,
        )
    if request.tool == "metasploit":
        settings = get_settings()
        return execute_metasploit_exploit(
            targets=request.targets,
            source_finding=(
                request.params.get("source_finding")
                if isinstance(request.params.get("source_finding"), dict)
                else {}
            ),
            module_name=(
                request.params.get("module_name")
                if isinstance(request.params.get("module_name"), str)
                else None
            ),
            auth_contexts=request.params.get("auth_contexts", []),
            lhost=(
                request.params.get("lhost")
                if isinstance(request.params.get("lhost"), str)
                else "127.0.0.1"
            ),
            lport=(
                request.params.get("lport")
                if isinstance(request.params.get("lport"), int)
                else 4444
            ),
            rport=(
                request.params.get("rport")
                if isinstance(request.params.get("rport"), int)
                else None
            ),
            rpc_url=settings.metasploit_rpc_url,
            rpc_username=settings.metasploit_rpc_user,
            rpc_password=settings.metasploit_rpc_password,
            rpc_verify_ssl=settings.metasploit_rpc_verify_ssl,
            msfrpcd_binary=settings.metasploit_rpc_start_binary,
            scope_allowlist=request.scope_allowlist,
            kill_switch_check=execution_kill_switch_enabled,
            start_rpc_daemon=settings.metasploit_rpc_auto_start,
            rpc_start_timeout_seconds=settings.metasploit_rpc_start_timeout_seconds,
        )
    if request.tool == "semgrep":
        return execute_semgrep_scan(
            targets=request.targets,
            jobs=max(rate_limit, 1),
            binary=os.getenv("SEMGREP_BINARY", "semgrep"),
        )
    if request.tool == "content-discovery":
        # Allow profile to specify binary (ffuf default, feroxbuster for recursive discovery)
        profile_binary = str(request.params.get("binary") or "").strip()
        chosen_binary = profile_binary or os.getenv("FFUF_BINARY", "ffuf")
        return execute_content_discovery(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            binary=chosen_binary,
            wordlist_path=str(
                request.params.get("wordlist_path") or os.getenv("FFUF_WORDLIST_PATH", "") or ""
            )
            or None,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "nikto":
        return execute_nikto_scan(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            binary=os.getenv("NIKTO_BINARY", "nikto"),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "sqlmap":
        return execute_sqlmap_confirmation(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            injectable_parameters=(
                request.params.get("injectable_parameters")
                if isinstance(request.params.get("injectable_parameters"), list)
                else []
            ),
            zap_flagged_parameters=(
                request.params.get("zap_flagged_parameters")
                if isinstance(request.params.get("zap_flagged_parameters"), list)
                else []
            ),
            binary=os.getenv("SQLMAP_BINARY", "sqlmap"),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "external-osint":
        return execute_external_osint_recon(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            shodan_api_key=os.getenv("SHODAN_API_KEY", "").strip() or None,
            censys_api_id=os.getenv("CENSYS_API_ID", "").strip() or None,
            censys_api_secret=os.getenv("CENSYS_API_SECRET", "").strip() or None,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "xxe-probe":
        return execute_xxe_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            xml_endpoints=(
                request.params.get("xml_endpoints")
                if isinstance(request.params.get("xml_endpoints"), list)
                else []
            ),
            evidence_records=(
                request.params.get("evidence_records")
                if isinstance(request.params.get("evidence_records"), list)
                else []
            ),
            oob_confirmation_refs=(
                request.params.get("oob_confirmation_refs")
                if isinstance(request.params.get("oob_confirmation_refs"), list)
                else []
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "jwt-probe":
        return execute_jwt_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            evidence_records=(
                request.params.get("evidence_records")
                if isinstance(request.params.get("evidence_records"), list)
                else []
            ),
            jwt_tokens=(
                request.params.get("jwt_tokens")
                if isinstance(request.params.get("jwt_tokens"), list)
                else []
            ),
            replay_contexts=(
                request.params.get("replay_contexts")
                if isinstance(request.params.get("replay_contexts"), list)
                else []
            ),
            public_key_materials=(
                request.params.get("public_key_materials")
                if isinstance(request.params.get("public_key_materials"), list)
                else []
            ),
            jwks_endpoints=(
                request.params.get("jwks_endpoints")
                if isinstance(request.params.get("jwks_endpoints"), list)
                else []
            ),
            weak_secrets=(
                request.params.get("weak_secrets")
                if isinstance(request.params.get("weak_secrets"), list)
                else []
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "vuln-components":
        return execute_vuln_components_scan(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            local_cve_records=(
                request.params.get("local_cve_records")
                if isinstance(request.params.get("local_cve_records"), list)
                else []
            ),
            dependency_paths=(
                request.params.get("dependency_paths")
                if isinstance(request.params.get("dependency_paths"), list)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "xss-extended":
        return execute_xss_extended_scan(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            upload_contexts=(
                request.params.get("upload_contexts")
                if isinstance(request.params.get("upload_contexts"), list)
                else []
            ),
            ajax_contexts=(
                request.params.get("ajax_contexts")
                if isinstance(request.params.get("ajax_contexts"), list)
                else []
            ),
            xssi_contexts=(
                request.params.get("xssi_contexts")
                if isinstance(request.params.get("xssi_contexts"), list)
                else []
            ),
            evidence_records=(
                request.params.get("evidence_records")
                if isinstance(request.params.get("evidence_records"), list)
                else []
            ),
            candidate_paths=(
                request.params.get("candidate_paths")
                if isinstance(request.params.get("candidate_paths"), list)
                else []
            ),
            xss_payload=(
                str(request.params.get("xss_payload"))
                if isinstance(request.params.get("xss_payload"), str)
                else "<html><script>alert('aegispt-xss')</script></html>"
            ),
            ajax_payload=(
                str(request.params.get("ajax_payload"))
                if isinstance(request.params.get("ajax_payload"), str)
                else "<script>alert('aegispt-json-xss')</script>"
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "xss-proof":
        return execute_xss_proof(
            targets=request.targets,
            xss_findings=(
                request.params.get("xss_findings")
                if isinstance(request.params.get("xss_findings"), list)
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "exec-plan":
        plan_obj = request.params.get("plan")
        if not isinstance(plan_obj, dict):
            raise ValueError("exec-plan requires a 'plan' dict in params")
        return execute_exec_plan(
            targets=request.targets,
            plan=plan_obj,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=max(timeout_seconds, 20.0),
        )
    if request.tool == "target-intel":
        return execute_target_intel(
            targets=request.targets,
            timeout_seconds=max(timeout_seconds, 20.0),
        )
    if request.tool == "exploit-developer-agent":
        from workers.runners.exploit_developer_agent.runner import (  # noqa: E402
            execute_exploit_developer_agent,
        )
        params = request.params or {}
        return execute_exploit_developer_agent(
            targets=request.targets,
            hypothesis=str(params.get("hypothesis") or ""),
            finding_title=str(params.get("finding_title") or ""),
            prior_requests=params.get("prior_requests") if isinstance(params.get("prior_requests"), list) else None,
            captured_credentials=params.get("captured_credentials") if isinstance(params.get("captured_credentials"), list) else None,
            observed_paths=params.get("observed_paths") if isinstance(params.get("observed_paths"), list) else None,
            timeout_seconds=max(timeout_seconds, 60.0),
        )
    if request.tool == "lan-intel":
        nmap_raw = request.params.get("nmap_stdout") or ""
        return execute_lan_intel(
            targets=request.targets,
            nmap_stdout=str(nmap_raw) if nmap_raw else None,
            timeout_seconds=max(timeout_seconds, 20.0),
        )
    if request.tool == "ai-pentest-agent":
        raw_cookie = request.params.get("session_cookie")
        agent_cookie = dict(raw_cookie) if isinstance(raw_cookie, dict) else None
        if not agent_cookie:
            for ctx in (request.params.get("auth_contexts") or []):
                if isinstance(ctx, dict):
                    ch = (ctx.get("headers") or {}).get("Cookie", "")
                    if ch and "=" in ch:
                        name, _, value = ch.partition("=")
                        agent_cookie = {name.strip(): value.strip()}
                        break
        return execute_ai_pentest_agent(
            targets=request.targets,
            max_rounds=int(request.params.get("max_rounds") or 8),
            session_cookie=agent_cookie,
            timeout_seconds=max(timeout_seconds, 30.0),
        )
    if request.tool == "smart-web-probe":
        raw_cookie = request.params.get("session_cookie")
        session_cookie = dict(raw_cookie) if isinstance(raw_cookie, dict) else None
        # Also accept from credential vault auth_contexts in params
        if not session_cookie:
            for ctx in (request.params.get("auth_contexts") or []):
                if not isinstance(ctx, dict):
                    continue
                cookie_header = (ctx.get("headers") or {}).get("Cookie", "")
                if cookie_header and "=" in cookie_header:
                    name, _, value = cookie_header.partition("=")
                    session_cookie = {name.strip(): value.strip()}
                    break
        return execute_smart_web_probe(
            targets=request.targets,
            session_cookie=session_cookie,
            previous_findings=(
                request.params.get("previous_findings")
                if isinstance(request.params.get("previous_findings"), list)
                else None
            ),
            engagement_id=str(request.params.get("engagement_id") or ""),
            timeout_seconds=max(timeout_seconds, 30.0),
        )
    if request.tool == "waf-detect":
        return execute_waf_detection(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            response_samples=(
                request.params.get("response_samples")
                if isinstance(request.params.get("response_samples"), list)
                else None
            ),
            auto_evasion_enabled=bool(
                request.params.get("auto_evasion_enabled")
                or request.params.get("enable_evasion")
                or request.params.get("evasion_enabled")
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "ssrf-probe":
        return execute_ssrf_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            request_contexts=(
                request.params.get("request_contexts")
                if isinstance(request.params.get("request_contexts"), list)
                else []
            ),
            header_contexts=(
                request.params.get("header_contexts")
                if isinstance(request.params.get("header_contexts"), list)
                else []
            ),
            candidate_paths=(
                request.params.get("candidate_paths")
                if isinstance(request.params.get("candidate_paths"), list)
                else []
            ),
            oob_confirmation_refs=(
                request.params.get("oob_confirmation_refs")
                if isinstance(request.params.get("oob_confirmation_refs"), list)
                else []
            ),
            callback_url=(
                str(request.params.get("callback_url")).strip()
                if request.params.get("callback_url")
                else None
            ),
            callback_base_url=(
                str(request.params.get("callback_base_url")).strip()
                if request.params.get("callback_base_url")
                else None
            ),
            callback_token=str(request.params.get("callback_token") or "aegispt-ssrf-oob"),
            internal_service_urls=(
                request.params.get("internal_service_urls")
                if isinstance(request.params.get("internal_service_urls"), list)
                else []
            ),
            cloud_metadata_probe_enabled=bool(request.params.get("cloud_metadata_probe_enabled")),
            cloud_hosted=bool(request.params.get("cloud_hosted")),
            cloud_provider=(
                str(request.params.get("cloud_provider")).strip()
                if request.params.get("cloud_provider")
                else None
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "deserialization-probe":
        return execute_deserialization_probe(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            request_contexts=(
                request.params.get("request_contexts")
                if isinstance(request.params.get("request_contexts"), list)
                else []
            ),
            evidence_records=(
                request.params.get("evidence_records")
                if isinstance(request.params.get("evidence_records"), list)
                else []
            ),
            candidate_paths=(
                request.params.get("candidate_paths")
                if isinstance(request.params.get("candidate_paths"), list)
                else []
            ),
            oob_confirmation_refs=(
                request.params.get("oob_confirmation_refs")
                if isinstance(request.params.get("oob_confirmation_refs"), list)
                else []
            ),
            callback_url=(
                str(request.params.get("callback_url")).strip()
                if request.params.get("callback_url")
                else None
            ),
            callback_base_url=(
                str(request.params.get("callback_base_url")).strip()
                if request.params.get("callback_base_url")
                else None
            ),
            callback_token=str(
                request.params.get("callback_token") or "aegispt-deserialization-oob"
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "session-security":
        return execute_session_security_analysis(
            targets=request.targets,
            auth_contexts=request.params.get("auth_contexts", []),
            scope_allowlist=request.scope_allowlist,
            request_contexts=(
                request.params.get("request_contexts")
                if isinstance(request.params.get("request_contexts"), list)
                else []
            ),
            candidate_paths=(
                request.params.get("candidate_paths")
                if isinstance(request.params.get("candidate_paths"), list)
                else []
            ),
            login_url=(
                str(request.params.get("login_url")).strip()
                if request.params.get("login_url")
                else None
            ),
            logout_url=(
                str(request.params.get("logout_url")).strip()
                if request.params.get("logout_url")
                else None
            ),
            protected_url=(
                str(request.params.get("protected_url")).strip()
                if request.params.get("protected_url")
                else None
            ),
            pre_login_url=(
                str(request.params.get("pre_login_url")).strip()
                if request.params.get("pre_login_url")
                else None
            ),
            token_sample_url=(
                str(request.params.get("token_sample_url")).strip()
                if request.params.get("token_sample_url")
                else None
            ),
            username_field=str(request.params.get("username_field") or "username"),
            password_field=str(request.params.get("password_field") or "password"),
            extra_form_fields=(
                request.params.get("extra_form_fields")
                if isinstance(request.params.get("extra_form_fields"), dict)
                else {}
            ),
            success_markers=(
                request.params.get("success_markers")
                if isinstance(request.params.get("success_markers"), list)
                else []
            ),
            login_markers=(
                request.params.get("login_markers")
                if isinstance(request.params.get("login_markers"), list)
                else []
            ),
            token_parameter_names=(
                request.params.get("token_parameter_names")
                if isinstance(request.params.get("token_parameter_names"), list)
                else []
            ),
            sample_count=(
                request.params.get("sample_count")
                if isinstance(request.params.get("sample_count"), int)
                else 10
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "auth-flow":
        # Detect registration URL from candidate_paths (httpx-discovered links)
        candidate_paths = request.params.get("candidate_paths") or []
        auto_reg_url: str | None = request.params.get("registration_url")
        if not auto_reg_url and isinstance(candidate_paths, list):
            for path in candidate_paths:
                p = str(path or "").lower()
                if any(kw in p for kw in ("/newaccount", "/register", "/signup", "/sign-up", "/create-account", "/join")):
                    auto_reg_url = str(path)
                    break
        # Translate flat username/password to auth_contexts list shape.
        # The picker empirically emits {username:"test", password:"test"}
        # when it discovers credentials in HTML (see v9/run 7bb21966
        # 2026-05-22), but the runner requires auth_contexts=[{...}]. The
        # mismatch caused 0% auth-flow execution despite the picker
        # consistently surfacing valid credentials → runner skip → exec_plan
        # blind-guess fallback that fails on the wrong endpoint. Building
        # auth_contexts from the flat shape here unblocks the credentialed
        # exploit path.
        auth_contexts_value = request.params.get("auth_contexts", [])
        if not auth_contexts_value or (isinstance(auth_contexts_value, list) and not auth_contexts_value):
            flat_username = request.params.get("username")
            flat_password = request.params.get("password")
            if flat_username and flat_password:
                auth_contexts_value = [{
                    "username": str(flat_username),
                    "password": str(flat_password),
                }]
        return execute_auth_flow_analysis(
            targets=request.targets,
            auth_contexts=auth_contexts_value,
            scope_allowlist=request.scope_allowlist,
            registration_url=auto_reg_url,
            reg_username_field=str(request.params.get("reg_username_field") or "username"),
            reg_password_field=str(request.params.get("reg_password_field") or "password"),
            extra_reg_fields=(
                request.params.get("extra_reg_fields")
                if isinstance(request.params.get("extra_reg_fields"), dict)
                else None
            ),
            login_url=(
                str(request.params.get("login_url")).strip()
                if request.params.get("login_url")
                else None
            ),
            password_reset_url=(
                str(request.params.get("password_reset_url")).strip()
                if request.params.get("password_reset_url")
                else None
            ),
            reset_consume_url=(
                str(request.params.get("reset_consume_url")).strip()
                if request.params.get("reset_consume_url")
                else None
            ),
            login_method=str(request.params.get("login_method") or "POST"),
            reset_method=str(request.params.get("reset_method") or "POST"),
            username_field=str(request.params.get("username_field") or "username"),
            password_field=str(request.params.get("password_field") or "password"),
            reset_username_field=str(request.params.get("reset_username_field") or "username"),
            reset_token_field=str(request.params.get("reset_token_field") or "token"),
            new_password_field=str(request.params.get("new_password_field") or "new_password"),
            extra_login_fields=(
                request.params.get("extra_login_fields")
                if isinstance(request.params.get("extra_login_fields"), dict)
                else None
            ),
            extra_reset_fields=(
                request.params.get("extra_reset_fields")
                if isinstance(request.params.get("extra_reset_fields"), dict)
                else None
            ),
            invalid_usernames=(
                request.params.get("invalid_usernames")
                if isinstance(request.params.get("invalid_usernames"), list)
                else []
            ),
            reset_token_samples=int(request.params.get("reset_token_samples") or 5),
            failed_login_attempts=int(request.params.get("failed_login_attempts") or 10),
            invalid_password=str(
                request.params.get("invalid_password") or "AegisPT-invalid-password-000!"
            ),
            reset_poison_host=(
                str(request.params.get("reset_poison_host")).strip()
                if request.params.get("reset_poison_host")
                else None
            ),
            lockout_markers=(
                request.params.get("lockout_markers")
                if isinstance(request.params.get("lockout_markers"), list)
                else []
            ),
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "zap":
        return execute_zap_scan(
            targets=request.targets,
            base_url=os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080"),
            api_key=os.getenv("ZAP_API_KEY", "change-me-zap-key"),
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            scan_mode=str(request.params.get("limits", {}).get("scan_mode", "spider-passive")),
            active_scanner_ids=(
                request.params.get("active_scanner_ids")
                if isinstance(request.params.get("active_scanner_ids"), list)
                else limits.get("zap_active_scanner_ids", [])
            ),
        )

    if request.tool == "recon-deliverable":
        return execute_recon_deliverable(
            targets=request.targets,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "code-exec-attack":
        return execute_code_exec_attack(
            targets=request.targets,
            script=str(request.params.get("script") or ""),
            scope_allowlist=request.scope_allowlist,
            # code-exec-attack scripts are multi-step exploit chains
            # (login + state-change + read + flag-scan + retries).
            # 10s default is too tight; chains time-out before reaching
            # the flag. 60s is the runner's own default.
            timeout_seconds=max(timeout_seconds, 60.0),
        )
    if request.tool == "pre-recon-source":
        return execute_pre_recon_source(
            targets=request.targets,
            source_dir=str(request.params.get("source_dir") or "") or None,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "pre-recon-cpg":
        return execute_pre_recon_cpg(
            targets=request.targets,
            source_dir=str(request.params.get("source_dir") or "") or None,
            scope_allowlist=request.scope_allowlist,
            timeout_seconds=timeout_seconds,
        )

    raise ValueError(f"unsupported tool runner: {request.tool}")


def _task_query(task_uuid: UUID):
    return (
        select(Task)
        .options(
            joinedload(Task.run).selectinload(Run.tasks),
        )
        .where(Task.id == task_uuid)
    )


def _scope_for_run(session, run: Run | None) -> Scope | None:
    if run is None:
        return None
    return session.scalar(latest_scope_query(run.engagement_id))


def _task_targets(task: Task) -> list[str]:
    configured_targets = task.params_json.get("targets")
    if isinstance(configured_targets, list):
        normalized_targets = [
            target.strip()
            for target in configured_targets
            if isinstance(target, str) and target.strip()
        ]
        if normalized_targets:
            return normalized_targets

    return [task.target_id]


def _resolve_secret_binding_value(session, binding: dict[str, object]) -> str | None:
    secret_ref_id = binding.get("secret_ref_id")
    if not isinstance(secret_ref_id, str) or not secret_ref_id.strip():
        return None
    try:
        secret_uuid = UUID(secret_ref_id)
    except ValueError:
        return None
    secret_ref = session.scalar(select(SecretRef).where(SecretRef.id == secret_uuid))
    if secret_ref is None:
        return None
    return _load_secret_ref_value(session, secret_ref)


def _load_secret_ref_value(
    session,
    secret_ref: SecretRef,
    *,
    visited: set[UUID] | None = None,
) -> str | None:
    if visited is None:
        visited = set()
    if secret_ref.id in visited:
        return None
    visited.add(secret_ref.id)

    value = load_secret_value(secret_ref, get_settings())
    if value is not None:
        return value

    pointer = str(secret_ref.vault_pointer or "").strip()
    if not pointer.startswith("aegispt://secret-ref/"):
        return None
    raw_secret_ref_id = pointer.removeprefix("aegispt://secret-ref/").strip()
    try:
        nested_secret_id = UUID(raw_secret_ref_id)
    except ValueError:
        return None
    nested_secret_ref = session.scalar(select(SecretRef).where(SecretRef.id == nested_secret_id))
    if nested_secret_ref is None:
        return None
    return _load_secret_ref_value(session, nested_secret_ref, visited=visited)


def _materialize_biz_logic_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    api_key_header = (
        str(task.params_json.get("api_key_header") or "X-API-Key").strip() or "X-API-Key"
    )
    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        headers: dict[str, str] = {}
        basic_auth = None
        bearer_value = _resolve_secret_binding_value(
            session, dict(bindings.get("bearer_token") or {})
        )
        if bearer_value:
            headers["Authorization"] = (
                bearer_value
                if bearer_value.lower().startswith("bearer ")
                else f"Bearer {bearer_value}"
            )
        session_value = _resolve_secret_binding_value(session, dict(bindings.get("session") or {}))
        if session_value:
            headers["Cookie"] = session_value
        api_key_value = _resolve_secret_binding_value(session, dict(bindings.get("api_key") or {}))
        if api_key_value:
            headers[api_key_header] = api_key_value

        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        username = str(raw_context.get("username") or "").strip()
        if password_value and username:
            basic_auth = {"username": username, "password": password_value}

        if not headers and basic_auth is None:
            continue

        materialized_contexts.append(
            {
                "label": str(
                    raw_context.get("label") or username or "Authenticated Account"
                ).strip()
                or "Authenticated Account",
                "username": username,
                "role": str(raw_context.get("role") or "User").strip() or "User",
                "tenant": str(raw_context.get("tenant") or "").strip() or None,
                "marker_tokens": [
                    token
                    for token in list(raw_context.get("marker_tokens") or [])
                    if isinstance(token, str) and token.strip()
                ],
                "owned_object_ids": [
                    str(item).strip()
                    for item in list(raw_context.get("owned_object_ids") or [])
                    if str(item).strip()
                ],
                "headers": headers,
                **({"basic_auth": basic_auth} if basic_auth is not None else {}),
            }
        )
    return materialized_contexts


def _materialize_api_assessment_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    api_key_header = (
        str(task.params_json.get("api_key_header") or "X-API-Key").strip() or "X-API-Key"
    )
    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        headers: dict[str, str] = {}
        basic_auth = None
        bearer_value = _resolve_secret_binding_value(
            session,
            dict(bindings.get("bearer_token") or {}),
        )
        if bearer_value:
            headers["Authorization"] = (
                bearer_value
                if bearer_value.lower().startswith("bearer ")
                else f"Bearer {bearer_value}"
            )
        session_value = _resolve_secret_binding_value(session, dict(bindings.get("session") or {}))
        if session_value:
            headers["Cookie"] = session_value
        api_key_value = _resolve_secret_binding_value(session, dict(bindings.get("api_key") or {}))
        if api_key_value:
            headers[api_key_header] = api_key_value

        password_value = _resolve_secret_binding_value(
            session,
            dict(bindings.get("password") or {}),
        )
        username = str(raw_context.get("username") or "").strip()
        if password_value and username:
            basic_auth = {"username": username, "password": password_value}

        if not headers and basic_auth is None:
            continue

        materialized_contexts.append(
            {
                "label": str(raw_context.get("label") or username or "API Access Context").strip()
                or "API Access Context",
                "username": username,
                "role": str(raw_context.get("role") or "User").strip() or "User",
                "tenant": str(raw_context.get("tenant") or "").strip() or None,
                "marker_tokens": [
                    token
                    for token in list(raw_context.get("marker_tokens") or [])
                    if isinstance(token, str) and token.strip()
                ],
                "owned_object_ids": [
                    str(item).strip()
                    for item in list(raw_context.get("owned_object_ids") or [])
                    if str(item).strip()
                ],
                "headers": headers,
                **({"basic_auth": basic_auth} if basic_auth is not None else {}),
            }
        )
    return materialized_contexts


def _materialize_playwright_web_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    api_key_header = (
        str(task.params_json.get("api_key_header") or "X-API-Key").strip() or "X-API-Key"
    )
    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        headers: dict[str, str] = {}
        bearer_value = _resolve_secret_binding_value(
            session, dict(bindings.get("bearer_token") or {})
        )
        if bearer_value:
            headers["Authorization"] = (
                bearer_value
                if bearer_value.lower().startswith("bearer ")
                else f"Bearer {bearer_value}"
            )
        session_value = _resolve_secret_binding_value(session, dict(bindings.get("session") or {}))
        if session_value:
            headers["Cookie"] = session_value
        api_key_value = _resolve_secret_binding_value(session, dict(bindings.get("api_key") or {}))
        if api_key_value:
            headers[api_key_header] = api_key_value

        if not headers:
            continue

        materialized_contexts.append(
            {
                "label": str(raw_context.get("label") or "Browser Session").strip()
                or "Browser Session",
                "role": str(raw_context.get("role") or "User").strip() or "User",
                "headers": headers,
            }
        )
    return materialized_contexts


def _materialize_session_security_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        username = str(raw_context.get("username") or "").strip()
        if not username or not password_value:
            continue

        headers: dict[str, str] = {}
        session_value = _resolve_secret_binding_value(session, dict(bindings.get("session") or {}))
        if session_value:
            headers["Cookie"] = session_value

        materialized_contexts.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password_value,
                "role": str(raw_context.get("role") or "User").strip() or "User",
                "headers": headers,
            }
        )
    return materialized_contexts


def _materialize_bloodhound_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue
        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        username = str(raw_context.get("username") or "").strip()
        if not username or not password_value:
            continue
        materialized_contexts.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password_value,
                "domain": str(raw_context.get("domain") or "").strip() or None,
            }
        )
    return materialized_contexts


def _materialize_netexec_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        username = str(raw_context.get("username") or "").strip()
        if not username:
            continue
        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        ntlm_hash_value = _resolve_secret_binding_value(
            session, dict(bindings.get("ntlm_hash") or {})
        )
        if not password_value and not ntlm_hash_value:
            continue

        materialized_context = {
            "label": str(raw_context.get("label") or username).strip() or username,
            "username": username,
            "domain": str(raw_context.get("domain") or "").strip() or None,
            "local_auth": bool(raw_context.get("local_auth", False)),
        }
        if password_value:
            materialized_context["password"] = password_value
        if ntlm_hash_value:
            materialized_context["ntlm_hash"] = ntlm_hash_value
        materialized_contexts.append(materialized_context)

    return materialized_contexts


def _materialize_priv_esc_linux_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        username = str(raw_context.get("username") or "").strip()
        if not username:
            continue
        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        if not password_value:
            continue

        materialized_context: dict[str, object] = {
            "label": str(raw_context.get("label") or username).strip() or username,
            "username": username,
            "password": password_value,
        }
        ssh_port = raw_context.get("ssh_port") or raw_context.get("port")
        if isinstance(ssh_port, int) and 1 <= ssh_port <= 65535:
            materialized_context["ssh_port"] = ssh_port
        materialized_contexts.append(materialized_context)

    return materialized_contexts


def _materialize_metasploit_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        username = str(raw_context.get("username") or "").strip()
        if not username:
            continue
        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        ntlm_hash_value = _resolve_secret_binding_value(
            session, dict(bindings.get("ntlm_hash") or {})
        )
        if not password_value and not ntlm_hash_value:
            continue

        materialized_context = {
            "label": str(raw_context.get("label") or username).strip() or username,
            "username": username,
            "domain": str(raw_context.get("domain") or "").strip() or None,
            "local_auth": bool(raw_context.get("local_auth", False)),
        }
        if password_value:
            materialized_context["password"] = password_value
        if ntlm_hash_value:
            materialized_context["ntlm_hash"] = ntlm_hash_value
        materialized_contexts.append(materialized_context)
    return materialized_contexts


def _materialize_impacket_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue

        username = str(raw_context.get("username") or "").strip()
        if not username:
            continue
        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        ntlm_hash_value = _resolve_secret_binding_value(
            session, dict(bindings.get("ntlm_hash") or {})
        )
        if not password_value and not ntlm_hash_value:
            continue

        materialized_context = {
            "label": str(raw_context.get("label") or username).strip() or username,
            "username": username,
            "domain": str(raw_context.get("domain") or "").strip() or None,
            "local_auth": bool(raw_context.get("local_auth", False)),
        }
        if password_value:
            materialized_context["password"] = password_value
        if ntlm_hash_value:
            materialized_context["ntlm_hash"] = ntlm_hash_value
        materialized_contexts.append(materialized_context)
    return materialized_contexts


def _materialize_credential_attack_auth_contexts(session, task: Task) -> list[dict[str, object]]:
    raw_contexts = task.params_json.get("auth_contexts")
    if not isinstance(raw_contexts, list):
        return []

    materialized_contexts: list[dict[str, object]] = []
    for raw_context in raw_contexts:
        if not isinstance(raw_context, dict):
            continue
        bindings = raw_context.get("secret_bindings")
        if not isinstance(bindings, dict):
            continue
        password_value = _resolve_secret_binding_value(
            session, dict(bindings.get("password") or {})
        )
        username = str(raw_context.get("username") or "").strip()
        if not username or not password_value:
            continue
        materialized_contexts.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password_value,
                "domain": str(raw_context.get("domain") or "").strip() or None,
            }
        )
    return materialized_contexts


def _materialize_credential_attack_hash_sources(
    session,
    task: Task,
) -> list[dict[str, object]]:
    raw_sources = task.params_json.get("hash_sources")
    if not isinstance(raw_sources, list):
        return []

    materialized_sources: list[dict[str, object]] = []
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            continue
        secret_value = _resolve_secret_binding_value(
            session,
            {
                "secret_ref_id": raw_source.get("secret_ref_id"),
            },
        )
        if not secret_value:
            continue
        materialized_sources.append(
            {
                "label": str(raw_source.get("label") or "Hash source").strip() or "Hash source",
                "secret_kind": str(raw_source.get("secret_kind") or "").strip(),
                "value": secret_value,
            }
        )
    return materialized_sources


def _materialize_credential_attack_password_candidates(
    session,
    task: Task,
) -> list[dict[str, object]]:
    raw_candidates = task.params_json.get("password_candidates")
    if not isinstance(raw_candidates, list):
        return []

    materialized_candidates: list[dict[str, object]] = []
    for raw_candidate in raw_candidates:
        if not isinstance(raw_candidate, dict):
            continue
        secret_value = _resolve_secret_binding_value(
            session,
            {
                "secret_ref_id": raw_candidate.get("secret_ref_id"),
            },
        )
        if not secret_value:
            continue
        materialized_candidates.append(
            {
                "label": str(raw_candidate.get("label") or "Password candidate").strip()
                or "Password candidate",
                "value": secret_value,
            }
        )
    return materialized_candidates


# #338 — tools that read stack-aware path augmentation. The set must be
# kept in sync with the probes that accept a `stack_hints` kwarg in
# workers/runners/<probe>/runner.py. Adding a tool here makes the
# orchestrator query EvidenceObservation rows and inject normalized
# hints into runner_params["stack_hints"] before dispatch.
_STACK_HINT_AWARE_TOOLS: frozenset[str] = frozenset({
    "info-disclosure-probe",
    "stored-xss-probe",
    "file-upload-probe",
    "param-pollution-probe",
    "cookie-tamper-probe",
})


def _attack_candidates_for_run(session, run_id) -> list[dict]:
    """Read target_intel's emitted ``attack_candidates`` for ``run_id``.

    Replaces the deleted ``_stack_hints_for_run`` per backlog-402 — instead
    of normalizing free-text technology_stack into a fixed stack-key
    vocabulary, the orchestrator now consumes target_intel's emergent
    per-target candidate paths directly.

    Returns [] when run_id is None, no observations exist, or no rows carry
    an ``attack_candidates`` field — the probes' baseline catalogs drive
    discovery unchanged.
    """
    if run_id is None:
        return []
    try:
        from workers.runners._path_augmentation import attack_candidates_for_run as _read
        return _read(session, run_id)
    except Exception:
        return []


def _runner_params_for_task(session, task: Task) -> dict[str, object]:
    params = dict(task.params_json or {})
    if task.tool == "api-assessment":
        params["auth_contexts"] = _materialize_api_assessment_auth_contexts(session, task)
    if task.tool == "biz-logic-probe":
        params["auth_contexts"] = _materialize_biz_logic_auth_contexts(session, task)
    if task.tool == "idor-bac":
        params["auth_contexts"] = _materialize_biz_logic_auth_contexts(session, task)
    if task.tool == "client-state":
        params["auth_contexts"] = _materialize_biz_logic_auth_contexts(session, task)
    if task.tool == "bloodhound-collect":
        params["auth_contexts"] = _materialize_bloodhound_auth_contexts(session, task)
    if task.tool == "credential-attacks":
        params["auth_contexts"] = _materialize_credential_attack_auth_contexts(session, task)
        params["hash_sources"] = _materialize_credential_attack_hash_sources(session, task)
        params["password_candidates"] = _materialize_credential_attack_password_candidates(
            session,
            task,
        )
    if task.tool == "impacket-lateral":
        params["auth_contexts"] = _materialize_impacket_auth_contexts(session, task)
    if task.tool == "metasploit":
        params["auth_contexts"] = _materialize_metasploit_auth_contexts(session, task)
    if task.tool == "netexec":
        params["auth_contexts"] = _materialize_netexec_auth_contexts(session, task)
    if task.tool == "priv-esc-linux":
        params["auth_contexts"] = _materialize_priv_esc_linux_auth_contexts(session, task)
    if task.tool == "playwright-web":
        params["auth_contexts"] = _materialize_playwright_web_auth_contexts(session, task)
    if task.tool == "session-security":
        params["auth_contexts"] = _materialize_session_security_auth_contexts(session, task)
    if task.tool == "auth-flow":
        params["auth_contexts"] = _materialize_session_security_auth_contexts(session, task)
    if task.tool in {"content-discovery", "nuclei", "zap"}:
        params["auth_contexts"] = _materialize_api_assessment_auth_contexts(session, task)
    return params


def _effective_command_preview_params(params: dict[str, object]) -> dict[str, object]:
    limits = params.get("limits")
    if not isinstance(limits, dict):
        return dict(params)
    return {**limits, **params}


def _runner_command_preview(tool: str, targets: list[str], params: dict[str, object]) -> str:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    effective_params = _effective_command_preview_params(params)
    if tool == "ai-shell":
        try:
            contract = normalize_ai_shell_params(
                params=effective_params,
                proposed_target=normalized_targets[0] if normalized_targets else "",
                require_runtime_scope=False,
            )
            return ai_shell_command_preview(contract=contract)
        except AiShellSafetyError as exc:
            return f"$ ai-shell --blocked {shlex.quote(exc.reason)} --approved-scope"
    if tool == "social-campaign":
        campaign_ref = str(
            effective_params.get("campaign_id")
            or effective_params.get("campaign_ref")
            or "imported-campaign"
        ).strip()
        return (
            "$ social-campaign --review-only --import "
            f"{shlex.quote(campaign_ref or 'imported-campaign')} --no-send --redact-secrets"
        )
    if tool == "waf-detect":
        target = normalized_targets[0] if normalized_targets else "<approved-target>"
        return (
            "$ waf-detect --defensive-detection "
            f"--target {shlex.quote(target)} --no-auto-evasion --operator-review"
        )
    if tool == "c2-ingest":
        source = str(
            effective_params.get("framework")
            or effective_params.get("source")
            or "imported-c2-export"
        ).strip()
        return (
            "$ c2-ingest --read-only --import "
            f"{shlex.quote(source or 'imported-c2-export')} --no-command-exec --redact-secrets"
        )
    if tool == "malware-sim":
        source = str(effective_params.get("source") or "imported-lab-telemetry").strip()
        return (
            "$ malware-sim --lab-only --import "
            f"{shlex.quote(source or 'imported-lab-telemetry')} --no-payload --no-beacon"
        )
    if tool == "leak-check":
        source = str(effective_params.get("source") or "imported-leak-metadata").strip()
        return (
            "$ leak-check --metadata-only --import "
            f"{shlex.quote(source or 'imported-leak-metadata')} --redact-secrets --no-auto-spray"
        )
    if tool == "nmap":
        command = [os.getenv("NMAP_BINARY", "nmap"), "-n", "-oX", "<evidence>/nmap-results.xml"]
        if bool(effective_params.get("ipv6", False)):
            command.insert(2, "-6")
        discovery_only = bool(effective_params.get("discovery_only", True))
        if discovery_only:
            command.append("-sn")
        else:
            if bool(effective_params.get("skip_discovery", False)):
                command.append("-Pn")
            if bool(effective_params.get("service_detection", False)):
                command.append("-sV")
                if isinstance(effective_params.get("version_intensity"), int):
                    command.extend(
                        ["--version-intensity", str(effective_params["version_intensity"])]
                    )
            if bool(effective_params.get("full_port_scan", False)):
                command.append("-p-")
            elif effective_params.get("ports"):
                ports_value = effective_params["ports"]
                if isinstance(ports_value, list):
                    command.extend(["-p", ",".join(str(port) for port in ports_value)])
                else:
                    command.extend(["-p", str(ports_value)])
            elif isinstance(effective_params.get("top_ports"), int) and effective_params.get(
                "top_ports"
            ):
                command.extend(["--top-ports", str(effective_params["top_ports"])])
            scripts_value = effective_params.get("scripts")
            if isinstance(scripts_value, list) and scripts_value:
                command.extend(["--script", ",".join(str(script) for script in scripts_value)])
                script_args = effective_params.get("script_args")
                if isinstance(script_args, dict) and script_args:
                    command.extend(
                        [
                            "--script-args",
                            ",".join(
                                f"{key}={value}"
                                for key, value in sorted(script_args.items())
                                if str(key).strip() and str(value).strip()
                            ),
                        ]
                    )
            timing_template = str(effective_params.get("timing_template") or "").strip().upper()
            if timing_template in {f"T{value}" for value in range(0, 6)}:
                command.append(f"-{timing_template}")
            if isinstance(effective_params.get("max_retries"), int):
                command.extend(["--max-retries", str(effective_params["max_retries"])])
            if isinstance(effective_params.get("host_timeout_seconds"), (int, float)):
                command.extend(
                    ["--host-timeout", f"{int(effective_params['host_timeout_seconds'])}s"]
                )
        command.extend(normalized_targets)
        return "$ " + " ".join(shlex.quote(part) for part in command)
    target_label = ", ".join(normalized_targets[:5]) or "approved scope"
    extra = f" (+{len(normalized_targets) - 5} more)" if len(normalized_targets) > 5 else ""
    if tool == "playwright-web":
        mode = str(effective_params.get("mode") or "passive").strip() or "passive"
        marker = " --proof-marker" if effective_params.get("proof_marker") else ""
        return f"$ playwright chromium --{mode} --approved-scope {target_label}{extra}{marker}"
    if tool == "crypto-audit":
        mode = str(effective_params.get("mode") or "passive").strip() or "passive"
        testssl_binary = os.getenv("TESTSSL_BINARY", "testssl.sh")
        ssh_audit_binary = os.getenv("SSH_AUDIT_BINARY", "ssh-audit")
        return (
            f"$ crypto-audit --mode {mode} --testssl-binary {shlex.quote(testssl_binary)} "
            f"--ssh-audit-binary {shlex.quote(ssh_audit_binary)} "
            f"--approved-scope {target_label}{extra} --no-bruteforce --no-decryption"
        )
    if tool == "content-discovery":
        wordlist = str(effective_params.get("wordlist_path") or "default-web-content").strip()
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        return (
            "$ ffuf -u "
            f"{shlex.quote((normalized_targets[0] if normalized_targets else '<target>').rstrip('/') + '/FUZZ')} "
            f"-w {shlex.quote(wordlist)} -rate {int(effective_params.get('max_rps') or 2)} "
            f"--auth-contexts {context_count} --approved-scope {target_label}{extra}"
        )
    if tool == "nikto":
        return f"$ nikto -host {target_label}{extra} -Format json --approved-scope"
    if tool == "nuclei":
        command = [
            os.getenv("NUCLEI_BINARY", "nuclei"),
            "-duc",
            "-l",
            "<evidence>/targets.txt",
            "-jsonl-export",
            "<evidence>/nuclei-results.jsonl",
            "-rl",
            str(int(effective_params.get("max_rps") or effective_params.get("rate_limit") or 1)),
            "-timeout",
            str(max(int(effective_params.get("timeout_seconds") or 10), 1)),
            "-retries",
            "0",
            "-no-stdin",
            "-nc",
        ]
        if bool(effective_params.get("rce_template_selection", False)):
            command.extend(["-t", "<aegispt-rce-generic-signal-detection.yaml>"])
            command.extend(["-id", "<service-matched-rce-cve-ids>"])
            if not (
                bool(effective_params.get("oob_enabled", False))
                and str(effective_params.get("interactsh_server") or "").strip()
            ):
                command.append("-no-interactsh")
            else:
                command.extend(["-iserver", str(effective_params["interactsh_server"])])
            prefix = (
                "$ nuclei -update-templates --approved; "
                if bool(effective_params.get("update_templates", False))
                and bool(effective_params.get("template_update_approved", False))
                else "$ "
            )
            return (
                prefix
                + " ".join(shlex.quote(str(part)) for part in command)
                + f" --approved-scope {target_label}{extra}"
            )
        template_label = str(effective_params.get("template_id") or "aegispt-http-status-200")
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        command.extend(["-t", f"<{template_label}.yaml>"])
        return (
            "$ "
            + " ".join(shlex.quote(str(part)) for part in command)
            + f" --auth-contexts {context_count}"
        )
    if tool == "sqlmap":
        parameter_count = (
            len(effective_params.get("injectable_parameters") or [])
            if isinstance(effective_params.get("injectable_parameters"), list)
            else 0
        )
        parameter_count += (
            len(effective_params.get("zap_flagged_parameters") or [])
            if isinstance(effective_params.get("zap_flagged_parameters"), list)
            else 0
        )
        return (
            "$ sqlmap phase-a --batch --smart --identify-waf --level 1 --risk 1; "
            "phase-b --level 3 --risk 2 --technique T "
            "--tamper space2comment,between,randomcase "
            f"--approved-parameters {parameter_count} --approved-scope {target_label}{extra}"
        )
    if tool == "external-osint":
        return f"$ shodan/censys-api --read-only --api-key-required --approved-scope {target_label}{extra}"
    if tool == "xxe-probe":
        endpoint_count = (
            len(effective_params.get("xml_endpoints") or [])
            if isinstance(effective_params.get("xml_endpoints"), list)
            else 0
        )
        return (
            "$ xxe-probe --read-only-file-uri file:///etc/passwd "
            f"--approved-endpoints {endpoint_count or len(normalized_targets)} --approved-scope {target_label}{extra}"
        )
    if tool == "jwt-probe":
        context_count = (
            len(effective_params.get("replay_contexts") or [])
            if isinstance(effective_params.get("replay_contexts"), list)
            else 0
        )
        token_count = (
            len(effective_params.get("jwt_tokens") or [])
            if isinstance(effective_params.get("jwt_tokens"), list)
            else 0
        )
        return (
            "$ jwt-probe --bounded-weak-secrets --no-token-storage "
            f"--provided-tokens {token_count} --replay-contexts {context_count} "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "vuln-components":
        record_count = (
            len(effective_params.get("local_cve_records") or [])
            if isinstance(effective_params.get("local_cve_records"), list)
            else 0
        )
        return (
            "$ vuln-components --fingerprint-responses --probe-exposed-dependency-files "
            f"--local-cve-records {record_count} --approved-scope {target_label}{extra}"
        )
    if tool == "idor-bac":
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        return (
            "$ idor-bac --bounded-id-substitution --max-id-delta 20 "
            f"--auth-contexts {context_count} --approved-scope {target_label}{extra}"
        )
    if tool == "client-state":
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        form_count = (
            len(effective_params.get("form_contexts") or [])
            if isinstance(effective_params.get("form_contexts"), list)
            else 0
        )
        cookie_count = (
            len(effective_params.get("cookie_contexts") or [])
            if isinstance(effective_params.get("cookie_contexts"), list)
            else 0
        )
        request_count = (
            len(effective_params.get("request_contexts") or [])
            if isinstance(effective_params.get("request_contexts"), list)
            else 0
        )
        return (
            "$ client-state --hidden-fields --cookies --request-params --price --workflow "
            f"--auth-contexts {context_count} --form-contexts {form_count} "
            f"--cookie-contexts {cookie_count} --request-contexts {request_count} "
            f"--configured-credentials-only --approved-scope {target_label}{extra}"
        )
    if tool == "headers-security":
        origin_count = (
            len(effective_params.get("additional_origins") or [])
            if isinstance(effective_params.get("additional_origins"), list)
            else 0
        )
        redirect_count = (
            len(effective_params.get("redirect_paths") or [])
            if isinstance(effective_params.get("redirect_paths"), list)
            else 0
        )
        return (
            "$ headers-security --passive-headers --cors-origin-reflection "
            f"--additional-origins {origin_count} --redirect-probes {redirect_count} "
            f"--no-cors-data-extraction --approved-scope {target_label}{extra}"
        )
    if tool == "graphql-probe":
        endpoint_count = (
            len(effective_params.get("endpoint_paths") or [])
            if isinstance(effective_params.get("endpoint_paths"), list)
            else 4
        )
        ide_count = (
            len(effective_params.get("ide_paths") or [])
            if isinstance(effective_params.get("ide_paths"), list)
            else 2
        )
        max_depth = min(max(int(effective_params.get("max_depth") or 20), 2), 20)
        return (
            "$ graphql-probe --discover-endpoints "
            f"{endpoint_count} --discover-ides {ide_count} --introspection --depth {max_depth} "
            "--field-suggestions --argument-injection --batch-size 2 "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "graphql-command-injection":
        command = str(
            effective_params.get("command") or "echo aegispt-command-injection-proof"
        ).strip()
        endpoint_path = str(effective_params.get("endpoint_path") or "/graphql").strip()
        return (
            "$ graphql-command-injection --local-dvga "
            f"{target_label} --endpoint {shlex.quote(endpoint_path)} "
            "--field systemDiagnostics --argument cmd "
            f"--command-allowlist-entry {shlex.quote(command)} "
            f"--intrusive-approval --approved-scope {target_label}{extra}"
        )
    if tool == "ssti-probe":
        parameter_count = (
            len(effective_params.get("parameter_names") or [])
            if isinstance(effective_params.get("parameter_names"), list)
            else 10
        )
        stored_count = (
            len(effective_params.get("stored_form_contexts") or [])
            if isinstance(effective_params.get("stored_form_contexts"), list)
            else 0
        )
        gruyere_count = (
            len(effective_params.get("gruyere_contexts") or [])
            if isinstance(effective_params.get("gruyere_contexts"), list)
            else 0
        )
        return (
            "$ ssti-probe --math-expressions-only --reflected-parameters "
            f"{parameter_count} --stored-contexts {stored_count} "
            f"--gruyere-contexts {gruyere_count} --no-command-payloads "
            f"--no-config-dump-payloads --approved-scope {target_label}{extra}"
        )
    if tool == "http-smuggling":
        evidence_count = (
            len(effective_params.get("proxy_evidence") or [])
            if isinstance(effective_params.get("proxy_evidence"), list)
            else 0
        )
        timeout_value = min(float(effective_params.get("timeout_seconds") or 5.0), 5.0)
        return (
            "$ http-smuggling --timing-only --variants CL.TE,TE.CL,TE.TE "
            f"--proxy-evidence-required --configured-proxy-evidence {evidence_count} "
            f"--timeout {timeout_value:g}s --no-confirming-request "
            f"--no-hijacking --no-cache-poisoning --approved-scope {target_label}{extra}"
        )
    if tool == "oauth-probe":
        authorization_count = (
            len(effective_params.get("authorization_urls") or [])
            if isinstance(effective_params.get("authorization_urls"), list)
            else 0
        )
        token_evidence_count = (
            len(effective_params.get("token_evidence") or [])
            if isinstance(effective_params.get("token_evidence"), list)
            else 0
        )
        return (
            "$ oauth-probe --discover-openid-configuration --discover-js-auth-requests "
            f"--configured-authorization-urls {authorization_count} "
            f"--token-evidence {token_evidence_count} --redirects-not-followed "
            "--no-third-party-idp-requests --no-token-exchange "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "logging-probe":
        admin_count = (
            len(effective_params.get("admin_paths") or [])
            if isinstance(effective_params.get("admin_paths"), list)
            else 7
        )
        debug_count = (
            len(effective_params.get("debug_paths") or [])
            if isinstance(effective_params.get("debug_paths"), list)
            else 6
        )
        error_count = (
            len(effective_params.get("error_paths") or [])
            if isinstance(effective_params.get("error_paths"), list)
            else 1
        )
        return (
            "$ logging-probe --error-leakage --admin-debug-paths "
            f"{admin_count + debug_count} --error-paths {error_count} "
            "--log-injection-crlf --log-format-strings --log4shell-pattern-detection-only "
            "--no-jndi-callback-listener --no-admin-takeover "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "ssh-brute":
        max_attempts = int(effective_params.get("max_attempts_per_service") or 200)
        rate_limit_value = min(float(effective_params.get("rate_limit_per_second") or 5), 5.0)
        return (
            "$ hydra --bounded-service-brute ssh,ftp,telnet,rdp "
            f"--top-50-first --max-attempts-per-service {max_attempts} "
            f"--rate-limit {rate_limit_value:g}/s --stop-after-lockouts 3 "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "xss-extended":
        upload_count = (
            len(effective_params.get("upload_contexts") or [])
            if isinstance(effective_params.get("upload_contexts"), list)
            else 0
        )
        ajax_count = (
            len(effective_params.get("ajax_contexts") or [])
            if isinstance(effective_params.get("ajax_contexts"), list)
            else 0
        )
        xssi_count = (
            len(effective_params.get("xssi_contexts") or [])
            if isinstance(effective_params.get("xssi_contexts"), list)
            else 0
        )
        return (
            "$ xss-extended --file-upload --ajax-json --xssi "
            f"--upload-contexts {upload_count} --ajax-contexts {ajax_count} "
            f"--xssi-contexts {xssi_count} --approved-scope {target_label}{extra}"
        )
    if tool == "ssrf-probe":
        request_count = (
            len(effective_params.get("request_contexts") or [])
            if isinstance(effective_params.get("request_contexts"), list)
            else 0
        )
        header_count = (
            len(effective_params.get("header_contexts") or [])
            if isinstance(effective_params.get("header_contexts"), list)
            else 0
        )
        internal_count = (
            len(effective_params.get("internal_service_urls") or [])
            if isinstance(effective_params.get("internal_service_urls"), list)
            else 0
        )
        cloud_enabled = "yes" if effective_params.get("cloud_metadata_probe_enabled") else "no"
        return (
            "$ ssrf-probe --url-params --forwarded-headers --governed-oob "
            f"--request-contexts {request_count or len(normalized_targets)} "
            f"--header-contexts {header_count or len(normalized_targets)} "
            f"--approved-internal-urls {internal_count} --cloud-metadata {cloud_enabled} "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "deserialization-probe":
        request_count = (
            len(effective_params.get("request_contexts") or [])
            if isinstance(effective_params.get("request_contexts"), list)
            else 0
        )
        evidence_count = (
            len(effective_params.get("evidence_records") or [])
            if isinstance(effective_params.get("evidence_records"), list)
            else 0
        )
        return (
            "$ deserialization-probe --java-urldns-only --php-object --python-pickle --dotnet-viewstate "
            f"--request-contexts {request_count or len(normalized_targets)} "
            f"--evidence-records {evidence_count} --no-rce-gadgets "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "session-security":
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        sample_count = int(effective_params.get("sample_count") or 10)
        return (
            "$ session-security --fixation --cookie-flags --entropy --logout-replay --token-url "
            f"--auth-contexts {context_count} --samples {min(max(sample_count, 2), 10)} "
            f"--configured-credentials-only --approved-scope {target_label}{extra}"
        )
    if tool == "auth-flow":
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        failed_attempts = int(effective_params.get("failed_login_attempts") or 10)
        reset_samples = int(effective_params.get("reset_token_samples") or 5)
        return (
            "$ auth-flow --password-reset --username-enumeration --bruteforce-protection "
            f"--auth-contexts {context_count} --reset-samples {min(max(reset_samples, 2), 5)} "
            f"--failed-login-attempts {min(max(failed_attempts, 1), 10)} "
            f"--configured-test-accounts-only --approved-scope {target_label}{extra}"
        )
    if tool == "zap":
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        return f"$ zap --spider-passive --auth-contexts {context_count} --approved-scope {target_label}{extra}"
    if tool == "api-assessment":
        sources = []
        if effective_params.get("openapi_spec"):
            sources.append("openapi")
        if effective_params.get("postman_collection"):
            sources.append("postman")
        if effective_params.get("graphql_introspection"):
            sources.append("graphql")
        source_label = ",".join(sources) if sources else "no-contract"
        return f"$ api-assessment --sources {source_label} --approved-scope {target_label}{extra}"
    if tool == "mobile-android":
        apk_label = str(effective_params.get("apk_path") or target_label).strip() or target_label
        return f"$ mobile-android-static --apk {shlex.quote(apk_label)} --static-only"
    if tool == "cloud-native":
        sources = []
        if effective_params.get("manifest_paths") or effective_params.get("manifests"):
            sources.append("manifests")
        if effective_params.get("image_metadata"):
            sources.append("images")
        if effective_params.get("cluster_posture"):
            sources.append("cluster-posture")
        source_label = ",".join(sources) if sources else "approved-input"
        return f"$ cloud-native-assessment --sources {source_label} --static-only --approved-scope {target_label}{extra}"
    if tool == "cicd-security":
        sources = []
        if effective_params.get("pipeline_paths") or effective_params.get("pipeline_configs"):
            sources.append("pipeline-configs")
        if effective_params.get("repository_metadata"):
            sources.append("repository-metadata")
        source_label = ",".join(sources) if sources else "approved-input"
        return f"$ cicd-security-assessment --sources {source_label} --static-only --approved-scope {target_label}{extra}"
    if tool == "desktop-client":
        sources = []
        if effective_params.get("artifact_paths"):
            sources.append("artifacts")
        if effective_params.get("helper_urls"):
            sources.append("local-helper-metadata")
        source_label = ",".join(sources) if sources else "approved-input"
        return f"$ desktop-client-assessment --sources {source_label} --static-only --approved-scope {target_label}{extra}"
    if tool == "mdns-ssdp":
        return f"$ mdns-ssdp-discovery --mdns --ssdp --approved-scope {target_label}{extra}"
    if tool == "wifi-survey":
        adapter = str(effective_params.get("adapter") or "approved-adapter").strip()
        site = str(effective_params.get("site") or target_label).strip()
        return (
            "$ wifi-survey --passive-only --no-deauth --no-handshake-capture "
            f"--adapter {shlex.quote(adapter)} --site {shlex.quote(site)} "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "iot-default-creds":
        return (
            "$ iot-default-creds-audit --http-management --max-attempts 3 "
            f"--redact-credentials --approved-scope {target_label}{extra}"
        )
    if tool == "network-segmentation":
        mode = str(effective_params.get("mode") or "passive").strip().lower() or "passive"
        if mode == "active":
            return (
                "$ network-segmentation --active-vlan-double-tag --max-probes 10 "
                f"--approved-scope {target_label}{extra}"
            )
        return f"$ network-segmentation --subnet-discovery --reachability --approved-scope {target_label}{extra}"
    if tool == "network-capture":
        capture_seconds = effective_params.get("capture_seconds")
        capture_label = int(capture_seconds) if isinstance(capture_seconds, (int, float)) else 60
        packet_limit = effective_params.get("packet_limit")
        packet_label = int(packet_limit) if isinstance(packet_limit, (int, float)) else 10000
        interface = str(effective_params.get("interface") or "approved-interface").strip()
        return (
            "$ network-capture --tcpdump-passive --no-pcap-store --redact-secrets "
            f"--interface {shlex.quote(interface)} --seconds {capture_label} "
            f"--packet-limit {packet_label} --arp-consistency --approved-scope {target_label}{extra}"
        )
    if tool == "snmp-enum":
        communities = effective_params.get("community_strings")
        community_count = len(communities) if isinstance(communities, list) else 8
        ports_value = effective_params.get("ports")
        if isinstance(ports_value, list):
            ports_label = ",".join(str(port) for port in ports_value) or "161"
        elif ports_value:
            ports_label = str(ports_value)
        else:
            ports_label = "161"
        return (
            f"$ snmp-enum --read-only --default-communities {community_count} "
            f"--ports {ports_label} --oids system,interfaces,arp,routes "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "smart-home":
        listen_seconds = effective_params.get("mqtt_listen_seconds")
        listen_label = int(listen_seconds) if isinstance(listen_seconds, (int, float)) else 30
        return (
            "$ smart-home-audit --mqtt-anonymous-readonly --mqtt-subscribe '#' "
            f"--listen-seconds {listen_label} --home-assistant-get-only "
            f"--redact-values --approved-scope {target_label}{extra}"
        )
    if tool == "camera-test":
        return (
            "$ camera-test --onvif-ws-discovery --rtsp-options-describe-only "
            "--snapshot-get-no-store --bounded-default-creds --no-ptz --no-config-change "
            f"--approved-scope {target_label}{extra}"
        )
    if tool == "ipv6-discovery":
        interface = str(effective_params.get("interface") or "").strip()
        interface_flag = (
            f" --interface {shlex.quote(interface)}" if interface else " --no-multicast"
        )
        return (
            "$ ipv6-discovery --neighbor-solicit ff02::1 --router-solicit ff02::2"
            f"{interface_flag} --nmap -6 --approved-scope {target_label}{extra}"
        )
    if tool == "priv-esc-linux":
        context_count = (
            len(effective_params.get("auth_contexts") or [])
            if isinstance(effective_params.get("auth_contexts"), list)
            else 0
        )
        return (
            "$ priv-esc-linux --ssh --read-only --sudo-list --suid-sgid --cron --path --weak-perms "
            f"--auth-contexts {context_count} --no-exploit --approved-scope {target_label}{extra}"
        )
    return f"$ {tool} --approved-scope {target_label}{extra}"


def _update_run_status(session, run: Run) -> None:
    if run.id is None:
        return

    session.flush()
    statuses = {
        status
        for status in session.scalars(select(Task.status).where(Task.run_id == run.id)).all()
        if isinstance(status, str)
    }

    if not statuses:
        return
    if statuses == {"cancelled"}:
        run.status = "cancelled"
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor="system:run-status",
            reason="all_tasks_cancelled",
        )
        return
    if "running" in statuses:
        run.status = "running"
        return
    if statuses == {"completed"}:
        # For ai_loop runs: do NOT mark the run completed just because all current
        # tasks finished. The AI loop may still want to queue iteration N+1 based on
        # the latest evidence. Only the assessment_loop itself (via loop_state.status)
        # decides when an AI-driven run is truly done.
        if run_uses_ai_loop(run):
            loop_state = (run.configuration_json or {}).get("ai_assessment_loop") or {}
            loop_status = str(loop_state.get("status") or "").strip().lower()
            if loop_status not in {"stopped", "completed", "failed"}:
                # Keep run in 'running' so post-task hooks can call advance_assessment_loop
                # which may queue another iteration. Run stays "alive" until loop explicitly stops.
                run.status = "running"
                return
        run.status = "completed"
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor="system:run-status",
            reason="all_tasks_completed",
        )
        return
    if "failed" in statuses and statuses.issubset({"completed", "failed"}):
        # Same ai_loop guard: a single failed runner shouldn't kill the AI loop.
        # The loop keeps planning — Claude can pick a different tool next.
        if run_uses_ai_loop(run):
            loop_state = (run.configuration_json or {}).get("ai_assessment_loop") or {}
            loop_status = str(loop_state.get("status") or "").strip().lower()
            if loop_status not in {"stopped", "completed", "failed"}:
                run.status = "running"
                return
        run.status = "completed_with_errors"
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor="system:run-status",
            reason="tasks_completed_with_errors",
        )
        return
    if "queued" in statuses:
        run.status = "queued"


def _store_execution(session, task: Task, execution: RunnerExecution) -> StoredExecutionResult:
    redacted_stdout = redact_text(execution.stdout)
    redacted_stderr = redact_text(execution.stderr)
    execution_record = ToolExecution(
        task=task,
        runner_digest=str(execution.metadata.get("runner_digest", "workers.unknown.runner:v1")),
        tool_version=str(execution.metadata.get("tool_version", task.tool)),
        exit_code=execution.exit_code,
        stdout_text=redacted_stdout.text,
        stderr_text=redacted_stderr.text,
    )
    session.add(execution_record)
    session.flush()

    settings = effective_runtime_settings_for_task(session, task=task, settings=get_settings())
    storage_config = artifact_storage_config_from_settings(settings)
    run_id = str(task.run_id) if task.run_id is not None else "unassigned-run"
    task_id = str(task.id)
    execution_id = str(execution_record.id)
    stored_artifact_pairs: list[tuple[EvidenceArtifact, EvidenceArtifactRecord]] = []
    protected_bindings_by_artifact: dict[str, dict[str, object]] = {}

    if execution.protected_outputs:
        settings = get_settings()
        for protected_output in execution.protected_outputs:
            secret_ref: SecretRef | None = None
            protected_metadata = (
                protected_output.metadata if isinstance(protected_output.metadata, dict) else {}
            )
            if task.run is not None and run_uses_ai_loop(task.run):
                try:
                    secret_ref = store_run_credential_vault_secret(
                        session,
                        run=task.run,
                        settings=settings,
                        secret_kind=protected_output.secret_kind,
                        value=protected_output.value,
                        label=protected_output.display_label,
                        source_task_id=str(task.id),
                        source_artifact_name=protected_output.artifact_name,
                        target=str(protected_metadata.get("target") or task.target_id or "").strip()
                        or None,
                        username=str(
                            protected_metadata.get("username")
                            or protected_metadata.get("account_name")
                            or ""
                        ).strip()
                        or None,
                        actor=f"runner:{task.tool}",
                        discovery_source="runner_protected_output",
                        source_tool=task.tool,
                    )
                except ValueError:
                    secret_ref = None
            if secret_ref is None:
                storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
                secret_ref_id = uuid.uuid4()
                secret_ref = SecretRef(
                    id=secret_ref_id,
                    engagement_id=task.run.engagement_id,
                    vault_pointer=f"aegispt://secret-ref/{secret_ref_id}",
                    purpose=protected_output.purpose,
                    secret_kind=protected_output.secret_kind,
                    storage_backend=storage_backend,
                    display_label=protected_output.display_label,
                    encrypted_value=encrypt_secret_value(
                        protected_output.value,
                        settings,
                        storage_backend=storage_backend,
                    ),
                    metadata_json={
                        "artifact_name": protected_output.artifact_name,
                        "content_type": protected_output.content_type,
                        "digest": protected_output.digest,
                        "raw_secret_material_exposed": False,
                        "run_id": str(task.run_id) if task.run_id else None,
                        "task_id": str(task.id),
                        "fallback_to_local_secret_key": (
                            fallback_to_local if storage_backend == "encrypted_local" else False
                        ),
                        **protected_metadata,
                    },
                )
                session.add(secret_ref)
            protected_bindings_by_artifact[protected_output.artifact_name] = public_secret_binding(
                secret_ref
            )

    for artifact in execution.artifacts:
        redacted_artifact = redact_artifact_bytes(
            name=artifact.name,
            content_type=artifact.content_type,
            data=artifact.data,
        )
        redacted_contract_artifact = EvidenceArtifact(
            name=artifact.name,
            content_type=artifact.content_type,
            data=redacted_artifact.data,
            kind=artifact.kind,
        )
        stored_artifact = store_artifact_bytes_with_fallback(
            config=storage_config,
            artifact_name=artifact.name,
            artifact_kind=artifact.kind,
            artifact_digest=redacted_contract_artifact.digest,
            content_type=artifact.content_type,
            data=redacted_artifact.data,
            run_id=run_id,
            task_id=task_id,
            execution_id=execution_id,
        )
        artifact_record = EvidenceArtifactRecord(
            kind=artifact.kind,
            uri=stored_artifact.uri,
            sha256=redacted_contract_artifact.digest,
            redaction_state=redacted_artifact.redaction_state,
            metadata_json={
                "name": artifact.name,
                "content_type": artifact.content_type,
                "size_bytes": len(redacted_artifact.data),
                "redaction_count": redacted_artifact.redaction_count,
                **{
                    key: value
                    for key, value in execution.metadata.items()
                    if key
                    in {
                        "template_id",
                        "template_sha256",
                        "template_source",
                        "template_update_status",
                        "rce_template_selection",
                        "selected_template_ids",
                        "oob_status",
                        "template_repository_status",
                        "rule_ids",
                        "rule_source",
                        "rule_sha256",
                    }
                },
                **stored_artifact.metadata,
                **(
                    {
                        "protected_secret_binding": protected_bindings_by_artifact[artifact.name],
                        "raw_secret_material_exposed": False,
                    }
                    if artifact.name in protected_bindings_by_artifact
                    else {}
                ),
            },
        )
        apply_artifact_integrity_metadata(
            settings=settings,
            storage_config=storage_config,
            artifact_record=artifact_record,
            artifact_name=artifact.name,
            data=redacted_artifact.data,
            run_id=run_id,
            task_id=task_id,
            execution_id=execution_id,
        )
        execution_record.artifacts.append(artifact_record)
        stored_artifact_pairs.append((redacted_contract_artifact, artifact_record))

    if task.tool == "ai-shell":
        output_material = f"{redacted_stdout.text or ''}\n{redacted_stderr.text or ''}"
        write_audit_event(
            session=session,
            actor=f"runner:{task.tool}",
            action="ai_shell.command_executed",
            object_type="tool_execution",
            object_id=str(execution_record.id),
            metadata={
                "run_id": str(task.run_id) if task.run_id else None,
                "task_id": str(task.id),
                "target_id": task.target_id,
                "exit_code": execution.exit_code,
                "status": execution.metadata.get("status"),
                "command_sha256": execution.metadata.get("command_sha256"),
                "output_sha256": sha256(output_material.encode("utf-8")).hexdigest(),
                "stdout_truncated": bool(execution.metadata.get("stdout_truncated")),
                "stderr_truncated": bool(execution.metadata.get("stderr_truncated")),
                "per_command_approval_required": True,
            },
        )

    if is_validation_task(task):
        finalize_validation_for_task(
            session=session,
            task=task,
            execution_record=execution_record,
            artifact_pairs=stored_artifact_pairs,
        )
        return StoredExecutionResult(created_finding_ids=[])

    created_findings = store_findings(
        session=session, task=task, artifact_pairs=stored_artifact_pairs
    )
    if created_findings:
        session.flush()
    snapshot = _store_inventory_snapshot_from_execution(
        session=session,
        task=task,
        execution=execution,
        artifact_pairs=stored_artifact_pairs,
    )
    if snapshot is not None:
        maybe_refresh_after_discovery_task(session, task=task, settings=get_settings())

    # Runner-emitted structured observations (backlog-372). Runners that opt in
    # populate metadata["observations"]; orchestrator persists them so
    # build_normalized_evidence_graph can merge them as first-class nodes.
    try:
        observations = execution.metadata.get("observations") if execution.metadata else None
        if observations and task.run is not None:
            from api.app.services.evidence_ingest import persist_runner_observations

            persist_runner_observations(
                session,
                run=task.run,
                task=task,
                tool=execution.tool,
                observations=observations,
            )
    except Exception as obs_exc:
        # Observations are advisory — a bad emission must not fail the task.
        logger.warning(
            "evidence_observations persist skipped for task=%s tool=%s: %s",
            task.id, execution.tool, obs_exc,
        )

    return StoredExecutionResult(created_finding_ids=[finding.id for finding in created_findings])


def _credential_attack_context_from_artifact(
    *,
    tool: str,
    artifact_bytes: bytes,
) -> dict[str, object] | None:
    try:
        payload = json.loads(artifact_bytes.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    domains: list[str] = []
    kerberoastable_accounts: list[dict[str, object]] = []
    asrep_roastable_accounts: list[dict[str, object]] = []
    privileged_names: set[str] = set()
    password_policy: dict[str, object] = {}

    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, list):
        return None

    for result in raw_targets:
        if not isinstance(result, dict) or result.get("status") not in {"ok", "partial"}:
            continue

        if tool == "ldap-enum":
            base_dn = str(result.get("base_dn") or "").strip()
            if base_dn:
                domain_parts = [
                    item.split("=", 1)[1].strip()
                    for item in base_dn.split(",")
                    if item.strip().lower().startswith("dc=")
                ]
                if domain_parts:
                    domain_name = ".".join(part for part in domain_parts if part).lower()
                    if domain_name and domain_name not in domains:
                        domains.append(domain_name)
            for membership in (
                result.get("privileged_memberships", [])
                if isinstance(result.get("privileged_memberships"), list)
                else []
            ):
                if not isinstance(membership, dict):
                    continue
                for field_name in ("account_name", "member_dn"):
                    value = str(membership.get(field_name) or "").strip().lower()
                    if value:
                        privileged_names.add(value)
            for item in (
                result.get("spn_accounts", [])
                if isinstance(result.get("spn_accounts"), list)
                else []
            ):
                if not isinstance(item, dict):
                    continue
                account_name = str(item.get("account_name") or "").strip()
                principal = str(item.get("user_principal_name") or "").strip()
                if not account_name and not principal:
                    continue
                kerberoastable_accounts.append(
                    {
                        "account_name": account_name or principal,
                        "user_principal_name": principal or None,
                        "service_principal_names": [
                            str(value).strip()
                            for value in list(item.get("service_principal_names") or [])
                            if str(value).strip()
                        ],
                    }
                )
            for item in (
                result.get("asrep_roastable_accounts", [])
                if isinstance(result.get("asrep_roastable_accounts"), list)
                else []
            ):
                if not isinstance(item, dict):
                    continue
                account_name = str(item.get("account_name") or "").strip()
                principal = str(item.get("user_principal_name") or "").strip()
                if not account_name and not principal:
                    continue
                asrep_roastable_accounts.append(
                    {
                        "account_name": account_name or principal,
                        "user_principal_name": principal or None,
                    }
                )
            if isinstance(result.get("password_policy"), dict) and not password_policy:
                password_policy = dict(result.get("password_policy") or {})
        elif tool == "bloodhound-collect":
            domain = str(result.get("domain") or "").strip().lower()
            if domain and domain not in domains:
                domains.append(domain)
            for membership in (
                result.get("privileged_memberships", [])
                if isinstance(result.get("privileged_memberships"), list)
                else []
            ):
                if not isinstance(membership, dict):
                    continue
                value = (
                    str(membership.get("member") or membership.get("account_name") or "")
                    .strip()
                    .lower()
                )
                if value:
                    privileged_names.add(value)
            for item in (
                result.get("kerberoastable_accounts", [])
                if isinstance(result.get("kerberoastable_accounts"), list)
                else []
            ):
                if not isinstance(item, dict):
                    continue
                account_name = str(item.get("account_name") or "").strip()
                principal = str(item.get("user_principal_name") or "").strip()
                if not account_name and not principal:
                    continue
                kerberoastable_accounts.append(
                    {
                        "account_name": account_name or principal,
                        "user_principal_name": principal or None,
                        "service_principal_names": [
                            str(value).strip()
                            for value in list(item.get("service_principal_names") or [])
                            if str(value).strip()
                        ],
                    }
                )
            for item in (
                result.get("asrep_roastable_accounts", [])
                if isinstance(result.get("asrep_roastable_accounts"), list)
                else []
            ):
                if not isinstance(item, dict):
                    continue
                account_name = str(item.get("account_name") or "").strip()
                principal = str(item.get("user_principal_name") or "").strip()
                if not account_name and not principal:
                    continue
                asrep_roastable_accounts.append(
                    {
                        "account_name": account_name or principal,
                        "user_principal_name": principal or None,
                    }
                )

    def _apply_privilege_level(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        enriched: list[dict[str, object]] = []
        for row in rows:
            account_name = str(row.get("account_name") or "").strip().lower()
            principal = str(row.get("user_principal_name") or "").strip().lower()
            privileged = bool(account_name and account_name in privileged_names) or bool(
                principal and principal in privileged_names
            )
            service_principal_names = row.get("service_principal_names")
            privilege_level = (
                "privileged"
                if privileged
                else ("service" if service_principal_names else "standard")
            )
            enriched.append({**row, "privilege_level": privilege_level})
        return enriched

    return {
        "domains": domains,
        "kerberoastable_accounts": _apply_privilege_level(kerberoastable_accounts),
        "asrep_roastable_accounts": _apply_privilege_level(asrep_roastable_accounts),
        "password_policy": password_policy,
        "privileged_names": sorted(privileged_names),
    }


def _store_inventory_snapshot_from_execution(
    *,
    session,
    task: Task,
    execution: RunnerExecution,
    artifact_pairs: list[tuple[EvidenceArtifact, EvidenceArtifactRecord]],
) -> InventorySnapshot | None:
    if execution.exit_code != 0 or task.run is None:
        return None

    if task.tool == "nmap":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "nmap-results.xml"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = nmap_observation_from_xml(
                xml_bytes=artifact.data, target_id=task.target_id
            )
        except Exception:
            return None

        notes = [
            f"Nmap discovery imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only hosts and services emitted by the nmap execution are reflected in this snapshot.",
            "Snapshot was derived after controlled execution and does not mutate the active runtime lane.",
        ]
    elif task.tool == "httpx":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "httpx-results.jsonl"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = httpx_observation_from_jsonl(
                jsonl_bytes=artifact.data, target_id=task.target_id
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"HTTP profiling imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only HTTP endpoints and fingerprints emitted by the httpx execution are reflected in this snapshot.",
            "HTTP endpoint visibility depends on the exact target list generated for the profiling run.",
        ]
    elif task.tool == "ldap-enum":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "ldap-enum-results.json"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = ldap_enum_observation_from_json(
                json_bytes=artifact.data, target_id=task.target_id
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"LDAP and AD read-only enumeration imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only directory users, groups, memberships, and policy signals emitted by the LDAP enumeration execution are reflected in this snapshot.",
            "LDAP enumeration is read-only and does not perform password spraying, Kerberoasting, AS-REP requests, lateral movement, or privilege escalation.",
        ]
    elif task.tool == "bloodhound-collect":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "bloodhound-results.json"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = bloodhound_observation_from_json(
                json_bytes=artifact.data, target_id=task.target_id
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"BloodHound read-only AD graph collection imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only sanitized BloodHound graph relationships and derived path context emitted by the read-only collector are reflected in this snapshot.",
            "The raw BloodHound collection ZIP remains encrypted through SecretRef storage; no exploitation, ticket requests, cracking, lateral movement, or AD modification was performed.",
        ]
    elif task.tool == "aws-inventory":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "aws-inventory-results.json"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = aws_inventory_observation_from_json(
                json_bytes=artifact.data, target_id=task.target_id
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"AWS read-only inventory imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only AWS account, region, VPC, subnet, security group, and EC2 metadata emitted by the AWS inventory execution are reflected in this snapshot.",
            "AWS inventory is read-only and does not mutate cloud resources, harvest credentials, infer IAM attack paths, test Kubernetes, or chain into active attack paths.",
        ]
    elif task.tool == "easm-discover":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "easm-results.json"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = easm_observation_from_json(
                json_bytes=artifact.data, target_id=task.target_id
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"External attack-surface discovery imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only passive EASM-discovered assets, DNS resolutions, and lightweight HTTP fingerprints emitted by the runner are reflected in this snapshot.",
            "Discovered assets are review-only until an operator explicitly adds them into approved scope through the normal scope snapshot flow.",
        ]
    elif task.tool == "external-infra":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == "external-infra-results.json"
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = external_infrastructure_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"External infrastructure assessment imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only hosts, services, and endpoints emitted by the bounded external infrastructure runner are reflected in this snapshot.",
            "Discovered IP expansion originated from approved root domains and remained inside the external infrastructure task lane.",
        ]
    elif task.tool == "mdns-ssdp":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == MDNS_SSDP_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = mdns_ssdp_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"mDNS/SSDP IoT discovery imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only passively advertised mDNS and SSDP/UPnP device metadata emitted by the runner is reflected in this snapshot.",
            "The mDNS/SSDP runner performs local discovery queries only and does not authenticate, modify devices, or exploit advertised services.",
        ]
    elif task.tool == "wifi-survey":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == WIFI_SURVEY_RESULTS_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = wifi_survey_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Passive WiFi survey imported from task {task.id}.",
            f"Run {task.run_id} wireless site {task.target_id}.",
        ]
        assumptions = [
            "Only passive wireless survey metadata emitted by the runner is reflected in this snapshot.",
            "The WiFi foundation runner does not deauthenticate clients, capture handshakes, brute-force WPS, jam RF, or create rogue access points.",
        ]
    elif task.tool == "network-capture":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = network_capture_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Passive network capture imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only redacted passive capture metadata, cleartext protocol indicators, and ARP consistency entries emitted by the runner are reflected in this snapshot.",
            "Raw packet payloads and captured credential values are not stored in the inventory snapshot.",
        ]
    elif task.tool == "snmp-enum":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == SNMP_ENUM_RESULTS_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = snmp_enum_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Read-only SNMP enumeration imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only SNMP data emitted by approved read-only walks is reflected in this snapshot.",
            "Community string testing was limited to the bounded default list from the active task package; no SNMP writes, SNMPv3 cracking, or broad community brute force was performed.",
        ]
    elif task.tool == "smart-home":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == SMART_HOME_RESULTS_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = smart_home_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Read-only smart-home audit imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only MQTT broker, Home Assistant, and smart-home hub signals emitted by the read-only audit are reflected in this snapshot.",
            "MQTT checks subscribed read-only and never published; Home Assistant and hub checks used safe GET requests only and did not trigger automations or device-control actions.",
        ]
    elif task.tool == "camera-test":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == CAMERA_TEST_RESULTS_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = camera_test_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Read-only camera audit imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only ONVIF discovery, RTSP OPTIONS/DESCRIBE, snapshot GET metadata, and bounded default-credential outcomes emitted by the camera audit are reflected in this snapshot.",
            "The camera audit did not perform RTSP SETUP/PLAY, media capture, PTZ control, configuration changes, firmware exploitation, or frame storage.",
        ]
    elif task.tool == "ipv6-discovery":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = ipv6_discovery_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"IPv6 neighbor discovery imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only IPv6 neighbors, prefixes, and bounded nmap -6 targets emitted by the runner are reflected in this snapshot.",
            "No rogue Router Advertisement, DHCPv6 attack, exploitation, or live multicast was performed unless an interface was explicitly configured for local-segment probing.",
        ]
    elif task.tool == "api-assessment":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == API_ASSESSMENT_INVENTORY_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = api_assessment_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"API-first inventory imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only endpoints and API types emitted by authorized OpenAPI, Postman, or GraphQL inputs are reflected in this snapshot.",
            "The API-first runner performs bounded contract-aware checks and does not fuzz, load-test, create accounts, or abuse business processes.",
        ]
    elif task.tool == "mobile-android":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == MOBILE_ANDROID_INVENTORY_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = mobile_android_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Android mobile inventory imported from task {task.id}.",
            f"Run {task.run_id} APK artifact {task.target_id}.",
        ]
        assumptions = [
            "Only static APK metadata emitted by the Android-first runner is reflected in this snapshot.",
            "The mobile runner does not perform iOS testing, emulator orchestration, rooting, malware triage, or destructive exploitation.",
        ]
    elif task.tool == "cloud-native":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == CLOUD_NATIVE_INVENTORY_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = cloud_native_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Cloud-native inventory imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only static/read-only Kubernetes manifest, image metadata, and supplied cluster posture inputs are reflected in this snapshot.",
            "The cloud-native runner does not mutate clusters, execute containers, perform privilege escalation, or perform lateral movement.",
        ]
    elif task.tool == "cicd-security":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == CICD_SECURITY_INVENTORY_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = cicd_security_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"CI/CD security inventory imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only static/read-only pipeline configuration and supplied repository metadata are reflected in this snapshot.",
            "The CI/CD security runner does not execute pipelines, mutate repositories or CI settings, rotate credentials, disclose raw secrets, or chain exploitation.",
        ]
    elif task.tool == "desktop-client":
        artifact_pair = next(
            (
                (artifact, artifact_record)
                for artifact, artifact_record in artifact_pairs
                if artifact.name == DESKTOP_CLIENT_INVENTORY_ARTIFACT_NAME
            ),
            None,
        )
        if artifact_pair is None:
            return None

        artifact, artifact_record = artifact_pair
        if not artifact.data:
            return None

        try:
            observation = desktop_client_observation_from_json(
                json_bytes=artifact.data,
                target_id=task.target_id,
            )
        except (ValueError, json.JSONDecodeError):
            return None

        notes = [
            f"Desktop/thick-client inventory imported from task {task.id}.",
            f"Run {task.run_id} target {task.target_id}.",
        ]
        assumptions = [
            "Only static desktop artifact metadata and scoped local-helper metadata emitted by the desktop runner are reflected in this snapshot.",
            "The desktop runner does not perform kernel driver analysis, process injection, malware triage, memory-corruption exploit development, or live helper probing.",
        ]
    else:
        return None

    snapshot = create_inventory_snapshot_record(
        engagement_id=task.run.engagement_id,
        requested_by=task.run.requested_by,
        source_tools=[task.tool],
        observations=[observation],
        environment_notes=notes,
        assumptions=assumptions,
        raw_inputs_json={
            "task_id": str(task.id),
            "run_id": str(task.run_id) if task.run_id else None,
            "target_id": task.target_id,
            "artifact_uri": artifact_record.uri,
            "runner_digest": execution.metadata.get("runner_digest"),
            "observations": [observation],
            **(
                {
                    "credential_attack_context": _credential_attack_context_from_artifact(
                        tool=task.tool,
                        artifact_bytes=artifact.data,
                    )
                }
                if task.tool in {"ldap-enum", "bloodhound-collect"}
                else {}
            ),
        },
    )
    session.add(snapshot)
    session.flush()
    suggested_watchlist_entries = suggest_watchlist_from_inventory_snapshot(
        session,
        inventory_snapshot_id=snapshot.id,
        tenant_id=None,
        actor=f"runner:{task.tool}",
    )
    write_audit_event(
        session=session,
        actor=f"runner:{task.tool}",
        action="inventory.snapshot.created",
        object_type="inventory_snapshot",
        object_id=str(snapshot.id),
        metadata={
            "engagement_id": str(task.run.engagement_id),
            "run_id": str(task.run_id) if task.run_id else None,
            "task_id": str(task.id),
            "source_tools": [task.tool],
            "derived_from_execution": True,
            "cve_watchlist_suggestion_count": len(suggested_watchlist_entries),
        },
    )
    return snapshot


def _cancel_autonomous_tasks_by_id(task_ids: list[UUID]) -> None:
    if not task_ids:
        return
    with session_scope() as session:
        tasks = list(session.scalars(select(Task).where(Task.id.in_(task_ids))))
        for task in tasks:
            if task.status == "queued":
                task.status = "cancelled"
        session.commit()


def _maybe_run_post_task_ai_analysis(session, task: Task):
    if task.id is None or task.status != "completed":
        return None
    if is_validation_task(task):
        return None
    # AI reasoning runs for ALL completed tasks, including ai_loop runs.
    # For ai_loop runs: proposals are stored as AgentReasoning/AgentProposal records
    # and displayed to the operator. The advance_assessment_loop reads these proposals
    # as the primary candidate before falling back to signal-based selection.
    # This is the core AI reasoning loop: every tool completion triggers reasoning.
    try:
        return run_post_task_analysis_for_task(session=session, task_id=task.id)
    except Exception:
        session.rollback()
        return None


def _maybe_advance_assessment_loop_after_task(session, task: Task) -> dict[str, object] | None:
    # "skipped" added 2026-05-21: runners returning exit_code=78 (EX_CONFIG,
    # see RUNNER_EXIT_CODE_SKIPPED) now map to task.status="skipped" instead
    # of "failed". Without including it here the post-task advance hook never
    # fires for runs where every dispatched tool is unconfigured (e.g. all
    # auth-flow / session-security dispatches skip on a fresh deployment),
    # leaving the loop in waiting_for_execution and the run.status in
    # "running" forever. Operator-reported 2026-05-21: 4 runs stuck in
    # waiting_for_execution, oldest since 08:48.
    if task.id is None or task.status not in ("completed", "failed", "skipped"):
        return None
    if is_validation_task(task):
        return None
    if task.run is None or not run_uses_ai_loop(task.run):
        return None
    scope = session.scalar(latest_scope_query(task.run.engagement_id))
    if scope is None:
        logger.warning("post-task: advance skipped run=%s — no scope", str(task.run_id)[:8])
        return None
    logger.info(
        "post-task: advancing loop after task=%s tool=%s run=%s",
        str(task.id)[:8], task.tool, str(task.run_id)[:8],
    )
    try:
        result = advance_assessment_loop(
            session=session,
            run=task.run,
            scope=scope,
            actor=f"runner:{task.tool}",
            operator_note="Automatically continue the evidence-driven AI loop after a completed runner task.",
        )
        logger.info(
            "post-task: advance returned queued_task_id=%s",
            result.get("queued_task_id") if isinstance(result, dict) else None,
        )
        return result
    except Exception as exc:
        logger.exception("post-task: advance_assessment_loop raised: %s", exc)
        session.rollback()
        return None


def _pivot_tool_risk_tier(tool: str) -> str:
    for cap in runner_capability_registry().get("capabilities", []):
        if isinstance(cap, dict) and cap.get("name") == tool:
            return str(cap.get("risk_tier", "active"))
    return "active"


def _queue_pivot_followup_task(
    session,
    run: Run,
    doc: TargetContextDocument,
    scope: Scope,
) -> UUID | None:
    """For ai_loop runs: queue the first non-intrusive recommended tool from a pivot context doc.

    Stores the task ID in provenance_json for idempotency. Returns the queued task UUID or None.
    """
    if (doc.provenance_json or {}).get("follow_up_task_id"):
        return None

    tools = [str(t).strip() for t in (doc.recommended_tools_json or []) if str(t).strip()]
    supported = supported_execution_tools()
    first_tool = next((t for t in tools if t in supported and _pivot_tool_risk_tier(t) != "intrusive"), None)
    if not first_tool:
        return None

    # Pick first in-scope target: endpoints are plain strings; source_targets are dicts.
    target: str | None = None
    for ep in list(doc.endpoints_discovered_json or []):
        candidate = str(ep if isinstance(ep, str) else ep.get("url") or ep.get("target") or "").strip()
        if candidate and target_is_allowed(scope, candidate):
            target = candidate
            break
    if not target:
        for st in list(doc.source_targets_json or []):
            candidate = str(st.get("value") or (st if isinstance(st, str) else "")).strip()
            if candidate and target_is_allowed(scope, candidate):
                target = candidate
                break
    if not target:
        return None

    pivot_task = Task(
        run=run,
        tool=first_tool,
        target_id=target,
        status="queued",
        params_json={
            "target_kind": "url",
            "source": "pivot_engine_followup",
            "pivot_context_id": str(doc.id),
            "pivot_type": (doc.provenance_json or {}).get("pivot_type"),
            "source_finding_id": (doc.provenance_json or {}).get("source_finding_id"),
            "registered_runner_required": True,
            "scope_enforced": True,
            "kill_switch_still_authoritative": True,
        },
    )
    session.add(pivot_task)
    session.flush()

    doc.provenance_json = {
        **(doc.provenance_json or {}),
        "follow_up_task_id": str(pivot_task.id),
        "follow_up_tool": first_tool,
        "follow_up_target": target,
    }
    return pivot_task.id


def _maybe_link_pivot_chain_findings(session, task: Task) -> None:
    """After a pivot-spawned task completes, link its findings to the source finding.

    Reads source_finding_id and pivot_type from task.params_json (set by the pivot
    engine when it queues the follow-up task). For each confirmed follow-up finding
    (status=open, evidence_ref non-empty), creates a FindingChain via
    link_pivot_chain_findings, escalating the source finding's severity if warranted,
    and writes an audit event for any escalation.
    """
    if task.status != "completed" or task.run_id is None:
        return
    params = dict(task.params_json or {})
    source_finding_id = params.get("source_finding_id")
    pivot_type = str(params.get("pivot_type") or "session_token_pivot")
    if not source_finding_id:
        return
    try:
        source_uuid = UUID(str(source_finding_id))
    except (ValueError, AttributeError):
        return

    source_finding = session.scalar(select(Finding).where(Finding.id == source_uuid))
    if source_finding is None:
        return

    # Collect recent confirmed findings from this task's run (newest first)
    follow_ups = list(
        session.scalars(
            select(Finding)
            .where(
                Finding.run_id == task.run_id,
                Finding.status == "open",
                Finding.evidence_ref.isnot(None),
                Finding.id != source_uuid,
            )
            .order_by(Finding.created_at.desc())
            .limit(5)
        ).all()
    )

    for follow_up in follow_ups:
        if not str(follow_up.evidence_ref or "").strip():
            continue
        try:
            chain = link_pivot_chain_findings(
                session=session,
                original_finding=source_finding,
                follow_up_finding=follow_up,
                pivot_type=pivot_type,
                run_id=task.run_id,
            )
        except Exception:
            continue
        if chain is None:
            continue
        proof = dict((chain.metadata_json or {}).get("impact_proof_json") or {})
        if proof.get("severity_escalated"):
            write_audit_event(
                session=session,
                actor="system:pivot_chain",
                action="finding.severity_escalated_by_pivot_chain",
                object_type="finding",
                object_id=str(source_finding.id),
                metadata={
                    "chain_id": str(chain.id),
                    "pivot_type": pivot_type,
                    "escalated_from": proof.get("original_severity"),
                    "escalated_to": proof.get("escalated_to"),
                    "follow_up_finding_id": str(follow_up.id),
                    "impact_summary": proof.get("summary"),
                },
            )


def _maybe_detect_and_record_pivots(session, task: Task) -> list[UUID]:
    """After a completed task, scan run findings for pivot opportunities.

    For ai_loop runs, also queues follow-up tasks for each new pivot context.
    Returns list of queued pivot follow-up task IDs (empty for standard runs).
    """
    if task.status != "completed" or task.run is None:
        return []
    run = task.run
    try:
        parent_context = latest_context_document(session, run_id=run.id, layer_name=PHASE0_LAYER_NAME)
        if parent_context is None:
            return []
        scope = session.scalar(
            select(Scope)
            .where(Scope.engagement_id == run.engagement_id)
            .order_by(Scope.created_at.desc())
        )
        if scope is None:
            return []
        created = generate_pivot_contexts_for_run(
            session,
            run=run,
            scope=scope,
            parent_context=parent_context,
        )
        if not created or not run_uses_ai_loop(run):
            return []
        queued_ids: list[UUID] = []
        for doc in created:
            task_id = _queue_pivot_followup_task(session, run, doc, scope)
            if task_id is not None:
                queued_ids.append(task_id)
        return queued_ids
    except Exception:
        session.rollback()
        return []


def _maybe_queue_next_step_hints(session, task: Task) -> list[UUID]:
    """Read next_step_hints from a completed task's stdout and queue follow-up tasks.

    Runners can output next_step_hints in their JSON stdout:
      {"next_step_hints": [{"tool": "idor-bac", "reason": "...", "params": {...}}]}

    This makes the exploitation chain self-directing: each runner decides
    what should happen next based on what it found, without hardcoding
    the chain in the orchestration layer.
    """
    if task.status != "completed" or task.run is None:
        return []
    if not run_uses_ai_loop(task.run):
        return []
    try:
        exe = session.scalar(
            select(ToolExecution)
            .where(ToolExecution.task_id == task.id)
            .order_by(ToolExecution.created_at.desc())
            .limit(1)
        )
        if exe is None or not exe.stdout_text:
            return []

        output = json.loads(exe.stdout_text)
        hints = output.get("next_step_hints") or []
        if not isinstance(hints, list) or not hints:
            return []

        run = task.run
        scope = session.scalar(latest_scope_query(run.engagement_id))
        if scope is None:
            return []

        queued: list[UUID] = []
        for hint in hints[:3]:
            if not isinstance(hint, dict):
                continue
            tool = str(hint.get("tool") or "").strip()
            reason = str(hint.get("reason") or "next-step-hint follow-up")
            extra_params = dict(hint.get("params") or {})

            if not tool or tool not in supported_execution_tools():
                continue

            target_id = str(task.target_id or "").strip()
            if not target_id:
                continue

            task_params = {
                "target_kind": "url",
                "source": "next_step_hint",
                "next_step_hint_tool": task.tool,
                "next_step_hint_reason": reason,
                **extra_params,
                "assessment_loop": {
                    "enabled": True,
                    "run_mode": "ai_loop",
                    "tier": "active",
                    "required_approvals": 0,
                    "registered_runner_required": True,
                },
            }

            # Skip if this exact (tool, target) already ran — prevents infinite loops
            existing = session.scalar(
                select(Task)
                .where(Task.run_id == run.id, Task.tool == tool, Task.target_id == target_id)
                .limit(1)
            )
            if existing is not None:
                continue

            # Each hint in its own try-block: one failure doesn't corrupt others
            try:
                new_task = Task(
                    run_id=run.id,
                    tool=tool,
                    target_id=target_id,
                    params_json=task_params,
                    status="queued",
                )
                session.add(new_task)
                session.flush()
                try:
                    inject_run_credential_vault_into_task(session, run=run, task=new_task)
                    session.flush()
                except Exception:
                    pass  # vault injection failure is non-fatal
                queued.append(new_task.id)
            except Exception:
                session.expunge(new_task) if new_task in session else None
                continue

        return queued
    except Exception:
        return []  # no rollback — let outer session handle state


def process_task_by_id(task_id: str) -> dict[str, object]:
    task_uuid = UUID(task_id)

    with session_scope() as session:
        task = session.scalar(_task_query(task_uuid))
        if task is None:
            raise ValueError(f"task not found: {task_id}")
        if task.run is None:
            raise ValueError(f"task {task_id} is not attached to a run")
        if task.status not in {"queued", "failed", "dispatching"}:
            return {"task_id": task_id, "status": task.status}
        if task.run.status in {"cancelled", "cancelling"}:
            task.status = "cancelled"
            mark_task_stdout_unavailable(
                task.id,
                "Task was cancelled before stdout could be captured.",
            )
            session.commit()
            return {"task_id": task_id, "status": task.status}
        if execution_kill_switch_enabled():
            task.status = "cancelled"
            task.run.status = "cancelled"
            mark_task_stdout_unavailable(
                task.id,
                "Execution kill switch cancelled the task before stdout capture.",
            )
            session.commit()
            return {"task_id": task_id, "status": task.status, "reason": "kill_switch"}

        task_targets = _task_targets(task)
        scope = _scope_for_run(session, task.run)
        if scope is None:
            raise ValueError(f"scope missing for run {task.run_id}")
        # backlog-409 — every dispatch authorization now routes through the
        # Layer 0 Governance Control Plane. The legacy inline call was
        # `target_is_allowed(scope, target)` on its own; the plane composes
        # scope + ROE + intrusive-tier in one verdict. Per ANTI_DRIFT Rule 3
        # the old inline call is REMOVED — there is no parallel pathway.
        # Local import keeps the worker→api boundary import-light at module load.
        from api.app.governance import GovernanceControlPlane  # noqa: E402
        plane = GovernanceControlPlane(session)
        tier = str(task.params_json.get("run_class") or "").strip() if isinstance(task.params_json, dict) else ""
        for task_target in task_targets:
            verdict = plane.authorize_dispatch(
                run=task.run,
                runner=str(task.tool or ""),
                target=task_target,
                tier=tier,
            )
            if not verdict.allow:
                logger.warning(
                    "post-task: rejecting task %s — %s (graceful fail)",
                    str(task.id)[:8], verdict.deny_reason or "denied by control plane",
                )
                task.status = "failed"
                mark_task_stdout_unavailable(
                    task.id,
                    f"Task rejected by Layer 0: {verdict.deny_reason or 'denied'}",
                )
                session.commit()
                return {
                    "task_id": task_id,
                    "status": "failed",
                    "reason": "out_of_scope" if not verdict.needs_approval else "needs_approval",
                    "deny_reason": verdict.deny_reason,
                    "needs_approval": verdict.needs_approval,
                }

        task.status = "running"
        task.run.status = "running"
        task.run.started_at = task.run.started_at or datetime.now(timezone.utc)
        mark_validation_running(session=session, task=task)
        reset_task_stdout_stream(
            task.id,
            reason="Runner started; stdout appears when the existing runner safely captures output.",
        )
        session.commit()

        try:
            runner_params = _runner_params_for_task(session, task)
            runner_params.setdefault(
                "timeout_seconds",
                float(os.getenv("RUNNER_TIMEOUT_SECONDS", "10.0")),
            )
            # #338 — for the 5 #328-migrated probes, query prior
            # target_intel-emitted EvidenceObservation rows on this run
            # and normalize their `technology_stack` strings into our
            # stack-hint vocabulary. Probes consume the resulting list
            # via the `stack_hints` kwarg they each accept; with no
            # observations / no matchable strings, the augmentation
            # is a no-op and probes fall back to their baseline
            # catalogs.
            if task.tool in _STACK_HINT_AWARE_TOOLS and "attack_candidates" not in runner_params:
                candidates = _attack_candidates_for_run(session, task.run_id)
                if candidates:
                    runner_params["attack_candidates"] = candidates
            append_task_stdout(
                task.id,
                _runner_command_preview(task.tool, task_targets, runner_params),
                stream="command",
            )
            session.commit()
            execution = dispatch_runner(
                RunnerRequest(
                    tool=task.tool,
                    targets=task_targets,
                    params=runner_params,
                    scope_allowlist=scope.allowlist_json,
                    initiated_by=task.run.requested_by,
                )
            )
        except Exception as exc:
            execution = RunnerExecution(
                tool=task.tool,
                exit_code=1,
                stdout="",
                stderr=str(exc),
                metadata={
                    "status": "failed",
                    "tool_version": task.tool,
                    "runner_digest": f"workers.{task.tool}.runner:v1",
                },
                artifacts=[],
            )

        task = session.scalar(_task_query(task_uuid))
        if task is None or task.run is None:
            raise ValueError(f"task disappeared during execution: {task_id}")

        stored_result = _store_execution(session, task, execution)
        append_task_stdout(task.id, execution.stdout)
        terminated_by_kill_switch = bool(execution.metadata.get("terminated_by_kill_switch"))
        mark_task_stdout_completed(
            task.id,
            reason=(
                "Execution kill switch terminated the task during runner execution."
                if terminated_by_kill_switch
                else "Runner completed without stdout in the bounded task stream."
            ),
        )
        previous_run_status = task.run.status
        if terminated_by_kill_switch:
            task.status = "cancelled"
            task.run.status = "cancelled"
            clear_run_credential_vault_if_terminal(
                session,
                run=task.run,
                actor=f"runner:{task.tool}",
                reason="execution_kill_switch_terminated_task",
            )
        else:
            # exit_code=78 is the EX_CONFIG convention for "runner unavailable
            # in this deployment" (e.g. missing credentials/API key) — see
            # assessment_loop.RUNNER_EXIT_CODE_SKIPPED. Map to status="skipped"
            # so the operator sees the honest reason; "failed" would
            # mis-classify these as bugs.
            if execution.exit_code == 0:
                task.status = "completed"
            elif execution.exit_code == 78:
                task.status = "skipped"
            else:
                task.status = "failed"
            _update_run_status(session, task.run)
            # Persist auth-flow's working credentials into the run credential
            # vault so downstream chain dispatches (autonomous agent sequence,
            # session-security with the same creds) can resolve `auth.username`
            # references without re-discovering them. Empirically gated on the
            # auth-flow runner's stdout reporting auth_context_count >= 1 —
            # that's the runner's signal that creds passed the loginability
            # check (not just that they were dispatched). Without this, the
            # second auth-flow dispatch in run 37aef115 (2026-05-22) skipped
            # because the chained params used password_source="…test_account…"
            # as a reference into an empty vault.
            if (
                execution.exit_code == 0
                and task.tool == "auth-flow"
                and run_uses_ai_loop(task.run)
            ):
                try:
                    persisted_username = str(runner_params.get("username") or "").strip()
                    persisted_password = str(runner_params.get("password") or "").strip()
                    if not (persisted_username and persisted_password):
                        # Fall back to auth_contexts[0] if the dispatcher
                        # converted flat to list before dispatch.
                        ac = runner_params.get("auth_contexts") or []
                        if isinstance(ac, list) and ac and isinstance(ac[0], dict):
                            persisted_username = str(ac[0].get("username") or "").strip() or persisted_username
                            persisted_password = str(ac[0].get("password") or "").strip() or persisted_password
                    # Only store when stdout reports the runner actually used
                    # the credentials (auth_context_count >= 1). Otherwise we
                    # could promote a never-validated guess.
                    stdout_text = str(execution.stdout or "")
                    if (
                        persisted_username
                        and persisted_password
                        and '"auth_context_count": 1' in stdout_text
                    ):
                        store_run_credential_vault_secret(
                            session=session,
                            run=task.run,
                            settings=get_settings(),
                            secret_kind="password",
                            value=persisted_password,
                            label=f"auth-flow:{persisted_username}",
                            source_task_id=str(task.id),
                            source_tool="auth-flow",
                            target=(task_targets[0] if task_targets else None),
                            username=persisted_username,
                            discovery_source="auth_flow_success",
                        )
                except Exception as exc:
                    logger.warning(
                        "auth-flow vault persistence skipped: %s", exc
                    )
        run_completion_reached = previous_run_status not in {
            "completed",
            "completed_with_errors",
        } and task.run.status in {"completed", "completed_with_errors"}
        if run_completion_reached:
            record_exposure_score(
                session=session,
                engagement_id=task.run.engagement_id,
                run_id=task.run_id,
            )
            if task.run_id is not None:
                compute_run_drift(
                    session=session,
                    run_id=task.run_id,
                    actor=f"runner:{task.tool}",
                )
        session.commit()
        active_settings = get_settings()
        if stored_result.created_finding_ids:
            deliver_critical_findings_to_configured_siems(
                session=session,
                finding_ids=stored_result.created_finding_ids,
                actor=f"runner:{task.tool}",
                settings=active_settings,
            )
            deliver_critical_finding_notifications(
                session=session,
                finding_ids=stored_result.created_finding_ids,
                actor=f"runner:{task.tool}",
                settings=active_settings,
            )
            session.commit()
        if stored_result.created_finding_ids:
            validation_run_ids = queue_automatic_validations(
                session=session,
                finding_ids=stored_result.created_finding_ids,
                settings=active_settings,
            )
            session.commit()
            dispatch_validation_runs(
                session=session,
                run_ids=validation_run_ids,
                settings=active_settings,
            )
        if run_completion_reached and task.run_id is not None:
            deliver_run_completion_to_configured_siems(
                session=session,
                run_id=task.run_id,
                actor=f"runner:{task.tool}",
                settings=active_settings,
            )
            deliver_run_completion_notifications(
                session=session,
                run_id=task.run_id,
                actor=f"runner:{task.tool}",
                settings=active_settings,
            )
            session.commit()
        # Order: advance loop first, then pivot/hints, then commit.
        # AI post-task analysis is temporarily disabled for ai_loop runs because
        # ChatGPT OAuth makes nested HTTP calls that create new DB sessions,
        # causing SQLite "database is locked" errors (SQLite single-writer limit).
        # TODO: enable when migrating to PostgreSQL or enabling SQLite WAL mode.
        _maybe_link_pivot_chain_findings(session, task)
        # AI loop runs: enable heuristic chains conditionally.
        # - next_step_hints from target-intel/lan-intel: ENABLED (these come
        #   directly from Claude's site analysis — top-priority tools that
        #   should always run, even before the ai-loop picker takes over).
        # - next_step_hints from other tools: DISABLED (would duplicate Claude).
        # - pivot engine: ENABLED for ai_loop (auto-spawns xss-proof on XSS
        #   findings, idor-bac on session theft, etc. — high-confidence chains
        #   that Claude tends to skip). Hard duplicate guard in the assessment
        #   loop's Claude path prevents Claude from re-picking the same pair.
        run_is_ai_loop = task.run is not None and run_uses_ai_loop(task.run)
        pivot_followup_ids = _maybe_detect_and_record_pivots(session, task)
        if run_is_ai_loop:
            # Only let hints from intelligence runners (target-intel, lan-intel)
            # queue follow-ups in ai_loop mode — they reflect a real per-target
            # plan and provide the seed chain Claude builds on top of.
            seed_intel_tools = {"target-intel", "lan-intel"}
            if str(task.tool or "") in seed_intel_tools:
                hint_followup_ids = _maybe_queue_next_step_hints(session, task)
                logger.info(
                    "post-task: ai_loop — letting %s next_step_hints fire (%d tasks)",
                    task.tool, len(hint_followup_ids or []),
                )
            else:
                hint_followup_ids = []
        else:
            hint_followup_ids = _maybe_queue_next_step_hints(session, task)
        loop_outcome = _maybe_advance_assessment_loop_after_task(session, task)
        session.commit()
        ai_outcome = _maybe_run_post_task_ai_analysis(session, task)  # WAL mode fixes concurrent access
        if ai_outcome and ai_outcome.autonomous_task_ids:
            session.commit()
        dispatch_settings = get_settings()
        if ai_outcome and ai_outcome.autonomous_task_ids:
            if execution_kill_switch_enabled(dispatch_settings):
                _cancel_autonomous_tasks_by_id(ai_outcome.autonomous_task_ids)
            else:
                dispatch_task_batch(ai_outcome.autonomous_task_ids, dispatch_settings)
        if pivot_followup_ids:
            if execution_kill_switch_enabled(dispatch_settings):
                _cancel_autonomous_tasks_by_id(pivot_followup_ids)
            else:
                dispatch_task_batch(pivot_followup_ids, dispatch_settings)
        if hint_followup_ids:
            if execution_kill_switch_enabled(dispatch_settings):
                _cancel_autonomous_tasks_by_id(hint_followup_ids)
            else:
                dispatch_task_batch(hint_followup_ids, dispatch_settings)
        queued_loop_task_id = loop_outcome.get("queued_task_id") if loop_outcome else None
        if queued_loop_task_id:
            loop_task_ids = [UUID(str(queued_loop_task_id))]
            if execution_kill_switch_enabled(dispatch_settings):
                _cancel_autonomous_tasks_by_id(loop_task_ids)
            else:
                dispatch_task_batch(loop_task_ids, dispatch_settings)
        if run_completion_reached and task.run_id is not None:
            advanced_chain = advance_assessment_chain_for_completed_run(
                session,
                run_id=task.run_id,
                actor=f"runner:{task.tool}",
                settings=active_settings,
            )
            if advanced_chain is not None and advanced_chain.status == "pending_phase_approval":
                deliver_phase_approval_needed_notifications(
                    session=session,
                    chain_id=advanced_chain.id,
                    actor=f"runner:{task.tool}",
                    settings=active_settings,
                )
            session.commit()
            if advanced_chain is not None:
                dispatch_assessment_chain_current_run(
                    session,
                    chain_id=advanced_chain.id,
                    actor=f"runner:{task.tool}",
                    settings=active_settings,
                )
                session.commit()

        return {
            "task_id": task_id,
            "status": task.status,
            "run_status": task.run.status,
            "exit_code": execution.exit_code,
        }


@dramatiq.actor(queue_name="aegispt")
def record_heartbeat(tool: str = "scheduler") -> dict[str, str]:
    return {"status": "ok", "tool": tool}


@dramatiq.actor(queue_name="aegispt")
def purge_expired_soft_deletes(actor: str = "system:retention") -> dict[str, object]:
    with session_scope() as session:
        result = purge_expired_soft_deleted_runs(session=session, actor=actor)
        session.commit()
        return result


@dramatiq.actor(queue_name="aegispt")
def execute_task(task_id: str) -> dict[str, object]:
    return process_task_by_id(task_id)
