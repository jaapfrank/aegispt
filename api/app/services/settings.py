from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app.auth import API_KEY_ROLES
from api.app.config import Settings, get_settings
from api.app.models import (
    CveFeedSyncLog,
    CveProductWatchlistEntry,
    Engagement,
    Finding,
    InstanceSetting,
    Run,
    ScheduledRun,
    SecretRef,
    Task,
    ThreatIntelRecord,
)
from api.app.schemas.settings import (
    ReadinessCapabilityRead,
    SettingOption,
    SettingRead,
    SettingsRead,
    SettingsReadinessRead,
    SettingsSectionRead,
    ToolReadinessRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.secrets import (
    direct_secret_storage_backend,
    encrypt_secret_value,
    secret_display_label,
)
from api.app.services.tool_certification import summarize_runner_tool_certification_matrix

DEFAULT_TENANT_SCOPE = "default"
DISABLED_AI_PROVIDER_NAMES = {"", "disabled", "none", "off"}


@dataclass(frozen=True)
class ToolReadinessDefinition:
    id: str
    title: str
    binary_names: tuple[str, ...]
    affected_assessment_families: tuple[str, ...]
    required: bool = True
    missing_next_step: str = "Install the binary in the runtime image or disable the related assessment family."
    required_binary_groups: tuple[tuple[str, ...], ...] = ()
    install_command: str = "sudo bash scripts/install_security_tools.sh"
    repair_command: str = "sudo bash scripts/install_security_tools.sh && bash scripts/verify_host.sh"
    repair_action_label: str = "Copy Install/Repair Command"
    software_installable: bool = True
    hardware_required: bool = False


TOOL_READINESS_DEFINITIONS: tuple[ToolReadinessDefinition, ...] = (
    ToolReadinessDefinition(
        id="nmap",
        title="Nmap",
        binary_names=("nmap",),
        affected_assessment_families=("LAN discovery", "Service enumeration", "NSE checks"),
    ),
    ToolReadinessDefinition(
        id="nuclei",
        title="Nuclei",
        binary_names=("nuclei",),
        affected_assessment_families=("Web CVE audit", "On-demand CVE checks"),
    ),
    ToolReadinessDefinition(
        id="httpx",
        title="httpx",
        binary_names=("httpx-toolkit", "httpx"),
        affected_assessment_families=("Web baseline", "External surface"),
        required_binary_groups=(("httpx-toolkit", "httpx"),),
    ),
    ToolReadinessDefinition(
        id="zap",
        title="OWASP ZAP",
        binary_names=("zaproxy", "zap.sh", "zap-baseline.py"),
        affected_assessment_families=("Web baseline", "Active web validation"),
        required=False,
        missing_next_step="Install OWASP ZAP or keep ZAP-backed checks disabled for web assessments.",
        required_binary_groups=(("zaproxy", "zap.sh", "zap-baseline.py"),),
    ),
    ToolReadinessDefinition(
        id="content-discovery",
        title="ffuf content discovery",
        binary_names=("ffuf",),
        affected_assessment_families=("Hidden endpoint discovery", "Web content discovery"),
        required=False,
        missing_next_step="Install ffuf before enabling content discovery.",
    ),
    ToolReadinessDefinition(
        id="nikto",
        title="Nikto",
        binary_names=("nikto",),
        affected_assessment_families=("Web server configuration review", "Web baseline"),
        required=False,
        missing_next_step="Install Nikto before enabling web server configuration scans.",
    ),
    ToolReadinessDefinition(
        id="sqlmap",
        title="sqlmap",
        binary_names=("sqlmap",),
        affected_assessment_families=("SQL injection confirmation", "Input validation testing"),
        required=False,
        missing_next_step="Install sqlmap before enabling approved parameter-only SQLi confirmation.",
    ),
    ToolReadinessDefinition(
        id="semgrep",
        title="Semgrep",
        binary_names=("semgrep",),
        affected_assessment_families=("Code security audit", "Static analysis"),
        required=False,
        missing_next_step="Install Semgrep before enabling local code security audits.",
    ),
    ToolReadinessDefinition(
        id="crypto-audit",
        title="Cryptographic audit tools",
        binary_names=("testssl.sh", "testssl", "ssh-audit"),
        affected_assessment_families=("TLS/SSH cryptographic configuration review", "Cryptographic weakness audit"),
        required=False,
        missing_next_step="Install testssl.sh and ssh-audit before enabling host-backed cryptographic audits.",
        required_binary_groups=(("testssl.sh", "testssl"), ("ssh-audit",)),
    ),
    ToolReadinessDefinition(
        id="responder",
        title="Responder",
        binary_names=("responder",),
        affected_assessment_families=("LLMNR/NBT-NS capture", "Intrusive LAN credential review"),
        required=False,
        missing_next_step="Install Responder before enabling intrusive LAN credential capture.",
    ),
    ToolReadinessDefinition(
        id="netexec",
        title="NetExec / CrackMapExec",
        binary_names=("nxc", "netexec", "crackmapexec"),
        affected_assessment_families=("SMB review", "Credentialed LAN validation"),
        required=False,
        missing_next_step="Install NetExec or CrackMapExec before credentialed SMB validation.",
        required_binary_groups=(("nxc", "netexec", "crackmapexec"),),
    ),
    ToolReadinessDefinition(
        id="bloodhound",
        title="BloodHound Python",
        binary_names=("bloodhound-python",),
        affected_assessment_families=("Active Directory attack path", "LDAP identity mapping"),
        required=False,
        missing_next_step="Install bloodhound-python and configure AD context before AD attack-path checks.",
    ),
    ToolReadinessDefinition(
        id="impacket",
        title="Impacket",
        binary_names=(
            "impacket-secretsdump",
            "impacket-psexec",
            "impacket-wmiexec",
            "secretsdump.py",
            "psexec.py",
            "wmiexec.py",
            "GetUserSPNs.py",
            "GetNPUsers.py",
        ),
        affected_assessment_families=("Remote exec confirmation", "Secretsdump", "DCSync"),
        required=False,
        missing_next_step="Install Impacket before enabling intrusive authenticated exploitation checks.",
        required_binary_groups=(
            ("secretsdump.py", "impacket-secretsdump"),
            ("psexec.py", "impacket-psexec"),
            ("wmiexec.py", "impacket-wmiexec"),
            ("GetUserSPNs.py",),
            ("GetNPUsers.py",),
        ),
    ),
    ToolReadinessDefinition(
        id="metasploit",
        title="Metasploit",
        binary_names=("msfconsole", "msfrpcd"),
        affected_assessment_families=("Exploit confirmation", "Metasploit RPC"),
        required=False,
        missing_next_step="Install Metasploit and configure RPC before exploit confirmation.",
        required_binary_groups=(("msfconsole",), ("msfrpcd",)),
    ),
    ToolReadinessDefinition(
        id="hashcat",
        title="Hashcat",
        binary_names=("hashcat",),
        affected_assessment_families=("Offline hash cracking", "Password audit"),
        required=False,
        missing_next_step="Install Hashcat before enabling protected offline password audit workflows.",
    ),
    ToolReadinessDefinition(
        id="snmp",
        title="SNMP tools",
        binary_names=("snmpwalk",),
        affected_assessment_families=("Network device enumeration", "Infrastructure review"),
        required=False,
        missing_next_step="Install snmpwalk before enabling SNMP-backed infrastructure checks.",
    ),
    ToolReadinessDefinition(
        id="wifi",
        title="WiFi analysis tools",
        binary_names=("iw", "airodump-ng", "aircrack-ng"),
        affected_assessment_families=("WiFi discovery", "Wireless security review"),
        required=False,
        missing_next_step="Install WiFi analysis software; adapter hardware readiness is reported separately.",
        required_binary_groups=(("iw",), ("airodump-ng",), ("aircrack-ng",)),
        hardware_required=True,
    ),
)


@dataclass(frozen=True)
class SettingDefinition:
    key: str
    section_id: str
    label: str
    input_type: str
    default_value: Callable[[Settings, str], Any]
    description: str
    sensitive: bool = False
    read_only: bool = False
    options: tuple[tuple[str, str], ...] = ()
    secret_kind: str = "setting_secret"
    settings_attr: str | None = None
    runtime_overlay: bool = False
    ui_hidden: bool = False
    min_value: float | None = None
    max_value: float | None = None
    step: float | None = None
    placeholder: str | None = None


SECTIONS: tuple[tuple[str, str, str], ...] = (
    (
        "ai_provider",
        "AI Provider",
        "Choose the instance default AI provider and see the ChatGPT OAuth model used by connected engagements.",
    ),
    (
        "enterprise_identity",
        "Enterprise Identity",
        "Disabled-by-default OIDC/SAML configuration, session policy, and local-development fallback clarity.",
    ),
    (
        "default_network_scope",
        "Default Network Scope",
        "Reusable LAN, domain, VLAN, and exclusion defaults for new mission planning.",
    ),
    (
        "default_scan_profile",
        "Default Scan Profile",
        "Preferred assessment profile, safety posture, and execution lane defaults.",
    ),
    (
        "runtime_execution",
        "Runtime Execution",
        "Operator-tunable local execution limits for queued tasks and safe parallel runner work.",
    ),
    (
        "remediation",
        "Remediation SLA",
        "Default remediation deadlines for newly stored findings and overdue dashboard posture.",
    ),
    (
        "integrations",
        "Integrations",
        "Provider endpoints and encrypted credential hooks for downstream handoffs.",
    ),
    (
        "notifications",
        "Notifications",
        "Default destinations for critical alerts and run-completion notices.",
    ),
    (
        "threat_intel",
        "Threat Intel",
        "Local CVE feed sync defaults, watchlist-scoped sources, and encrypted optional feed credentials.",
    ),
    (
        "evidence_integrity",
        "Evidence Integrity",
        "SHA-256 artifact verification and optional RFC 3161 trusted timestamping for stored evidence.",
    ),
    (
        "deployment_hardening",
        "Deployment Hardening",
        "Read-only production posture for TLS, proxy, offline updates, encryption, and secure session assumptions.",
    ),
    (
        "instance",
        "Instance",
        "Operator-facing instance identity and public URL defaults.",
    ),
)


def _csv_default(value: str | None) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _tenant_default(settings: Settings, tenant_id: str) -> str:
    return str(settings.settings_tenant_id or tenant_id or DEFAULT_TENANT_SCOPE)


SETTING_DEFINITIONS: tuple[SettingDefinition, ...] = (
    SettingDefinition(
        key="ai.provider",
        section_id="ai_provider",
        label="Provider",
        input_type="select",
        default_value=lambda settings, _: settings.ai_provider,
        description="Instance default only. Feature-specific enable flags still gate actual provider calls.",
        options=(("disabled", "Disabled"), ("chatgpt_oauth", "ChatGPT OAuth"), ("http", "HTTP provider")),
        settings_attr="ai_provider",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="ai.chatgpt_model",
        section_id="ai_provider",
        label="ChatGPT OAuth model",
        input_type="text",
        default_value=lambda settings, _: settings.chatgpt_oauth_model,
        description="Model sent to the ChatGPT backend by the OAuth provider.",
        read_only=True,
    ),
    SettingDefinition(
        key="ai.http_endpoint",
        section_id="ai_provider",
        label="HTTP provider endpoint",
        input_type="url",
        default_value=lambda settings, _: settings.ai_finding_enrichment_endpoint,
        description="Optional endpoint for a future HTTP provider default. It does not enable calls by itself.",
        settings_attr="ai_finding_enrichment_endpoint",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="ai.http_api_key",
        section_id="ai_provider",
        label="HTTP provider API key",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Encrypted at rest and never returned in plain text.",
        sensitive=True,
        secret_kind="api_key",
    ),
    SettingDefinition(
        key="ai.finding_enrichment_enabled",
        section_id="ai_provider",
        label="Finding enrichment",
        input_type="checkbox",
        default_value=lambda settings, _: settings.ai_finding_enrichment_enabled,
        description="Adds grounded business-impact and remediation narrative to newly stored findings.",
        settings_attr="ai_finding_enrichment_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="ai.post_task_analysis_enabled",
        section_id="ai_provider",
        label="Post-task analysis / AI Signal",
        input_type="checkbox",
        default_value=lambda settings, _: settings.ai_agent_post_task_analysis_enabled,
        description="Lets AI Signal review completed task output and propose bounded next steps for operator approval.",
        settings_attr="ai_agent_post_task_analysis_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="ai.intake_intelligence_enabled",
        section_id="ai_provider",
        label="Intake intelligence",
        input_type="checkbox",
        default_value=lambda settings, _: settings.ai_intake_interpretation_enabled,
        description="Adds advisory intake clarification without changing deterministic scope, access, or approval rules.",
        settings_attr="ai_intake_interpretation_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="ai.autofix_enabled",
        section_id="ai_provider",
        label="AutoFix patches",
        input_type="checkbox",
        default_value=lambda settings, _: settings.ai_autofix_enabled,
        description="Generates advisory patch suggestions for supported findings without mutating canonical evidence.",
        settings_attr="ai_autofix_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="ai.report_drafting_enabled",
        section_id="ai_provider",
        label="Report drafting",
        input_type="checkbox",
        default_value=lambda settings, _: settings.ai_report_drafting_enabled,
        description="Enables review-only AI-assisted report draft generation from stored run evidence.",
        settings_attr="ai_report_drafting_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="identity.enterprise_sso_provider",
        section_id="enterprise_identity",
        label="Enterprise SSO provider",
        input_type="select",
        default_value=lambda _settings, _tenant_id: "disabled",
        description="Disabled keeps local development/API-key auth active. OIDC/SAML entries only record governed configuration in this slice.",
        options=(("disabled", "Disabled"), ("oidc", "OIDC"), ("saml", "SAML")),
    ),
    SettingDefinition(
        key="identity.session_timeout_minutes",
        section_id="enterprise_identity",
        label="Session timeout minutes",
        input_type="number",
        default_value=lambda _settings, _tenant_id: 480,
        description="Operator-visible inactivity policy for browser sessions. Local X-Actor fallback has no server session to revoke.",
        min_value=5,
        max_value=1440,
        step=1,
        placeholder="480",
    ),
    SettingDefinition(
        key="identity.logout_redirect_url",
        section_id="enterprise_identity",
        label="Logout redirect URL",
        input_type="url",
        default_value=lambda _settings, _tenant_id: "",
        description="Optional post-logout landing URL for future enterprise identity providers.",
    ),
    SettingDefinition(
        key="identity.oidc_issuer_url",
        section_id="enterprise_identity",
        label="OIDC issuer URL",
        input_type="url",
        default_value=lambda _settings, _tenant_id: "",
        description="Issuer metadata URL for a future OIDC login flow. Required only when OIDC is selected.",
    ),
    SettingDefinition(
        key="identity.oidc_client_id",
        section_id="enterprise_identity",
        label="OIDC client ID",
        input_type="text",
        default_value=lambda _settings, _tenant_id: "",
        description="Client identifier for the OIDC application registration.",
    ),
    SettingDefinition(
        key="identity.oidc_client_secret",
        section_id="enterprise_identity",
        label="OIDC client secret",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Optional encrypted client secret. It is never returned in plaintext.",
        sensitive=True,
        secret_kind="client_secret",
    ),
    SettingDefinition(
        key="identity.saml_entity_id",
        section_id="enterprise_identity",
        label="SAML entity ID",
        input_type="text",
        default_value=lambda _settings, _tenant_id: "",
        description="Service-provider or relying-party entity ID for a future SAML flow.",
    ),
    SettingDefinition(
        key="identity.saml_sso_url",
        section_id="enterprise_identity",
        label="SAML SSO URL",
        input_type="url",
        default_value=lambda _settings, _tenant_id: "",
        description="Identity-provider SSO endpoint. Required only when SAML is selected.",
    ),
    SettingDefinition(
        key="identity.saml_certificate",
        section_id="enterprise_identity",
        label="SAML signing certificate",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Encrypted IdP signing certificate or certificate reference. It is never returned in plaintext.",
        sensitive=True,
        secret_kind="certificate",
    ),
    SettingDefinition(
        key="network.default_lan_cidr",
        section_id="default_network_scope",
        label="Default LAN CIDR",
        input_type="text",
        default_value=lambda settings, _: settings.settings_default_lan_cidr,
        description="Suggested CIDR for new internal missions. This does not expand existing run scope.",
    ),
    SettingDefinition(
        key="network.default_domain",
        section_id="default_network_scope",
        label="Default domain",
        input_type="text",
        default_value=lambda settings, _: settings.settings_default_domain,
        description="Optional default domain for new external or mixed missions.",
    ),
    SettingDefinition(
        key="network.default_vlan_cidrs",
        section_id="default_network_scope",
        label="Additional VLAN CIDRs",
        input_type="list",
        default_value=lambda settings, _: _csv_default(settings.settings_default_vlan_cidrs),
        description="Comma-separated CIDRs shown as planning defaults only.",
    ),
    SettingDefinition(
        key="network.default_excluded_ranges",
        section_id="default_network_scope",
        label="Default excluded ranges",
        input_type="list",
        default_value=lambda settings, _: _csv_default(settings.settings_default_excluded_ranges),
        description="Comma-separated ranges to suggest as default exclusions.",
    ),
    SettingDefinition(
        key="scan.default_profile",
        section_id="default_scan_profile",
        label="Assessment profile",
        input_type="select",
        default_value=lambda settings, _: settings.settings_default_scan_profile,
        description="Default operator-facing profile suggestion for new mission planning.",
        options=(("Standard", "Standard"), ("Deep", "Deep"), ("Discovery", "Discovery")),
    ),
    SettingDefinition(
        key="scan.default_safety_level",
        section_id="default_scan_profile",
        label="Safety level",
        input_type="select",
        default_value=lambda settings, _: settings.settings_default_safety_level,
        description="Default safety posture. Existing approval gates still control intrusive work.",
        options=(("passive", "Passive"), ("standard", "Standard"), ("intrusive", "Intrusive gated")),
    ),
    SettingDefinition(
        key="scan.default_execution_lane",
        section_id="default_scan_profile",
        label="Execution lane",
        input_type="select",
        default_value=lambda settings, _: settings.settings_default_execution_lane,
        description="Default lane suggestion. This settings screen does not dispatch or bind runners.",
        options=(
            ("passive-network-discovery", "Passive network discovery"),
            ("passive-network-service-enumeration", "Passive service enumeration"),
            ("passive-web-nuclei-audit", "Passive web audit"),
        ),
    ),
    SettingDefinition(
        key="runtime.inline_task_workers",
        section_id="runtime_execution",
        label="Parallel task workers",
        input_type="number",
        default_value=lambda settings, _: settings.inline_task_workers,
        description=(
            "How many queued inline tasks may run in parallel on this host. Use 1 for serial execution; "
            "4-8 is typical on a laptop; maximum 32. Applies to newly dispatched inline runs."
        ),
        settings_attr="inline_task_workers",
        runtime_overlay=True,
        min_value=1,
        max_value=32,
        step=1,
        placeholder="4",
    ),
    SettingDefinition(
        key="remediation.sla_days_critical",
        section_id="remediation",
        label="Critical SLA days",
        input_type="number",
        default_value=lambda _settings, _tenant_id: 1,
        description="Default remediation deadline for critical findings.",
        min_value=1,
        max_value=3650,
        step=1,
        placeholder="1",
    ),
    SettingDefinition(
        key="remediation.sla_days_high",
        section_id="remediation",
        label="High SLA days",
        input_type="number",
        default_value=lambda _settings, _tenant_id: 7,
        description="Default remediation deadline for high findings.",
        min_value=1,
        max_value=3650,
        step=1,
        placeholder="7",
    ),
    SettingDefinition(
        key="remediation.sla_days_medium",
        section_id="remediation",
        label="Medium SLA days",
        input_type="number",
        default_value=lambda _settings, _tenant_id: 30,
        description="Default remediation deadline for medium findings.",
        min_value=1,
        max_value=3650,
        step=1,
        placeholder="30",
    ),
    SettingDefinition(
        key="remediation.sla_days_low",
        section_id="remediation",
        label="Low SLA days",
        input_type="number",
        default_value=lambda _settings, _tenant_id: 90,
        description="Default remediation deadline for low findings.",
        min_value=1,
        max_value=3650,
        step=1,
        placeholder="90",
    ),
    SettingDefinition(
        key="integrations.jira_base_url",
        section_id="integrations",
        label="Jira base URL",
        input_type="url",
        default_value=lambda settings, _: settings.settings_jira_base_url,
        description="Default Jira URL for future handoff configuration.",
    ),
    SettingDefinition(
        key="integrations.jira_project_key",
        section_id="integrations",
        label="Jira project key",
        input_type="text",
        default_value=lambda settings, _: settings.settings_jira_project_key,
        description="Default Jira project key.",
    ),
    SettingDefinition(
        key="integrations.jira_token",
        section_id="integrations",
        label="Jira API token",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Encrypted at rest. The API only returns a configured indicator.",
        sensitive=True,
        secret_kind="api_key",
    ),
    SettingDefinition(
        key="integrations.slack_webhook_url",
        section_id="notifications",
        label="Slack webhook URL",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Encrypted at rest. When configured, Slack receives critical, run-completion, and phase-approval notices.",
        sensitive=True,
        secret_kind="webhook_url",
    ),
    SettingDefinition(
        key="integrations.teams_webhook_url",
        section_id="notifications",
        label="Teams webhook URL",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Encrypted at rest. When configured, Teams receives Adaptive Card notifications.",
        sensitive=True,
        secret_kind="webhook_url",
    ),
    SettingDefinition(
        key="integrations.servicenow_instance_url",
        section_id="integrations",
        label="ServiceNow instance URL",
        input_type="password",
        default_value=lambda settings, _: settings.settings_servicenow_instance_url,
        description="Stored encrypted per task scope.",
        sensitive=True,
        secret_kind="service_url",
    ),
    SettingDefinition(
        key="notifications.critical_destination",
        section_id="notifications",
        label="Critical alert destination",
        input_type="select",
        default_value=lambda settings, _: settings.settings_critical_alert_destination,
        description="Operator preference label for critical finding alerts. Configured channels all remain optional.",
        options=(("none", "None"), ("email", "Email"), ("slack", "Slack"), ("teams", "Teams")),
    ),
    SettingDefinition(
        key="notifications.email_enabled",
        section_id="notifications",
        label="Email notifications",
        input_type="checkbox",
        default_value=lambda settings, _: settings.settings_email_notifications_enabled,
        description="Enable SMTP delivery after host, sender, and recipient settings are configured.",
    ),
    SettingDefinition(
        key="notifications.smtp_host",
        section_id="notifications",
        label="SMTP host",
        input_type="text",
        default_value=lambda settings, _: settings.settings_smtp_host,
        description="SMTP server used for operator email alerts.",
        placeholder="smtp.example.com",
    ),
    SettingDefinition(
        key="notifications.smtp_port",
        section_id="notifications",
        label="SMTP port",
        input_type="number",
        default_value=lambda settings, _: settings.settings_smtp_port,
        description="SMTP server port.",
        min_value=1,
        max_value=65535,
        step=1,
        placeholder="587",
    ),
    SettingDefinition(
        key="notifications.smtp_username",
        section_id="notifications",
        label="SMTP username",
        input_type="text",
        default_value=lambda settings, _: settings.settings_smtp_username,
        description="Optional SMTP username. Leave empty when the relay does not require authentication.",
        placeholder="aegispt@example.com",
    ),
    SettingDefinition(
        key="notifications.smtp_password",
        section_id="notifications",
        label="SMTP password",
        input_type="password",
        default_value=lambda _settings, _tenant_id: None,
        description="Encrypted at rest. The plaintext password is never returned by the API.",
        sensitive=True,
        secret_kind="password",
    ),
    SettingDefinition(
        key="notifications.smtp_use_tls",
        section_id="notifications",
        label="Use STARTTLS",
        input_type="checkbox",
        default_value=lambda settings, _: settings.settings_smtp_use_tls,
        description="Use STARTTLS before SMTP authentication and delivery.",
    ),
    SettingDefinition(
        key="notifications.smtp_from",
        section_id="notifications",
        label="Email sender",
        input_type="text",
        default_value=lambda settings, _: settings.settings_smtp_from,
        description="From address for AegisPT notification emails.",
        placeholder="aegispt@example.com",
    ),
    SettingDefinition(
        key="notifications.smtp_to",
        section_id="notifications",
        label="Email recipients",
        input_type="list",
        default_value=lambda settings, _: _csv_default(settings.settings_smtp_to),
        description="Comma-separated operator email recipients.",
        placeholder="secops@example.com, owner@example.com",
    ),
    SettingDefinition(
        key="notifications.run_completion",
        section_id="notifications",
        label="Notify on run completion",
        input_type="checkbox",
        default_value=lambda settings, _: settings.settings_notify_on_run_completion,
        description="Default completion notification preference.",
    ),
    SettingDefinition(
        key="notifications.phase_approval_needed",
        section_id="notifications",
        label="Notify when phase approval is needed",
        input_type="checkbox",
        default_value=lambda settings, _: settings.settings_notify_on_phase_approval_needed,
        description="Alert operators when an assessment-chain phase completes and the next phase waits for approval.",
    ),
    SettingDefinition(
        key="notifications.delivery_timeout_seconds",
        section_id="notifications",
        label="Delivery timeout seconds",
        input_type="number",
        default_value=lambda settings, _: settings.settings_notification_timeout_seconds,
        description="Network timeout for Slack, Teams, and SMTP delivery attempts.",
        min_value=1,
        max_value=120,
        step=1,
        placeholder="10",
    ),
    SettingDefinition(
        key="threat_intel.sync_enabled",
        section_id="threat_intel",
        label="Daily CVE sync",
        input_type="checkbox",
        default_value=lambda settings, _: settings.cve_feed_sync_enabled,
        description="Runs the relevance-first CVE cache sync daily at 03:00. Finding analysis remains local-cache only.",
        settings_attr="cve_feed_sync_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="threat_intel.cisa_kev_url",
        section_id="threat_intel",
        label="CISA KEV feed URL",
        input_type="url",
        default_value=lambda settings, _: settings.cve_feed_cisa_kev_url,
        description="Always synced in full because KEV entries are already relevance-filtered by exploitation evidence.",
        settings_attr="cve_feed_cisa_kev_url",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="threat_intel.ncsc_nl_rss_url",
        section_id="threat_intel",
        label="NCSC NL RSS URL",
        input_type="url",
        default_value=lambda settings, _: settings.cve_feed_ncsc_nl_rss_url,
        description="Always synced in full as a compact national advisory source.",
        settings_attr="cve_feed_ncsc_nl_rss_url",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="threat_intel.nvd_api_url",
        section_id="threat_intel",
        label="NVD API URL",
        input_type="url",
        default_value=lambda settings, _: settings.cve_feed_nvd_api_url,
        description="Queried only for approved watchlist products and never mirrored in full.",
        settings_attr="cve_feed_nvd_api_url",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="threat_intel.nvd_api_key",
        section_id="threat_intel",
        label="NVD API key",
        input_type="password",
        default_value=lambda settings, _: settings.cve_feed_nvd_api_key,
        description="Optional. Stored encrypted when configured; sync skips gracefully without it.",
        sensitive=True,
        secret_kind="api_key",
    ),
    SettingDefinition(
        key="threat_intel.opencve_api_url",
        section_id="threat_intel",
        label="OpenCVE API URL",
        input_type="url",
        default_value=lambda settings, _: settings.cve_feed_opencve_api_url,
        description="Queried only for approved watchlist products when an OpenCVE token is configured.",
        settings_attr="cve_feed_opencve_api_url",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="threat_intel.opencve_api_token",
        section_id="threat_intel",
        label="OpenCVE API token",
        input_type="password",
        default_value=lambda settings, _: settings.cve_feed_opencve_api_token,
        description="Optional. Stored encrypted when configured; OpenCVE sync is skipped when absent.",
        sensitive=True,
        secret_kind="api_key",
    ),
    SettingDefinition(
        key="evidence.timestamping_enabled",
        section_id="evidence_integrity",
        label="RFC 3161 timestamping",
        input_type="checkbox",
        default_value=lambda settings, _: settings.evidence_timestamping_enabled,
        description="Requests a trusted timestamp response after each stored artifact hash. Disable for air-gapped environments.",
        settings_attr="evidence_timestamping_enabled",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="evidence.timestamp_authority_url",
        section_id="evidence_integrity",
        label="Timestamp Authority URL",
        input_type="url",
        default_value=lambda settings, _: settings.evidence_timestamp_authority_url,
        description="RFC 3161 TSA endpoint used when timestamping is enabled.",
        settings_attr="evidence_timestamp_authority_url",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="evidence.timestamp_timeout_seconds",
        section_id="evidence_integrity",
        label="Timestamp timeout seconds",
        input_type="number",
        default_value=lambda settings, _: settings.evidence_timestamp_timeout_seconds,
        description="Maximum time spent on a timestamp request before storing evidence with timestamp-unavailable.",
        settings_attr="evidence_timestamp_timeout_seconds",
        runtime_overlay=True,
    ),
    SettingDefinition(
        key="deployment.tls_terminated_by_proxy",
        section_id="deployment_hardening",
        label="TLS terminated by reverse proxy",
        input_type="checkbox",
        default_value=lambda settings, _: settings.deployment_tls_terminated_by_proxy,
        description="Read-only environment truth. Production installs must terminate HTTPS at a trusted reverse proxy or equivalent ingress.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.secure_cookies",
        section_id="deployment_hardening",
        label="Secure browser cookies required",
        input_type="checkbox",
        default_value=lambda settings, _: settings.deployment_secure_cookies,
        description="Read-only environment truth for production browser-session assumptions. Local development can stay false.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.trusted_certificate_bundle",
        section_id="deployment_hardening",
        label="Trusted certificate bundle path",
        input_type="text",
        default_value=lambda settings, _: settings.deployment_trusted_certificate_bundle,
        description="Optional path to an enterprise CA bundle for outbound TLS validation. Certificate material is not displayed here.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.outbound_proxy_url",
        section_id="deployment_hardening",
        label="Outbound proxy URL",
        input_type="password",
        default_value=lambda settings, _: settings.deployment_outbound_proxy_url,
        description="Optional outbound proxy for enterprise egress. Treated as sensitive because proxy URLs can contain credentials.",
        sensitive=True,
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.no_internet_mode",
        section_id="deployment_hardening",
        label="No-internet / air-gapped mode",
        input_type="checkbox",
        default_value=lambda settings, _: settings.deployment_no_internet_mode,
        description="Read-only environment truth. When enabled, feed/tool/template updates must use manual offline bundles.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.offline_update_path",
        section_id="deployment_hardening",
        label="Offline feed/template update path",
        input_type="text",
        default_value=lambda settings, _: settings.deployment_offline_update_path,
        description="Directory or mount where signed/offline feed and template bundles are staged.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.manual_tool_update_path",
        section_id="deployment_hardening",
        label="Manual tool update path",
        input_type="text",
        default_value=lambda settings, _: settings.deployment_manual_tool_update_path,
        description="Directory or runbook path for offline tool/image updates in restricted networks.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.database_encryption_confirmed",
        section_id="deployment_hardening",
        label="Database encryption confirmed",
        input_type="checkbox",
        default_value=lambda settings, _: settings.deployment_database_encryption_confirmed,
        description="Set from deployment configuration after platform/database encryption at rest has been verified.",
        read_only=True,
    ),
    SettingDefinition(
        key="deployment.artifact_storage_encryption_confirmed",
        section_id="deployment_hardening",
        label="Artifact storage encryption confirmed",
        input_type="checkbox",
        default_value=lambda settings, _: settings.deployment_artifact_storage_encryption_confirmed,
        description="Set from deployment configuration after inline volume or object-store evidence encryption has been verified.",
        read_only=True,
    ),
    SettingDefinition(
        key="instance.app_public_base_url",
        section_id="instance",
        label="App public base URL",
        input_type="url",
        default_value=lambda settings, _: settings.app_public_base_url,
        description="Public URL used in operator-facing links and OAuth return context.",
    ),
    SettingDefinition(
        key="instance.operator_display_name",
        section_id="instance",
        label="Operator display name",
        input_type="text",
        default_value=lambda settings, _: settings.settings_operator_display_name,
        description="Default display name for the operator shell.",
    ),
    SettingDefinition(
        key="instance.tenant_id",
        section_id="instance",
        label="Tenant ID",
        input_type="text",
        default_value=_tenant_default,
        description="Tenant scope for this settings payload. Set through X-Tenant-ID or environment.",
        read_only=True,
    ),
    SettingDefinition(
        key="instance.build_lane_mode",
        section_id="instance",
        label="Developer build-lane mode",
        input_type="checkbox",
        default_value=lambda _settings, _tenant_id: False,
        description=(
            "Shows supervised Codex build-lane panels in Pack Forge for development and review operators. "
            "Keep off for normal pentest operation."
        ),
    ),
    SettingDefinition(
        key="instance.onboarding_completed",
        section_id="instance",
        label="Onboarding completed",
        input_type="checkbox",
        default_value=lambda _settings, _tenant_id: False,
        description="System-only first-run onboarding state.",
        ui_hidden=True,
    ),
    SettingDefinition(
        key="instance.setup_checklist_dismissed",
        section_id="instance",
        label="Setup checklist dismissed",
        input_type="checkbox",
        default_value=lambda _settings, _tenant_id: False,
        description="System-only Dashboard setup checklist dismissal state.",
        ui_hidden=True,
    ),
)

SETTING_BY_KEY = {definition.key: definition for definition in SETTING_DEFINITIONS}


def tenant_scope_key(tenant_id: str | None) -> str:
    normalized = (tenant_id or "").strip()
    return normalized or DEFAULT_TENANT_SCOPE


def effective_runtime_settings(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings | None = None,
) -> Settings:
    base = settings or get_settings()
    tenant_key = tenant_scope_key(tenant_id)
    rows = _load_rows(session, tenant_key)
    updates: dict[str, Any] = {}
    for definition in SETTING_DEFINITIONS:
        if not definition.runtime_overlay or not definition.settings_attr or definition.sensitive:
            continue
        row = rows.get(definition.key)
        if row is None:
            continue
        updates[definition.settings_attr] = _normalize_plain_value(
            definition,
            row.value_json.get("value") if isinstance(row.value_json, dict) else None,
        )
    effective_provider = str(updates.get("ai_provider", base.ai_provider) or "").strip().lower()
    if (
        "ai.finding_enrichment_enabled" not in rows
        and not bool(updates.get("ai_finding_enrichment_enabled", base.ai_finding_enrichment_enabled))
        and effective_provider not in DISABLED_AI_PROVIDER_NAMES
    ):
        updates["ai_finding_enrichment_enabled"] = True
    if not updates:
        return base
    return base.model_copy(update=updates)


def effective_runtime_settings_for_engagement(
    session: Session,
    *,
    engagement_id: UUID | str,
    settings: Settings | None = None,
) -> Settings:
    tenant_id = session.scalar(select(Engagement.tenant_id).where(Engagement.id == engagement_id))
    return effective_runtime_settings(session, tenant_id=tenant_id, settings=settings)


def effective_runtime_settings_for_run(
    session: Session,
    *,
    run: Run | UUID,
    settings: Settings | None = None,
) -> Settings:
    tenant_id = None
    if isinstance(run, Run):
        tenant_id = getattr(getattr(run, "engagement", None), "tenant_id", None)
        if tenant_id is None:
            tenant_id = session.scalar(
                select(Engagement.tenant_id).join(Run, Engagement.id == Run.engagement_id).where(Run.id == run.id)
            )
    else:
        tenant_id = session.scalar(
            select(Engagement.tenant_id).join(Run, Engagement.id == Run.engagement_id).where(Run.id == run)
        )
    return effective_runtime_settings(session, tenant_id=tenant_id, settings=settings)


def effective_runtime_settings_for_task(
    session: Session,
    *,
    task: Task | UUID,
    settings: Settings | None = None,
) -> Settings:
    tenant_id = None
    if isinstance(task, Task):
        tenant_id = getattr(getattr(getattr(task, "run", None), "engagement", None), "tenant_id", None)
        if tenant_id is None and task.run_id is not None:
            tenant_id = session.scalar(
                select(Engagement.tenant_id).join(Run, Engagement.id == Run.engagement_id).where(Run.id == task.run_id)
            )
    else:
        tenant_id = session.scalar(
            select(Engagement.tenant_id)
            .join(Run, Engagement.id == Run.engagement_id)
            .join(Task, Task.run_id == Run.id)
            .where(Task.id == task)
        )
    return effective_runtime_settings(session, tenant_id=tenant_id, settings=settings)


def effective_runtime_settings_for_finding(
    session: Session,
    *,
    finding: Finding | UUID,
    settings: Settings | None = None,
) -> Settings:
    tenant_id = None
    if isinstance(finding, Finding):
        tenant_id = getattr(getattr(getattr(finding, "run", None), "engagement", None), "tenant_id", None)
        if tenant_id is None and finding.run_id is not None:
            tenant_id = session.scalar(
                select(Engagement.tenant_id).join(Run, Engagement.id == Run.engagement_id).where(Run.id == finding.run_id)
            )
    else:
        tenant_id = session.scalar(
            select(Engagement.tenant_id)
            .join(Run, Engagement.id == Run.engagement_id)
            .join(Finding, Finding.run_id == Run.id)
            .where(Finding.id == finding)
        )
    return effective_runtime_settings(session, tenant_id=tenant_id, settings=settings)


def read_instance_settings(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
) -> SettingsRead:
    tenant_key = tenant_scope_key(tenant_id)
    rows = _load_rows(session, tenant_key)
    sections = []
    for section_id, title, description in SECTIONS:
        section_settings = [
            _render_setting(definition, rows.get(definition.key), settings=settings, tenant_key=tenant_key)
            for definition in SETTING_DEFINITIONS
            if definition.section_id == section_id
        ]
        sections.append(
            SettingsSectionRead(
                id=section_id,
                title=title,
                description=description,
                settings=section_settings,
            )
        )
    return SettingsRead(tenant_id=tenant_key, sections=sections, sensitive_plaintext_exposed=False)


def read_settings_readiness(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
) -> SettingsReadinessRead:
    tenant_key = tenant_scope_key(tenant_id)
    generated_at = datetime.now(tz=UTC)
    effective = effective_runtime_settings(session, tenant_id=tenant_key, settings=settings)
    rows = _load_rows(session, tenant_key)

    tools = [_render_tool_readiness(definition) for definition in TOOL_READINESS_DEFINITIONS]
    capabilities = [
        _runtime_concurrency_readiness(effective),
        _dispatch_mode_readiness(effective),
        _tool_summary_readiness(tools),
        _wireless_readiness(tools),
        _runner_tool_certification_readiness(),
        _enterprise_identity_readiness(session, tenant_key=tenant_key, settings=settings, rows=rows),
        _ai_provider_readiness(session, tenant_key=tenant_key, settings=effective),
        _scheduler_readiness(session),
        _threat_intel_readiness(session, tenant_key=tenant_key, settings=effective),
        _integrations_readiness(rows),
        _secret_storage_readiness(effective),
        _artifact_storage_readiness(effective),
        _deployment_hardening_readiness(effective),
        _host_health_readiness(effective),
    ]
    overall_status = _worst_status([capability.status for capability in capabilities] + [tool.status for tool in tools])
    artifact = {
        "kind": "aegispt.settings_readiness",
        "tenant_id": tenant_key,
        "generated_at": generated_at.isoformat(),
        "overall_status": overall_status,
        "capabilities": [capability.model_dump() for capability in capabilities],
        "tools": [tool.model_dump() for tool in tools],
    }
    return SettingsReadinessRead(
        tenant_id=tenant_key,
        generated_at=generated_at,
        overall_status=overall_status,
        capabilities=capabilities,
        tools=tools,
        artifact=artifact,
    )


def _render_tool_readiness(definition: ToolReadinessDefinition) -> ToolReadinessRead:
    detected_paths = {
        binary: detected
        for binary in definition.binary_names
        if (detected := shutil.which(binary))
    }
    detected_path = next(iter(detected_paths.values()), None)
    binary_groups = definition.required_binary_groups or tuple((binary,) for binary in definition.binary_names)
    missing_groups = ["/".join(group) for group in binary_groups if not any(binary in detected_paths for binary in group)]
    installed = not missing_groups
    status = "ready" if installed else ("missing" if definition.required else "degraded")
    return ToolReadinessRead(
        id=definition.id,
        title=definition.title,
        binary_names=list(definition.binary_names),
        required_binary_groups=[list(group) for group in binary_groups],
        missing_binaries=missing_groups,
        required=definition.required,
        installed=installed,
        detected_path=detected_path,
        detected_paths=detected_paths,
        status=status,
        affected_assessment_families=list(definition.affected_assessment_families),
        operator_next_step=(
            "Software ready for mapped assessment families."
            if installed
            else f"{definition.missing_next_step} Missing: {', '.join(missing_groups)}."
        ),
        install_command=definition.install_command,
        repair_command=definition.repair_command,
        repair_action_label=definition.repair_action_label,
        software_installable=definition.software_installable,
        hardware_required=definition.hardware_required,
    )


def _capability(
    *,
    capability_id: str,
    title: str,
    status: str,
    summary: str,
    details: list[str] | None = None,
    operator_next_step: str,
    affected_assessment_families: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ReadinessCapabilityRead:
    return ReadinessCapabilityRead(
        id=capability_id,
        title=title,
        status=status,
        summary=summary,
        details=details or [],
        operator_next_step=operator_next_step,
        affected_assessment_families=affected_assessment_families or [],
        metadata=metadata or {},
    )


def _setting_patch_action(
    *,
    action_id: str,
    label: str,
    settings_patch: dict[str, Any],
    safety_note: str,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "kind": "setting_patch",
        "label": label,
        "settings_patch": settings_patch,
        "safety_note": safety_note,
    }


def _focus_setting_action(
    *,
    action_id: str,
    label: str,
    setting_key: str,
    safety_note: str,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "kind": "focus_setting",
        "label": label,
        "setting_key": setting_key,
        "safety_note": safety_note,
    }


def enterprise_identity_snapshot(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
) -> dict[str, Any]:
    tenant_key = tenant_scope_key(tenant_id)
    rows = _load_rows(session, tenant_key)
    return _enterprise_identity_snapshot_from_rows(tenant_key=tenant_key, settings=settings, rows=rows)


def _setting_value(rows: dict[str, InstanceSetting], key: str, default: Any = "") -> Any:
    row = rows.get(key)
    if row is None or not isinstance(row.value_json, dict):
        return default
    return row.value_json.get("value", default)


def _sensitive_setting_configured(rows: dict[str, InstanceSetting], key: str) -> bool:
    row = rows.get(key)
    return bool(row and row.sensitive and row.encrypted_value)


def _enterprise_identity_readiness_boundary(
    *,
    provider: str,
    configured: bool,
    status: str,
) -> str:
    if provider == "disabled":
        return "local_dev_identity_only"
    if status == "error":
        return "identity_configuration_blocked"
    if configured:
        return "configuration_recorded_not_enterprise_enforced"
    return "identity_configuration_not_enterprise_enforced"


def _enterprise_identity_access_boundaries(
    *,
    tenant_key: str,
    provider: str,
    configured: bool,
    status: str,
    session_timeout: int,
) -> dict[str, dict[str, Any]]:
    if provider == "disabled":
        browser_sso_status = "disabled"
        browser_sso_summary = "Enterprise browser SSO is disabled; local fallback and API-key auth are the active paths."
    elif configured:
        browser_sso_status = "configured_not_enforced"
        browser_sso_summary = (
            f"{provider.upper()} configuration is stored, but no browser SSO callback/session enforcement is active."
        )
    elif status == "error":
        browser_sso_status = "blocked"
        browser_sso_summary = "Enterprise browser SSO is blocked by incomplete or invalid provider configuration."
    else:
        browser_sso_status = "not_enforced"
        browser_sso_summary = "Enterprise browser SSO is not enforced."

    return {
        "browser_sso": {
            "status": browser_sso_status,
            "provider": provider,
            "configuration_recorded": configured,
            "browser_sso_enforced": False,
            "full_sso_login_enabled": False,
            "summary": browser_sso_summary,
            "operator_next_step": (
                "Implement and test the governed browser SSO callback before claiming enterprise sign-in enforcement."
            ),
        },
        "tenant_membership": {
            "status": "blocked",
            "tenant_id": tenant_key,
            "request_tenant_header_scopes_records": True,
            "membership_model_enforced": False,
            "invitation_flow_enabled": False,
            "tenant_admin_ui_enabled": False,
            "summary": (
                "X-Tenant-ID narrows tenant-scoped records, but there is no authenticated tenant membership model yet."
            ),
            "operator_next_step": "Add tenant organizations, memberships, invitations, and tenant-admin workflows.",
        },
        "role_enforcement": {
            "status": "enforced",
            "api_key_roles_enforced": True,
            "supported_roles": sorted(API_KEY_ROLES),
            "admin_only_paths": [
                "PATCH /api/v1/settings",
                "POST /api/v1/auth/keys",
                "GET /api/v1/auth/keys",
                "POST /api/v1/auth/keys/{key_id}/revoke",
            ],
            "local_fallback_role": "admin_development_only",
            "audit_events": ["auth.api_key.created", "auth.api_key.revoked"],
            "summary": "API-key admin/operator/reviewer roles are enforced by protected endpoints.",
        },
        "session_enforcement": {
            "status": "configured_not_enforced",
            "timeout_minutes": session_timeout,
            "server_session_enforced": False,
            "expiry_enforced": False,
            "logout_audit_backed": True,
            "logout_mutates_active_runs": False,
            "audit_events": ["auth.login", "auth.logout"],
            "summary": (
                "Session timeout and logout policy are visible and audit-backed, but local fallback has no server session."
            ),
        },
        "scim": {
            "status": "unsupported",
            "provisioning_enabled": False,
            "summary": "SCIM provisioning is not implemented in this slice.",
            "operator_next_step": "Keep identity import/provisioning disabled until a governed SCIM connector exists.",
        },
        "tenant_admin": {
            "status": "unsupported",
            "admin_ui_enabled": False,
            "tenant_switcher_enabled": False,
            "summary": "Tenant administration and tenant switching are not implemented in this slice.",
            "operator_next_step": "Add tenant-admin screens only after authenticated memberships and audit export exist.",
        },
    }


def _enterprise_identity_snapshot_from_rows(
    *,
    tenant_key: str,
    settings: Settings,
    rows: dict[str, InstanceSetting],
) -> dict[str, Any]:
    provider = str(_setting_value(rows, "identity.enterprise_sso_provider", "disabled") or "disabled").strip().lower()
    session_timeout = int(_setting_value(rows, "identity.session_timeout_minutes", 480) or 480)
    logout_redirect_url = str(_setting_value(rows, "identity.logout_redirect_url", "") or "").strip()
    missing: list[str] = []
    configured_secrets: list[str] = []

    if provider == "oidc":
        for key, label in (
            ("identity.oidc_issuer_url", "OIDC issuer URL"),
            ("identity.oidc_client_id", "OIDC client ID"),
        ):
            if not str(_setting_value(rows, key, "") or "").strip():
                missing.append(label)
        if _sensitive_setting_configured(rows, "identity.oidc_client_secret"):
            configured_secrets.append("OIDC client secret")
    elif provider == "saml":
        for key, label in (
            ("identity.saml_entity_id", "SAML entity ID"),
            ("identity.saml_sso_url", "SAML SSO URL"),
        ):
            if not str(_setting_value(rows, key, "") or "").strip():
                missing.append(label)
        if _sensitive_setting_configured(rows, "identity.saml_certificate"):
            configured_secrets.append("SAML signing certificate")

    if provider == "disabled":
        status = "disabled"
        configured = False
        summary = "Enterprise SSO is disabled; local development fallback and API keys remain active."
        next_step = "Configure OIDC or SAML when this host needs enterprise sign-in controls."
    elif provider not in {"oidc", "saml"}:
        status = "error"
        configured = False
        summary = f"Enterprise SSO provider {provider!r} is not recognized."
        next_step = "Select Disabled, OIDC, or SAML in Settings."
    elif missing:
        status = "error"
        configured = False
        summary = f"{provider.upper()} is selected but required configuration is incomplete."
        next_step = "Fill the missing identity fields before treating enterprise sign-in as configured."
    else:
        status = "configured"
        configured = True
        summary = (
            f"{provider.upper()} configuration is recorded and secrets remain masked; "
            "browser SSO enforcement is not active yet."
        )
        next_step = (
            "Use this as the governed configuration baseline only; enable and test the browser SSO "
            "callback, tenant memberships, SCIM, and server sessions before hosted enterprise auth can be claimed."
        )

    access_boundaries = _enterprise_identity_access_boundaries(
        tenant_key=tenant_key,
        provider=provider,
        configured=configured,
        status=status,
        session_timeout=session_timeout,
    )
    readiness_boundary = _enterprise_identity_readiness_boundary(
        provider=provider,
        configured=configured,
        status=status,
    )

    return {
        "tenant_id": tenant_key,
        "provider": provider,
        "status": status,
        "configured": configured,
        "missing_fields": missing,
        "configured_secret_labels": configured_secrets,
        "summary": summary,
        "operator_next_step": next_step,
        "session_policy": {
            "timeout_minutes": session_timeout,
            "logout_redirect_url": logout_redirect_url or None,
            "server_session_enforced": False,
            "local_fallback_has_server_session": False,
            "expiry_enforced": False,
            "expiry_status": "configured_not_enforced",
            "logout_audit_backed": True,
            "logout_mutates_active_runs": False,
        },
        "local_auth": {
            "x_actor_fallback_enabled": True,
            "api_keys_enabled": True,
            "enterprise_auth_enforced": False,
            "warning": "Local X-Actor fallback is for supervised local/dev use and is not enterprise authentication.",
        },
        "access_boundaries": access_boundaries,
        "metadata": {
            "public_base_url": settings.app_public_base_url,
            "secrets_plaintext_exposed": False,
            "full_sso_login_enabled": False,
            "browser_sso_enforced": False,
            "enterprise_ready": False,
            "readiness_boundary": readiness_boundary,
            "role_enforcement_proven": True,
            "tenant_membership_enforced": False,
            "session_expiry_enforced": False,
            "logout_mutates_active_runs": False,
            "scim_enabled": False,
            "tenant_admin_enabled": False,
            "access_boundaries": access_boundaries,
        },
    }


def _enterprise_identity_readiness(
    session: Session,
    *,
    tenant_key: str,
    settings: Settings,
    rows: dict[str, InstanceSetting],
) -> ReadinessCapabilityRead:
    snapshot = _enterprise_identity_snapshot_from_rows(tenant_key=tenant_key, settings=settings, rows=rows)
    if snapshot["metadata"].get("enterprise_ready") is True:
        status = "ready"
    elif snapshot["status"] == "error":
        status = "blocked"
    else:
        status = "degraded"
    return _capability(
        capability_id="enterprise_identity",
        title="Enterprise identity and sessions",
        status=status,
        summary=str(snapshot["summary"]),
        details=[
            f"Provider state: {snapshot['status']}.",
            f"Session timeout: {snapshot['session_policy']['timeout_minutes']} minutes.",
            "Local X-Actor fallback and API keys remain available; they are labeled separately from enterprise auth.",
            f"Browser SSO enforcement: {snapshot['access_boundaries']['browser_sso']['status']}.",
            f"Tenant membership: {snapshot['access_boundaries']['tenant_membership']['status']}.",
            f"Role enforcement: {snapshot['access_boundaries']['role_enforcement']['status']}.",
            "Session logout is audit-backed and does not mutate active runs; server-side session expiry is not enforced.",
            "SCIM, invitation, and tenant-admin paths are unsupported until explicit future implementation.",
        ],
        operator_next_step=str(snapshot["operator_next_step"]),
        metadata={
            **snapshot,
            **snapshot["metadata"],
            "actions": [
                _focus_setting_action(
                    action_id="configure_enterprise_identity",
                    label="Configure SSO",
                    setting_key="identity.enterprise_sso_provider",
                    safety_note="Records identity configuration only; it does not disable local fallback or enable hosted SSO callbacks.",
                )
            ],
        },
    )


def _runtime_concurrency_readiness(settings: Settings) -> ReadinessCapabilityRead:
    workers = max(1, min(int(settings.inline_task_workers), 32))
    return _capability(
        capability_id="runtime_concurrency",
        title="Runtime concurrency",
        status="ready",
        summary=f"{workers} inline task workers configured.",
        details=[
            "Minimum 1, maximum 32, default 4.",
            "Use 1 for serial execution; 4-8 is usually suitable for a workstation; higher values need CPU and network headroom.",
            "Applies to newly dispatched inline tasks and does not mutate active runs.",
        ],
        operator_next_step="Tune Parallel task workers in Runtime Execution when local checks are too slow or too noisy.",
        metadata={"current": workers, "default": 4, "min": 1, "max": 32},
    )


def _dispatch_mode_readiness(settings: Settings) -> ReadinessCapabilityRead:
    mode = str(settings.task_dispatch_mode or "manual").strip().lower() or "manual"
    background = bool(settings.inline_dispatch_background)
    status = "ready" if mode in {"manual", "inline", "worker"} else "degraded"
    return _capability(
        capability_id="dispatch_mode",
        title="Scheduler and dispatch mode",
        status=status,
        summary=f"Dispatch mode is {mode}; inline background dispatch is {'enabled' if background else 'disabled'}.",
        details=[
            "Settings only reports the effective mode; run dispatch still uses the existing approval-aware path.",
            "Manual mode can leave queued work waiting for explicit operator action.",
        ],
        operator_next_step="Switch task dispatch mode through deployment configuration if this host should auto-dispatch queued work.",
        metadata={
            "task_dispatch_mode": mode,
            "inline_dispatch_background": background,
            "actions": [
                {
                    "id": "document_dispatch_mode",
                    "kind": "configuration_note",
                    "label": "Deployment Config Required",
                    "safety_note": "Dispatch mode is controlled by deployment environment; Settings does not bypass approval-aware run dispatch.",
                }
            ],
        },
    )


def _tool_summary_readiness(tools: list[ToolReadinessRead]) -> ReadinessCapabilityRead:
    missing_required = [tool for tool in tools if tool.status == "missing"]
    degraded = [tool for tool in tools if tool.status == "degraded"]
    affected = sorted({family for tool in missing_required + degraded for family in tool.affected_assessment_families})
    if missing_required:
        status = "missing"
        summary = f"{len(missing_required)} required tool groups are missing."
    elif degraded:
        status = "degraded"
        summary = f"{len(degraded)} optional tool groups are not installed."
    else:
        status = "ready"
        summary = "All tracked tool groups are available."
    return _capability(
        capability_id="tool_readiness",
        title="Pentest tool readiness",
        status=status,
        summary=summary,
        details=[
            f"{sum(1 for tool in tools if tool.installed)} of {len(tools)} tracked tool groups detected.",
            "Missing software tool groups expose exact binaries and a copyable official repair command.",
        ],
        operator_next_step="Run the official installer or rebuild the Compose image; hardware-only blockers are reported separately.",
        affected_assessment_families=affected,
        metadata={
            "ready_count": sum(1 for tool in tools if tool.status == "ready"),
            "degraded_count": len(degraded),
            "missing_count": len(missing_required),
            "host_installer_command": "sudo bash scripts/install_security_tools.sh",
            "container_rebuild_command": "docker compose -f infra/compose/docker-compose.yml build --no-cache",
        },
    )


def _runner_tool_certification_readiness() -> ReadinessCapabilityRead:
    summary = summarize_runner_tool_certification_matrix()
    status = str(summary["readiness_status"])
    if status == "ready":
        headline = "Runner/tool certification matrix has no recorded certification gaps."
    elif status == "missing":
        headline = "Runner/tool certification matrix is not available."
    else:
        headline = (
            f"Runner/tool certification matrix records {summary['supported_with_gap_tool_count']} gap(s) "
            f"and {summary['blocked_tool_count']} blocker(s)."
        )
    return _capability(
        capability_id="runner_tool_certification",
        title="Runner/tool certification",
        status=status,
        summary=headline,
        details=[
            f"Matrix path: {summary['path']}.",
            f"{summary['certified_tool_count']} of {summary['tool_count']} tracked runners are certified by deterministic evidence.",
            "Gaps and hardware blockers are evidence records only; they do not install tools or authorize execution.",
        ],
        operator_next_step=(
            "Run python3 scripts/build_runner_tool_certification_matrix.py and review codex/results/runner-tool-certification-matrix.md."
            if status == "missing"
            else "Review certification gaps before making support claims; use Settings tool readiness for current host binary state."
        ),
        metadata=summary,
    )


def _detect_wireless_adapters() -> list[str]:
    net_root = Path("/sys/class/net")
    if not net_root.exists():
        return []
    adapters: list[str] = []
    for entry in sorted(net_root.iterdir(), key=lambda item: item.name):
        if (entry / "wireless").exists():
            adapters.append(entry.name)
    return adapters


def _wireless_readiness(tools: list[ToolReadinessRead]) -> ReadinessCapabilityRead:
    wifi_tool = next((tool for tool in tools if tool.id == "wifi"), None)
    adapters = _detect_wireless_adapters()
    required_binaries = wifi_tool.binary_names if wifi_tool is not None else ["iw", "airodump-ng", "aircrack-ng"]
    installed = bool(wifi_tool and wifi_tool.installed)
    if adapters and installed:
        status = "ready"
        summary = f"{len(adapters)} wireless adapter(s) detected and passive WiFi tooling is available."
        next_step = "Use passive WiFi survey only with explicit site, SSID/BSSID allowlist, adapter context, and wireless ROE."
    elif adapters:
        status = "degraded"
        summary = f"{len(adapters)} wireless adapter(s) detected, but WiFi analysis software tooling is incomplete."
        next_step = "Install WiFi software with the official tool installer; hardware is already visible to the host."
    else:
        status = "blocked"
        summary = (
            "WiFi analysis software is ready, but no wireless adapter is detected on this host."
            if installed
            else "No wireless adapter is detected on this host; WiFi analysis software tooling is also incomplete."
        )
        next_step = (
            "Attach authorized wireless hardware; software installation is already satisfied."
            if installed
            else "Run the official tool installer, then attach authorized wireless hardware for host-backed WiFi readiness."
        )
    return _capability(
        capability_id="wireless_readiness",
        title="Wireless adapter readiness",
        status=status,
        summary=summary,
        details=[
            "Foundation WiFi support is passive-only.",
            "AegisPT does not enable monitor mode, deauthenticate clients, capture handshakes, brute-force WPS, jam RF, or create rogue APs in this slice.",
            "Monitor-mode capability and channel support are reported as unknown until a future explicit lab validation task adds safe hardware probing.",
        ],
        operator_next_step=next_step,
        affected_assessment_families=["WiFi discovery", "Wireless security review"],
        metadata={
            "detected_adapters": adapters,
            "required_binaries": required_binaries,
            "tool_group_installed": installed,
            "software_missing_binaries": wifi_tool.missing_binaries if wifi_tool is not None else required_binaries,
            "hardware_required": True,
            "hardware_blocked": not bool(adapters),
            "monitor_mode_capability": "unknown",
            "channel_support": "unknown",
            "safe_parallelism_limit": 1,
            "rf_disruptive_actions_allowed": False,
            "handshake_capture_allowed": False,
        },
    )


def _ai_provider_readiness(session: Session, *, tenant_key: str, settings: Settings) -> ReadinessCapabilityRead:
    provider = str(settings.ai_provider or "disabled").strip().lower() or "disabled"
    feature_enabled = any(
        [
            settings.ai_finding_enrichment_enabled,
            settings.ai_agent_post_task_analysis_enabled,
            settings.ai_intake_interpretation_enabled,
            settings.ai_autofix_enabled,
            settings.ai_report_drafting_enabled,
        ]
    )
    reusable_sessions = session.scalar(
        select(func.count(SecretRef.id)).where(SecretRef.purpose == "ai_provider.chatgpt_oauth")
    ) or 0
    if provider in DISABLED_AI_PROVIDER_NAMES:
        status = "blocked" if feature_enabled else "degraded"
        summary = "AI provider is disabled."
        next_step = "Select ChatGPT OAuth and connect an engagement-scoped account before expecting AI Signal or repair support."
        actions = [
            _setting_patch_action(
                action_id="enable_chatgpt_oauth_provider",
                label="Enable ChatGPT OAuth",
                settings_patch={"ai.provider": "chatgpt_oauth"},
                safety_note="Writes provider configuration only; AI calls still require an OAuth session and enabled feature toggles.",
            )
        ]
    elif provider == "chatgpt_oauth":
        status = "ready" if reusable_sessions else "degraded"
        summary = f"ChatGPT OAuth selected; {reusable_sessions} reusable token set(s) stored."
        next_step = "Use the ChatGPT OAuth panel to connect or reuse a session for the active engagement."
        actions = [
            _focus_setting_action(
                action_id="review_ai_feature_toggles",
                label="Review AI Toggles",
                setting_key="ai.post_task_analysis_enabled",
                safety_note="Toggles only enable review features; runtime calls still follow provider, scope, run path, and evidence gates.",
            )
        ]
    else:
        status = "degraded"
        summary = f"Provider {provider} is selected; verify its endpoint and credentials before relying on AI features."
        next_step = "Store provider endpoint and key in AI Provider settings, then validate with an engagement run."
        actions = [
            _focus_setting_action(
                action_id="configure_http_ai_provider",
                label="Configure Provider",
                setting_key="ai.http_endpoint",
                safety_note="Stores endpoint configuration only; it does not execute AI calls.",
            )
        ]
    return _capability(
        capability_id="ai_provider",
        title="AI provider and ChatGPT OAuth",
        status=status,
        summary=summary,
        details=[
            f"Feature toggles enabled: {'yes' if feature_enabled else 'no'}.",
            f"Tenant scope: {tenant_key}.",
            "Runtime AI calls remain disabled unless both the provider and feature toggle are enabled for the run path.",
        ],
        operator_next_step=next_step,
        metadata={
            "provider": provider,
            "feature_enabled": feature_enabled,
            "reusable_chatgpt_sessions": reusable_sessions,
            "actions": actions,
        },
    )


def _scheduler_readiness(session: Session) -> ReadinessCapabilityRead:
    enabled = session.scalar(select(func.count(ScheduledRun.id)).where(ScheduledRun.status == "enabled")) or 0
    paused = session.scalar(select(func.count(ScheduledRun.id)).where(ScheduledRun.status != "enabled")) or 0
    return _capability(
        capability_id="scheduled_scans",
        title="Scheduled scans",
        status="ready" if enabled else "degraded",
        summary=f"{enabled} enabled scheduled scan(s), {paused} paused or inactive.",
        details=["Schedules dispatch through the existing approval-aware run creation path."],
        operator_next_step="Create a scheduled scan in Settings after selecting an engagement if recurring baselines are needed.",
        metadata={
            "enabled": enabled,
            "inactive": paused,
            "actions": [
                {
                    "id": "configure_scheduled_scan",
                    "kind": "panel_action",
                    "label": "Configure Schedule",
                    "panel_id": "scheduled_scans",
                    "safety_note": "Schedules only create future approval-aware runs; intrusive profiles remain unavailable for schedules.",
                }
            ],
        },
    )


def _threat_intel_readiness(session: Session, *, tenant_key: str, settings: Settings) -> ReadinessCapabilityRead:
    record_count = session.scalar(select(func.count(ThreatIntelRecord.id))) or 0
    approved_watchlist = session.scalar(
        select(func.count(CveProductWatchlistEntry.id)).where(
            CveProductWatchlistEntry.tenant_id == tenant_key,
            CveProductWatchlistEntry.status == "approved",
        )
    ) or 0
    latest_sync = session.scalar(
        select(CveFeedSyncLog).where(CveFeedSyncLog.tenant_id == tenant_key).order_by(CveFeedSyncLog.started_at.desc())
    )
    status = "ready" if settings.cve_feed_sync_enabled else "degraded"
    if latest_sync is not None and latest_sync.status == "failed":
        status = "degraded"
    actions = [
        _focus_setting_action(
            action_id="configure_threat_intel",
            label="Configure Feeds",
            setting_key="threat_intel.nvd_api_key",
            safety_note="Stores feed configuration only; finding analysis remains local-cache scoped.",
        )
    ]
    if not settings.cve_feed_sync_enabled:
        actions.insert(
            0,
            _setting_patch_action(
                action_id="enable_threat_intel_sync",
                label="Enable Daily CVE Sync",
                settings_patch={"threat_intel.sync_enabled": True},
                safety_note="Enables scheduled cache maintenance only; it does not call feeds during active runner execution.",
            ),
        )
    return _capability(
        capability_id="threat_intel_cache",
        title="Threat intel cache",
        status=status,
        summary=f"{record_count} cached records and {approved_watchlist} approved product watchlist item(s).",
        details=[
            f"Daily sync is {'enabled' if settings.cve_feed_sync_enabled else 'disabled'}.",
            f"Latest sync: {latest_sync.source} {latest_sync.status}" if latest_sync else "No sync log recorded yet.",
        ],
        operator_next_step="Refresh or sync the cache from Settings; NVD/OpenCVE remain watchlist-scoped.",
        metadata={
            "cached_records": record_count,
            "approved_watchlist": approved_watchlist,
            "latest_sync_status": getattr(latest_sync, "status", None),
            "actions": actions,
        },
    )


def _integrations_readiness(rows: dict[str, InstanceSetting]) -> ReadinessCapabilityRead:
    configured = [
        key
        for key in (
            "integrations.jira_token",
            "integrations.slack_webhook_url",
            "integrations.teams_webhook_url",
            "integrations.servicenow_instance_url",
        )
        if key in rows
    ]
    return _capability(
        capability_id="integrations",
        title="Integrations",
        status="ready" if configured else "degraded",
        summary=f"{len(configured)} encrypted integration setting(s) configured.",
        details=[
            "Jira, Slack, Teams, ServiceNow, SIEM, and CI/CD connectors keep credentials encrypted at rest.",
            "Unconfigured integrations do not block local assessment execution.",
        ],
        operator_next_step="Configure only the handoff channels this tenant uses; empty integrations stay safely inactive.",
        metadata={
            "configured_setting_keys": configured,
            "actions": [
                _focus_setting_action(
                    action_id="configure_integrations",
                    label="Configure Handoff",
                    setting_key="integrations.jira_base_url",
                    safety_note="Stores encrypted handoff settings only; no finding or run is pushed until existing handoff flows are used.",
                )
            ],
        },
    )


def _secret_storage_readiness(settings: Settings) -> ReadinessCapabilityRead:
    try:
        storage_backend, fallback = direct_secret_storage_backend(settings)
        status = "ready" if storage_backend != "encrypted_local" or not fallback else "degraded"
        summary = f"Secret storage backend is {storage_backend}."
        next_step = "Set DEPLOYMENT_SECRET_ENCRYPTION_KEY for production deployments." if fallback else "No action required."
    except ValueError as exc:
        status = "blocked"
        summary = str(exc)
        next_step = "Configure a deployment secret encryption key before storing new secrets."
        storage_backend = "unavailable"
        fallback = False
    return _capability(
        capability_id="database_encryption",
        title="Secret and database encryption",
        status=status,
        summary=summary,
        details=[
            "Sensitive Settings values are encrypted and returned only as masked configured indicators.",
            f"Database URL scheme: {str(settings.database_url).split(':', 1)[0]}.",
        ],
        operator_next_step=next_step,
        metadata={"storage_backend": storage_backend, "fallback_to_local_secret_key": fallback},
    )


def _artifact_storage_readiness(settings: Settings) -> ReadinessCapabilityRead:
    mode = str(settings.artifacts_storage_mode or "inline").strip().lower() or "inline"
    details = [f"Storage mode: {mode}."]
    metadata: dict[str, Any] = {"mode": mode}
    status = "ready"
    next_step = "No action required."
    if mode == "inline":
        path = Path(settings.artifacts_inline_dir)
        metadata["inline_dir"] = str(path)
        metadata["inline_dir_exists"] = path.exists()
        details.append(f"Inline artifact directory: {path}.")
        next_step = "Ensure the inline artifact directory is backed up and writable by the app process."
    elif mode == "s3":
        metadata["bucket"] = settings.artifacts_s3_bucket
        metadata["endpoint"] = settings.artifacts_s3_endpoint
        details.append(f"S3 bucket: {settings.artifacts_s3_bucket}.")
        if not settings.artifacts_s3_enforce_sse:
            status = "degraded"
            next_step = "Enable server-side encryption enforcement for production S3 evidence storage."
    else:
        status = "blocked"
        next_step = "Use inline or s3 artifact storage mode."
    return _capability(
        capability_id="artifact_storage",
        title="Evidence artifact storage",
        status=status,
        summary=f"Evidence artifacts use {mode} storage.",
        details=details,
        operator_next_step=next_step,
        metadata=metadata,
    )


def _is_production_like(settings: Settings) -> bool:
    env = str(settings.app_env or "development").strip().lower()
    return env not in {"", "dev", "development", "local", "test", "testing"}


def _public_base_url_is_https(settings: Settings) -> bool:
    return str(settings.app_public_base_url or "").strip().lower().startswith("https://")


def _database_encryption_state(settings: Settings, *, production_like: bool) -> tuple[str, str]:
    url = str(settings.database_url or "")
    scheme = url.split(":", 1)[0].lower()
    if scheme.startswith("sqlite"):
        if settings.aegispt_db_key:
            return "ready", "SQLite database encryption key is configured."
        if production_like:
            return "blocked", "SQLite database is not encrypted; set AEGISPT_DB_KEY or use a managed encrypted database."
        return "degraded", "Development SQLite database encryption key is not configured."
    if settings.deployment_database_encryption_confirmed:
        return "ready", "External database encryption at rest is confirmed by deployment configuration."
    if production_like:
        return "degraded", "External database encryption is deployment-managed but not confirmed in AegisPT configuration."
    return "degraded", "External database encryption confirmation is not set."


def _artifact_encryption_state(settings: Settings, *, production_like: bool) -> tuple[str, str]:
    mode = str(settings.artifacts_storage_mode or "inline").strip().lower() or "inline"
    if mode == "s3":
        if settings.artifacts_s3_enforce_sse or settings.deployment_artifact_storage_encryption_confirmed:
            return "ready", "Object storage encryption is enforced or confirmed."
        if production_like:
            return "blocked", "Production S3/MinIO artifact storage does not enforce or confirm encryption."
        return "degraded", "S3/MinIO artifact storage encryption is not enforced."
    if mode == "inline":
        if settings.deployment_artifact_storage_encryption_confirmed:
            return "ready", "Inline artifact volume encryption is confirmed by deployment configuration."
        if production_like:
            return "degraded", "Inline artifact storage needs host/disk encryption confirmation for production."
        return "degraded", "Inline artifact storage relies on local filesystem controls in development."
    return "blocked", f"Artifact storage mode {mode!r} is not recognized."


def _redacted_proxy_status(settings: Settings) -> str:
    if not settings.deployment_outbound_proxy_url:
        return "not configured"
    return "configured"


def _deployment_hardening_readiness(settings: Settings) -> ReadinessCapabilityRead:
    production_like = _is_production_like(settings)
    https_public_url = _public_base_url_is_https(settings)
    tls_ok = https_public_url and bool(settings.deployment_tls_terminated_by_proxy)
    secure_cookie_ok = bool(settings.deployment_secure_cookies)
    no_internet = bool(settings.deployment_no_internet_mode)
    offline_feed_path = bool(str(settings.deployment_offline_update_path or "").strip())
    offline_tool_path = bool(str(settings.deployment_manual_tool_update_path or "").strip())
    db_status, db_detail = _database_encryption_state(settings, production_like=production_like)
    artifact_status, artifact_detail = _artifact_encryption_state(settings, production_like=production_like)

    details: list[str] = [
        f"Environment: {settings.app_env}.",
        f"Public base URL uses HTTPS: {'yes' if https_public_url else 'no'}.",
        f"TLS reverse proxy declared: {'yes' if settings.deployment_tls_terminated_by_proxy else 'no'}.",
        f"Secure browser cookies declared: {'yes' if secure_cookie_ok else 'no'}.",
        db_detail,
        artifact_detail,
    ]
    if no_internet:
        details.append(
            "No-internet mode is enabled; offline feed/template and tool update paths are required for maintenance."
        )
    elif settings.deployment_outbound_proxy_url:
        details.append("Outbound proxy is configured; proxy credentials are not exposed.")
    else:
        details.append("No outbound proxy or no-internet mode is configured; egress is treated as direct/local.")

    blocker_reasons: list[str] = []
    warning_reasons: list[str] = []
    if production_like and not tls_ok:
        blocker_reasons.append("production public access must use HTTPS behind a declared trusted reverse proxy")
    elif not tls_ok:
        warning_reasons.append("TLS/reverse-proxy hardening is not configured for production use")
    if production_like and not secure_cookie_ok:
        blocker_reasons.append("secure browser cookie/session posture is not declared")
    elif not secure_cookie_ok:
        warning_reasons.append("secure cookie/session posture is development-grade")
    if db_status == "blocked":
        blocker_reasons.append(db_detail)
    elif db_status == "degraded":
        warning_reasons.append(db_detail)
    if artifact_status == "blocked":
        blocker_reasons.append(artifact_detail)
    elif artifact_status == "degraded":
        warning_reasons.append(artifact_detail)
    if no_internet and not (offline_feed_path and offline_tool_path):
        blocker_reasons.append("air-gapped mode needs both offline feed/template and manual tool update paths")
    if production_like and not settings.deployment_trusted_certificate_bundle:
        warning_reasons.append("trusted enterprise CA bundle path is not declared")

    if blocker_reasons:
        status = "blocked"
        summary = f"Production deployment hardening has {len(blocker_reasons)} blocking gap(s)."
        next_step = "Resolve blocking deployment gaps before treating this host as enterprise-production ready."
    elif production_like and warning_reasons:
        status = "degraded"
        summary = f"Production deployment hardening has {len(warning_reasons)} warning gap(s)."
        next_step = "Confirm encryption, certificate, proxy/offline, and secure-cookie settings in deployment configuration."
    elif production_like:
        status = "ready"
        summary = "Production deployment hardening assumptions are declared."
        next_step = "Keep TLS certificates, offline bundles, feed updates, and storage encryption under change control."
    else:
        status = "degraded"
        summary = "Development deployment is allowed, but production hardening is not fully declared."
        next_step = "Before enterprise rollout, switch APP_ENV to production and configure TLS, secure cookies, encryption, proxy/offline, and update paths."

    return _capability(
        capability_id="deployment_hardening",
        title="Production deployment hardening",
        status=status,
        summary=summary,
        details=details[:8],
        operator_next_step=next_step,
        affected_assessment_families=["Enterprise deployment", "Support diagnostics", "Offline update operations"],
        metadata={
            "production_like": production_like,
            "app_env": settings.app_env,
            "https_public_base_url": https_public_url,
            "tls_terminated_by_proxy": bool(settings.deployment_tls_terminated_by_proxy),
            "secure_cookies": secure_cookie_ok,
            "database_encryption_status": db_status,
            "artifact_encryption_status": artifact_status,
            "outbound_proxy": _redacted_proxy_status(settings),
            "no_internet_mode": no_internet,
            "offline_update_path_configured": offline_feed_path,
            "manual_tool_update_path_configured": offline_tool_path,
            "trusted_certificate_bundle_configured": bool(settings.deployment_trusted_certificate_bundle),
            "blocking_gap_count": len(blocker_reasons),
            "warning_gap_count": len(warning_reasons),
            "blocking_reasons": blocker_reasons,
            "warning_reasons": warning_reasons,
            "enterprise_production_ready": production_like and status == "ready",
            "readiness_boundary": (
                "enterprise_production_ready"
                if production_like and status == "ready"
                else "production_like_blocked"
                if production_like and status == "blocked"
                else "production_like_degraded"
                if production_like
                else "development_ready_not_enterprise_production"
            ),
            "secrets_plaintext_exposed": False,
        },
    )


def _host_health_readiness(settings: Settings) -> ReadinessCapabilityRead:
    return _capability(
        capability_id="host_health",
        title="Live app health",
        status="ready",
        summary=f"{settings.app_name} reports healthy runtime state in {settings.app_env}.",
        details=[
            f"Public base URL: {settings.app_public_base_url}.",
            f"API prefix: {settings.api_prefix}.",
            "Runtime state vocabulary: healthy, degraded, shutting_down, unreachable.",
        ],
        operator_next_step=(
            "Use /health/live with a short client timeout for uptime checks; restart the local host if it reports "
            "shutting_down or becomes unreachable."
        ),
        metadata={
            "app_name": settings.app_name,
            "app_env": settings.app_env,
            "public_base_url": settings.app_public_base_url,
            "runtime_state": "healthy",
            "state_vocabulary": ["healthy", "degraded", "shutting_down", "unreachable"],
        },
    )


def _worst_status(statuses: list[str]) -> str:
    rank = {"ready": 0, "degraded": 1, "missing": 2, "blocked": 3}
    normalized = [str(status or "degraded").lower() for status in statuses]
    return max(normalized, key=lambda status: rank.get(status, 1)) if normalized else "ready"


def update_instance_settings(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
    patch: dict[str, Any],
    actor: str,
) -> SettingsRead:
    tenant_key = tenant_scope_key(tenant_id)
    rows = _load_rows(session, tenant_key)
    identity_keys_changed: list[str] = []
    for key, raw_value in patch.items():
        definition = SETTING_BY_KEY.get(key)
        if definition is None:
            raise HTTPException(status_code=400, detail=f"unknown setting key: {key}")
        if definition.read_only:
            raise HTTPException(status_code=400, detail=f"setting is read-only: {key}")

        existing = rows.get(key)
        if definition.sensitive:
            row = _upsert_sensitive_setting(
                session,
                existing=existing,
                definition=definition,
                tenant_key=tenant_key,
                raw_value=raw_value,
                settings=settings,
                actor=actor,
            )
        else:
            row = _upsert_plain_setting(
                session,
                existing=existing,
                definition=definition,
                tenant_key=tenant_key,
                raw_value=raw_value,
                actor=actor,
            )
        if row is None:
            rows.pop(key, None)
        else:
            rows[key] = row
        if definition.section_id == "enterprise_identity":
            identity_keys_changed.append(key)

    if identity_keys_changed:
        write_audit_event(
            session,
            actor=actor,
            action="settings.enterprise_identity.updated",
            object_type="enterprise_identity_settings",
            object_id=tenant_key,
            metadata={
                "tenant_id": tenant_key,
                "setting_keys": sorted(identity_keys_changed),
                "sensitive_plaintext_exposed": False,
            },
        )
    session.flush()
    return read_instance_settings(session, tenant_id=tenant_key, settings=settings)


def _load_rows(session: Session, tenant_key: str) -> dict[str, InstanceSetting]:
    statement = select(InstanceSetting).where(InstanceSetting.tenant_id == tenant_key)
    return {row.setting_key: row for row in session.scalars(statement).all()}


def _render_setting(
    definition: SettingDefinition,
    row: InstanceSetting | None,
    *,
    settings: Settings,
    tenant_key: str,
) -> SettingRead:
    options = [SettingOption(value=value, label=label) for value, label in definition.options]
    if row is not None and definition.sensitive:
        return SettingRead(
            key=definition.key,
            label=definition.label,
            value=None,
            input_type=definition.input_type,
            source="database",
            sensitive=True,
            configured=True,
            masked_value=row.display_label or "Stored securely",
            read_only=definition.read_only,
            description=definition.description,
            options=options,
            ui_hidden=definition.ui_hidden,
            min_value=definition.min_value,
            max_value=definition.max_value,
            step=definition.step,
            placeholder=definition.placeholder,
        )
    if row is not None:
        return SettingRead(
            key=definition.key,
            label=definition.label,
            value=row.value_json.get("value"),
            input_type=definition.input_type,
            source="database",
            sensitive=False,
            configured=True,
            read_only=definition.read_only,
            description=definition.description,
            options=options,
            ui_hidden=definition.ui_hidden,
            min_value=definition.min_value,
            max_value=definition.max_value,
            step=definition.step,
            placeholder=definition.placeholder,
        )

    default_value = _normalize_plain_value(definition, definition.default_value(settings, tenant_key))
    configured = default_value not in (None, "", [])
    return SettingRead(
        key=definition.key,
        label=definition.label,
        value=None if definition.sensitive else default_value,
        input_type=definition.input_type,
        source="environment" if configured else "default",
        sensitive=definition.sensitive,
        configured=configured,
        masked_value="Environment default configured" if definition.sensitive and configured else None,
        read_only=definition.read_only,
        description=definition.description,
        options=options,
        ui_hidden=definition.ui_hidden,
        min_value=definition.min_value,
        max_value=definition.max_value,
        step=definition.step,
        placeholder=definition.placeholder,
    )


def _upsert_plain_setting(
    session: Session,
    *,
    existing: InstanceSetting | None,
    definition: SettingDefinition,
    tenant_key: str,
    raw_value: Any,
    actor: str,
) -> InstanceSetting | None:
    if raw_value is None:
        if existing is not None:
            session.delete(existing)
        return None

    value = _normalize_plain_value(definition, raw_value)
    row = existing or InstanceSetting(
        tenant_id=tenant_key,
        setting_key=definition.key,
        created_by=actor,
    )
    row.value_json = {"value": value}
    row.sensitive = False
    row.storage_backend = None
    row.encrypted_value = None
    row.display_label = None
    row.metadata_json = {"raw_secret_material_exposed": False}
    row.updated_by = actor
    session.add(row)
    return row


def _upsert_sensitive_setting(
    session: Session,
    *,
    existing: InstanceSetting | None,
    definition: SettingDefinition,
    tenant_key: str,
    raw_value: Any,
    settings: Settings,
    actor: str,
) -> InstanceSetting | None:
    if raw_value is None:
        if existing is not None:
            session.delete(existing)
        return None

    value = str(raw_value or "").strip()
    if not value:
        return existing

    try:
        storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    row = existing or InstanceSetting(
        tenant_id=tenant_key,
        setting_key=definition.key,
        created_by=actor,
    )
    row.value_json = {}
    row.sensitive = True
    row.storage_backend = storage_backend
    row.encrypted_value = encrypt_secret_value(value, settings, storage_backend=storage_backend)
    row.display_label = secret_display_label(
        value,
        secret_kind=definition.secret_kind,
        storage_backend=storage_backend,
    )
    row.metadata_json = {
        "raw_secret_material_exposed": False,
        "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
    }
    row.updated_by = actor
    session.add(row)
    return row


def _normalize_plain_value(definition: SettingDefinition, raw_value: Any) -> Any:
    if definition.input_type == "checkbox":
        if isinstance(raw_value, str):
            return raw_value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(raw_value)
    if definition.input_type == "list":
        if isinstance(raw_value, list):
            return [str(item).strip() for item in raw_value if str(item).strip()]
        return _csv_default(str(raw_value or ""))
    if definition.input_type == "number":
        try:
            value = float(raw_value)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"setting must be a number: {definition.key}") from exc
        if definition.min_value is not None and value < definition.min_value:
            raise HTTPException(
                status_code=400,
                detail=f"setting {definition.key} must be at least {definition.min_value:g}",
            )
        if definition.max_value is not None and value > definition.max_value:
            raise HTTPException(
                status_code=400,
                detail=f"setting {definition.key} must be at most {definition.max_value:g}",
            )
        if definition.step == 1:
            return int(value)
        return value
    if definition.input_type == "select":
        value = str(raw_value or "").strip()
        allowed = {option[0] for option in definition.options}
        if allowed and value not in allowed:
            raise HTTPException(status_code=400, detail=f"setting {definition.key} must be one of: {', '.join(sorted(allowed))}")
        return value
    if raw_value is None:
        return None
    return str(raw_value).strip()
