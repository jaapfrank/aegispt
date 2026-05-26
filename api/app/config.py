from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_local_secret_key() -> str:
    digest = hashlib.sha256(b"aegispt-development-local-secret-key").digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    app_name: str = "AegisPT"
    app_env: str = "development"
    aegispt_env: str | None = None
    api_prefix: str = "/api/v1"
    aegispt_allowed_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    task_dispatch_mode: str = "inline"  # inline=run tasks in-process; manual=operator must click dispatch; dramatiq=worker queue
    database_url: str = "postgresql+psycopg://aegispt:aegispt_dev_pw@127.0.0.1:5432/aegispt"
    aegispt_db_key: str | None = None
    redis_url: str = "redis://localhost:6379/0"
    artifacts_storage_mode: str = "inline"
    artifacts_s3_endpoint: str = "http://localhost:9000"
    artifacts_s3_bucket: str = "aegispt-artifacts"
    artifacts_s3_access_key: str = "minioadmin"
    artifacts_s3_secret_key: str = "change-me"
    artifacts_s3_enforce_sse: bool = False
    artifacts_inline_dir: str = ".aegispt-artifacts"
    evidence_timestamping_enabled: bool = True
    evidence_timestamp_authority_url: str = "https://freetsa.org/tsr"
    evidence_timestamp_timeout_seconds: float = 5.0
    evidence_timestamp_openssl_binary: str = "openssl"
    zap_api_key: str = "change-me-zap-key"
    burp_api_url: str | None = None
    burp_api_key: str | None = None
    metasploit_rpc_url: str = "http://127.0.0.1:55553/api/1.0"
    metasploit_rpc_user: str = "aegispt"
    metasploit_rpc_password: str = "change-me-metasploit"
    metasploit_rpc_verify_ssl: bool = False
    metasploit_rpc_auto_start: bool = True
    metasploit_rpc_start_binary: str = "msfrpcd"
    metasploit_rpc_start_timeout_seconds: float = 15.0
    app_public_base_url: str = "http://127.0.0.1:8000"
    deployment_tls_terminated_by_proxy: bool = False
    deployment_secure_cookies: bool = False
    deployment_trusted_certificate_bundle: str | None = None
    deployment_outbound_proxy_url: str | None = None
    deployment_no_internet_mode: bool = False
    deployment_offline_update_path: str | None = None
    deployment_manual_tool_update_path: str | None = None
    deployment_database_encryption_confirmed: bool = False
    deployment_artifact_storage_encryption_confirmed: bool = False
    local_secret_encryption_key: str = _default_local_secret_key()
    secret_materialization_mode: str = "encrypted_local"
    deployment_secret_encryption_key: str | None = None
    require_deployment_secret_encryption_key: bool = False
    auto_create_tables: bool = True
    runner_timeout_seconds: float = 60.0
    execution_kill_switch: bool = False
    inline_dispatch_background: bool = True  # dispatch tasks in background thread to avoid SQLite lock conflicts
    inline_task_workers: int = 4
    ai_provider: str = "disabled"
    ai_finding_enrichment_enabled: bool = False
    ai_finding_enrichment_provider: str = "disabled"
    ai_finding_enrichment_endpoint: str | None = None
    ai_finding_enrichment_api_key_env: str | None = None
    ai_finding_enrichment_model: str = "aegispt-finding-enrichment"
    ai_finding_enrichment_timeout_seconds: float = 5.0
    ai_finding_enrichment_failure_cooldown_seconds: float = 300.0
    auto_validate_findings: bool = False
    ai_autofix_enabled: bool = False
    ai_autofix_provider: str = "disabled"
    ai_autofix_model: str = "aegispt-autofix"
    ai_report_drafting_enabled: bool = False
    ai_report_drafting_provider: str = "disabled"
    ai_agent_post_task_analysis_enabled: bool = False
    ai_agent_post_task_analysis_provider: str = "disabled"
    ai_agent_post_task_analysis_model: str = "aegispt-post-task-analysis"
    ai_intake_interpretation_enabled: bool = False
    ai_intake_interpretation_provider: str = "disabled"
    ai_intake_interpretation_model: str = "aegispt-intake-interpretation"
    chatgpt_oauth_client_id: str | None = "app_EMoamEEZ73f0CkXaXp7hrann"
    chatgpt_oauth_authorize_url: str = "https://auth.openai.com/oauth/authorize"
    chatgpt_oauth_token_url: str = "https://auth.openai.com/oauth/token"
    chatgpt_oauth_backend_api_url: str = "https://chatgpt.com/backend-api"
    chatgpt_oauth_backend_api_path: str = "/codex/responses"
    chatgpt_oauth_redirect_uri: str | None = None
    chatgpt_oauth_local_callback_enabled: bool = True
    chatgpt_oauth_local_callback_url: str = "http://localhost:1455/auth/callback"
    chatgpt_oauth_scopes: str = "openid profile email offline_access"
    chatgpt_oauth_originator: str = "aegispt"
    # Model: gpt-5.5 (bare). Empirically validated 2026-05-22 against the
    # /codex/responses surface — `gpt-5.5` returns 200; `gpt-5.5-codex` is
    # explicitly rejected ("not supported when using Codex with a ChatGPT
    # account"); `gpt-5` bare is also rejected. Operator confirmed 5.5 is
    # the right model name (no -codex suffix).
    chatgpt_oauth_model: str = "gpt-5.5"
    # Reasoning effort: gpt-5.5 supports {none, low, medium, high, xhigh}
    # — operator-cited url confirms xhigh exists; empirically the 400
    # body on `effort=minimal` reveals the full enum. Operator chose
    # xhigh for the highest-quality picker decisions, accepting longer
    # wall-clock per call.
    chatgpt_oauth_reasoning_effort: str = "xhigh"
    # service_tier: per Codex CLI's models.json, gpt-5.5's "Fast" mode
    # maps to id="priority" in the actual API request. Docs claim 1.5x
    # speed. Empirically (2026-05-22, 8 paired measurements across 4
    # effort levels on the real picker prompt + 600-word output) this
    # account sees `priority` CONSISTENTLY slower — likely because the
    # active OAuth token isn't on a ChatGPT Pro/Fast-Mode-enabled tier.
    # Backend still accepts the field (200 OK) but no fast routing
    # engages. Empty default omits the field; operators with Fast-Mode
    # access can set "priority" to opt in.
    chatgpt_oauth_service_tier: str = ""
    # text.verbosity: gpt-5.5 separates "thinking depth" (reasoning.effort)
    # from "output expansiveness" (text.verbosity).
    #
    # Empirical 2026-05-26 (smoke 33 vs 34 on XBEN-002 with otherwise
    # identical config): default verbosity produced 2 completed exec_plans;
    # verbosity=low produced 0. The cookbook recommendation "high reasoning
    # + low verbosity for well-considered concise answers" does NOT
    # generalise to multi-step exec-plan generation -- the model needs
    # output budget to write out the chain-of-step plan body, even when
    # the schema is strict.
    #
    # Default back to empty (omit the field, server-side default applies).
    # Operators who want concise narrative output can override via env.
    chatgpt_oauth_verbosity: str = ""
    # Picker prompt is ~23KB + structured-output schema → first-token latency
    # plus reasoning is well over 90s on high effort. 240s aligns with the
    # Claude picker's effective budget (90s per messages.create × ~3 retries).
    chatgpt_oauth_timeout_seconds: float = 240.0
    chatgpt_oauth_refresh_margin_seconds: int = 300
    github_oauth_client_id: str | None = None
    github_oauth_client_secret: str | None = None
    github_oauth_authorize_url: str = "https://github.com/login/oauth/authorize"
    github_oauth_token_url: str = "https://github.com/login/oauth/access_token"
    github_api_url: str = "https://api.github.com"
    gitlab_oauth_client_id: str | None = None
    gitlab_oauth_client_secret: str | None = None
    gitlab_oauth_authorize_url: str = "https://gitlab.com/oauth/authorize"
    gitlab_oauth_token_url: str = "https://gitlab.com/oauth/token"
    gitlab_api_url: str = "https://gitlab.com/api/v4"
    settings_default_lan_cidr: str = "10.0.0.0/8"
    settings_default_domain: str | None = None
    settings_default_vlan_cidrs: str = ""
    settings_default_excluded_ranges: str = ""
    settings_default_scan_profile: str = "Standard"
    settings_default_safety_level: str = "passive"
    settings_default_execution_lane: str = "passive-network-discovery"
    settings_jira_base_url: str | None = None
    settings_jira_project_key: str | None = None
    settings_servicenow_instance_url: str | None = None
    settings_email_notifications_enabled: bool = False
    settings_smtp_host: str | None = None
    settings_smtp_port: int = 587
    settings_smtp_username: str | None = None
    settings_smtp_from: str | None = None
    settings_smtp_to: str = ""
    settings_smtp_use_tls: bool = True
    settings_critical_alert_destination: str = "none"
    settings_notify_on_run_completion: bool = False
    settings_notify_on_phase_approval_needed: bool = True
    settings_notification_timeout_seconds: float = 10.0
    settings_operator_display_name: str = "operator-ui"
    settings_tenant_id: str | None = None
    cve_feed_sync_enabled: bool = True
    cve_feed_cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cve_feed_ncsc_nl_rss_url: str = "https://advisories.ncsc.nl/rss/advisories"
    cve_feed_nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_feed_opencve_api_url: str = "https://www.opencve.io/api/cve"
    cve_feed_nvd_api_key: str | None = None
    cve_feed_opencve_api_token: str | None = None
    cve_feed_timeout_seconds: float = 20.0
    cve_feed_max_records_per_source: int = 1000
    cve_feed_min_cvss_score: float = 6.0
    # X-Actor fallback: set to False in production to require bearer API key authentication.
    # When True AND the resolved environment is local/dev/test, unauthenticated requests
    # fall back to admin role via X-Actor header (legacy local dev convenience).
    allow_x_actor_fallback: bool = True

    @property
    def is_local_dev_environment(self) -> bool:
        env = str(self.aegispt_env or self.app_env or "development").strip().lower()
        return env in {"development", "dev", "test", "local"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
