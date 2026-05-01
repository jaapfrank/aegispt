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
    api_prefix: str = "/api/v1"
    task_dispatch_mode: str = "manual"
    database_url: str = "sqlite+pysqlite:///./aegispt.db"
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
    local_secret_encryption_key: str = _default_local_secret_key()
    secret_materialization_mode: str = "encrypted_local"
    deployment_secret_encryption_key: str | None = None
    require_deployment_secret_encryption_key: bool = False
    auto_create_tables: bool = True
    runner_timeout_seconds: float = 60.0
    execution_kill_switch: bool = False
    inline_dispatch_background: bool = False
    inline_task_workers: int = 4
    ai_provider: str = "disabled"
    ai_finding_enrichment_enabled: bool = False
    ai_finding_enrichment_provider: str = "disabled"
    ai_finding_enrichment_endpoint: str | None = None
    ai_finding_enrichment_api_key_env: str | None = None
    ai_finding_enrichment_model: str = "aegispt-finding-enrichment"
    ai_finding_enrichment_timeout_seconds: float = 5.0
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
    chatgpt_oauth_model: str = "gpt-5.4"
    chatgpt_oauth_timeout_seconds: float = 10.0
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
    settings_critical_alert_destination: str = "none"
    settings_notify_on_run_completion: bool = False
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
