from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

_PROTECTED_AUTH_REF_PREFIXES = (
    "vault://",
    "env://",
    "ref://",
    "secret://",
    "aegispt://",
)


class JiraIntegrationConfigurationUpsert(BaseModel):
    integration_type: Literal["jira"] = "jira"
    display_name: str | None = Field(default=None, max_length=255)
    base_url: str = Field(max_length=2048)
    project_key: str | None = Field(default=None, max_length=100)
    auth_ref: str | None = Field(default=None, max_length=255)
    settings_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("base_url must start with http:// or https://")
        return normalized

    @field_validator("display_name", "project_key", "auth_ref")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class WebhookIntegrationConfigurationUpsert(BaseModel):
    integration_type: Literal["webhook"] = "webhook"
    display_name: str | None = Field(default=None, max_length=255)
    base_url: str = Field(max_length=2048)
    auth_ref: str | None = Field(default=None, max_length=255)
    settings_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("base_url must start with http:// or https://")
        return normalized

    @field_validator("display_name", "auth_ref")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class PortfolioIntegrationConfigurationUpsert(BaseModel):
    integration_type: Literal["slack", "teams", "servicenow"]
    display_name: str | None = Field(default=None, max_length=255)
    base_url: str = Field(max_length=2048)
    project_key: str | None = Field(default=None, max_length=100)
    auth_ref: str | None = Field(default=None, max_length=255)
    settings_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("base_url must start with http:// or https://")
        return normalized

    @field_validator("display_name", "project_key", "auth_ref")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("auth_ref")
    @classmethod
    def validate_protected_auth_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if not normalized.lower().startswith(_PROTECTED_AUTH_REF_PREFIXES):
            raise ValueError(
                "auth_ref must be a protected reference such as vault://, env://, ref://, secret://, or aegispt://"
            )
        return normalized


class IntegrationConfigurationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    integration_type: str
    display_name: str | None
    base_url: str
    project_key: str | None
    auth_ref: str | None
    settings_json: dict[str, Any]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class JiraFindingLinkUpsert(BaseModel):
    issue_key: str = Field(max_length=100)
    issue_url: str = Field(max_length=2048)
    issue_status: str | None = Field(default=None, max_length=100)

    @field_validator("issue_key")
    @classmethod
    def validate_issue_key(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("issue_key is required")
        return normalized

    @field_validator("issue_url")
    @classmethod
    def validate_issue_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("issue_url must start with http:// or https://")
        return normalized

    @field_validator("issue_status")
    @classmethod
    def normalize_issue_status(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class JiraFindingLinkRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    integration_configuration_id: UUID
    issue_key: str
    issue_url: str
    issue_status: str | None
    last_sync_state: str
    last_synced_at: datetime | None
    last_sync_error: str | None
    last_sync_payload_json: dict[str, Any]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class WebhookFindingHandoffRequest(BaseModel):
    handoff_key: str | None = Field(default=None, max_length=100)
    handoff_url: str | None = Field(default=None, max_length=2048)
    operator_note: str | None = Field(default=None, max_length=2000)

    @field_validator("handoff_key", "operator_note")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("handoff_url")
    @classmethod
    def validate_handoff_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("handoff_url must start with http:// or https://")
        return normalized


class ProviderFindingHandoffRequest(BaseModel):
    handoff_key: str | None = Field(default=None, max_length=100)
    handoff_url: str | None = Field(default=None, max_length=2048)
    operator_note: str | None = Field(default=None, max_length=2000)

    @field_validator("handoff_key", "operator_note")
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("handoff_url")
    @classmethod
    def validate_handoff_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("handoff_url must start with http:// or https://")
        return normalized


class WebhookFindingHandoffRead(BaseModel):
    id: UUID
    finding_id: UUID
    integration_configuration_id: UUID
    handoff_key: str
    handoff_url: str
    handoff_status: str | None
    last_sync_state: str
    last_synced_at: datetime | None
    last_sync_error: str | None
    last_sync_payload_json: dict[str, Any]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class ProviderFindingHandoffRead(BaseModel):
    id: UUID
    finding_id: UUID
    integration_configuration_id: UUID
    integration_type: str
    handoff_key: str
    handoff_url: str
    handoff_status: str | None
    last_sync_state: str
    last_synced_at: datetime | None
    last_sync_error: str | None
    last_sync_payload_json: dict[str, Any]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class SiemIntegrationConfigurationUpsert(BaseModel):
    integration_type: Literal["splunk", "elastic", "sentinel"]
    display_name: str | None = Field(default=None, max_length=255)
    base_url: str = Field(max_length=2048)
    credential: str | None = Field(default=None, max_length=4096)
    enabled: bool = True
    push_on_run_completion: bool = True
    push_on_critical_finding: bool = True
    include_sigma: bool = False
    index_name: str | None = Field(default=None, max_length=255)
    sourcetype: str | None = Field(default=None, max_length=255)
    custom_log_table: str | None = Field(default=None, max_length=255)
    stream_name: str | None = Field(default=None, max_length=255)
    timeout_seconds: float | None = Field(default=None, ge=1, le=120)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("base_url must start with http:// or https://")
        return normalized

    @field_validator(
        "display_name",
        "credential",
        "index_name",
        "sourcetype",
        "custom_log_table",
        "stream_name",
    )
    @classmethod
    def normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class SiemIntegrationConfigurationRead(BaseModel):
    id: UUID
    engagement_id: UUID
    integration_type: Literal["splunk", "elastic", "sentinel"]
    provider_label: str
    display_name: str | None = None
    base_url: str
    enabled: bool = True
    push_on_run_completion: bool = True
    push_on_critical_finding: bool = True
    include_sigma: bool = False
    index_name: str | None = None
    sourcetype: str | None = None
    custom_log_table: str | None = None
    stream_name: str | None = None
    timeout_seconds: float | None = None
    credential_configured: bool = False
    credential_display_label: str | None = None
    token_exposed: bool = False
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class SiemIntegrationCollectionRead(BaseModel):
    engagement_id: UUID
    providers: list[SiemIntegrationConfigurationRead] = Field(default_factory=list)
    sensitive_plaintext_exposed: bool = False


class RepositoryAuthorizationStartRead(BaseModel):
    provider: Literal["github", "gitlab"]
    authorization_url: str
    redirect_uri: str
    state: str
    token_exposed: bool = False


class RepositoryIntegrationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    provider: str
    repository_url: str
    repository_path: str
    default_branch: str
    account_login: str | None
    status: str
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    token_exposed: bool = False
    created_at: datetime
    updated_at: datetime


class RepositoryAuthorizationCompleteRead(BaseModel):
    provider: Literal["github", "gitlab"]
    connected: bool = True
    repository_url: str
    repository_path: str
    default_branch: str
    account_login: str | None = None
    token_exposed: bool = False


class RepositoryFixPullRequestRead(BaseModel):
    provider: Literal["github", "gitlab"]
    repository_url: str
    branch_name: str
    pull_request_url: str
    pull_request_id: str
    auto_merge_enabled: bool = False
