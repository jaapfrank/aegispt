from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

TriggerSource = Literal["github", "gitlab", "generic"]


class CicdTriggerUpsert(BaseModel):
    enabled: bool = True
    enabled_profiles: list[str] = Field(default_factory=list)
    branch_filters: list[str] = Field(default_factory=list)
    scope_override_allowed: bool = False
    webhook_secret: str | None = None


class CicdTriggerRead(BaseModel):
    id: UUID | None = None
    engagement_id: UUID
    trigger_source: TriggerSource
    status: str
    configured: bool = False
    enabled_profiles: list[str] = Field(default_factory=list)
    branch_filters: list[str] = Field(default_factory=list)
    scope_override_allowed: bool = False
    webhook_secret_configured: bool = False
    webhook_display_label: str | None = None
    last_triggered_at: datetime | None = None
    last_run_id: UUID | None = None
    last_run_status: str | None = None


class CicdTriggerEventRead(BaseModel):
    id: UUID
    cicd_trigger_id: UUID
    trigger_source: TriggerSource
    profile_name: str | None = None
    ref: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    status: str
    status_detail: str | None = None
    signature_valid: bool = False
    scope_override_applied: bool = False
    override_target_url: str | None = None
    run_id: UUID | None = None
    run_status: str | None = None
    created_at: datetime


class CicdTriggerSettingsRead(BaseModel):
    engagement_id: UUID
    triggers: list[CicdTriggerRead] = Field(default_factory=list)
    history: list[CicdTriggerEventRead] = Field(default_factory=list)


class CicdWebhookPayload(BaseModel):
    engagement_id: UUID
    trigger_source: TriggerSource
    ref: str
    commit_sha: str
    target_url_override: str | None = None
    repository_url: str | None = None
    environment: str | None = None
    metadata_json: dict[str, object] = Field(default_factory=dict)


class CicdWebhookReceiptRead(BaseModel):
    accepted: bool
    engagement_id: UUID
    trigger_source: TriggerSource
    ref: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    event_count: int = 0
    events: list[CicdTriggerEventRead] = Field(default_factory=list)


class CicdEphemeralScanCreate(BaseModel):
    target_url: str
    ref: str | None = None
    commit_sha: str | None = None
    repository_url: str | None = None
    environment: str | None = None
    callback_url: str | None = None
    metadata_json: dict[str, object] = Field(default_factory=dict)


class CicdEphemeralScanRead(BaseModel):
    accepted: bool
    engagement_id: UUID
    run_id: UUID | None = None
    run_status: str | None = None
    profile_name: str
    target_url: str
    ref: str | None = None
    commit_sha: str | None = None
    pass_fail_status: Literal["pending", "pass", "fail", "error"]
    status_url: str | None = None
    callback_url_configured: bool = False
    callback_pending: bool = False
    scope_enforced: bool = True
    approval_required: bool = False
    detail: str
