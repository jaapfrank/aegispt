from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class McpResourceRead(BaseModel):
    name: str
    uri_template: str
    description: str
    fields: list[str] = Field(default_factory=list)
    read_only: bool = True


class McpResourcesRead(BaseModel):
    interface: str
    read_only: bool
    resources: list[McpResourceRead] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    disabled_actions: list[str] = Field(default_factory=list)
    write_methods_allowed: list[str] = Field(default_factory=list)
    secret_policy: str
    safety_notes: list[str] = Field(default_factory=list)


class McpOperatorContextRead(BaseModel):
    interface: str
    read_only: bool
    actor: str
    resource_allowlist: list[str] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    disabled_actions: list[str] = Field(default_factory=list)
    write_methods_allowed: list[str] = Field(default_factory=list)
    engagement: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)
    selected_run: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    reports: list[dict[str, Any]] = Field(default_factory=list)
    packs: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    safety: dict[str, Any] = Field(default_factory=dict)


class McpToolRead(BaseModel):
    name: str
    title: str
    description: str
    status: str
    state_changing: bool = False
    confirmation_required: bool = False
    operator_review_required: bool = True
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_contract: dict[str, Any] = Field(default_factory=dict)
    safety_notes: list[str] = Field(default_factory=list)


class McpToolsRead(BaseModel):
    interface: str
    read_only_context_interface: str
    action_tools_enabled: bool
    tools: list[McpToolRead] = Field(default_factory=list)
    disabled_actions: list[str] = Field(default_factory=list)
    write_methods_allowed: list[str] = Field(default_factory=list)
    secret_policy: str
    safety_notes: list[str] = Field(default_factory=list)


class McpToolConfirmation(BaseModel):
    confirmed: bool = False
    statement: str | None = Field(default=None, max_length=500)


class McpToolInvocationRequest(BaseModel):
    engagement_id: UUID | None = None
    finding_id: UUID | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    confirmation: McpToolConfirmation | None = None


class McpToolInvocationRead(BaseModel):
    tool_name: str
    status: str
    state_changed: bool = False
    domain_state_changed: bool = False
    audit_recorded: bool = False
    audit_event_id: UUID | None = None
    confirmation_required: bool = False
    operator_review_required: bool = True
    result: dict[str, Any] = Field(default_factory=dict)
    safety: dict[str, Any] = Field(default_factory=dict)
