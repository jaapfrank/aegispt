from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SettingOption(BaseModel):
    value: str
    label: str


class SettingRead(BaseModel):
    key: str
    label: str
    value: Any = None
    input_type: str = "text"
    source: str
    sensitive: bool = False
    configured: bool = False
    masked_value: str | None = None
    read_only: bool = False
    description: str | None = None
    options: list[SettingOption] = Field(default_factory=list)
    ui_hidden: bool = False
    min_value: float | None = None
    max_value: float | None = None
    step: float | None = None
    placeholder: str | None = None


class SettingsSectionRead(BaseModel):
    id: str
    title: str
    description: str
    settings: list[SettingRead]


class SettingsRead(BaseModel):
    tenant_id: str
    sections: list[SettingsSectionRead]
    sensitive_plaintext_exposed: bool = False


class SettingsPatch(BaseModel):
    settings: dict[str, Any] = Field(default_factory=dict)


class ToolReadinessRead(BaseModel):
    id: str
    title: str
    binary_names: list[str] = Field(default_factory=list)
    required_binary_groups: list[list[str]] = Field(default_factory=list)
    missing_binaries: list[str] = Field(default_factory=list)
    required: bool = True
    installed: bool = False
    detected_path: str | None = None
    detected_paths: dict[str, str] = Field(default_factory=dict)
    status: str
    affected_assessment_families: list[str] = Field(default_factory=list)
    operator_next_step: str
    install_command: str | None = None
    repair_command: str | None = None
    repair_action_label: str | None = None
    repair_action_kind: str = "copy_command"
    software_installable: bool = True
    hardware_required: bool = False


class ReadinessCapabilityRead(BaseModel):
    id: str
    title: str
    status: str
    summary: str
    details: list[str] = Field(default_factory=list)
    operator_next_step: str
    affected_assessment_families: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SettingsReadinessRead(BaseModel):
    tenant_id: str
    generated_at: datetime
    overall_status: str
    capabilities: list[ReadinessCapabilityRead]
    tools: list[ToolReadinessRead]
    artifact: dict[str, Any] = Field(default_factory=dict)
