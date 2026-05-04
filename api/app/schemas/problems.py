from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

ProblemStatus = Literal["open", "in_progress", "resolved", "verified", "reoccurred"]
ProblemBulkAction = Literal["assign", "status", "resolve", "schedule_retest", "delete"]


class ProblemLifecycleStepRead(BaseModel):
    key: str
    label: str
    state: Literal["done", "current", "pending", "warning"] = "pending"


class ProblemEngagementOptionRead(BaseModel):
    id: UUID
    name: str


class ProblemFilterOptionsRead(BaseModel):
    engagements: list[ProblemEngagementOptionRead] = Field(default_factory=list)
    assignees: list[str] = Field(default_factory=list)
    methodologies: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    age_buckets: list[str] = Field(default_factory=list)


class ProblemRead(BaseModel):
    id: UUID
    finding_id: UUID
    run_id: UUID
    engagement_id: UUID
    engagement_name: str
    title: str
    severity: str
    target_id: str
    status: str
    problem_status: ProblemStatus
    assignee: str | None = None
    days_open: int
    age_bucket: str
    remediation_state: str
    verification_status: str
    methodology_tags: list[str] = Field(default_factory=list)
    latest_retest_run_id: UUID | None = None
    latest_retest_status: str | None = None
    lifecycle: list[ProblemLifecycleStepRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ProblemsStatsRead(BaseModel):
    open_critical: int = 0
    open_high: int = 0
    open_medium: int = 0
    avg_days_to_resolve_30d: float = 0.0
    resolved_this_week: int = 0
    total_findings: int = 0
    total_filtered: int = 0
    total_open: int = 0
    total_in_progress: int = 0
    total_resolved: int = 0
    total_verified: int = 0
    total_false_positive: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_problem_status: dict[str, int] = Field(default_factory=dict)
    by_finding_status: dict[str, int] = Field(default_factory=dict)
    total_recently_resolved: int = 0


class ProblemsRead(BaseModel):
    generated_at: datetime
    items: list[ProblemRead] = Field(default_factory=list)
    recently_resolved: list[ProblemRead] = Field(default_factory=list)
    stats: ProblemsStatsRead
    filters: ProblemFilterOptionsRead
    lifecycle_summary: dict[str, object] = Field(default_factory=dict)
    next_cursor: str | None = None


class ProblemBulkUpdateCreate(BaseModel):
    finding_ids: list[UUID] = Field(min_length=1, max_length=200)
    action: ProblemBulkAction
    status: ProblemStatus | None = None
    assignee: str | None = Field(default=None, max_length=255)
    retest_notes: str | None = None

    @field_validator("assignee")
    @classmethod
    def normalize_assignee(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class ProblemBulkSkippedRead(BaseModel):
    finding_id: UUID
    reason: str


class ProblemBulkUpdateRead(BaseModel):
    action: ProblemBulkAction
    requested_count: int
    updated_count: int
    retest_run_ids: list[UUID] = Field(default_factory=list)
    skipped: list[ProblemBulkSkippedRead] = Field(default_factory=list)
    message: str
