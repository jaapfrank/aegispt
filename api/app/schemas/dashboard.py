from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class DashboardActiveRunRead(BaseModel):
    id: UUID
    engagement_id: UUID
    engagement_name: str
    profile_name: str
    status: str
    phase_label: str
    phase_progress_label: str
    tasks_total: int
    tasks_running: int
    tasks_completed: int
    finding_count: int
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    updated_at: datetime


class DashboardRiskHistoryPointRead(BaseModel):
    run_id: UUID | None = None
    score: float
    trend: str = "stable"
    computed_at: datetime


class DashboardRiskScoreRead(BaseModel):
    score: float
    trend: str
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    history: list[DashboardRiskHistoryPointRead] = Field(default_factory=list)
    advisory_note: str


class DashboardOpenProblemsRead(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    total: int = 0
    overdue_critical_count: int = 0
    overdue_high_count: int = 0


class DashboardUpcomingScanRead(BaseModel):
    id: UUID
    engagement_id: UUID
    engagement_name: str
    profile_name: str
    cadence: str
    status: str
    next_run_at: datetime
    eta_label: str


class DashboardRecentActivityRead(BaseModel):
    id: str
    activity_type: str
    label: str
    detail: str
    happened_at: datetime
    engagement_id: UUID | None = None
    engagement_name: str | None = None
    run_id: UUID | None = None
    finding_id: UUID | None = None
    severity: str | None = None
    status: str | None = None


class DashboardActivityFeedItemRead(BaseModel):
    id: str
    timestamp: datetime
    label: str
    icon: str
    engagement_name: str | None = None
    detail: str | None = None


class DashboardQuickActionRead(BaseModel):
    id: str
    label: str
    target_screen: str
    enabled: bool = True
    description: str | None = None


class DashboardSetupChecklistItemRead(BaseModel):
    id: str
    label: str
    done: bool
    detail: str


class DashboardFirstRunOnboardingCardRead(BaseModel):
    id: str
    label: str
    done: bool = False
    detail: str
    target_screen: str | None = None


class DashboardFirstRunOnboardingRead(BaseModel):
    show: bool = False
    title: str
    detail: str
    cards: list[DashboardFirstRunOnboardingCardRead] = Field(default_factory=list)


class DashboardEngagementSummaryRead(BaseModel):
    id: UUID
    name: str
    client: str | None = None
    last_run_at: datetime | None = None
    last_run_status: str | None = None
    risk_score: float
    open_critical_count: int
    open_high_count: int
    run_count: int


class DashboardRead(BaseModel):
    generated_at: datetime
    has_engagements: bool
    active_run: DashboardActiveRunRead | None = None
    risk_score: DashboardRiskScoreRead
    open_problems: DashboardOpenProblemsRead
    upcoming_scans: list[DashboardUpcomingScanRead] = Field(default_factory=list)
    recent_activity: list[DashboardRecentActivityRead] = Field(default_factory=list)
    activity_feed: list[DashboardActivityFeedItemRead] = Field(default_factory=list)
    quick_actions: list[DashboardQuickActionRead] = Field(default_factory=list)
    setup_checklist_dismissed: bool = False
    setup_checklist: list[DashboardSetupChecklistItemRead] = Field(default_factory=list)
    first_run_onboarding: DashboardFirstRunOnboardingRead | None = None
    engagements: list[DashboardEngagementSummaryRead] = Field(default_factory=list)
