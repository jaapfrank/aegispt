from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SafeClickDecision = Literal["allow", "review", "block"]
SafeClickSignalSeverity = Literal["info", "low", "medium", "high"]


class SafeClickBoundaryRead(BaseModel):
    live_browsing_performed: bool = False
    arbitrary_public_url_fetch_performed: bool = False
    credential_collection_performed: bool = False
    browser_extension_deployed: bool = False
    runtime_dispatch_performed: bool = False
    deterministic_review_only: bool = True


class SafeClickEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)
    html_fixture: str | None = Field(default=None, max_length=100_000)
    page_title: str | None = Field(default=None, max_length=500)
    visible_text: str | None = Field(default=None, max_length=20_000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SafeClickSignalRead(BaseModel):
    id: str
    label: str
    severity: SafeClickSignalSeverity
    evidence_ref: str
    rationale: str


class SafeClickEvaluationRead(BaseModel):
    decision: SafeClickDecision
    confidence: float = Field(ge=0.0, le=1.0)
    url: str
    normalized_host: str | None
    signals: list[SafeClickSignalRead] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    operator_guidance: str
    boundary: SafeClickBoundaryRead = Field(default_factory=SafeClickBoundaryRead)
