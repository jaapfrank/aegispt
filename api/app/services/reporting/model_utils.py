from __future__ import annotations

from collections import Counter
from typing import Any
from uuid import UUID

FINDING_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def sort_findings(findings: list[Any]) -> list[Any]:
    return sorted(
        findings,
        key=lambda finding: (
            FINDING_SEVERITY_ORDER.get(getattr(finding, "severity", None), FINDING_SEVERITY_ORDER["unknown"]),
            str(getattr(finding, "title", "")).lower(),
            str(getattr(finding, "target_id", "")).lower(),
        ),
    )


def sort_tasks(tasks: list[Any]) -> list[Any]:
    return sorted(tasks, key=lambda task: (task.tool, task.target_id, task.created_at, task.id.hex))


def sort_approvals(approvals: list[Any]) -> list[Any]:
    return sorted(approvals, key=lambda approval: (approval.created_at, approval.id.hex))


def sort_artifacts(artifacts: list[Any]) -> list[Any]:
    return sorted(
        artifacts,
        key=lambda artifact: (
            str(artifact.metadata_json.get("name", "")),
            artifact.created_at,
            artifact.id.hex,
        ),
    )


def artifact_download_path(artifact_id: UUID) -> str:
    return f"/api/v1/artifacts/{artifact_id}/content"


def task_targets_display(task: Any) -> str:
    configured_targets = task.params_json.get("targets")
    if isinstance(configured_targets, list):
        normalized_targets = [target.strip() for target in configured_targets if isinstance(target, str) and target.strip()]
        if normalized_targets:
            return ", ".join(normalized_targets)

    return task.target_id


def findings_summary(findings: list[Any]) -> tuple[dict[str, int], dict[str, int]]:
    by_severity = dict(Counter(finding.severity for finding in findings))
    by_status = dict(Counter(finding.status for finding in findings))
    return by_severity, by_status


def latest_scope_for_engagement(engagement: Any | None) -> Any | None:
    if engagement is None:
        return None
    if not engagement.scopes:
        return None
    return sorted(engagement.scopes, key=lambda scope: (scope.created_at, scope.id.hex), reverse=True)[0]
