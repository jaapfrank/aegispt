from __future__ import annotations

from typing import Any

REPORT_EXPORT_READY_STATUSES = {"completed"}
REPORT_DRAFT_ONLY_STATUSES = {"completed_with_errors", "failed", "cancelled"}
REPORT_UNAVAILABLE_STATUSES = {"pending_approval", "queued", "running", "cancelling", "rejected"}


def status_counts(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown").strip().lower() or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def report_lifecycle_summary(
    run: Any,
    context: dict[str, object],
    *,
    linked_evidence: int | None = None,
) -> dict[str, object]:
    tasks = list(context.get("tasks") or [])
    findings = list(context.get("findings") or [])
    inventory_summary = context.get("inventory_summary") if isinstance(context.get("inventory_summary"), dict) else {}
    task_statuses = status_counts([str(getattr(task, "status", "")) for task in tasks if hasattr(task, "status")])
    finding_statuses = status_counts(
        [str(getattr(finding, "status", "")) for finding in findings if hasattr(finding, "status")]
    )
    artifact_count = sum(
        len(list(getattr(execution, "artifacts", []) or []))
        for task in tasks
        if hasattr(task, "executions")
        for execution in list(getattr(task, "executions", []) or [])
    )
    test_coverage = context.get("test_coverage") if isinstance(context.get("test_coverage"), dict) else {}
    executed_task_count = int(test_coverage.get("executed_task_count", 0) or 0)
    linked_finding_count = (
        int(linked_evidence)
        if linked_evidence is not None
        else sum(1 for finding in findings if getattr(finding, "evidence_ref", None))
    )
    data_points = {
        "findings": len(findings),
        "linked_findings": linked_finding_count,
        "artifacts": artifact_count,
        "executed_tasks": executed_task_count,
        "hosts": int(inventory_summary.get("host_count", 0) or 0),
        "services": int(inventory_summary.get("service_count", 0) or 0),
        "endpoints": int(inventory_summary.get("endpoint_count", 0) or 0),
    }
    has_report_data = any(value > 0 for value in data_points.values())
    run_status = str(getattr(run, "status", None) or "unknown").strip().lower()
    if run_status in REPORT_UNAVAILABLE_STATUSES:
        lifecycle_state = "in_progress"
    elif run_status in REPORT_DRAFT_ONLY_STATUSES:
        lifecycle_state = "completed_with_gaps" if has_report_data else "failed_no_evidence"
    elif run_status in REPORT_EXPORT_READY_STATUSES and not findings:
        lifecycle_state = "completed_zero_findings"
    elif run_status in REPORT_EXPORT_READY_STATUSES:
        lifecycle_state = "completed_finding_rich"
    else:
        lifecycle_state = "review_required"

    return {
        "run_id": str(getattr(run, "id", "")),
        "run_status": getattr(run, "status", None),
        "lifecycle_state": lifecycle_state,
        "has_report_data": has_report_data,
        "task_count": len(tasks),
        "task_statuses": task_statuses,
        "finding_count": len(findings),
        "finding_statuses": finding_statuses,
        "finding_severities": dict(context.get("findings_by_severity") or {}),
        "evidence": {
            "linked_findings": linked_finding_count,
            "artifact_count": artifact_count,
            "completeness_ratio": linked_finding_count / len(findings) if findings else 0.0,
        },
        "inventory": {
            "host_count": data_points["hosts"],
            "service_count": data_points["services"],
            "endpoint_count": data_points["endpoints"],
        },
        "data_points": data_points,
    }


def report_availability_for_run(
    run: Any,
    context: dict[str, object],
    lifecycle_summary: dict[str, object],
) -> dict[str, object]:
    _ = context
    run_status = str(getattr(run, "status", None) or "unknown").strip().lower()
    has_report_data = bool(lifecycle_summary.get("has_report_data"))
    task_statuses = lifecycle_summary.get("task_statuses") if isinstance(lifecycle_summary.get("task_statuses"), dict) else {}
    failed_tasks = int(task_statuses.get("failed", 0) or 0)
    skipped_tasks = int(task_statuses.get("skipped", 0) or 0)

    if run_status in REPORT_UNAVAILABLE_STATUSES:
        return {
            "status": "unavailable",
            "label": "Unavailable",
            "reason": "This run is not finished yet. Reports unlock after execution stores task, finding, inventory, or artifact evidence.",
            "preview_allowed": False,
            "export_allowed": False,
            "draft_allowed": False,
        }

    if run_status in REPORT_DRAFT_ONLY_STATUSES:
        return {
            "status": "draft_only",
            "label": "Draft only",
            "reason": (
                "The run did not complete cleanly. Draft review is available for stored evidence, "
                "but this should not be treated as a final export-ready report."
            )
            if has_report_data
            else "The run did not complete cleanly and no reportable evidence was recorded.",
            "preview_allowed": has_report_data,
            "export_allowed": False,
            "draft_allowed": has_report_data,
        }

    if failed_tasks or skipped_tasks:
        return {
            "status": "draft_only",
            "label": "Draft only",
            "reason": "The run has recorded task gaps. Review coverage and evidence before treating exports as final.",
            "preview_allowed": has_report_data,
            "export_allowed": False,
            "draft_allowed": has_report_data,
        }

    if run_status == "completed" and has_report_data:
        return {
            "status": "export_ready",
            "label": "Export ready",
            "reason": "The run completed and has stored findings, inventory, tasks, or artifact evidence for the report dossier.",
            "preview_allowed": True,
            "export_allowed": True,
            "draft_allowed": True,
        }

    return {
        "status": "draft_only",
        "label": "Draft only",
        "reason": "The run is terminal but has no stored reportable findings, inventory, task output, or artifacts.",
        "preview_allowed": False,
        "export_allowed": False,
        "draft_allowed": False,
    }
