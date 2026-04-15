from __future__ import annotations

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Approval, Finding, Run, RunProfile, Scope, Task
from api.app.policy.engine import normalize_profile_limits
from workers.runners.httpx.runner import normalize_http_target

TARGET_KEY_MAP = {
    "domains": "domain",
    "urls": "url",
    "paths": "path",
    "cidrs": "cidr",
    "hosts": "host",
    "targets": "target",
}


def required_approvals(profile: RunProfile) -> int:
    normalized_limits = normalize_profile_limits(profile.run_class, profile.limits_json)
    configured = normalized_limits.get("required_approvals")
    return max(configured, 0) if isinstance(configured, int) else 0


def granted_approvals(run: Run, step_id: str = "run.launch") -> int:
    return sum(
        1
        for approval in run.approvals
        if approval.step_id == step_id and approval.decision == "approved"
    )


def pending_approvals(run: Run, profile: RunProfile, step_id: str = "run.launch") -> int:
    if run.status in {"rejected", "cancelled", "cancelling"}:
        return 0
    return max(required_approvals(profile) - granted_approvals(run, step_id=step_id), 0)


def latest_scope_query(engagement_id) -> Select[tuple[Scope]]:
    return (
        select(Scope)
        .where(Scope.engagement_id == engagement_id)
        .order_by(Scope.created_at.desc(), Scope.id.desc())
    )


def derive_targets(scope: Scope) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    for key, kind in TARGET_KEY_MAP.items():
        values = scope.allowlist_json.get(key, [])
        if not isinstance(values, list):
            continue

        for value in values:
            if not isinstance(value, str):
                continue
            normalized = value.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            targets.append({"kind": kind, "value": normalized})

    return targets


def planned_tools(profile: RunProfile) -> list[str]:
    tools = profile.limits_json.get("tools", [])
    if not isinstance(tools, list):
        return []

    normalized_tools = [tool.strip() for tool in tools if isinstance(tool, str) and tool.strip()]
    return normalized_tools


def _target_preference(kind: str) -> int:
    order = {
        "url": 0,
        "host": 1,
        "domain": 2,
        "target": 3,
        "cidr": 4,
    }
    return order.get(kind, len(order))


def planned_targets_for_tool(tool: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    if tool != "zap":
        return list(targets)

    planned_targets: list[dict[str, str]] = []
    planned_indexes: dict[str, int] = {}

    for target in targets:
        normalized_value = normalize_http_target(target["value"])
        existing_index = planned_indexes.get(normalized_value)
        if existing_index is None:
            planned_indexes[normalized_value] = len(planned_targets)
            planned_targets.append(target)
            continue

        existing_target = planned_targets[existing_index]
        if _target_preference(target["kind"]) < _target_preference(existing_target["kind"]):
            planned_targets[existing_index] = target

    return planned_targets


def queue_run_tasks(session: Session, run: Run, scope: Scope, profile: RunProfile) -> list[Task]:
    existing_tasks = session.scalars(
        select(Task).where(Task.run_id == run.id).order_by(Task.tool, Task.target_id)
    ).all()
    if existing_tasks:
        run.status = "queued"
        return list(existing_tasks)

    tasks: list[Task] = []
    targets = derive_targets(scope)
    tools = planned_tools(profile)
    normalized_limits = normalize_profile_limits(profile.run_class, profile.limits_json)

    for tool in tools:
        tool_targets = planned_targets_for_tool(tool, targets)
        if tool == "zap":
            if not tool_targets:
                continue

            target_values = [target["value"] for target in tool_targets]
            task = Task(
                run=run,
                tool=tool,
                target_id=target_values[0],
                status="queued",
                params_json={
                    "target_kind": tool_targets[0]["kind"] if len(tool_targets) == 1 else "multi-target",
                    "targets": target_values,
                    "profile_name": profile.name,
                    "run_class": profile.run_class,
                    "limits": normalized_limits,
                },
            )
            session.add(task)
            tasks.append(task)
            continue

        for target in tool_targets:
            task = Task(
                run=run,
                tool=tool,
                target_id=target["value"],
                status="queued",
                params_json={
                    "target_kind": target["kind"],
                    "profile_name": profile.name,
                    "run_class": profile.run_class,
                    "limits": normalized_limits,
                },
            )
            session.add(task)
            tasks.append(task)

    run.status = "queued"
    return tasks


def load_run(session: Session, run_id) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.profile),
            selectinload(Run.approvals),
            selectinload(Run.tasks),
            selectinload(Run.findings),
        )
        .where(Run.id == run_id)
    )


def sorted_approvals(run: Run) -> list[Approval]:
    return sorted(run.approvals, key=lambda approval: (approval.created_at, approval.id.hex))


def sorted_tasks(run: Run) -> list[Task]:
    return sorted(run.tasks, key=lambda task: (task.tool, task.target_id, task.created_at, task.id.hex))


def sorted_findings(run: Run) -> list[Finding]:
    return sorted(run.findings, key=lambda finding: (finding.severity, finding.title, finding.target_id))


def cancel_run_tasks(run: Run) -> bool:
    if run.status in {"completed", "completed_with_errors", "failed", "rejected", "cancelled"}:
        return False

    changed = False
    has_running_tasks = False

    for task in run.tasks:
        if task.status == "queued":
            task.status = "cancelled"
            changed = True
        elif task.status == "running":
            has_running_tasks = True

    desired_status = "cancelling" if has_running_tasks else "cancelled"
    if run.status != desired_status:
        run.status = desired_status
        changed = True

    return changed
