from __future__ import annotations

import copy
from urllib.parse import urlparse

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Approval, CapabilityPack, Engagement, Finding, Run, RunProfile, Scope, Task
from api.app.policy.engine import normalize_profile_limits
from api.app.services.packs import artifact_refs_for_tool
from workers.runners.httpx.runner import normalize_http_target

TARGET_KEY_MAP = {
    "domains": "domain",
    "subdomains": "domain",
    "urls": "url",
    "api_base_urls": "url",
    "paths": "path",
    "cidrs": "cidr",
    "cidr_ranges": "cidr",
    "hosts": "host",
    "ip_addresses": "host",
    "targets": "target",
}


def align_run_configuration_with_engagement(
    configuration: dict[str, object] | None,
    *,
    engagement: Engagement,
) -> dict[str, object]:
    payload = copy.deepcopy(configuration or {})
    intake = payload.get("intake")
    if not isinstance(intake, dict):
        return payload

    engagement_context = intake.get("engagement_context")
    if not isinstance(engagement_context, dict):
        return payload

    normalized_context = dict(engagement_context)
    normalized_context["engagement_id"] = str(engagement.id)
    normalized_context["engagement_name"] = (
        str(normalized_context.get("engagement_name") or "").strip() or engagement.name
    )

    if not str(normalized_context.get("client") or "").strip() and engagement.client:
        normalized_context["client"] = engagement.client
    if not str(normalized_context.get("roe_ref") or "").strip() and engagement.roe_ref:
        normalized_context["roe_ref"] = engagement.roe_ref

    intake["engagement_context"] = normalized_context
    return payload


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
    return derive_targets_from_target_map(scope.allowlist_json)


def derive_targets_from_target_map(target_map: dict[str, object] | None) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    for key, kind in TARGET_KEY_MAP.items():
        values = (target_map or {}).get(key, [])
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


def derive_targets_for_run(scope: Scope, run: Run) -> list[dict[str, str]]:
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    configured_targets = configuration.get("targets", {})
    if isinstance(configured_targets, dict):
        derived = derive_targets_from_target_map(configured_targets)
        if derived:
            return derived
    return derive_targets(scope)


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
    if tool == "nmap":
        return [
            target
            for target in targets
            if target["kind"] in {"host", "cidr", "domain", "target"}
        ]

    if tool == "nuclei":
        url_targets = [target for target in targets if target["kind"] == "url"]
        if url_targets:
            return list(url_targets)
        return [
            target
            for target in targets
            if target["kind"] in {"host", "domain", "target"}
        ]

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
    targets = derive_targets_for_run(scope, run)
    tools = planned_tools(profile)
    normalized_limits = normalize_profile_limits(profile.run_class, profile.limits_json)
    pack: CapabilityPack | None = None
    if run.bound_pack_id is not None:
        pack = session.scalar(
            select(CapabilityPack)
            .options(selectinload(CapabilityPack.artifacts))
            .where(CapabilityPack.id == run.bound_pack_id)
        )

    for tool in tools:
        tool_targets = planned_targets_for_tool(tool, targets)
        pack_metadata = None
        if pack is not None:
            pack_metadata = {
                "pack_id": str(pack.id),
                "version": pack.version,
                "deployment_id": str(run.bound_pack_deployment_id) if run.bound_pack_deployment_id else None,
                "methodology_tags": list(pack.methodology_tags),
                "source_inventory_snapshot_id": (
                    str(pack.source_inventory_snapshot_id) if pack.source_inventory_snapshot_id else None
                ),
                "relevance_decision_id": str(pack.relevance_decision_id) if pack.relevance_decision_id else None,
                "artifact_refs": artifact_refs_for_tool(pack, tool),
            }
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
                    **({"capability_pack": pack_metadata} if pack_metadata is not None else {}),
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
                    **({"capability_pack": pack_metadata} if pack_metadata is not None else {}),
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
            selectinload(Run.bound_pack).selectinload(CapabilityPack.artifacts),
            selectinload(Run.bound_pack_deployment),
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
