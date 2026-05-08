from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import RationaleLedgerEntry, Run, Scope, TargetContextDocument

CONTEXT_PROFILE_VERSION = "2026-05-08.1"
PHASE0_LAYER_NAME = "phase_0_contextual_profile"
RECURSIVE_CONTEXT_KIND = "recursive_surface_micro_plan"


def ensure_context_document(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any] | None = None,
) -> TargetContextDocument:
    existing = latest_context_document(session, run_id=run.id, layer_name=PHASE0_LAYER_NAME)
    if existing is not None:
        return existing

    return build_context_document(
        session,
        run=run,
        scope=scope,
        targets=targets,
        plan=plan or {},
        layer_name=PHASE0_LAYER_NAME,
        context_kind="phase_0_contextual_profile",
        parent_context_document_id=None,
    )


def latest_context_document(
    session: Session,
    *,
    run_id: uuid.UUID,
    layer_name: str | None = None,
) -> TargetContextDocument | None:
    query = select(TargetContextDocument).where(TargetContextDocument.run_id == run_id)
    if layer_name:
        query = query.where(TargetContextDocument.layer_name == layer_name)
    return session.scalar(
        query.order_by(
            TargetContextDocument.updated_at.desc(),
            TargetContextDocument.created_at.desc(),
            TargetContextDocument.parent_context_document_id.isnot(None).desc(),
            TargetContextDocument.id.desc(),
        )
    )


def build_context_document(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    layer_name: str,
    context_kind: str,
    parent_context_document_id: uuid.UUID | None = None,
    discovered_layer: dict[str, Any] | None = None,
) -> TargetContextDocument:
    inventory = _run_inventory(run)
    signals = _signal_keys(inventory)
    technologies = _technologies_from_context(
        targets=targets,
        inventory=inventory,
        signals=signals,
        discovered_layer=discovered_layer or {},
    )
    endpoints = _endpoints_from_context(
        targets=targets,
        inventory=inventory,
        discovered_layer=discovered_layer or {},
    )
    preferred_tools = _as_list((discovered_layer or {}).get("recommended_tools"))
    recommended_tools = _recommended_tools_from_plan(
        plan,
        targets=targets,
        technologies=technologies,
        endpoints=endpoints,
        signals=signals,
        context_kind=context_kind,
        preferred_tools=preferred_tools,
    )
    micro_plan = _micro_plan(recommended_tools, targets=targets, endpoints=endpoints, signals=signals)
    evidence_refs = _evidence_refs(run=run, inventory=inventory, signals=signals)
    context_summary = _context_summary(
        layer_name=layer_name,
        technologies=technologies,
        endpoints=endpoints,
        recommended_tools=recommended_tools,
    )
    document = TargetContextDocument(
        run_id=run.id,
        parent_context_document_id=parent_context_document_id,
        layer_name=layer_name,
        context_kind=context_kind,
        status="recorded",
        source_targets_json=targets,
        technologies_detected_json=technologies,
        endpoints_discovered_json=endpoints,
        recommended_tools_json=recommended_tools,
        micro_plan_json=micro_plan,
        evidence_refs_json=evidence_refs,
        context_summary=context_summary,
        provenance_json={
            "version": CONTEXT_PROFILE_VERSION,
            "source": "deterministic_ai_contextual_planner",
            "scope_enforced": True,
            "approved_scope_ref": str(scope.id),
            "live_target_actions_performed": False,
            "passive_profile_sources_planned": ["headers", "robots.txt", "sitemap.xml", "javascript manifests"],
            "runner_registry_bypassed": False,
            "approval_gates_bypassed": False,
            "runtime_self_modification": False,
        },
    )
    session.add(document)
    session.flush()
    return document


def generate_sub_plan(
    session: Session,
    *,
    run: Run,
    parent_context: TargetContextDocument,
    layer_name: str,
    discovered_layer: dict[str, Any],
    plan: dict[str, Any] | None = None,
) -> TargetContextDocument:
    targets = _targets_from_discovered_layer(discovered_layer) or parent_context.source_targets_json or []
    return build_context_document(
        session,
        run=run,
        scope=_scope_for_run(session, run),
        targets=targets,
        plan=plan or {},
        layer_name=layer_name,
        context_kind=RECURSIVE_CONTEXT_KIND,
        parent_context_document_id=parent_context.id,
        discovered_layer=discovered_layer,
    )


def ensure_recursive_surface_context(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    parent_context: TargetContextDocument,
    plan: dict[str, Any] | None = None,
) -> TargetContextDocument | None:
    layers = discover_recursive_layers(run=run, parent_context=parent_context)
    if not layers:
        return _latest_child_context(session, parent_context=parent_context)

    existing_children = {
        child.layer_name: child
        for child in session.scalars(
            select(TargetContextDocument).where(
                TargetContextDocument.run_id == run.id,
                TargetContextDocument.parent_context_document_id == parent_context.id,
            )
        )
    }
    for layer in layers:
        layer_name = str(layer.get("layer_name") or "").strip()
        if not layer_name or layer_name in existing_children:
            continue
        return build_context_document(
            session,
            run=run,
            scope=scope,
            targets=_targets_from_discovered_layer(layer) or parent_context.source_targets_json or [],
            plan=plan or {},
            layer_name=layer_name,
            context_kind=RECURSIVE_CONTEXT_KIND,
            parent_context_document_id=parent_context.id,
            discovered_layer=layer,
        )
    return _latest_child_context(session, parent_context=parent_context)


def discover_recursive_layers(
    *,
    run: Run,
    parent_context: TargetContextDocument,
) -> list[dict[str, Any]]:
    inventory = _run_inventory(run)
    stack = _as_dict(inventory.get("tech_stack_profile"))
    profile = _as_dict(inventory.get("signal_profile"))
    signals = _signal_keys(inventory)
    root_targets = {
        str(target.get("value") or "").strip()
        for target in _as_list(parent_context.source_targets_json)
        if isinstance(target, dict)
    }
    layers: list[dict[str, Any]] = []

    def add_layer(kind: str, endpoint: object, technologies: list[str], tools: list[str], evidence_type: str) -> None:
        endpoint_text = _endpoint_text(endpoint)
        if not endpoint_text or endpoint_text in root_targets:
            return
        if _same_url_without_path(endpoint_text, root_targets):
            return
        layers.append(
            {
                "kind": kind,
                "layer_name": f"{kind}_{_stable_layer_suffix(endpoint_text)}",
                "endpoints": [endpoint_text],
                "technologies": technologies,
                "recommended_tools": tools,
                "evidence_refs": [{"type": evidence_type, "endpoint": endpoint_text}],
            }
        )

    for endpoint in _as_list(stack.get("graphql_endpoints")):
        add_layer("graphql", endpoint, ["graphql"], ["graphql-probe"], "tech_stack_profile.graphql_endpoints")
    should_add_api_layers = (
        "api_endpoint_present" in signals
        or (
            "graphql_endpoint" not in signals
            and "login_form_found" not in signals
            and _as_list(stack.get("api_endpoints"))
        )
    )
    if should_add_api_layers:
        for endpoint in _as_list(stack.get("api_endpoints")) + _as_list(stack.get("api_base_urls")):
            add_layer("api", endpoint, ["api"], ["api-assessment", "content-discovery"], "tech_stack_profile.api_endpoints")
    for endpoint in _as_list(stack.get("login_forms")):
        add_layer("auth", endpoint, ["authenticated-web-flow"], ["auth-flow"], "tech_stack_profile.login_forms")
    for endpoint in _as_list(stack.get("file_upload_endpoints")):
        add_layer("upload", endpoint, ["file-upload"], ["content-discovery", "xss-extended"], "tech_stack_profile.file_upload_endpoints")

    for record in _as_list(profile.get("signals")):
        if not isinstance(record, dict):
            continue
        key = str(record.get("key") or "").strip()
        if key == "graphql_endpoint":
            add_layer("graphql", _record_endpoint(record), ["graphql"], ["graphql-probe"], "signal_profile.graphql_endpoint")
        elif key == "api_endpoint_present":
            add_layer("api", _record_endpoint(record), ["api"], ["api-assessment"], "signal_profile.api_endpoint_present")
        elif key == "login_form_found":
            add_layer("auth", _record_endpoint(record), ["authenticated-web-flow"], ["auth-flow"], "signal_profile.login_form_found")
        elif key == "file_upload_endpoint":
            add_layer("upload", _record_endpoint(record), ["file-upload"], ["content-discovery", "xss-extended"], "signal_profile.file_upload_endpoint")

    for layer in _as_list(inventory.get("discovered_layers")):
        if not isinstance(layer, dict):
            continue
        kind = str(layer.get("kind") or "layer").strip() or "layer"
        endpoints = _as_list(layer.get("endpoints"))
        if not endpoints:
            endpoints = _as_list(layer.get("endpoint"))
        technologies = _normalized_strings(_as_list(layer.get("technologies")))
        tools = _normalized_strings(_as_list(layer.get("recommended_tools")))
        for endpoint in endpoints:
            add_layer(kind, endpoint, technologies, tools or ["api-assessment"], "inventory.discovered_layers")

    if "graphql_endpoint" in signals and not any(layer["kind"] == "graphql" for layer in layers):
        for endpoint in _as_list(stack.get("api_endpoints")):
            add_layer("graphql", endpoint, ["graphql"], ["graphql-probe"], "signal_profile.graphql_endpoint")

    return _dedupe_layers(layers)


def record_rationale(
    session: Session,
    *,
    run: Run,
    tool_name: str,
    rationale: str,
    parameters: dict[str, Any],
    context_document: TargetContextDocument | None = None,
    target: str | None = None,
    action_type: str = "tool_dispatch",
    decision_source: dict[str, Any] | None = None,
    task_id: uuid.UUID | None = None,
    agent_proposal_id: uuid.UUID | None = None,
    status: str = "recorded",
) -> RationaleLedgerEntry:
    observed_context = _observed_context_payload(context_document)
    dispatch_contract = _dispatch_contract_payload(
        tool_name=tool_name,
        target=target,
        parameters=parameters,
        action_type=action_type,
    )
    rationale_statement = _rationale_statement(
        context_document=context_document,
        tool_name=tool_name,
        target=target,
        parameters=parameters,
        rationale=rationale,
    )
    decision_payload = {
        **(decision_source or {}),
        "observed_context": observed_context,
        "dispatch_contract": dispatch_contract,
        "rationale_contract": {
            "template": "I observed X in the Context Document, therefore I am dispatching Tool Y with parameters Z.",
            "format_version": CONTEXT_PROFILE_VERSION,
            "recorded_before_queue_or_approval": True,
            "registered_runner_required": True,
            "approval_gates_bypassed": False,
            "immutable_content_fields": [
                "context_document_id",
                "tool_name",
                "target",
                "rationale_text",
                "decision_source_json",
                "parameters_json",
            ],
        },
    }
    entry = RationaleLedgerEntry(
        run_id=run.id,
        context_document_id=context_document.id if context_document is not None else None,
        task_id=task_id,
        agent_proposal_id=agent_proposal_id,
        action_type=action_type,
        tool_name=tool_name,
        target=target,
        rationale_text=rationale_statement,
        decision_source_json=decision_payload,
        parameters_json=parameters,
        status=status,
        provenance_json={
            "version": CONTEXT_PROFILE_VERSION,
            "source": "deterministic_ai_contextual_planner",
            "recorded_before_dispatch": task_id is None and agent_proposal_id is None,
            "rationale_statement_style": "observed_context_therefore_action",
            "registered_runner_required": True,
            "approval_gates_bypassed": False,
            "kill_switch_still_authoritative": True,
        },
    )
    session.add(entry)
    session.flush()
    return entry


def _observed_context_payload(context_document: TargetContextDocument | None) -> dict[str, Any]:
    if context_document is None:
        return {
            "context_document_id": None,
            "summary": "No Context Document was linked to this action.",
            "evidence_refs": [],
            "recommended_tools": [],
            "micro_plan": [],
        }
    return {
        "context_document_id": str(context_document.id),
        "layer_name": context_document.layer_name,
        "context_kind": context_document.context_kind,
        "summary": context_document.context_summary,
        "technologies": list(context_document.technologies_detected_json or []),
        "endpoints": list(context_document.endpoints_discovered_json or []),
        "evidence_refs": list(context_document.evidence_refs_json or []),
        "recommended_tools": list(context_document.recommended_tools_json or []),
        "micro_plan": list(context_document.micro_plan_json or []),
    }


def _dispatch_contract_payload(
    *,
    tool_name: str,
    target: str | None,
    parameters: dict[str, Any],
    action_type: str,
) -> dict[str, Any]:
    tier = str(parameters.get("tier") or "").strip() or "unknown"
    approval_required = tier in {"active", "intrusive"}
    return {
        "action_type": action_type,
        "tool_name": tool_name,
        "target": target,
        "parameters": parameters,
        "tier": tier,
        "dispatch_path": "registered_runner_queue" if not approval_required else "operator_approval_then_registered_runner",
        "approval_required": approval_required,
        "scope_enforced": True,
        "roe_enforced": True,
        "kill_switch_still_authoritative": True,
    }


def _rationale_statement(
    *,
    context_document: TargetContextDocument | None,
    tool_name: str,
    target: str | None,
    parameters: dict[str, Any],
    rationale: str,
) -> str:
    context_id = str(context_document.id) if context_document is not None else "unlinked"
    observation = (
        context_document.context_summary
        if context_document is not None
        else "no linked Context Document; this should be treated as an audit gap"
    )
    parameter_summary = _parameter_summary(parameters)
    planner_reason = str(rationale or "").strip()
    suffix = f" Planner reason: {planner_reason}" if planner_reason else ""
    return (
        f"I observed {observation} in Context Document {context_id}, therefore I am dispatching "
        f"Tool {tool_name} against target {target or 'not recorded'} with parameters {parameter_summary}. "
        "Execution remains bound to the registered runner registry, scope/ROE checks, approval gates, "
        f"and kill switch.{suffix}"
    )


def _parameter_summary(parameters: dict[str, Any]) -> str:
    try:
        text = json.dumps(parameters, sort_keys=True, default=str)
    except TypeError:
        text = str(parameters)
    if len(text) > 700:
        return text[:697] + "..."
    return text


def _latest_child_context(
    session: Session,
    *,
    parent_context: TargetContextDocument,
) -> TargetContextDocument | None:
    return session.scalar(
        select(TargetContextDocument)
        .where(
            TargetContextDocument.run_id == parent_context.run_id,
            TargetContextDocument.parent_context_document_id == parent_context.id,
            TargetContextDocument.context_kind == RECURSIVE_CONTEXT_KIND,
        )
        .order_by(
            TargetContextDocument.updated_at.desc(),
            TargetContextDocument.created_at.desc(),
            TargetContextDocument.id.desc(),
        )
    )


def _scope_for_run(session: Session, run: Run) -> Scope:
    scope = session.scalar(
        select(Scope)
        .where(Scope.engagement_id == run.engagement_id)
        .order_by(Scope.created_at.desc(), Scope.id.desc())
    )
    if scope is None:
        raise ValueError("contextual profiling requires an approved scope record")
    return scope


def _run_inventory(run: Run) -> dict[str, Any]:
    snapshot = run.source_inventory_snapshot
    if snapshot is None:
        return {}
    inventory = snapshot.normalized_inventory_json
    return inventory if isinstance(inventory, dict) else {}


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _normalized_strings(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in normalized:
            normalized.append(text)
    return normalized


def _signal_keys(inventory: dict[str, Any]) -> set[str]:
    profile = _as_dict(inventory.get("signal_profile"))
    signals = set()
    for record in _as_list(profile.get("signals")):
        if not isinstance(record, dict):
            continue
        key = str(record.get("key") or "").strip()
        if key:
            signals.add(key)
    return signals


def _technologies_from_context(
    *,
    targets: list[dict[str, str]],
    inventory: dict[str, Any],
    signals: set[str],
    discovered_layer: dict[str, Any],
) -> list[str]:
    stack = _as_dict(inventory.get("tech_stack_profile"))
    technologies: list[object] = [
        *(_as_list(stack.get("language"))),
        *(_as_list(stack.get("cms"))),
        *(_as_list(stack.get("server"))),
        *(_as_list(stack.get("framework"))),
        *(_as_list(discovered_layer.get("technologies"))),
    ]
    target_values = " ".join(str(target.get("value") or "").lower() for target in targets)
    if any(str(target.get("kind") or "") == "url" for target in targets):
        technologies.append("http")
    if "graphql_endpoint" in signals:
        technologies.append("graphql")
    if "jwt_in_response" in signals or "authorization_bearer_header" in signals:
        technologies.append("jwt")
    if "login_form_found" in signals:
        technologies.append("authenticated-web-flow")
    if "gruyere" in target_values:
        technologies.extend(["python", "google-app-engine"])
    return _normalized_strings(technologies)


def _endpoints_from_context(
    *,
    targets: list[dict[str, str]],
    inventory: dict[str, Any],
    discovered_layer: dict[str, Any],
) -> list[str]:
    stack = _as_dict(inventory.get("tech_stack_profile"))
    endpoints: list[object] = [
        *(_as_list(discovered_layer.get("endpoints"))),
        *(_as_list(stack.get("api_endpoints"))),
        *(_as_list(stack.get("graphql_endpoints"))),
        *(_as_list(stack.get("login_forms"))),
        *(_as_list(stack.get("file_upload_endpoints"))),
    ]
    for target in targets:
        value = str(target.get("value") or "").strip()
        if value:
            endpoints.append(value)
    return _normalized_strings(_endpoint_text(item) for item in endpoints)


def _endpoint_text(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("url") or value.get("endpoint") or value.get("path") or "").strip()
    return str(value or "").strip()


def _record_endpoint(record: dict[str, Any]) -> object:
    for key in ("endpoint", "url", "path", "target"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
    value = record.get("value")
    return value if isinstance(value, str) and value.strip() else None


def _targets_from_discovered_layer(discovered_layer: dict[str, Any]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    for endpoint in _as_list(discovered_layer.get("endpoints")):
        endpoint_text = _endpoint_text(endpoint)
        if endpoint_text:
            targets.append({"kind": "url" if "://" in endpoint_text else "target", "value": endpoint_text})
    return targets


def _same_url_without_path(endpoint: str, root_targets: set[str]) -> bool:
    parsed_endpoint = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
    endpoint_host = parsed_endpoint.hostname or ""
    endpoint_path = parsed_endpoint.path or "/"
    if endpoint_path not in {"", "/"}:
        return False
    for root in root_targets:
        parsed_root = urlparse(root if "://" in root else f"//{root}")
        if endpoint_host and endpoint_host == (parsed_root.hostname or ""):
            return True
    return False


def _stable_layer_suffix(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    text = f"{parsed.hostname or ''}{parsed.path or ''}".strip("/") or value
    chars = [char.lower() if char.isalnum() else "_" for char in text]
    suffix = "".join(chars).strip("_")
    while "__" in suffix:
        suffix = suffix.replace("__", "_")
    return suffix[:80] or "surface"


def _dedupe_layers(layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for layer in layers:
        endpoints = _normalized_strings(layer.get("endpoints") or [])
        if not endpoints:
            continue
        key = (str(layer.get("kind") or ""), endpoints[0])
        if key in seen:
            continue
        seen.add(key)
        layer["endpoints"] = endpoints
        layer["technologies"] = _normalized_strings(layer.get("technologies") or [])
        layer["recommended_tools"] = _normalized_strings(layer.get("recommended_tools") or [])
        deduped.append(layer)
    return deduped


def _recommended_tools_from_plan(
    plan: dict[str, Any],
    *,
    targets: list[dict[str, str]],
    technologies: list[str],
    endpoints: list[str],
    signals: set[str],
    context_kind: str,
    preferred_tools: list[Any],
) -> list[str]:
    recommended: list[str] = []
    recommended.extend(str(tool).strip() for tool in preferred_tools if str(tool or "").strip())
    if context_kind != RECURSIVE_CONTEXT_KIND or not recommended:
        for target in targets:
            kind = str(target.get("kind") or "").strip()
            if kind in {"url", "target"}:
                recommended.append("httpx")
            elif kind in {"host", "cidr"}:
                recommended.append("nmap")
            elif kind == "domain":
                recommended.append("easm-discover")
    for item in _as_list(plan.get("runners")):
        if not isinstance(item, dict):
            continue
        decision = str(item.get("decision") or "").upper()
        runner = str(item.get("runner") or item.get("tool") or "").strip()
        if runner and decision in {"RUN", "NEEDS_APPROVAL"}:
            recommended.append(runner)
    lower_technologies = {item.lower() for item in technologies}
    if endpoints and not recommended:
        recommended.append("httpx")
    if "graphql" in lower_technologies or "graphql_endpoint" in signals:
        recommended.append("graphql-probe")
    if "jwt" in lower_technologies:
        recommended.append("jwt-probe")
    if "login_form_found" in signals or "authenticated-web-flow" in lower_technologies:
        recommended.append("auth-flow")
    if "injectable_parameter" in signals or "sql_error_pattern" in signals:
        recommended.append("sqlmap")
    return _normalized_strings(recommended)


def _micro_plan(
    recommended_tools: list[str],
    *,
    targets: list[dict[str, str]],
    endpoints: list[str],
    signals: set[str],
) -> list[dict[str, Any]]:
    target_values = [str(target.get("value") or "").strip() for target in targets if str(target.get("value") or "").strip()]
    planned_targets = endpoints or target_values
    steps: list[dict[str, Any]] = []
    for index, tool in enumerate(recommended_tools, start=1):
        steps.append(
            {
                "order": index,
                "tool": tool,
                "target_candidates": planned_targets,
                "reason": _tool_reason(tool, signals),
                "execution_contract": "registered_runner_or_existing_approval_flow_only",
            }
        )
    return steps


def _tool_reason(tool: str, signals: set[str]) -> str:
    if tool == "sqlmap":
        return "Use only when injectable-parameter or SQL-error evidence is present."
    if tool == "auth-flow":
        return "Use for approved login/session flow evidence with explicit authorization gates."
    if tool == "graphql-probe":
        return "Use because GraphQL endpoint evidence is present."
    if tool == "jwt-audit":
        return "Use because JWT or bearer-token signals are present."
    if tool == "httpx":
        return "Collect low-impact HTTP fingerprint evidence before active checks."
    return f"Use {tool} because the planner selected it from current evidence signals: {sorted(signals)}."


def _evidence_refs(*, run: Run, inventory: dict[str, Any], signals: set[str]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if run.source_inventory_snapshot_id:
        refs.append({"type": "inventory_snapshot", "id": str(run.source_inventory_snapshot_id)})
    for task in list(run.tasks or []):
        if str(task.status or "").lower() in {"completed", "failed", "skipped"}:
            refs.append({"type": "task", "id": str(task.id), "tool": task.tool, "status": task.status})
    for finding in list(run.findings or []):
        refs.append({"type": "finding", "id": str(finding.id), "target": finding.target_id})
    if signals:
        refs.append({"type": "signal_profile", "keys": sorted(signals)})
    if inventory:
        refs.append({"type": "inventory", "summary": _as_dict(inventory.get("summary"))})
    return refs


def _context_summary(
    *,
    layer_name: str,
    technologies: list[str],
    endpoints: list[str],
    recommended_tools: list[str],
) -> str:
    tech_text = ", ".join(technologies) if technologies else "no specific technology signals"
    endpoint_text = f"{len(endpoints)} endpoint candidate(s)"
    tool_text = ", ".join(recommended_tools) if recommended_tools else "no active runner candidates"
    return (
        f"{layer_name} recorded {tech_text}, {endpoint_text}, and targeted tool plan: {tool_text}. "
        "The plan is advisory and execution remains bound to registered runners and existing approval gates."
    )
