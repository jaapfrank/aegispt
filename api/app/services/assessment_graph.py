from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import (
    AgentProposal,
    Approval,
    EvidenceArtifact,
    Finding,
    FindingChain,
    InventorySnapshot,
    RationaleLedgerEntry,
    Run,
    Scope,
    SecretRef,
    TargetContextDocument,
    Task,
    ToolExecution,
)
from api.app.services.reports import report_context_for_run
from api.app.services.runner_registry import runner_capability_registry

ASSESSMENT_GRAPH_VERSION = "assessment-knowledge-graph-v1"
HYPOTHESIS_ENGINE_VERSION = "assessment-hypothesis-engine-v1"
NORMALIZED_EVIDENCE_GRAPH_VERSION = "normalized-evidence-graph-v1"
OBSERVED_SCOPE_PREREQUISITE = "approved_scope"


def build_assessment_graph(
    session: Session,
    *,
    run: Run | None = None,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    assessment_run = _load_run(session, run=run, run_id=run_id)
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    graph_run_id = _node_id("run", assessment_run.id)
    _add_node(
        nodes,
        kind="run",
        source_id=assessment_run.id,
        label=f"Run {assessment_run.id}",
        data={
            "status": assessment_run.status,
            "profile_name": assessment_run.profile.name if assessment_run.profile else None,
            "run_mode": _safe_dict(assessment_run.configuration_json).get("run_mode"),
            "autonomous_mode": assessment_run.autonomous_mode,
            "autonomous_intrusive_allowed": assessment_run.autonomous_intrusive_allowed,
            "source_inventory_snapshot_id": _string_or_none(
                assessment_run.source_inventory_snapshot_id
            ),
            "created_at": _iso(assessment_run.created_at),
            "started_at": _iso(assessment_run.started_at),
        },
    )

    scope = _latest_scope(assessment_run)
    if scope is not None:
        scope_id = _add_scope_node(nodes, scope)
        _add_edge(
            edges,
            source=scope_id,
            target=graph_run_id,
            relationship="authorizes_run_scope",
            evidence="latest engagement scope record",
        )

    inventory_snapshots = _inventory_snapshots_for_run(assessment_run)
    for snapshot in inventory_snapshots:
        snapshot_id = _add_inventory_snapshot_node(nodes, snapshot)
        _add_edge(
            edges,
            source=graph_run_id,
            target=snapshot_id,
            relationship="uses_inventory_snapshot",
            evidence="run inventory provenance",
        )
        for inventory_node_id in _add_inventory_item_nodes(nodes, snapshot):
            _add_edge(
                edges,
                source=snapshot_id,
                target=inventory_node_id,
                relationship="contains_inventory_node",
                evidence="normalized inventory",
            )

    report_context = report_context_for_run(assessment_run, session=session)
    report_node_id = _add_report_evidence_node(nodes, assessment_run, report_context)
    _add_edge(
        edges,
        source=report_node_id,
        target=graph_run_id,
        relationship="summarizes_run_evidence",
        evidence="report context",
    )

    task_ids_by_model_id: dict[str, str] = {}
    execution_ids_by_model_id: dict[str, str] = {}
    artifact_refs: dict[str, str] = {}
    runner_tools: set[str] = set()

    for task in sorted(list(assessment_run.tasks or []), key=lambda item: (item.created_at, item.id)):
        task_node_id = _add_task_node(nodes, task)
        task_ids_by_model_id[str(task.id)] = task_node_id
        runner_tools.add(task.tool)
        _add_edge(edges, source=graph_run_id, target=task_node_id, relationship="has_task")
        _add_edge(edges, source=task_node_id, target=_runner_node_id(task.tool), relationship="uses_runner")
        if task.source_finding_id is not None:
            _add_edge(
                edges,
                source=task_node_id,
                target=_node_id("finding", task.source_finding_id),
                relationship="validates_source_finding",
            )
        for execution in sorted(list(task.executions or []), key=lambda item: (item.created_at, item.id)):
            execution_node_id = _add_execution_node(nodes, execution)
            execution_ids_by_model_id[str(execution.id)] = execution_node_id
            _add_edge(edges, source=task_node_id, target=execution_node_id, relationship="produced_execution")
            for artifact in sorted(list(execution.artifacts or []), key=lambda item: (item.created_at, item.id)):
                artifact_node_id = _add_artifact_node(nodes, artifact)
                _index_artifact_refs(artifact_refs, artifact, artifact_node_id)
                _add_edge(
                    edges,
                    source=execution_node_id,
                    target=artifact_node_id,
                    relationship="produced_artifact",
                )
                _add_edge(
                    edges,
                    source=report_node_id,
                    target=artifact_node_id,
                    relationship="reports_evidence_artifact",
                )

    for finding in sorted(list(assessment_run.findings or []), key=lambda item: (item.severity, item.title, item.id)):
        finding_node_id = _add_finding_node(nodes, finding)
        _add_edge(edges, source=graph_run_id, target=finding_node_id, relationship="has_finding")
        _add_edge(
            edges,
            source=report_node_id,
            target=finding_node_id,
            relationship="reports_finding",
        )
        if finding.source_inventory_snapshot_id is not None:
            _add_edge(
                edges,
                source=finding_node_id,
                target=_node_id("inventory_snapshot", finding.source_inventory_snapshot_id),
                relationship="observed_from_inventory_snapshot",
            )
        evidence_node_id = artifact_refs.get(str(finding.evidence_ref or "").strip())
        if evidence_node_id:
            _add_edge(
                edges,
                source=finding_node_id,
                target=evidence_node_id,
                relationship="supported_by_artifact",
                evidence=finding.evidence_ref,
            )

    for approval in sorted(list(assessment_run.approvals or []), key=lambda item: (item.created_at, item.id)):
        approval_node_id = _add_approval_node(nodes, approval)
        _add_edge(edges, source=graph_run_id, target=approval_node_id, relationship="has_approval")
        _add_edge(
            edges,
            source=report_node_id,
            target=approval_node_id,
            relationship="reports_approval",
        )

    for context in sorted(
        list(assessment_run.context_documents or []),
        key=lambda item: (item.created_at, item.id),
    ):
        context_node_id = _add_context_node(nodes, context)
        runner_tools.update(_safe_list(context.recommended_tools_json))
        _add_edge(edges, source=graph_run_id, target=context_node_id, relationship="has_context_document")
        if context.parent_context_document_id is not None:
            _add_edge(
                edges,
                source=_node_id("context_document", context.parent_context_document_id),
                target=context_node_id,
                relationship="has_recursive_context",
            )
        for evidence_ref in _context_evidence_refs(context):
            linked_artifact_id = artifact_refs.get(evidence_ref)
            if linked_artifact_id:
                _add_edge(
                    edges,
                    source=context_node_id,
                    target=linked_artifact_id,
                    relationship="context_uses_artifact",
                    evidence=evidence_ref,
                )
        for tool_name in _safe_list(context.recommended_tools_json):
            _add_edge(
                edges,
                source=context_node_id,
                target=_runner_node_id(tool_name),
                relationship="recommends_runner",
            )

    for proposal in sorted(
        list(assessment_run.agent_proposals or []),
        key=lambda item: (item.priority, item.created_at, item.id),
    ):
        proposal_node_id = _add_proposal_node(nodes, proposal)
        runner_tools.add(proposal.proposed_tool)
        _add_edge(edges, source=graph_run_id, target=proposal_node_id, relationship="has_agent_proposal")
        _add_edge(
            edges,
            source=proposal_node_id,
            target=_runner_node_id(proposal.proposed_tool),
            relationship="proposes_runner",
        )

    for entry in sorted(
        list(assessment_run.rationale_ledger_entries or []),
        key=lambda item: (item.created_at, item.id),
    ):
        rationale_node_id = _add_rationale_node(nodes, entry)
        runner_tools.add(entry.tool_name)
        _add_edge(edges, source=graph_run_id, target=rationale_node_id, relationship="has_rationale_entry")
        _add_edge(
            edges,
            source=report_node_id,
            target=rationale_node_id,
            relationship="reports_rationale_entry",
        )
        _add_edge(
            edges,
            source=rationale_node_id,
            target=_runner_node_id(entry.tool_name),
            relationship="rationale_selects_runner",
        )
        if entry.context_document_id is not None:
            _add_edge(
                edges,
                source=rationale_node_id,
                target=_node_id("context_document", entry.context_document_id),
                relationship="rationale_observed_context",
            )
        if entry.task_id is not None:
            _add_edge(
                edges,
                source=rationale_node_id,
                target=task_ids_by_model_id.get(str(entry.task_id), _node_id("task", entry.task_id)),
                relationship="rationale_dispatches_task",
            )
        if entry.agent_proposal_id is not None:
            _add_edge(
                edges,
                source=rationale_node_id,
                target=_node_id("agent_proposal", entry.agent_proposal_id),
                relationship="rationale_links_proposal",
            )

    for chain in sorted(list(assessment_run.finding_chains or []), key=lambda item: (item.pattern_id, item.id)):
        chain_node_id = _add_finding_chain_node(nodes, chain)
        _add_edge(edges, source=graph_run_id, target=chain_node_id, relationship="has_finding_chain")
        for finding_id in _safe_list(chain.component_finding_ids_json):
            _add_edge(
                edges,
                source=chain_node_id,
                target=_node_id("finding", finding_id),
                relationship="chains_finding",
            )

    _add_runner_nodes(nodes, runner_tools)

    return {
        "graph_version": ASSESSMENT_GRAPH_VERSION,
        "run_id": str(assessment_run.id),
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "mutates_approvals": False,
            "mutates_scope": False,
            "runtime_self_modification": False,
            "runner_registry_bypassed": False,
            "claims_unobserved_impact": False,
        },
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges.values(), key=lambda item: (item["source"], item["relationship"], item["target"])),
    }


def build_assessment_hypotheses(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = {node["id"]: node for node in graph.get("nodes", []) if isinstance(node, dict)}
    edges = [edge for edge in graph.get("edges", []) if isinstance(edge, dict)]
    runner_nodes = {
        node_id: node
        for node_id, node in nodes.items()
        if node.get("kind") == "runner_metadata"
    }
    observed_prerequisites = _observed_prerequisites(nodes)

    hypotheses: list[dict[str, Any]] = []
    for finding in sorted(
        (node for node in nodes.values() if node.get("kind") == "finding"),
        key=lambda item: item["id"],
    ):
        data = _safe_dict(finding.get("data"))
        if str(data.get("status") or "").lower() in {"resolved", "false_positive"}:
            continue
        evidence_node_ids = _evidence_sources_for_node(finding["id"], nodes, edges)
        candidates = _candidate_runner_observations(finding, evidence_node_ids, nodes, edges, runner_nodes)
        if not candidates:
            continue
        missing = _missing_prerequisites(candidates, runner_nodes, observed_prerequisites)
        hypotheses.append(
            {
                "id": f"hypothesis:{finding['id']}:next-observation",
                "hypothesis_version": HYPOTHESIS_ENGINE_VERSION,
                "finding_node_id": finding["id"],
                "source_ids": evidence_node_ids,
                "observed_evidence": {
                    "finding_title": data.get("title"),
                    "severity": data.get("severity"),
                    "status": data.get("status"),
                    "evidence_ref": data.get("evidence_ref"),
                    "source_node_ids": evidence_node_ids,
                },
                "inferred_next_question": (
                    "Which registered runner can safely collect the next observation for this "
                    "evidence-backed finding?"
                ),
                "safe_next_observation_candidates": candidates,
                "missing_prerequisites": missing,
                "confidence": _hypothesis_confidence(data, evidence_node_ids),
                "claims_unobserved_impact": False,
                "unsupported_claims": [],
            }
        )

    return {
        "hypothesis_engine_version": HYPOTHESIS_ENGINE_VERSION,
        "graph_version": graph.get("graph_version"),
        "run_id": graph.get("run_id"),
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "mutates_approvals": False,
            "mutates_scope": False,
            "runtime_self_modification": False,
            "claims_unobserved_impact": False,
        },
        "hypotheses": hypotheses,
    }


def build_assessment_graph_with_hypotheses(
    session: Session,
    *,
    run: Run | None = None,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    graph = build_assessment_graph(session, run=run, run_id=run_id)
    return {**graph, "hypothesis_report": build_assessment_hypotheses(graph)}


def build_normalized_evidence_graph(
    session: Session,
    *,
    run: Run | None = None,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    assessment_run = _load_run(session, run=run, run_id=run_id)
    source_graph = build_assessment_graph(session, run=assessment_run)
    normalized_nodes: dict[str, dict[str, Any]] = {}
    normalized_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    source_node_map: dict[str, str] = {}

    for node in source_graph.get("nodes", []):
        if not isinstance(node, dict):
            continue
        normalized_node = _normalize_source_graph_node(node)
        if normalized_node is None:
            continue
        _merge_normalized_node(normalized_nodes, normalized_node)
        source_node_map[str(node["id"])] = normalized_node["id"]

    for node in _run_vault_credential_nodes(session, assessment_run):
        _merge_normalized_node(normalized_nodes, node)

    for node in _inventory_semantic_nodes(assessment_run):
        _merge_normalized_node(normalized_nodes, node)

    run_node_id = _normalized_node_id("run", str(assessment_run.id))
    for node_id, node in sorted(normalized_nodes.items()):
        if node_id == run_node_id:
            continue
        node_type = str(node.get("type") or "")
        if node_type in {"asset", "api", "identity", "saas_connector", "permission", "credential_ref"}:
            _add_normalized_edge(
                normalized_edges,
                source=run_node_id,
                target=node_id,
                relationship=f"has_{node_type}",
                confidence=_node_confidence(node),
                evidence_refs=_safe_list(node.get("evidence_refs")),
                provenance={
                    "source": "normalized_run_evidence",
                    "source_ids": [str(assessment_run.id), *list(node.get("source_ids") or [])],
                    "reason": f"Existing run evidence contains normalized {node_type} data.",
                },
            )

    for edge in source_graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source_id = source_node_map.get(str(edge.get("source")))
        target_id = source_node_map.get(str(edge.get("target")))
        if not source_id or not target_id:
            continue
        _add_normalized_edge(
            normalized_edges,
            source=source_id,
            target=target_id,
            relationship=str(edge.get("relationship") or "related_to"),
            confidence=_edge_confidence(edge, normalized_nodes.get(source_id), normalized_nodes.get(target_id)),
            evidence_refs=_edge_evidence_refs(edge, normalized_nodes.get(source_id), normalized_nodes.get(target_id)),
            provenance={
                "source": "assessment_graph_edge",
                "source_edge_id": str(edge.get("id") or ""),
                "source_ids": [str(edge.get("source") or ""), str(edge.get("target") or "")],
                "source_relationship": str(edge.get("relationship") or ""),
            },
        )

    return {
        "graph_version": NORMALIZED_EVIDENCE_GRAPH_VERSION,
        "source_graph_version": source_graph.get("graph_version"),
        "run_id": str(assessment_run.id),
        "summary": {
            "node_count": len(normalized_nodes),
            "edge_count": len(normalized_edges),
            "node_types": sorted({str(node.get("type")) for node in normalized_nodes.values()}),
            "edge_relationships": sorted({str(edge.get("relationship")) for edge in normalized_edges.values()}),
        },
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "creates_tasks": False,
            "approves_proposals": False,
            "mutates_approvals": False,
            "mutates_scope": False,
            "materializes_secrets": False,
            "accesses_live_targets": False,
            "runtime_self_modification": False,
        },
        "nodes": sorted(normalized_nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(
            normalized_edges.values(),
            key=lambda item: (item["source"], item["relationship"], item["target"]),
        ),
    }


def _load_run(session: Session, *, run: Run | None, run_id: UUID | str | None) -> Run:
    if run is not None:
        return run
    if run_id is None:
        raise ValueError("run or run_id is required")
    loaded = session.get(Run, UUID(str(run_id)))
    if loaded is None:
        raise ValueError(f"run not found: {run_id}")
    return loaded


def _node_id(kind: str, source_id: UUID | str) -> str:
    return f"{kind}:{source_id}"


def _runner_node_id(tool_name: str) -> str:
    return _node_id("runner_metadata", tool_name)


def _normalized_node_id(node_type: str, source_id: str) -> str:
    return f"normalized:{node_type}:{_slug(source_id)}"


def _add_node(
    nodes: dict[str, dict[str, Any]],
    *,
    kind: str,
    source_id: UUID | str,
    label: str,
    data: dict[str, Any] | None = None,
) -> str:
    node_id = _node_id(kind, source_id)
    nodes[node_id] = {
        "id": node_id,
        "kind": kind,
        "source_id": str(source_id),
        "label": label,
        "data": data or {},
    }
    return node_id


def _add_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    *,
    source: str,
    target: str,
    relationship: str,
    evidence: str | None = None,
) -> None:
    key = (source, relationship, target)
    edge = {
        "id": f"edge:{source}:{relationship}:{target}",
        "source": source,
        "target": target,
        "relationship": relationship,
    }
    if evidence:
        edge["evidence"] = evidence
    edges[key] = edge


def _merge_normalized_node(
    nodes: dict[str, dict[str, Any]],
    node: dict[str, Any],
) -> None:
    node_id = str(node["id"])
    existing = nodes.get(node_id)
    if existing is None:
        node["source_ids"] = sorted(set(str(item) for item in _safe_list(node.get("source_ids")) if str(item)))
        node["evidence_refs"] = sorted(set(str(item) for item in _safe_list(node.get("evidence_refs")) if str(item)))
        nodes[node_id] = node
        return
    existing["source_ids"] = sorted(
        set(_safe_list(existing.get("source_ids")) + _safe_list(node.get("source_ids")))
    )
    existing["evidence_refs"] = sorted(
        set(_safe_list(existing.get("evidence_refs")) + _safe_list(node.get("evidence_refs")))
    )
    existing["confidence"] = max(float(existing.get("confidence") or 0.0), float(node.get("confidence") or 0.0))
    existing_data = _safe_dict(existing.get("data"))
    existing_data.update(_safe_dict(node.get("data")))
    existing["data"] = existing_data


def _normalized_node(
    *,
    node_type: str,
    source_id: object,
    label: str,
    subtype: str | None = None,
    confidence: float = 0.7,
    evidence_refs: Iterable[object] | None = None,
    source_ids: Iterable[object] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_source_id = str(source_id)
    return {
        "id": _normalized_node_id(node_type, normalized_source_id),
        "type": node_type,
        "subtype": subtype,
        "source_id": normalized_source_id,
        "source_ids": [str(item) for item in list(source_ids or [normalized_source_id]) if str(item)],
        "label": label,
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "evidence_refs": [str(item) for item in list(evidence_refs or []) if str(item)],
        "data": data or {},
    }


def _add_normalized_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    *,
    source: str,
    target: str,
    relationship: str,
    confidence: float,
    evidence_refs: Iterable[object] | None,
    provenance: dict[str, Any],
) -> None:
    key = (source, relationship, target)
    refs = sorted(set(str(item) for item in list(evidence_refs or []) if str(item)))
    edge = {
        "id": f"normalized-edge:{_slug(source)}:{_slug(relationship)}:{_slug(target)}",
        "source": source,
        "target": target,
        "relationship": relationship,
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "evidence_refs": refs,
        "provenance": provenance,
    }
    existing = edges.get(key)
    if existing is None:
        edges[key] = edge
        return
    existing["confidence"] = max(float(existing.get("confidence") or 0.0), edge["confidence"])
    existing["evidence_refs"] = sorted(set(_safe_list(existing.get("evidence_refs")) + refs))
    existing["provenance"] = {
        "source": "merged",
        "sources": [existing.get("provenance"), provenance],
    }


def _normalize_source_graph_node(node: dict[str, Any]) -> dict[str, Any] | None:
    kind = str(node.get("kind") or "")
    data = _safe_dict(node.get("data"))
    source_id = str(node.get("source_id") or node.get("id") or "")
    label = str(node.get("label") or source_id)
    evidence_refs = _node_evidence_refs(node)
    confidence = _confidence_from_node(node)
    if kind == "run":
        return _normalized_node(
            node_type="run",
            subtype="assessment_run",
            source_id=source_id,
            label=label,
            confidence=1.0,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "scope":
        return _normalized_node(
            node_type="scope",
            subtype="engagement_scope",
            source_id=source_id,
            label=label,
            confidence=0.95,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind.startswith("inventory_"):
        subtype = kind.removeprefix("inventory_")
        node_type = "api" if subtype == "endpoint" and _looks_like_api(label) else "asset"
        return _normalized_node(
            node_type=node_type,
            subtype=subtype,
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "finding":
        return _normalized_node(
            node_type="finding",
            subtype=str(data.get("severity") or "finding"),
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "task":
        return _normalized_node(
            node_type="task",
            subtype=str(data.get("tool") or "task"),
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=_sanitize_task_node_data(data),
        )
    if kind in {"tool_execution", "evidence_artifact", "context_document", "report_evidence", "rationale_entry"}:
        return _normalized_node(
            node_type="evidence_ref",
            subtype=kind,
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "approval":
        return _normalized_node(
            node_type="approval",
            subtype=str(data.get("decision") or "approval"),
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "agent_proposal":
        return _normalized_node(
            node_type="proposal",
            subtype=str(data.get("proposed_tool") or "agent_proposal"),
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "runner_metadata":
        return _normalized_node(
            node_type="runner_capability",
            subtype=str(data.get("risk_tier") or "runner"),
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    if kind == "finding_chain":
        return _normalized_node(
            node_type="attack_path",
            subtype=str(data.get("pattern_id") or "finding_chain"),
            source_id=source_id,
            label=label,
            confidence=confidence,
            evidence_refs=evidence_refs,
            source_ids=[str(node.get("id") or source_id)],
            data=data,
        )
    return None


def _inventory_semantic_nodes(run: Run) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for snapshot in _inventory_snapshots_for_run(run):
        inventory = _safe_dict(snapshot.normalized_inventory_json)
        source_ids = [f"inventory_snapshot:{snapshot.id}"]
        evidence_refs = [str(snapshot.id)]
        for value in sorted(_inventory_values(inventory, ("api_endpoints", "graphql_endpoints", "openapi_specs", "api_base_urls"))):
            nodes.append(
                _normalized_node(
                    node_type="api",
                    subtype="inventory_api",
                    source_id=f"{snapshot.id}:api:{value}",
                    label=value,
                    confidence=float(snapshot.confidence_score or 0.7),
                    evidence_refs=evidence_refs,
                    source_ids=source_ids,
                    data={"inventory_snapshot_id": str(snapshot.id), "value": value},
                )
            )
        for identity in _semantic_records(inventory, ("identities", "identity_subjects", "users", "groups", "service_accounts")):
            value = _record_label(identity)
            if value:
                nodes.append(
                    _normalized_node(
                        node_type="identity",
                        subtype=str(identity.get("type") or identity.get("kind") or "identity") if isinstance(identity, dict) else "identity",
                        source_id=f"{snapshot.id}:identity:{value}",
                        label=value,
                        confidence=float(snapshot.confidence_score or 0.7),
                        evidence_refs=evidence_refs,
                        source_ids=source_ids,
                        data=_safe_dict(identity),
                    )
                )
        for connector in _semantic_records(inventory, ("saas_connectors", "connectors", "oauth_clients", "oauth_apps")):
            value = _record_label(connector)
            if value:
                nodes.append(
                    _normalized_node(
                        node_type="saas_connector",
                        subtype=str(connector.get("type") or connector.get("kind") or "connector") if isinstance(connector, dict) else "connector",
                        source_id=f"{snapshot.id}:saas_connector:{value}",
                        label=value,
                        confidence=float(snapshot.confidence_score or 0.7),
                        evidence_refs=evidence_refs,
                        source_ids=source_ids,
                        data=_safe_dict(connector),
                    )
                )
        for permission in _semantic_records(inventory, ("permissions", "scopes", "oauth_scopes", "iam_permissions")):
            value = _record_label(permission)
            if value:
                nodes.append(
                    _normalized_node(
                        node_type="permission",
                        subtype=str(permission.get("type") or permission.get("kind") or "permission") if isinstance(permission, dict) else "permission",
                        source_id=f"{snapshot.id}:permission:{value}",
                        label=value,
                        confidence=float(snapshot.confidence_score or 0.7),
                        evidence_refs=evidence_refs,
                        source_ids=source_ids,
                        data=_safe_dict(permission),
                    )
                )
    return nodes


def _run_vault_credential_nodes(session: Session, run: Run) -> list[dict[str, Any]]:
    refs = session.scalars(
        select(SecretRef)
        .where(SecretRef.engagement_id == run.engagement_id)
        .order_by(SecretRef.created_at.asc(), SecretRef.id.asc())
    ).all()
    nodes: list[dict[str, Any]] = []
    for ref in refs:
        metadata = _safe_dict(ref.metadata_json)
        if metadata.get("run_id") != str(run.id):
            continue
        nodes.append(
            _normalized_node(
                node_type="credential_ref",
                subtype=ref.secret_kind,
                source_id=ref.id,
                label=ref.display_label or ref.secret_kind,
                confidence=0.86,
                evidence_refs=[str(ref.id), ref.vault_pointer],
                source_ids=[f"secret_ref:{ref.id}"],
                data={
                    "secret_ref_id": str(ref.id),
                    "secret_kind": ref.secret_kind,
                    "purpose": ref.purpose,
                    "storage_backend": ref.storage_backend,
                    "vault_pointer": ref.vault_pointer,
                    "raw_secret_material_exposed": False,
                    "metadata": {
                        key: value
                        for key, value in metadata.items()
                        if key not in {"value", "secret", "token", "password"}
                    },
                },
            )
        )
    return nodes


def _latest_scope(run: Run) -> Scope | None:
    scopes = list(run.engagement.scopes or []) if run.engagement is not None else []
    if not scopes:
        return None
    return sorted(scopes, key=lambda item: (item.created_at, item.id))[-1]


def _inventory_snapshots_for_run(run: Run) -> list[InventorySnapshot]:
    snapshots: dict[str, InventorySnapshot] = {}
    if run.source_inventory_snapshot is not None:
        snapshots[str(run.source_inventory_snapshot.id)] = run.source_inventory_snapshot
    for finding in run.findings or []:
        if finding.source_inventory_snapshot is not None:
            snapshots[str(finding.source_inventory_snapshot.id)] = finding.source_inventory_snapshot
    return sorted(snapshots.values(), key=lambda item: (item.created_at, item.id))


def _add_scope_node(nodes: dict[str, dict[str, Any]], scope: Scope) -> str:
    return _add_node(
        nodes,
        kind="scope",
        source_id=scope.id,
        label=f"Scope {scope.id}",
        data={
            "engagement_id": str(scope.engagement_id),
            "allowlist": _safe_dict(scope.allowlist_json),
            "denylist": _safe_dict(scope.denylist_json),
            "created_at": _iso(scope.created_at),
        },
    )


def _add_inventory_snapshot_node(
    nodes: dict[str, dict[str, Any]],
    snapshot: InventorySnapshot,
) -> str:
    return _add_node(
        nodes,
        kind="inventory_snapshot",
        source_id=snapshot.id,
        label=f"Inventory snapshot {snapshot.id}",
        data={
            "status": snapshot.status,
            "source_tools": _safe_list(snapshot.source_tools_json),
            "summary": _safe_dict(snapshot.summary_json),
            "confidence_score": snapshot.confidence_score,
            "created_at": _iso(snapshot.created_at),
        },
    )


def _add_inventory_item_nodes(
    nodes: dict[str, dict[str, Any]],
    snapshot: InventorySnapshot,
) -> list[str]:
    inventory = _safe_dict(snapshot.normalized_inventory_json)
    extracted = {
        "inventory_host": _inventory_values(inventory, ("hosts", "hostnames", "domains", "targets")),
        "inventory_endpoint": _inventory_values(
            inventory,
            ("endpoints", "api_endpoints", "urls", "paths", "targets"),
        ),
        "inventory_technology": _inventory_values(
            inventory,
            ("technologies", "technology", "frameworks", "languages"),
        ),
        "inventory_service": _inventory_values(inventory, ("services", "ports")),
    }
    nested = _safe_dict(inventory.get("tech_stack_profile"))
    extracted["inventory_endpoint"].update(_inventory_values(nested, ("api_endpoints", "endpoints")))
    extracted["inventory_technology"].update(
        _inventory_values(nested, ("technology", "technologies", "frameworks", "language", "languages"))
    )

    node_ids: list[str] = []
    for kind, values in sorted(extracted.items()):
        for value in sorted(values):
            source_id = f"{snapshot.id}:{_slug(value)}"
            node_ids.append(
                _add_node(
                    nodes,
                    kind=kind,
                    source_id=source_id,
                    label=value,
                    data={
                        "inventory_snapshot_id": str(snapshot.id),
                        "value": value,
                    },
                )
            )
    return node_ids


def _add_report_evidence_node(
    nodes: dict[str, dict[str, Any]],
    run: Run,
    context: dict[str, object],
) -> str:
    return _add_node(
        nodes,
        kind="report_evidence",
        source_id=f"{run.id}:technical",
        label="Technical report evidence context",
        data={
            "profile_name": context.get("profile_name"),
            "finding_count": len(context.get("findings", []) or []),
            "task_count": len(context.get("tasks", []) or []),
            "approval_count": len(context.get("approvals", []) or []),
            "rationale_entry_count": len(context.get("rationale_ledger", []) or []),
            "report_sections": context.get("report_sections", []),
            "coverage": context.get("coverage", {}),
        },
    )


def _add_task_node(nodes: dict[str, dict[str, Any]], task: Task) -> str:
    return _add_node(
        nodes,
        kind="task",
        source_id=task.id,
        label=f"{task.tool} -> {task.target_id}",
        data={
            "tool": task.tool,
            "target_id": task.target_id,
            "status": task.status,
            "params": _safe_dict(task.params_json),
            "source_finding_id": _string_or_none(task.source_finding_id),
            "created_at": _iso(task.created_at),
        },
    )


def _add_execution_node(nodes: dict[str, dict[str, Any]], execution: ToolExecution) -> str:
    return _add_node(
        nodes,
        kind="tool_execution",
        source_id=execution.id,
        label=f"Execution {execution.id}",
        data={
            "task_id": str(execution.task_id),
            "runner_digest": execution.runner_digest,
            "tool_version": execution.tool_version,
            "exit_code": execution.exit_code,
            "stdout_observed": bool(execution.stdout_text),
            "stderr_observed": bool(execution.stderr_text),
            "created_at": _iso(execution.created_at),
        },
    )


def _add_artifact_node(nodes: dict[str, dict[str, Any]], artifact: EvidenceArtifact) -> str:
    return _add_node(
        nodes,
        kind="evidence_artifact",
        source_id=artifact.id,
        label=f"{artifact.kind} evidence",
        data={
            "tool_execution_id": str(artifact.tool_execution_id),
            "kind": artifact.kind,
            "uri": artifact.uri,
            "sha256": artifact.sha256,
            "redaction_state": artifact.redaction_state,
            "metadata": _safe_dict(artifact.metadata_json),
            "timestamp_token_uri": artifact.timestamp_token_uri,
            "timestamp_verified_at": _iso(artifact.timestamp_verified_at),
            "created_at": _iso(artifact.created_at),
        },
    )


def _add_finding_node(nodes: dict[str, dict[str, Any]], finding: Finding) -> str:
    return _add_node(
        nodes,
        kind="finding",
        source_id=finding.id,
        label=finding.title,
        data={
            "title": finding.title,
            "severity": finding.severity,
            "target_id": finding.target_id,
            "evidence_ref": finding.evidence_ref,
            "status": finding.status,
            "validation_status": finding.validation_status,
            "summary": finding.summary,
            "methodology_tags": _safe_list(finding.methodology_tags),
            "ptes_phase": finding.ptes_phase,
            "nist_phase": finding.nist_phase,
            "wstg_id": finding.wstg_id,
            "source_inventory_snapshot_id": _string_or_none(finding.source_inventory_snapshot_id),
            "created_at": _iso(finding.created_at),
        },
    )


def _add_approval_node(nodes: dict[str, dict[str, Any]], approval: Approval) -> str:
    return _add_node(
        nodes,
        kind="approval",
        source_id=approval.id,
        label=f"{approval.step_id}: {approval.decision}",
        data={
            "run_id": str(approval.run_id),
            "step_id": approval.step_id,
            "decision": approval.decision,
            "approver_id": approval.approver_id,
            "created_at": _iso(approval.created_at),
        },
    )


def _add_context_node(nodes: dict[str, dict[str, Any]], context: TargetContextDocument) -> str:
    return _add_node(
        nodes,
        kind="context_document",
        source_id=context.id,
        label=context.layer_name,
        data={
            "layer_name": context.layer_name,
            "context_kind": context.context_kind,
            "status": context.status,
            "recommended_tools": _safe_list(context.recommended_tools_json),
            "technologies_detected": _safe_list(context.technologies_detected_json),
            "endpoints_discovered": _safe_list(context.endpoints_discovered_json),
            "evidence_refs": _safe_list(context.evidence_refs_json),
            "context_summary": context.context_summary,
            "provenance": _safe_dict(context.provenance_json),
            "created_at": _iso(context.created_at),
        },
    )


def _add_proposal_node(nodes: dict[str, dict[str, Any]], proposal: AgentProposal) -> str:
    return _add_node(
        nodes,
        kind="agent_proposal",
        source_id=proposal.id,
        label=f"{proposal.proposed_tool} proposal",
        data={
            "proposed_tool": proposal.proposed_tool,
            "proposed_target": proposal.proposed_target,
            "risk_tier": proposal.risk_tier,
            "status": proposal.status,
            "confidence_score": proposal.confidence_score,
            "metadata": _safe_dict(proposal.metadata_json),
            "created_at": _iso(proposal.created_at),
        },
    )


def _add_rationale_node(nodes: dict[str, dict[str, Any]], entry: RationaleLedgerEntry) -> str:
    return _add_node(
        nodes,
        kind="rationale_entry",
        source_id=entry.id,
        label=f"{entry.tool_name} rationale",
        data={
            "action_type": entry.action_type,
            "tool_name": entry.tool_name,
            "target": entry.target,
            "status": entry.status,
            "rationale_text": entry.rationale_text,
            "decision_source": _safe_dict(entry.decision_source_json),
            "parameters": _safe_dict(entry.parameters_json),
            "context_document_id": _string_or_none(entry.context_document_id),
            "task_id": _string_or_none(entry.task_id),
            "agent_proposal_id": _string_or_none(entry.agent_proposal_id),
            "created_at": _iso(entry.created_at),
        },
    )


def _add_finding_chain_node(nodes: dict[str, dict[str, Any]], chain: FindingChain) -> str:
    return _add_node(
        nodes,
        kind="finding_chain",
        source_id=chain.id,
        label=chain.title,
        data={
            "pattern_id": chain.pattern_id,
            "status": chain.status,
            "confidence_score": chain.confidence_score,
            "component_finding_ids": _safe_list(chain.component_finding_ids_json),
            "evidence_refs": _safe_list(chain.evidence_refs_json),
            "combined_impact_text": chain.combined_impact_text,
            "created_at": _iso(chain.created_at),
        },
    )


def _add_runner_nodes(nodes: dict[str, dict[str, Any]], tool_names: Iterable[str]) -> None:
    registry = runner_capability_registry()
    capabilities = {
        str(capability.get("name")): capability
        for capability in _safe_list(registry.get("capabilities"))
        if isinstance(capability, dict)
    }
    registered_tools = set(_safe_list(registry.get("registered_tools")))
    selected_tools = {str(tool).strip() for tool in tool_names if str(tool).strip()}
    for tool_name in list(selected_tools):
        selected_tools.update(_safe_list(_safe_dict(capabilities.get(tool_name)).get("follow_up_tools")))
    for tool_name in sorted(selected_tools):
        capability = _safe_dict(capabilities.get(tool_name))
        _add_node(
            nodes,
            kind="runner_metadata",
            source_id=tool_name,
            label=tool_name,
            data={
                "registered": tool_name in registered_tools,
                "category": capability.get("category"),
                "risk_tier": capability.get("risk_tier"),
                "required_approvals": capability.get("required_approvals"),
                "prerequisites": _safe_list(capability.get("prerequisites")),
                "triggers": _safe_list(capability.get("triggers")),
                "weak_triggers": _safe_list(capability.get("weak_triggers")),
                "follow_up_tools": _safe_list(capability.get("follow_up_tools")),
                "expected_evidence": _safe_list(capability.get("expected_evidence")),
                "description": capability.get("description"),
                "metadata_source": capability.get("metadata_source"),
            },
        )


def _index_artifact_refs(
    artifact_refs: dict[str, str],
    artifact: EvidenceArtifact,
    artifact_node_id: str,
) -> None:
    for value in (artifact.id, artifact.uri, artifact.sha256):
        ref = str(value or "").strip()
        if ref:
            artifact_refs[ref] = artifact_node_id


def _context_evidence_refs(context: TargetContextDocument) -> list[str]:
    refs: list[str] = []
    for item in _safe_list(context.evidence_refs_json):
        if isinstance(item, dict):
            for key in ("artifact_id", "evidence_ref", "uri", "sha256", "ref"):
                value = str(item.get(key) or "").strip()
                if value:
                    refs.append(value)
        else:
            value = str(item or "").strip()
            if value:
                refs.append(value)
    return sorted(set(refs))


def _node_evidence_refs(node: dict[str, Any]) -> list[str]:
    data = _safe_dict(node.get("data"))
    refs: list[str] = []
    for key in ("evidence_ref", "uri", "sha256", "source_inventory_snapshot_id"):
        value = str(data.get(key) or "").strip()
        if value:
            refs.append(value)
    refs.extend(str(item) for item in _safe_list(data.get("evidence_refs")) if str(item).strip())
    refs.extend(str(item) for item in _safe_list(data.get("component_finding_ids")) if str(item).strip())
    source_id = str(node.get("source_id") or "").strip()
    if node.get("kind") in {"finding", "tool_execution", "evidence_artifact", "context_document", "rationale_entry"} and source_id:
        refs.append(source_id)
    return sorted(set(refs))


def _edge_evidence_refs(
    edge: dict[str, Any],
    source_node: dict[str, Any] | None,
    target_node: dict[str, Any] | None,
) -> list[str]:
    refs: list[str] = []
    if edge.get("evidence"):
        refs.append(str(edge["evidence"]))
    for node in (source_node, target_node):
        if node:
            refs.extend(str(item) for item in _safe_list(node.get("evidence_refs")) if str(item).strip())
    return sorted(set(refs))


def _confidence_from_node(node: dict[str, Any]) -> float:
    data = _safe_dict(node.get("data"))
    for key in ("confidence_score", "confidence"):
        value = data.get(key)
        if isinstance(value, int | float):
            return round(max(0.0, min(1.0, float(value))), 2)
    kind = str(node.get("kind") or "")
    if kind in {"finding", "evidence_artifact", "tool_execution", "approval"}:
        return 0.9
    if kind in {"task", "context_document", "rationale_entry"}:
        return 0.82
    if kind.startswith("inventory_"):
        return 0.74
    return 0.7


def _node_confidence(node: dict[str, Any] | None) -> float:
    if not node:
        return 0.7
    return float(node.get("confidence") or 0.7)


def _edge_confidence(
    edge: dict[str, Any],
    source_node: dict[str, Any] | None,
    target_node: dict[str, Any] | None,
) -> float:
    if edge.get("evidence"):
        return min(0.96, max(_node_confidence(source_node), _node_confidence(target_node)))
    return round(min(_node_confidence(source_node), _node_confidence(target_node), 0.88), 2)


def _sanitize_task_node_data(data: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(data)
    params = _safe_dict(sanitized.get("params"))
    if params:
        sanitized["params"] = _sanitize_graph_payload(params)
    return sanitized


def _sanitize_graph_payload(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in {"value", "secret", "token", "password", "cookie", "authorization"}:
                sanitized[str(key)] = "[redacted]"
            else:
                sanitized[str(key)] = _sanitize_graph_payload(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_graph_payload(item) for item in value]
    return value


def _semantic_records(payload: dict[str, Any], keys: Iterable[str]) -> list[Any]:
    records: list[Any] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            records.extend(value)
        elif value:
            records.append(value)
    nested = _safe_dict(payload.get("tech_stack_profile"))
    if nested:
        for key in keys:
            value = nested.get(key)
            if isinstance(value, list):
                records.extend(value)
            elif value:
                records.append(value)
    return records


def _record_label(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("name", "label", "id", "client_id", "subject", "principal", "scope", "permission", "value", "dataset"):
            text = str(value.get(key) or "").strip()
            if text:
                return text
        return ""
    return str(value or "").strip()


def _looks_like_api(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ("api", "graphql", "openapi", "swagger", "/v1", "/v2"))


def _inventory_values(payload: dict[str, Any], keys: Iterable[str]) -> set[str]:
    values: set[str] = set()
    for key in keys:
        values.update(_flatten_inventory_value(payload.get(key)))
    return values


def _flatten_inventory_value(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        stripped = value.strip()
        return {stripped} if stripped else set()
    if isinstance(value, dict):
        candidates: set[str] = set()
        for key in ("url", "uri", "host", "hostname", "domain", "name", "technology", "service", "port", "path", "value"):
            if key in value:
                candidates.update(_flatten_inventory_value(value.get(key)))
        return candidates
    if isinstance(value, list | tuple | set):
        candidates: set[str] = set()
        for item in value:
            candidates.update(_flatten_inventory_value(item))
        return candidates
    return {str(value).strip()} if str(value).strip() else set()


def _observed_prerequisites(nodes: dict[str, dict[str, Any]]) -> set[str]:
    observed = set()
    if any(node.get("kind") == "scope" for node in nodes.values()):
        observed.add(OBSERVED_SCOPE_PREREQUISITE)
    text = " ".join(
        str(node.get("data") or {}).lower()
        for node in nodes.values()
        if node.get("kind") != "runner_metadata"
    )
    if any(marker in text for marker in ("auth_context", "operator_auth_context", "credential_ref", "secret_binding_ref", "session_ref")):
        observed.add("operator_auth_context")
    return observed


def _evidence_sources_for_node(
    node_id: str,
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
) -> list[str]:
    evidence_ids = {node_id}
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        relationship = edge.get("relationship")
        if source == node_id or target == node_id:
            if source in nodes:
                evidence_ids.add(source)
            if target in nodes:
                evidence_ids.add(target)
            if relationship in {
                "supported_by_artifact",
                "validates_source_finding",
                "chains_finding",
                "reports_finding",
            }:
                for adjacent in (source, target):
                    if adjacent in nodes:
                        evidence_ids.add(adjacent)
    return sorted(evidence_ids)


def _candidate_runner_observations(
    finding: dict[str, Any],
    evidence_node_ids: list[str],
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    runner_nodes: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    finding_text = _searchable_finding_text(finding)
    candidate_names: set[str] = set()
    for runner in runner_nodes.values():
        runner_data = _safe_dict(runner.get("data"))
        trigger_text = " ".join(_safe_list(runner_data.get("triggers")) + _safe_list(runner_data.get("weak_triggers")))
        if _trigger_matches(finding_text, trigger_text):
            candidate_names.add(runner["source_id"])

    adjacent_runners = _adjacent_runner_names(finding["id"], edges, nodes)
    for runner_name in adjacent_runners:
        runner = runner_nodes.get(_runner_node_id(runner_name))
        if runner is None:
            continue
        candidate_names.update(_safe_list(_safe_dict(runner.get("data")).get("follow_up_tools")))

    candidates: list[dict[str, Any]] = []
    for name in sorted(candidate_names):
        runner = runner_nodes.get(_runner_node_id(name))
        if runner is None:
            continue
        data = _safe_dict(runner.get("data"))
        if data.get("registered") is not True:
            continue
        candidates.append(
            {
                "runner": name,
                "runner_node_id": runner["id"],
                "risk_tier": data.get("risk_tier"),
                "required_approvals": data.get("required_approvals"),
                "expected_evidence": _safe_list(data.get("expected_evidence")),
                "source_ids": sorted(set(evidence_node_ids + [runner["id"]])),
                "dispatches_work": False,
            }
        )
    return candidates


def _adjacent_runner_names(
    finding_node_id: str,
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
) -> set[str]:
    task_node_ids = {
        edge.get("source")
        for edge in edges
        if edge.get("target") == finding_node_id and edge.get("relationship") == "validates_source_finding"
    }
    task_node_ids.update(
        edge.get("target")
        for edge in edges
        if edge.get("source") == finding_node_id and edge.get("relationship") == "validates_source_finding"
    )
    runners: set[str] = set()
    for edge in edges:
        if edge.get("relationship") != "uses_runner":
            continue
        if edge.get("source") in task_node_ids and edge.get("target") in nodes:
            runner_node = nodes[edge["target"]]
            if runner_node.get("kind") == "runner_metadata":
                runners.add(str(runner_node.get("source_id")))
    return runners


def _missing_prerequisites(
    candidates: list[dict[str, Any]],
    runner_nodes: dict[str, dict[str, Any]],
    observed_prerequisites: set[str],
) -> list[dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    for candidate in candidates:
        runner = runner_nodes.get(candidate["runner_node_id"])
        prerequisites = set(_safe_list(_safe_dict(runner.get("data") if runner else {}).get("prerequisites")))
        absent = sorted(prerequisites - observed_prerequisites)
        if absent:
            missing.append(
                {
                    "runner": candidate["runner"],
                    "missing": absent,
                    "explanation": (
                        "The graph contains no stored evidence for "
                        + ", ".join(absent)
                        + "; collect or attach that prerequisite before proposing this observation."
                    ),
                }
            )
    return missing


def _hypothesis_confidence(finding_data: dict[str, Any], evidence_node_ids: list[str]) -> float:
    severity = str(finding_data.get("severity") or "").lower()
    base = {
        "critical": 0.78,
        "high": 0.72,
        "medium": 0.64,
        "low": 0.54,
        "info": 0.46,
    }.get(severity, 0.5)
    evidence_bonus = min(0.18, max(0, len(evidence_node_ids) - 1) * 0.03)
    return round(min(0.92, base + evidence_bonus), 2)


def _searchable_finding_text(finding: dict[str, Any]) -> str:
    data = _safe_dict(finding.get("data"))
    return " ".join(
        str(data.get(key) or "")
        for key in ("title", "summary", "evidence_ref", "methodology_tags", "target_id", "wstg_id")
    ).lower()


def _trigger_matches(finding_text: str, trigger_text: str) -> bool:
    if not finding_text or not trigger_text:
        return False
    for trigger in _safe_list(trigger_text.split()):
        normalized = trigger.replace("_", " ").replace("-", " ").lower()
        words = [word for word in re.split(r"\W+", normalized) if len(word) >= 4]
        if words and all(word in finding_text for word in words[:2]):
            return True
    return False


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    if value is None:
        return []
    return [value]


def _string_or_none(value: UUID | str | None) -> str | None:
    return str(value) if value is not None else None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.:-]+", "-", value.strip().lower()).strip("-")
    return slug[:160] or "unknown"
