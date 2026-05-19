from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from api.app.services.attack_paths import build_attack_path_summary

PREDICTIVE_BOUNDARY = {
    "mode": "read-only-hypothetical-simulation",
    "hypothetical_edges_persisted": False,
    "factual_evidence_persisted": False,
    "runtime_dispatch_performed": False,
    "automatic_approval_created": False,
    "credential_testing_performed": False,
    "scope_expansion_performed": False,
}


def simulate_predictive_attack_paths(
    session: Session,
    *,
    run_id: UUID,
    starting_point_label: str,
    starting_point_type: str | None = None,
    max_paths: int = 5,
) -> dict[str, Any] | None:
    summary = build_attack_path_summary(session, run_id)
    if summary is None:
        return None

    label = str(starting_point_label or "").strip()
    if not label:
        raise ValueError("starting_point_label is required")
    nodes = [dict(node) for node in summary.get("nodes", []) if isinstance(node, dict)]
    edges = [dict(edge) for edge in summary.get("edges", []) if isinstance(edge, dict)]
    nodes_by_id = {str(node.get("id")): node for node in nodes if str(node.get("id") or "")}
    start_node = {
        "id": "hypothetical:start",
        "type": starting_point_type or "hypothetical_start",
        "label": label,
        "confidence": 1.0,
        "source": "operator_hypothesis",
        "hypothetical": True,
        "metadata": {
            "operator_supplied": True,
            "factual_evidence_persisted": False,
        },
    }
    nodes_by_id[start_node["id"]] = start_node

    anchors = _anchor_nodes(label, nodes, summary)
    hypothetical_edges = [
        {
            "id": f"hypothetical-edge:{index + 1}",
            "source": start_node["id"],
            "target": anchor["id"],
            "type": "hypothetical-compromise-start",
            "classification": "hypothetical",
            "confidence": round(0.72 * float(anchor.get("confidence") or 0.6), 3),
            "rationale": (
                f"Operator asked to simulate from '{label}'. This edge is hypothetical and "
                "does not represent observed compromise evidence."
            ),
            "evidence_refs": [],
            "operator_review_required": True,
            "runtime_dispatch_performed": False,
            "factual_evidence_persisted": False,
        }
        for index, anchor in enumerate(anchors)
    ]
    graph_edges = [*edges, *hypothetical_edges]
    targets = _critical_target_nodes(nodes, summary)
    adjacency = _adjacency(graph_edges)
    simulated_paths: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, ...]] = set()
    for target in targets:
        path = _shortest_path(adjacency, start_node["id"], target["id"], max_depth=7)
        if not path:
            continue
        key = tuple(path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        simulated_paths.append(_path_payload(path, nodes_by_id, graph_edges, target, label))
        if len(simulated_paths) >= max(1, max_paths):
            break

    return {
        "status": "ready" if simulated_paths else "no_paths",
        "run_id": str(run_id),
        "generated_at": datetime.now(UTC).isoformat(),
        "simulation_mode": True,
        "starting_point": start_node,
        "anchors": anchors,
        "hypothetical_edges": hypothetical_edges,
        "simulated_paths": simulated_paths,
        "summary": {
            "simulated_path_count": len(simulated_paths),
            "anchor_count": len(anchors),
            "critical_target_count": len(targets),
            "factual_candidate_path_count": int(
                (summary.get("summary") or {}).get("candidate_path_count") or 0
            ),
            "factual_evidence_persisted": False,
            "runtime_dispatch_performed": False,
        },
        "boundary": dict(PREDICTIVE_BOUNDARY),
        "source_attack_path_model": summary.get("evaluation_model"),
    }


def _anchor_nodes(label: str, nodes: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    tokens = {token for token in label.lower().replace("-", " ").split() if len(token) >= 3}
    matched = [
        node
        for node in nodes
        if tokens and any(token in str(node.get("label") or "").lower() for token in tokens)
    ]
    if matched:
        return matched[:4]

    choke_node_ids = [
        str(item.get("node_id"))
        for item in summary.get("choke_points", [])
        if isinstance(item, dict) and str(item.get("node_id") or "")
    ]
    by_id = {str(node.get("id")): node for node in nodes}
    anchors = [by_id[node_id] for node_id in choke_node_ids if node_id in by_id]
    if anchors:
        return anchors[:4]
    preferred = [
        node
        for node in nodes
        if str(node.get("type") or "") in {"host", "identity_subject", "cloud_resource", "endpoint"}
    ]
    return preferred[:4]


def _critical_target_nodes(nodes: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    by_id = {str(node.get("id")): node for node in nodes}
    targets: list[dict[str, Any]] = []
    for path in summary.get("candidate_paths", []) if isinstance(summary.get("candidate_paths"), list) else []:
        if not isinstance(path, dict):
            continue
        severity = str(path.get("severity") or "").lower()
        impact = path.get("business_impact") if isinstance(path.get("business_impact"), dict) else {}
        important = severity in {"critical", "high"} or float(impact.get("score") or 0.0) >= 70
        if not important:
            continue
        for node_id in reversed([str(item) for item in path.get("node_ids", []) if str(item)]):
            node = by_id.get(node_id)
            if node is not None and node.get("type") == "finding":
                targets.append(node)
                break
    if targets:
        return _dedupe_nodes(targets)
    findings = [
        node
        for node in nodes
        if node.get("type") == "finding"
        and str((node.get("metadata") or {}).get("severity") or "").lower() in {"critical", "high"}
    ]
    return _dedupe_nodes(findings)


def _adjacency(edges: list[dict[str, Any]]) -> dict[str, list[str]]:
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if not source or not target:
            continue
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, []).append(source)
    return adjacency


def _shortest_path(
    adjacency: dict[str, list[str]],
    start: str,
    target: str,
    *,
    max_depth: int,
) -> list[str]:
    queue = deque([[start]])
    seen = {start}
    while queue:
        path = queue.popleft()
        node_id = path[-1]
        if node_id == target:
            return path
        if len(path) > max_depth:
            continue
        for neighbor in adjacency.get(node_id, []):
            if neighbor in seen:
                continue
            seen.add(neighbor)
            queue.append([*path, neighbor])
    return []


def _path_payload(
    node_ids: list[str],
    nodes_by_id: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    target: dict[str, Any],
    starting_point_label: str,
) -> dict[str, Any]:
    edge_lookup = _edge_lookup(edges)
    path_edges = []
    confidences = []
    evidence_refs = []
    for source, destination in zip(node_ids, node_ids[1:], strict=False):
        edge = edge_lookup.get((source, destination)) or edge_lookup.get((destination, source))
        if edge is None:
            continue
        path_edges.append(edge)
        if isinstance(edge.get("confidence"), (int, float)):
            confidences.append(float(edge["confidence"]))
        evidence_refs.extend(str(ref) for ref in edge.get("evidence_refs", []) if str(ref))
    node_confidences = [
        float(nodes_by_id[node_id].get("confidence") or 0.5)
        for node_id in node_ids
        if node_id in nodes_by_id
    ]
    confidences.extend(node_confidences)
    confidence = round(sum(confidences) / len(confidences), 3) if confidences else 0.5
    return {
        "id": f"simulated:{abs(hash('|'.join(node_ids)))}",
        "hypothetical": True,
        "node_ids": node_ids,
        "labels": [str(nodes_by_id[node_id].get("label") or node_id) for node_id in node_ids if node_id in nodes_by_id],
        "target_node_id": target["id"],
        "target_label": target.get("label"),
        "target_type": target.get("type"),
        "confidence": confidence,
        "edge_classifications": [str(edge.get("classification") or "confirmed") for edge in path_edges],
        "evidence_refs": sorted(set(evidence_refs)),
        "factual_evidence_persisted": False,
        "runtime_dispatch_performed": False,
        "explanation": (
            f"If '{starting_point_label}' were compromised, stored graph relationships suggest a "
            f"possible route to '{target.get('label')}'. Hypothetical edges are visually and "
            "semantically distinct from evidence-backed edges."
        ),
    }


def _edge_lookup(edges: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(edge.get("source")), str(edge.get("target"))): edge
        for edge in edges
        if str(edge.get("source") or "") and str(edge.get("target") or "")
    }


def _dedupe_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for node in nodes:
        node_id = str(node.get("id") or "")
        if not node_id or node_id in seen:
            continue
        seen.add(node_id)
        result.append(node)
    return result
