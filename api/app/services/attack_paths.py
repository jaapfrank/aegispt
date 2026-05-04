from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Engagement, Finding, InventorySnapshot, Run
from api.app.services.inventory import aggregate_inventory_snapshots

CHOKE_POINT_PATH_THRESHOLD = 3
DEFAULT_WEB_PORTS = {
    "http": 80,
    "https": 443,
}


def build_attack_path_summary(session: Session, run_id: UUID | str) -> dict[str, Any] | None:
    run = _load_run_for_attack_paths(session, run_id)
    if run is None:
        return None
    return _build_attack_path_summary_for_run(run)


def build_attack_graph(session: Session, run_id: UUID | str) -> dict[str, Any] | None:
    return build_attack_path_summary(session, run_id)


def build_attack_path_summary_for_loaded_run(run: Run) -> dict[str, Any]:
    return _build_attack_path_summary_for_run(run)


def evaluate_paths(session: Session, run_id: UUID | str) -> dict[str, Any] | None:
    summary = build_attack_path_summary(session, run_id)
    if summary is None:
        return None
    return {
        "status": summary["status"],
        "run_id": summary["run_id"],
        "candidate_paths": summary["candidate_paths"],
        "choke_points": summary["choke_points"],
        "evaluation_model": summary["evaluation_model"],
        "summary": summary["summary"],
    }


def _load_run_for_attack_paths(session: Session, run_id: UUID | str) -> Run | None:
    try:
        normalized_run_id = run_id if isinstance(run_id, UUID) else UUID(str(run_id))
    except ValueError:
        return None

    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.engagement).selectinload(Engagement.inventory_snapshots),
            selectinload(Run.findings),
        )
        .where(Run.id == normalized_run_id, Run.deleted_at.is_(None))
    )


def _effective_inventory_for_run(run: Run) -> dict[str, Any] | None:
    if run.engagement is None:
        return None

    snapshots = list(run.engagement.inventory_snapshots or [])
    run_id = str(run.id)
    derived = sorted(
        (
            snapshot
            for snapshot in snapshots
            if isinstance(snapshot.raw_inputs_json, dict)
            and str(snapshot.raw_inputs_json.get("run_id") or "") == run_id
        ),
        key=lambda snapshot: (snapshot.created_at, snapshot.id.hex),
        reverse=True,
    )
    if derived:
        aggregated = aggregate_inventory_snapshots(derived)
        representative = derived[0]
        if aggregated is not None:
            return {
                "id": str(representative.id),
                "aggregated_snapshot_count": len(derived),
                "normalized_inventory_json": aggregated["normalized_inventory_json"],
                "summary_json": aggregated["summary_json"],
                "source_tools_json": aggregated["source_tools_json"],
                "confidence_score": aggregated["confidence_score"],
            }
        return _snapshot_payload(representative)

    if run.source_inventory_snapshot_id is not None:
        for snapshot in snapshots:
            if snapshot.id == run.source_inventory_snapshot_id:
                return _snapshot_payload(snapshot)

    return None


def _snapshot_payload(snapshot: InventorySnapshot) -> dict[str, Any]:
    return {
        "id": str(snapshot.id),
        "aggregated_snapshot_count": 1,
        "normalized_inventory_json": dict(snapshot.normalized_inventory_json or {}),
        "summary_json": dict(snapshot.summary_json or {}),
        "source_tools_json": list(snapshot.source_tools_json or []),
        "confidence_score": float(snapshot.confidence_score or 0.0),
    }


def _build_attack_path_summary_for_run(run: Run) -> dict[str, Any]:
    inventory_snapshot = _effective_inventory_for_run(run)
    normalized_inventory = (
        dict(inventory_snapshot.get("normalized_inventory_json") or {})
        if inventory_snapshot is not None
        else {}
    )
    findings = sorted(
        list(run.findings or []),
        key=lambda finding: (finding.severity, finding.title, finding.id.hex),
    )

    graph = _build_inventory_graph(normalized_inventory, inventory_snapshot)
    lateral_analysis = _add_inferred_lateral_context(
        graph,
        normalized_inventory=normalized_inventory,
        inventory_snapshot=inventory_snapshot,
    )
    for finding in findings:
        _add_finding_node(graph, finding)

    candidate_paths = _build_candidate_paths(
        graph,
        findings,
        inventory_snapshot,
        normalized_inventory=normalized_inventory,
    )
    choke_points = _build_choke_points(graph["nodes_by_id"], candidate_paths)
    status = _summary_status(inventory_snapshot, findings, candidate_paths)
    path_confidences = [
        float(path.get("confidence") or 0.0)
        for path in candidate_paths
        if isinstance(path.get("confidence"), (int, float))
    ]
    mean_path_confidence = (
        round(sum(path_confidences) / len(path_confidences), 3)
        if path_confidences
        else 0.0
    )

    return {
        "status": status,
        "run_id": str(run.id),
        "engagement_id": str(run.engagement_id),
        "evaluation_model": "evidence-first-choke-point-v1",
        "choke_point_threshold": CHOKE_POINT_PATH_THRESHOLD,
        "sources": {
            "inventory_snapshot_id": inventory_snapshot.get("id") if inventory_snapshot else None,
            "aggregated_snapshot_count": (
                inventory_snapshot.get("aggregated_snapshot_count") if inventory_snapshot else 0
            ),
            "inventory_confidence": inventory_snapshot.get("confidence_score") if inventory_snapshot else 0.0,
            "source_tools": inventory_snapshot.get("source_tools_json") if inventory_snapshot else [],
            "finding_count": len(findings),
        },
        "summary": {
            "status": status,
            "node_count": len(graph["nodes"]),
            "edge_count": len(graph["edges"]),
            "confirmed_edge_count": len(
                [edge for edge in graph["edges"] if edge.get("classification") == "confirmed"]
            ),
            "inferred_edge_count": len(graph["inferred_edges"]),
            "lateral_analysis_note_count": len(lateral_analysis["notes"]),
            "candidate_path_count": len(candidate_paths),
            "choke_point_count": len(choke_points),
            "mean_path_confidence": mean_path_confidence,
            "reason": _summary_reason(status, inventory_snapshot, findings),
        },
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "inferred_edges": graph["inferred_edges"],
        "lateral_analysis": lateral_analysis,
        "candidate_paths": candidate_paths,
        "choke_points": choke_points,
    }


def _build_inventory_graph(
    normalized_inventory: dict[str, Any],
    inventory_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    graph = {
        "nodes": [],
        "nodes_by_id": {},
        "edges": [],
        "edge_keys": set(),
        "host_nodes_by_host": {},
        "service_nodes_by_host_port": {},
        "service_nodes_by_host": {},
        "endpoint_nodes_by_url": {},
        "endpoint_nodes_by_host": {},
        "identity_subject_nodes_by_key": {},
        "identity_group_nodes_by_key": {},
        "cloud_resource_nodes_by_key": {},
        "cloud_security_group_nodes_by_key": {},
        "cloud_iam_principal_nodes_by_key": {},
        "cloud_iam_policy_nodes_by_key": {},
        "kubernetes_cluster_nodes_by_key": {},
        "kubernetes_workload_nodes_by_key": {},
        "inferred_edges": [],
        "lateral_notes": [],
    }

    inventory_ref = f"inventory:{inventory_snapshot['id']}" if inventory_snapshot else None
    hosts = _dict_list(normalized_inventory.get("hosts"))
    services = _dict_list(normalized_inventory.get("services"))
    endpoints = _dict_list(normalized_inventory.get("http_endpoints"))

    for host in hosts:
        host_value = _clean_string(host.get("host"))
        if host_value:
            _ensure_host_node(graph, host_value, host, inventory_ref)

    for service in services:
        host_value = _clean_string(service.get("host"))
        port = _integer_or_none(service.get("port"))
        protocol = _clean_string(service.get("protocol")) or "tcp"
        if not host_value or port is None:
            continue

        host_node = _ensure_host_node(graph, host_value, {"host": host_value}, inventory_ref)
        service_id = f"service:{host_value.lower()}:{port}/{protocol.lower()}"
        service_label = f"{host_value}:{port}/{protocol.lower()}"
        service_node = _add_node(
            graph,
            {
                "id": service_id,
                "type": "service",
                "label": service_label,
                "confidence": _confidence(service.get("confidence"), default=0.5),
                "source": "inventory",
                "metadata": {
                    "host": host_value,
                    "port": port,
                    "protocol": protocol,
                    "service": service.get("service") or service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "inventory_snapshot_id": inventory_snapshot.get("id") if inventory_snapshot else None,
                },
            },
        )
        graph["service_nodes_by_host_port"][(host_value.lower(), port)] = service_node
        graph["service_nodes_by_host"].setdefault(host_value.lower(), []).append(service_node)
        _add_edge(
            graph,
            host_node["id"],
            service_node["id"],
            "exposes-service",
            evidence_refs=[inventory_ref] if inventory_ref else [],
        )

    for endpoint in endpoints:
        url = _clean_string(endpoint.get("url") or endpoint.get("endpoint"))
        if not url:
            continue
        endpoint_host, endpoint_port, endpoint_scheme = _target_host_port(url)
        endpoint_node = _add_node(
            graph,
            {
                "id": f"endpoint:{url.lower()}",
                "type": "endpoint",
                "label": url,
                "confidence": _confidence(endpoint.get("confidence"), default=0.5),
                "source": "inventory",
                "metadata": {
                    "url": url,
                    "host": endpoint_host,
                    "port": endpoint_port,
                    "scheme": endpoint_scheme,
                    "methods": endpoint.get("methods") if isinstance(endpoint.get("methods"), list) else [],
                    "status_code": endpoint.get("status_code"),
                    "title": endpoint.get("title"),
                    "inventory_snapshot_id": inventory_snapshot.get("id") if inventory_snapshot else None,
                },
            },
        )
        graph["endpoint_nodes_by_url"][_normalized_url_key(url)] = endpoint_node
        if endpoint_host:
            graph["endpoint_nodes_by_host"].setdefault(endpoint_host.lower(), []).append(endpoint_node)
            host_node = _ensure_host_node(graph, endpoint_host, {"host": endpoint_host}, inventory_ref)
            web_service = _service_for_endpoint(graph, endpoint_host, endpoint_port, endpoint_scheme)
            if web_service is not None:
                _add_edge(
                    graph,
                    web_service["id"],
                    endpoint_node["id"],
                    "serves-endpoint",
                    evidence_refs=[inventory_ref] if inventory_ref else [],
                )
            else:
                _add_edge(
                    graph,
                    host_node["id"],
                    endpoint_node["id"],
                    "hosts-endpoint",
                    evidence_refs=[inventory_ref] if inventory_ref else [],
                )

    _add_context_nodes(graph, normalized_inventory, inventory_ref)
    _add_bloodhound_confirmed_edges(graph, normalized_inventory, inventory_ref)
    return graph


def _ensure_host_node(
    graph: dict[str, Any],
    host_value: str,
    host_payload: dict[str, Any],
    inventory_ref: str | None,
) -> dict[str, Any]:
    host_key = host_value.lower()
    existing = graph["host_nodes_by_host"].get(host_key)
    if existing is not None:
        return existing

    host_node = _add_node(
        graph,
        {
            "id": f"host:{host_key}",
            "type": "host",
            "label": host_value,
            "confidence": _confidence(host_payload.get("confidence"), default=0.5),
            "source": "inventory",
            "metadata": {
                "host": host_value,
                "inventory_ref": inventory_ref,
                "source": host_payload.get("source"),
                "notes": host_payload.get("notes") if isinstance(host_payload.get("notes"), list) else [],
            },
        },
    )
    graph["host_nodes_by_host"][host_key] = host_node
    return host_node


def _add_finding_node(graph: dict[str, Any], finding: Finding) -> None:
    _add_node(
        graph,
        {
            "id": f"finding:{finding.id}",
            "type": "finding",
            "label": finding.title,
            "confidence": 1.0,
            "source": "finding",
            "metadata": {
                "finding_id": str(finding.id),
                "severity": finding.severity,
                "status": finding.status,
                "target_id": finding.target_id,
                "evidence_ref": finding.evidence_ref,
                "source_inventory_snapshot_id": (
                    str(finding.source_inventory_snapshot_id)
                    if finding.source_inventory_snapshot_id
                    else None
                ),
            },
        },
    )


def _add_context_nodes(
    graph: dict[str, Any],
    normalized_inventory: dict[str, Any],
    inventory_ref: str | None,
) -> None:
    for subject in _dict_list(normalized_inventory.get("identity_subjects")):
        label = _clean_string(
            subject.get("account_name") or subject.get("principal") or subject.get("dn")
        )
        if not label:
            continue
        key = _identity_key(label)
        node = _add_node(
            graph,
            {
                "id": f"identity-subject:{key}",
                "type": "identity_subject",
                "label": label,
                "confidence": _confidence(subject.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "principal": subject.get("principal"),
                    "dn": subject.get("dn"),
                    "enabled": subject.get("enabled"),
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["identity_subject_nodes_by_key"][key] = node
        for alias in (subject.get("principal"), subject.get("dn")):
            alias_key = _identity_key(alias)
            if alias_key:
                graph["identity_subject_nodes_by_key"].setdefault(alias_key, node)

    for group in _dict_list(normalized_inventory.get("identity_groups")):
        label = _clean_string(group.get("name") or group.get("dn"))
        if not label:
            continue
        key = _identity_key(label)
        node = _add_node(
            graph,
            {
                "id": f"identity-group:{key}",
                "type": "identity_group",
                "label": label,
                "confidence": _confidence(group.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "dn": group.get("dn"),
                    "member_count": group.get("member_count"),
                    "privileged": bool(group.get("privileged")),
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["identity_group_nodes_by_key"][key] = node
        alias_key = _identity_key(group.get("dn"))
        if alias_key:
            graph["identity_group_nodes_by_key"].setdefault(alias_key, node)

    for resource in _dict_list(normalized_inventory.get("cloud_resources")):
        resource_id = _clean_string(resource.get("resource_id"))
        if not resource_id:
            continue
        key = _cloud_key(
            resource.get("provider"),
            resource.get("account_id"),
            resource.get("region"),
            resource.get("resource_type"),
            resource_id,
        )
        node = _add_node(
            graph,
            {
                "id": f"cloud-resource:{key}",
                "type": "cloud_resource",
                "label": _clean_string(resource.get("name")) or resource_id,
                "confidence": _confidence(resource.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "provider": resource.get("provider"),
                    "account_id": resource.get("account_id"),
                    "region": resource.get("region"),
                    "resource_type": resource.get("resource_type"),
                    "resource_id": resource_id,
                    "state": resource.get("state"),
                    "metadata": _safe_dict(resource.get("metadata")),
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["cloud_resource_nodes_by_key"][key] = node
        graph["cloud_resource_nodes_by_key"].setdefault(_node_key(resource_id), node)

    for group in _dict_list(normalized_inventory.get("cloud_security_groups")):
        group_id = _clean_string(group.get("group_id"))
        if not group_id:
            continue
        key = _cloud_key(
            group.get("provider"),
            group.get("account_id"),
            group.get("region"),
            "security-group",
            group_id,
        )
        node = _add_node(
            graph,
            {
                "id": f"cloud-security-group:{key}",
                "type": "cloud_security_group",
                "label": _clean_string(group.get("group_name")) or group_id,
                "confidence": _confidence(group.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "provider": group.get("provider"),
                    "account_id": group.get("account_id"),
                    "region": group.get("region"),
                    "group_id": group_id,
                    "vpc_id": group.get("vpc_id"),
                    "rule_count": group.get("rule_count"),
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["cloud_security_group_nodes_by_key"][key] = node
        graph["cloud_security_group_nodes_by_key"].setdefault(_node_key(group_id), node)

    for principal in _dict_list(normalized_inventory.get("cloud_iam_principals")):
        principal_id = _clean_string(principal.get("principal_id") or principal.get("arn"))
        if not principal_id:
            continue
        key = _cloud_key(
            principal.get("provider"),
            principal.get("account_id"),
            principal.get("principal_type"),
            principal_id,
        )
        node = _add_node(
            graph,
            {
                "id": f"cloud-iam-principal:{key}",
                "type": "cloud_iam_principal",
                "label": _clean_string(principal.get("name")) or principal_id,
                "confidence": _confidence(principal.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "provider": principal.get("provider"),
                    "account_id": principal.get("account_id"),
                    "principal_type": principal.get("principal_type"),
                    "principal_id": principal_id,
                    "arn": principal.get("arn"),
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["cloud_iam_principal_nodes_by_key"][key] = node
        graph["cloud_iam_principal_nodes_by_key"].setdefault(_node_key(principal_id), node)
        graph["cloud_iam_principal_nodes_by_key"].setdefault(_node_key(principal.get("arn")), node)

    for policy in _dict_list(normalized_inventory.get("cloud_iam_policies")):
        policy_id = _clean_string(policy.get("policy_id") or policy.get("arn"))
        if not policy_id:
            continue
        key = _cloud_key(policy.get("provider"), policy.get("account_id"), policy_id)
        node = _add_node(
            graph,
            {
                "id": f"cloud-iam-policy:{key}",
                "type": "cloud_iam_policy",
                "label": _clean_string(policy.get("policy_name")) or policy_id,
                "confidence": _confidence(policy.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "provider": policy.get("provider"),
                    "account_id": policy.get("account_id"),
                    "policy_id": policy_id,
                    "arn": policy.get("arn"),
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["cloud_iam_policy_nodes_by_key"][key] = node
        graph["cloud_iam_policy_nodes_by_key"].setdefault(_node_key(policy_id), node)
        graph["cloud_iam_policy_nodes_by_key"].setdefault(_node_key(policy.get("arn")), node)

    for cluster in _dict_list(normalized_inventory.get("kubernetes_clusters")):
        cluster_id = _clean_string(cluster.get("cluster_id"))
        if not cluster_id:
            continue
        key = _cloud_key(
            cluster.get("provider"),
            cluster.get("account_id"),
            cluster.get("region"),
            cluster_id,
        )
        node = _add_node(
            graph,
            {
                "id": f"kubernetes-cluster:{key}",
                "type": "kubernetes_cluster",
                "label": _clean_string(cluster.get("name")) or cluster_id,
                "confidence": _confidence(cluster.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "provider": cluster.get("provider"),
                    "account_id": cluster.get("account_id"),
                    "region": cluster.get("region"),
                    "cluster_id": cluster_id,
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["kubernetes_cluster_nodes_by_key"][key] = node
        graph["kubernetes_cluster_nodes_by_key"].setdefault(_node_key(cluster_id), node)

    for workload in _dict_list(normalized_inventory.get("kubernetes_workloads")):
        cluster_id = _clean_string(workload.get("cluster_id"))
        workload_name = _clean_string(workload.get("name"))
        if not cluster_id or not workload_name:
            continue
        namespace = _clean_string(workload.get("namespace")) or "default"
        kind = _clean_string(workload.get("kind")) or "workload"
        key = _cloud_key(
            workload.get("provider"),
            workload.get("account_id"),
            cluster_id,
            namespace,
            kind,
            workload_name,
        )
        _add_node(
            graph,
            {
                "id": f"kubernetes-workload:{key}",
                "type": "kubernetes_workload",
                "label": f"{namespace}/{workload_name}",
                "confidence": _confidence(workload.get("confidence"), default=0.55),
                "source": "inventory",
                "metadata": {
                    "provider": workload.get("provider"),
                    "account_id": workload.get("account_id"),
                    "cluster_id": cluster_id,
                    "namespace": namespace,
                    "kind": kind,
                    "inventory_ref": inventory_ref,
                },
            },
        )
        graph["kubernetes_workload_nodes_by_key"][key] = graph["nodes_by_id"][f"kubernetes-workload:{key}"]


def _add_bloodhound_confirmed_edges(
    graph: dict[str, Any],
    normalized_inventory: dict[str, Any],
    inventory_ref: str | None,
) -> None:
    for edge_payload in _dict_list(normalized_inventory.get("bloodhound_confirmed_edges")):
        source_node = _ensure_bloodhound_edge_node(
            graph,
            node_id=edge_payload.get("source_id"),
            node_type=edge_payload.get("source_type"),
            label=edge_payload.get("source_label"),
            inventory_ref=inventory_ref,
        )
        target_node = _ensure_bloodhound_edge_node(
            graph,
            node_id=edge_payload.get("target_id"),
            node_type=edge_payload.get("target_type"),
            label=edge_payload.get("target_label"),
            inventory_ref=inventory_ref,
        )
        if source_node is None or target_node is None:
            continue
        _add_edge(
            graph,
            source_node["id"],
            target_node["id"],
            _clean_string(edge_payload.get("relationship")) or "bloodhound-edge",
            evidence_refs=[inventory_ref] if inventory_ref else [],
            confidence=_confidence(edge_payload.get("confidence"), default=0.75),
            rationale=_clean_string(edge_payload.get("rationale"))
            or "Stored BloodHound analysis confirms this Active Directory path relationship.",
        )


def _ensure_bloodhound_edge_node(
    graph: dict[str, Any],
    *,
    node_id: Any,
    node_type: Any,
    label: Any,
    inventory_ref: str | None,
) -> dict[str, Any] | None:
    normalized_id = _clean_string(node_id)
    if normalized_id:
        existing = graph["nodes_by_id"].get(normalized_id)
        if existing is not None:
            return existing

    normalized_label = _clean_string(label)
    normalized_type = _clean_string(node_type).lower()
    if not normalized_label:
        return None
    if normalized_type in {"host", "computer"}:
        return _ensure_host_node(
            graph,
            normalized_label,
            {"host": normalized_label, "confidence": 0.82},
            inventory_ref,
        )
    if normalized_type == "identity_group":
        key = _identity_key(normalized_label)
        node = graph["identity_group_nodes_by_key"].get(key)
        if node is not None:
            return node
        node = _add_node(
            graph,
            {
                "id": normalized_id or f"identity-group:{key}",
                "type": "identity_group",
                "label": normalized_label,
                "confidence": 0.82,
                "source": "inventory",
                "metadata": {"inventory_ref": inventory_ref},
            },
        )
        graph["identity_group_nodes_by_key"][key] = node
        return node
    key = _identity_key(normalized_label)
    node = graph["identity_subject_nodes_by_key"].get(key)
    if node is not None:
        return node
    node = _add_node(
        graph,
        {
            "id": normalized_id or f"identity-subject:{key}",
            "type": "identity_subject",
            "label": normalized_label,
            "confidence": 0.82,
            "source": "inventory",
            "metadata": {"inventory_ref": inventory_ref},
        },
    )
    graph["identity_subject_nodes_by_key"][key] = node
    return node


def _add_inferred_lateral_context(
    graph: dict[str, Any],
    *,
    normalized_inventory: dict[str, Any],
    inventory_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    inventory_ref = f"inventory:{inventory_snapshot['id']}" if inventory_snapshot else None
    notes: list[dict[str, Any]] = []

    for membership in _dict_list(normalized_inventory.get("privileged_memberships")):
        subject = graph["identity_subject_nodes_by_key"].get(_identity_key(membership.get("member")))
        group = graph["identity_group_nodes_by_key"].get(_identity_key(membership.get("group")))
        if subject is None or group is None:
            continue
        confidence = _combined_confidence(subject, group, membership)
        _add_edge(
            graph,
            subject["id"],
            group["id"],
            "inferred-privileged-membership",
            evidence_refs=[inventory_ref],
            classification="inferred",
            confidence=confidence,
            rationale=(
                "Read-only identity inventory indicates privileged membership; this is review-only "
                "context and does not perform credential reuse or lateral movement."
            ),
        )
        notes.append(
            _lateral_note(
                "identity-privilege-context",
                "Privileged identity relationship observed",
                f"{subject['label']} is linked to privileged group {group['label']} in stored inventory.",
                confidence,
                [inventory_ref],
            )
        )

    for attachment in _dict_list(normalized_inventory.get("cloud_iam_attachments")):
        principal = graph["cloud_iam_principal_nodes_by_key"].get(
            _node_key(attachment.get("principal_id"))
        )
        policy = graph["cloud_iam_policy_nodes_by_key"].get(_node_key(attachment.get("policy_id")))
        if principal is None or policy is None:
            continue
        confidence = _combined_confidence(principal, policy, attachment)
        _add_edge(
            graph,
            principal["id"],
            policy["id"],
            "inferred-iam-policy-attachment",
            evidence_refs=[inventory_ref],
            classification="inferred",
            confidence=confidence,
            rationale=(
                "Stored IAM attachment metadata links this principal and policy for review; "
                "AegisPT does not assume privileges, test credentials, or pivot from this edge."
            ),
        )
        notes.append(
            _lateral_note(
                "cloud-iam-attachment-context",
                "IAM attachment context observed",
                f"{principal['label']} is linked to policy {policy['label']} in stored cloud inventory.",
                confidence,
                [inventory_ref],
            )
        )

    for policy in _dict_list(normalized_inventory.get("cloud_iam_policies")):
        policy_node = graph["cloud_iam_policy_nodes_by_key"].get(_node_key(policy.get("policy_id")))
        attached_to = policy.get("attached_to") if isinstance(policy.get("attached_to"), list) else []
        for principal_id in attached_to:
            principal = graph["cloud_iam_principal_nodes_by_key"].get(_node_key(principal_id))
            if principal is None or policy_node is None:
                continue
            confidence = _combined_confidence(principal, policy_node, policy)
            _add_edge(
                graph,
                principal["id"],
                policy_node["id"],
                "inferred-iam-policy-attachment",
                evidence_refs=[inventory_ref],
                classification="inferred",
                confidence=confidence,
                rationale=(
                    "Stored IAM policy metadata lists this principal as attached; this remains "
                    "review-only context and does not execute cloud actions."
                ),
            )

    for resource in _dict_list(normalized_inventory.get("cloud_resources")):
        resource_node = graph["cloud_resource_nodes_by_key"].get(_node_key(resource.get("resource_id")))
        if resource_node is None:
            continue
        metadata = _safe_dict(resource.get("metadata"))
        for group_id in _string_list(metadata.get("security_group_ids")):
            group_node = graph["cloud_security_group_nodes_by_key"].get(_node_key(group_id))
            if group_node is None:
                continue
            confidence = _combined_confidence(resource_node, group_node, resource)
            _add_edge(
                graph,
                resource_node["id"],
                group_node["id"],
                "inferred-security-group-association",
                evidence_refs=[inventory_ref],
                classification="inferred",
                confidence=confidence,
                rationale=(
                    "Stored cloud metadata associates this resource with a security group; "
                    "the edge is analysis-only and does not mutate cloud resources."
                ),
            )
        for host_alias in _resource_host_aliases(resource):
            host_node = graph["host_nodes_by_host"].get(host_alias.lower())
            if host_node is None:
                continue
            confidence = _combined_confidence(host_node, resource_node, resource)
            _add_edge(
                graph,
                host_node["id"],
                resource_node["id"],
                "inferred-cloud-host-context",
                evidence_refs=[inventory_ref],
                classification="inferred",
                confidence=confidence,
                rationale=(
                    "The inventory host label matches stored cloud resource address metadata; "
                    "this does not broaden scope or trigger cloud-to-host exploitation."
                ),
            )

    for workload in _dict_list(normalized_inventory.get("kubernetes_workloads")):
        workload_key = _cloud_key(
            workload.get("provider"),
            workload.get("account_id"),
            workload.get("cluster_id"),
            _clean_string(workload.get("namespace")) or "default",
            _clean_string(workload.get("kind")) or "workload",
            workload.get("name"),
        )
        workload_node = graph["kubernetes_workload_nodes_by_key"].get(workload_key)
        cluster_node = graph["kubernetes_cluster_nodes_by_key"].get(
            _node_key(workload.get("cluster_id"))
        )
        if workload_node is None or cluster_node is None:
            continue
        confidence = _combined_confidence(workload_node, cluster_node, workload)
        _add_edge(
            graph,
            cluster_node["id"],
            workload_node["id"],
            "inferred-kubernetes-workload-context",
            evidence_refs=[inventory_ref],
            classification="inferred",
            confidence=confidence,
            rationale=(
                "Stored Kubernetes inventory places this workload in the cluster; this is "
                "review-only context and does not execute Kubernetes actions."
            ),
        )

    return {
        "status": "inferred_context_available" if graph["inferred_edges"] else "confirmed_only",
        "notes": _dedupe_lateral_notes(notes),
        "boundary": {
            "mode": "review_only_inference",
            "operator_review_required": True,
            "active_pivoting_performed": False,
            "credential_testing_performed": False,
            "lateral_movement_performed": False,
            "scope_expansion_performed": False,
            "automatic_dispatch_performed": False,
            "message": (
                "Inferred attack-path context is review-only. It does not authorize new scope, "
                "test credentials, pivot laterally, dispatch tasks, or mutate cloud or identity systems."
            ),
        },
    }


def _build_candidate_paths(
    graph: dict[str, Any],
    findings: list[Finding],
    inventory_snapshot: dict[str, Any] | None,
    *,
    normalized_inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    candidate_paths: list[dict[str, Any]] = _build_bloodhound_candidate_paths(
        graph,
        normalized_inventory=normalized_inventory,
        findings=findings,
        inventory_snapshot=inventory_snapshot,
    )
    consumed_findings = {
        str(path.get("finding_id") or "")
        for path in candidate_paths
        if str(path.get("finding_id") or "")
    }
    for finding in findings:
        if str(finding.id) in consumed_findings:
            continue
        finding_node_id = f"finding:{finding.id}"
        host, port, scheme = _target_host_port(finding.target_id)
        endpoint_node = graph["endpoint_nodes_by_url"].get(_normalized_url_key(finding.target_id))
        if endpoint_node is None and host:
            endpoint_node = _best_endpoint_for_host(graph, host)

        host_node = graph["host_nodes_by_host"].get(host.lower()) if host else None
        service_node = None
        if host and port is not None:
            service_node = graph["service_nodes_by_host_port"].get((host.lower(), port))
        if service_node is None and host and endpoint_node is not None:
            service_node = _service_for_endpoint(
                graph,
                host,
                endpoint_node.get("metadata", {}).get("port"),
                endpoint_node.get("metadata", {}).get("scheme") or scheme,
            )

        node_ids = []
        for node in (host_node, service_node, endpoint_node):
            if node is not None and node["id"] not in node_ids:
                node_ids.append(node["id"])
        node_ids.append(finding_node_id)

        if len(node_ids) > 1:
            previous = node_ids[-2]
            _add_edge(
                graph,
                previous,
                finding_node_id,
                "evidences-finding",
                evidence_refs=[finding.evidence_ref],
            )

        confidence = _path_confidence(graph["nodes_by_id"], node_ids, inventory_snapshot)
        candidate_paths.append(
            {
                "id": f"path:{len(candidate_paths) + 1}",
                "node_ids": node_ids,
                "labels": [
                    graph["nodes_by_id"][node_id]["label"]
                    for node_id in node_ids
                    if node_id in graph["nodes_by_id"]
                ],
                "finding_id": str(finding.id),
                "finding_title": finding.title,
                "severity": finding.severity,
                "target_id": finding.target_id,
                "confidence": confidence,
                "evidence_refs": [finding.evidence_ref],
                "explanation": _path_explanation(host_node, service_node, endpoint_node, finding),
            }
        )

    return candidate_paths


def _build_bloodhound_candidate_paths(
    graph: dict[str, Any],
    *,
    normalized_inventory: dict[str, Any],
    findings: list[Finding],
    inventory_snapshot: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    findings_by_signature = {
        (finding.title.strip().lower(), finding.target_id.strip().lower()): finding
        for finding in findings
    }
    candidate_paths: list[dict[str, Any]] = []
    for path_payload in _dict_list(normalized_inventory.get("bloodhound_attack_paths")):
        node_ids = [
            str(node_id).strip()
            for node_id in path_payload.get("node_ids", [])
            if isinstance(node_id, str) and str(node_id).strip()
        ]
        node_ids = [node_id for node_id in node_ids if node_id in graph["nodes_by_id"]]
        if not node_ids:
            continue
        finding = findings_by_signature.get(
            (
                _clean_string(path_payload.get("finding_title")).lower(),
                _clean_string(path_payload.get("finding_target_id")).lower(),
            )
        )
        if finding is not None:
            finding_node_id = f"finding:{finding.id}"
            if finding_node_id not in node_ids:
                _add_edge(
                    graph,
                    node_ids[-1],
                    finding_node_id,
                    "evidences-finding",
                    evidence_refs=[finding.evidence_ref],
                    confidence=_confidence(path_payload.get("confidence"), default=0.75),
                    rationale="Stored BloodHound path evidence is linked to the normalized finding record.",
                )
                node_ids = [*node_ids, finding_node_id]
        candidate_paths.append(
            {
                "id": str(path_payload.get("path_id") or f"path:{len(candidate_paths) + 1}"),
                "node_ids": node_ids,
                "labels": [
                    graph["nodes_by_id"][node_id]["label"]
                    for node_id in node_ids
                    if node_id in graph["nodes_by_id"]
                ],
                "finding_id": str(finding.id) if finding is not None else None,
                "finding_title": (
                    finding.title
                    if finding is not None
                    else _clean_string(path_payload.get("finding_title"))
                ),
                "severity": (
                    finding.severity
                    if finding is not None
                    else _clean_string(path_payload.get("severity")) or "high"
                ),
                "target_id": (
                    finding.target_id
                    if finding is not None
                    else _clean_string(path_payload.get("finding_target_id"))
                ),
                "confidence": _confidence(
                    path_payload.get("confidence"),
                    default=_path_confidence(graph["nodes_by_id"], node_ids, inventory_snapshot),
                ),
                "evidence_refs": [finding.evidence_ref] if finding is not None else [],
                "explanation": _clean_string(path_payload.get("summary"))
                or "Stored BloodHound analysis supplied this confirmed Active Directory path.",
            }
        )
    return candidate_paths


def _build_choke_points(
    nodes_by_id: dict[str, dict[str, Any]],
    candidate_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    path_counts: Counter[str] = Counter()
    finding_ids_by_node: dict[str, set[str]] = {}
    severity_by_node: dict[str, Counter[str]] = {}

    for path in candidate_paths:
        finding_id = str(path.get("finding_id") or "")
        severity = str(path.get("severity") or "unknown")
        for node_id in path.get("node_ids", []):
            node = nodes_by_id.get(node_id)
            if node is None or node.get("type") == "finding":
                continue
            path_counts[node_id] += 1
            finding_ids_by_node.setdefault(node_id, set()).add(finding_id)
            severity_by_node.setdefault(node_id, Counter())[severity] += 1

    choke_points: list[dict[str, Any]] = []
    for node_id, path_count in path_counts.items():
        if path_count < CHOKE_POINT_PATH_THRESHOLD:
            continue
        node = nodes_by_id[node_id]
        choke_points.append(
            {
                "node_id": node_id,
                "type": node["type"],
                "label": node["label"],
                "path_count": path_count,
                "finding_count": len(finding_ids_by_node.get(node_id, set())),
                "affected_findings": sorted(finding_ids_by_node.get(node_id, set())),
                "severity_breakdown": dict(severity_by_node.get(node_id, Counter())),
                "summary": (
                    f"{node['label']} appears in {path_count} candidate paths; "
                    "reviewing this point first may close multiple evidence-backed routes."
                ),
            }
        )

    return sorted(choke_points, key=lambda item: (-item["path_count"], item["type"], item["label"]))


def _add_node(graph: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    existing = graph["nodes_by_id"].get(node["id"])
    if existing is not None:
        return existing
    graph["nodes_by_id"][node["id"]] = node
    graph["nodes"].append(node)
    return node


def _add_edge(
    graph: dict[str, Any],
    source: str,
    target: str,
    relationship: str,
    *,
    evidence_refs: list[str],
    classification: str = "confirmed",
    confidence: float = 1.0,
    rationale: str | None = None,
) -> None:
    edge_key = (source, target, relationship)
    if edge_key in graph["edge_keys"]:
        return
    graph["edge_keys"].add(edge_key)
    normalized_classification = (
        "inferred" if str(classification).lower() == "inferred" else "confirmed"
    )
    edge = {
        "id": f"edge:{len(graph['edges']) + 1}",
        "source": source,
        "target": target,
        "type": relationship,
        "classification": normalized_classification,
        "confidence": _confidence(confidence, default=0.5),
        "rationale": rationale
        or (
            "Stored selected-run evidence confirms this relationship."
            if normalized_classification == "confirmed"
            else "Stored selected-run evidence supports this review-only inferred relationship."
        ),
        "evidence_refs": [ref for ref in evidence_refs if ref],
    }
    if normalized_classification == "inferred":
        edge["operator_review_required"] = True
        edge["active_pivoting_performed"] = False
        edge["credential_testing_performed"] = False
        edge["lateral_movement_performed"] = False
        edge["scope_expansion_performed"] = False
        edge["automatic_dispatch_performed"] = False
        graph["inferred_edges"].append(edge)
    graph["edges"].append(edge)


def _service_for_endpoint(
    graph: dict[str, Any],
    host: str | None,
    endpoint_port: int | None,
    scheme: str | None,
) -> dict[str, Any] | None:
    if not host:
        return None
    port = endpoint_port
    if port is None and scheme:
        port = DEFAULT_WEB_PORTS.get(scheme.lower())
    if port is not None:
        service = graph["service_nodes_by_host_port"].get((host.lower(), port))
        if service is not None:
            return service

    web_services = [
        service
        for service in graph["service_nodes_by_host"].get(host.lower(), [])
        if _looks_like_web_service(service)
    ]
    return web_services[0] if web_services else None


def _best_endpoint_for_host(graph: dict[str, Any], host: str) -> dict[str, Any] | None:
    endpoints = graph["endpoint_nodes_by_host"].get(host.lower(), [])
    return endpoints[0] if endpoints else None


def _looks_like_web_service(service_node: dict[str, Any]) -> bool:
    metadata = service_node.get("metadata", {})
    service_name = _clean_string(metadata.get("service")).lower()
    port = metadata.get("port")
    return port in {80, 443, 8000, 8080, 8443} or "http" in service_name or "web" in service_name


def _target_host_port(value: Any) -> tuple[str | None, int | None, str | None]:
    raw_value = _clean_string(value)
    if not raw_value:
        return None, None, None

    if "://" in raw_value:
        parsed = urlparse(raw_value)
        return parsed.hostname, parsed.port, parsed.scheme or None

    if ":" in raw_value:
        host_part, port_part = raw_value.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip() or None, int(port_part), None

    return raw_value, None, None


def _normalized_url_key(value: Any) -> str:
    normalized = _clean_string(value).lower()
    return normalized[:-1] if normalized.endswith("/") else normalized


def _path_confidence(
    nodes_by_id: dict[str, dict[str, Any]],
    node_ids: list[str],
    inventory_snapshot: dict[str, Any] | None,
) -> float:
    if len(node_ids) == 1:
        return 0.35 if inventory_snapshot is None else 0.45

    confidences = [
        float(nodes_by_id[node_id].get("confidence") or 0.0)
        for node_id in node_ids
        if node_id in nodes_by_id and nodes_by_id[node_id].get("type") != "finding"
    ]
    if not confidences:
        return 0.35
    return round(max(0.1, min(confidences)), 3)


def _path_explanation(
    host_node: dict[str, Any] | None,
    service_node: dict[str, Any] | None,
    endpoint_node: dict[str, Any] | None,
    finding: Finding,
) -> str:
    if endpoint_node is not None:
        return (
            f"Finding '{finding.title}' is tied to endpoint {endpoint_node['label']} "
            "through the selected run inventory."
        )
    if service_node is not None:
        return (
            f"Finding '{finding.title}' is tied to exposed service {service_node['label']} "
            "through the selected run inventory."
        )
    if host_node is not None:
        return (
            f"Finding '{finding.title}' is tied to host {host_node['label']} "
            "through the selected run inventory."
        )
    return (
        f"Finding '{finding.title}' has no matching selected-run inventory node yet; "
        "the path is retained as low-confidence finding-only evidence."
    )


def _summary_status(
    inventory_snapshot: dict[str, Any] | None,
    findings: list[Finding],
    candidate_paths: list[dict[str, Any]],
) -> str:
    if inventory_snapshot is None and not findings:
        return "empty"
    if not candidate_paths:
        return "empty"
    if any(len(path.get("node_ids", [])) == 1 for path in candidate_paths):
        return "low_confidence"
    return "ready"


def _summary_reason(
    status: str,
    inventory_snapshot: dict[str, Any] | None,
    findings: list[Finding],
) -> str:
    if status == "ready":
        return "Candidate paths were derived from selected-run inventory and finding evidence."
    if status == "low_confidence":
        return "Some findings could not be matched to selected-run inventory nodes, so their paths remain low-confidence."
    if inventory_snapshot is not None and not findings:
        return "Selected-run inventory exists, but no findings are available to derive candidate attack paths yet."
    return "No selected-run inventory or finding evidence is available for attack-path derivation yet."


def _lateral_note(
    note_id: str,
    title: str,
    description: str,
    confidence: float,
    source_refs: list[str | None],
) -> dict[str, Any]:
    return {
        "id": note_id,
        "title": title,
        "description": description,
        "confidence": _confidence(confidence, default=0.5),
        "source_refs": [ref for ref in source_refs if ref],
        "operator_review_required": True,
        "active_pivoting_performed": False,
        "credential_testing_performed": False,
        "scope_expansion_performed": False,
    }


def _dedupe_lateral_notes(notes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for note in notes:
        key = (str(note.get("id") or ""), str(note.get("description") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(note)
    return deduped


def _combined_confidence(*items: Any) -> float:
    values: list[float] = []
    for item in items:
        if isinstance(item, dict):
            value = item.get("confidence")
        else:
            value = item
        if isinstance(value, (int, float)):
            values.append(_confidence(value, default=0.5))
    if not values:
        return 0.5
    return round(max(0.1, min(values)), 3)


def _resource_host_aliases(resource: dict[str, Any]) -> list[str]:
    metadata = _safe_dict(resource.get("metadata"))
    aliases = [
        resource.get("resource_id"),
        resource.get("name"),
        metadata.get("public_ip"),
        metadata.get("private_ip"),
        metadata.get("public_dns"),
        metadata.get("private_dns"),
        metadata.get("dns_name"),
    ]
    return _dedupe_strings([_clean_string(alias) for alias in aliases if _clean_string(alias)])


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clean_string(item) for item in value if _clean_string(item)]


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = _clean_string(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _identity_key(value: Any) -> str:
    return _node_key(value).lower()


def _cloud_key(*parts: Any) -> str:
    return ":".join(_node_key(part) for part in parts if _node_key(part))


def _node_key(value: Any) -> str:
    cleaned = _clean_string(value).lower()
    if not cleaned:
        return ""
    return "".join(character if character.isalnum() else "-" for character in cleaned).strip("-")


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _clean_string(value: Any) -> str:
    return str(value or "").strip()


def _integer_or_none(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _confidence(value: Any, *, default: float) -> float:
    if isinstance(value, (int, float)):
        return round(max(0.0, min(float(value), 1.0)), 3)
    return default
