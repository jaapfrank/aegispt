from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from api.app.models import Run
from api.app.services.assessment_graph import build_normalized_evidence_graph

SAAS_IDENTITY_TRUST_VERSION = "saas-identity-trust-chain-v1"
EXCESSIVE_SCOPE_TERMS = {
    "admin",
    "all",
    "delete",
    "export",
    "files:read:all",
    "offline",
    "read:all",
    "write",
}


def build_saas_identity_trust_model(
    session: Session,
    *,
    run: Run | None = None,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    graph = build_normalized_evidence_graph(session, run=run, run_id=run_id)
    return build_saas_identity_trust_model_from_graph(graph)


def build_saas_identity_trust_model_from_graph(graph: dict[str, Any]) -> dict[str, Any]:
    source_nodes = [node for node in graph.get("nodes", []) if isinstance(node, dict)]
    trust_nodes: dict[str, dict[str, Any]] = {}
    trust_edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    connectors = [node for node in source_nodes if node.get("type") == "saas_connector"]
    identities = [node for node in source_nodes if _is_service_account(node)]
    scopes = [node for node in source_nodes if node.get("type") == "permission"]

    for connector in connectors:
        app_node = _upsert_node(
            trust_nodes,
            node_type="saas_app",
            source=connector,
            label=_connector_app_label(connector),
            subtype="imported_saas_app",
        )
        oauth_node = _upsert_node(
            trust_nodes,
            node_type="oauth_client",
            source=connector,
            label=_oauth_client_label(connector),
            subtype="imported_oauth_client",
        )
        connector_node = _upsert_node(
            trust_nodes,
            node_type="connector",
            source=connector,
            label=str(connector.get("label") or "SaaS connector"),
            subtype=str(connector.get("subtype") or "connector"),
        )
        _add_edge(trust_edges, app_node, oauth_node, "registers_oauth_client", connector)
        _add_edge(trust_edges, oauth_node, connector_node, "authorizes_connector", connector)

        dataset_value = _dataset_label(connector)
        if dataset_value:
            dataset_node = _upsert_synthetic_node(
                trust_nodes,
                node_type="dataset",
                source=connector,
                label=dataset_value,
                subtype="imported_dataset",
                data={"dataset": dataset_value, "sensitivity": _dataset_sensitivity(dataset_value)},
            )
            _add_edge(trust_edges, connector_node, dataset_node, "can_reach_dataset", connector)

        for identity in identities:
            identity_node = _upsert_node(
                trust_nodes,
                node_type="service_account",
                source=identity,
                label=str(identity.get("label") or "Service account"),
                subtype=str(identity.get("subtype") or "service_account"),
            )
            _add_edge(trust_edges, connector_node, identity_node, "uses_service_account", identity)

        for scope in scopes:
            scope_node = _upsert_node(
                trust_nodes,
                node_type="oauth_scope",
                source=scope,
                label=str(scope.get("label") or "OAuth scope"),
                subtype=str(scope.get("subtype") or "scope"),
            )
            _add_edge(trust_edges, oauth_node, scope_node, "grants_scope", scope)
            if _is_excessive_scope(scope):
                scope_node["flags"].append(
                    {
                        "type": "excessive_scope",
                        "severity": "high",
                        "reason": "Scope text indicates broad read/write/export/admin access.",
                        "evidence_refs": _string_list(scope.get("evidence_refs")),
                    }
                )

    flags = _trust_flags(trust_nodes)
    paths = _risk_paths(trust_nodes, trust_edges, flags)
    return {
        "trust_chain_version": SAAS_IDENTITY_TRUST_VERSION,
        "source_graph_version": graph.get("graph_version"),
        "run_id": graph.get("run_id"),
        "summary": {
            "node_count": len(trust_nodes),
            "edge_count": len(trust_edges),
            "risk_path_count": len(paths),
            "flag_count": len(flags),
            "node_types": sorted({node["type"] for node in trust_nodes.values()}),
        },
        "execution_contract": {
            "analysis_only": True,
            "read_only_imported_evidence": True,
            "uses_tokens": False,
            "uses_credentials": False,
            "materializes_secrets": False,
            "mutates_saas_api": False,
            "simulates_exfiltration": False,
            "dispatches_work_directly": False,
            "creates_tasks": False,
            "approves_proposals": False,
            "mutates_scope": False,
            "runtime_self_modification": False,
        },
        "nodes": sorted(trust_nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(trust_edges.values(), key=lambda item: (item["source"], item["relationship"], item["target"])),
        "flags": flags,
        "risk_paths": paths,
    }


def _upsert_node(
    nodes: dict[str, dict[str, Any]],
    *,
    node_type: str,
    source: dict[str, Any],
    label: str,
    subtype: str,
) -> dict[str, Any]:
    return _upsert_synthetic_node(
        nodes,
        node_type=node_type,
        source=source,
        label=label,
        subtype=subtype,
        data=_safe_dict(source.get("data")),
    )


def _upsert_synthetic_node(
    nodes: dict[str, dict[str, Any]],
    *,
    node_type: str,
    source: dict[str, Any],
    label: str,
    subtype: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    source_id = str(source.get("source_id") or source.get("id") or label)
    node_id = f"trust:{node_type}:{_slug(source_id)}:{_slug(label)}"
    existing = nodes.get(node_id)
    if existing is not None:
        existing["evidence_refs"] = sorted(set(existing["evidence_refs"]) | set(_string_list(source.get("evidence_refs"))))
        existing["source_ids"] = sorted(set(existing["source_ids"]) | set(_string_list(source.get("source_ids"))))
        return existing
    node = {
        "id": node_id,
        "type": node_type,
        "subtype": subtype,
        "label": label,
        "confidence": _confidence(source),
        "evidence_refs": _string_list(source.get("evidence_refs")),
        "source_ids": _string_list(source.get("source_ids")) or [source_id],
        "data": data,
        "flags": [],
        "provenance": {
            "source": "normalized_evidence_graph",
            "source_node_id": source.get("id"),
            "imported_evidence_only": True,
        },
    }
    nodes[node_id] = node
    return node


def _add_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    source: dict[str, Any],
    target: dict[str, Any],
    relationship: str,
    evidence_source: dict[str, Any],
) -> None:
    key = (source["id"], relationship, target["id"])
    refs = sorted(
        set(source.get("evidence_refs", []))
        | set(target.get("evidence_refs", []))
        | set(_string_list(evidence_source.get("evidence_refs")))
    )
    edges[key] = {
        "id": f"trust-edge:{_slug(source['id'])}:{_slug(relationship)}:{_slug(target['id'])}",
        "source": source["id"],
        "target": target["id"],
        "relationship": relationship,
        "confidence": round(min(float(source.get("confidence") or 0.0), float(target.get("confidence") or 0.0)), 2),
        "evidence_refs": refs,
        "provenance": {
            "source": "imported_saas_identity_evidence",
            "source_node_id": evidence_source.get("id"),
            "token_use": False,
            "saas_api_mutation": False,
            "exfiltration_simulation": False,
        },
    }


def _trust_flags(nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    flags: list[dict[str, Any]] = []
    has_connector = any(node["type"] == "connector" for node in nodes.values())
    has_identity = any(node["type"] == "service_account" for node in nodes.values())
    has_dataset = any(node["type"] == "dataset" for node in nodes.values())
    excessive_scopes = [
        node
        for node in nodes.values()
        if any(flag.get("type") == "excessive_scope" for flag in node.get("flags", []))
    ]
    for node in excessive_scopes:
        flags.extend(
            {
                "id": f"flag:{_slug(node['id'])}:{_slug(flag['type'])}",
                "type": flag["type"],
                "severity": flag["severity"],
                "node_id": node["id"],
                "reason": flag["reason"],
                "evidence_refs": flag["evidence_refs"],
            }
            for flag in node.get("flags", [])
        )
    if has_connector and has_identity and has_dataset:
        refs = sorted({ref for node in nodes.values() for ref in _string_list(node.get("evidence_refs"))})
        flags.append(
            {
                "id": "flag:cross-system-trust:connector-service-account-dataset",
                "type": "cross_system_trust",
                "severity": "medium",
                "node_id": None,
                "reason": "Imported evidence links a SaaS connector, service account, and reachable dataset.",
                "evidence_refs": refs,
            }
        )
    return sorted(flags, key=lambda item: (item["type"], item["id"]))


def _risk_paths(
    nodes: dict[str, dict[str, Any]],
    edges: dict[tuple[str, str, str], dict[str, Any]],
    flags: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not flags:
        return []
    by_type: dict[str, list[dict[str, Any]]] = {}
    for node in nodes.values():
        by_type.setdefault(node["type"], []).append(node)
    required = ["saas_app", "oauth_client", "connector", "service_account", "oauth_scope", "dataset"]
    if not all(by_type.get(node_type) for node_type in required):
        return []
    path_nodes = [by_type[node_type][0] for node_type in required]
    evidence_refs = sorted({ref for node in path_nodes for ref in _string_list(node.get("evidence_refs"))})
    edge_ids = [
        edge["id"]
        for edge in edges.values()
        if edge["source"] in {node["id"] for node in path_nodes}
        and edge["target"] in {node["id"] for node in path_nodes}
    ]
    return [
        {
            "id": "risk-path:saas-oauth-connector-service-account-dataset",
            "path_type": "saas_identity_trust_chain",
            "node_ids": [node["id"] for node in path_nodes],
            "edge_ids": sorted(edge_ids),
            "confidence": round(min(float(node.get("confidence") or 0.0) for node in path_nodes), 2),
            "risk_summary": "Evidence-backed SaaS/OAuth connector chain reaches a dataset through a service account and broad scope.",
            "flags": [flag["id"] for flag in flags],
            "evidence_refs": evidence_refs,
            "provenance": {
                "source": "imported_configuration_and_evidence",
                "token_use": False,
                "saas_api_mutation": False,
                "exfiltration_simulation": False,
            },
        }
    ]


def _connector_app_label(node: dict[str, Any]) -> str:
    data = _safe_dict(node.get("data"))
    label = str(data.get("app") or data.get("application") or data.get("provider") or node.get("label") or "SaaS app")
    return label.replace("connector", "").strip() or label


def _oauth_client_label(node: dict[str, Any]) -> str:
    data = _safe_dict(node.get("data"))
    return str(data.get("client_id") or data.get("oauth_client") or data.get("name") or node.get("label") or "OAuth client")


def _dataset_label(node: dict[str, Any]) -> str | None:
    data = _safe_dict(node.get("data"))
    value = data.get("target_dataset") or data.get("dataset") or data.get("records")
    return str(value).strip() if value else None


def _dataset_sensitivity(label: str) -> str:
    lowered = label.lower()
    if any(term in lowered for term in ("sensitive", "customer", "record", "export", "pii")):
        return "sensitive"
    return "unknown"


def _is_service_account(node: dict[str, Any]) -> bool:
    if node.get("type") != "identity":
        return False
    text = " ".join(
        str(value)
        for value in (
            node.get("label"),
            node.get("subtype"),
            _safe_dict(node.get("data")).get("type"),
            _safe_dict(node.get("data")).get("subject"),
        )
    ).lower()
    return "service" in text or "oauth" in text or "connector" in text


def _is_excessive_scope(node: dict[str, Any]) -> bool:
    text = f"{node.get('label')} {_safe_dict(node.get('data'))}".lower()
    return any(term in text for term in EXCESSIVE_SCOPE_TERMS)


def _confidence(node: dict[str, Any]) -> float:
    try:
        value = float(node.get("confidence") or 0.7)
    except (TypeError, ValueError):
        return 0.7
    return round(max(0.0, min(1.0, value)), 2)


def _safe_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple | set):
        return [str(item) for item in value if str(item)]
    return [str(value)] if str(value) else []


def _slug(value: object) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value)).strip("-")[:96] or "item"
