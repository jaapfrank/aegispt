from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from io import BytesIO
from typing import Any
from zipfile import BadZipFile, ZipFile

USEFUL_ACE_RIGHTS = frozenset(
    {
        "addallowedtoact",
        "addkeycredentiallink",
        "addmember",
        "adminTo".lower(),
        "allExtendedRights".lower(),
        "allowedtoact".lower(),
        "canchangepassword",
        "canpsremote",
        "canrdp",
        "executedcom",
        "forcechangepassword",
        "genericall",
        "genericwrite",
        "gpLink".lower(),
        "hasSession".lower(),
        "owns",
        "readlapspassword",
        "writedacl",
        "writeowner",
        "writespn",
    }
)
HIGH_VALUE_GROUP_NAMES = {
    "domain admins": "domain_admins",
    "enterprise admins": "enterprise_admins",
}
PRIVILEGED_GROUP_NAMES = frozenset(
    {
        "account operators",
        "administrators",
        "backup operators",
        "domain admins",
        "domain controllers",
        "enterprise admins",
        "schema admins",
        "server operators",
    }
)
LIST_RELATIONSHIP_KEYS = {
    "AllowedToAct": "allowed-to-act",
    "AllowedToDelegate": "allowed-to-delegate",
    "CanPSRemote": "psremote-to",
    "CanRDP": "rdp-to",
    "ExecuteDCOM": "execute-dcom",
    "HasSession": "has-session",
    "LocalAdmins": "admin-to",
    "PSRemoteUsers": "psremote-to",
    "RemoteDesktopUsers": "rdp-to",
}
MAX_ATTACK_PATHS = 25
MAX_PATH_DEPTH = 6
CHOKE_POINT_THRESHOLD = 3


def analyze_bloodhound_collection(
    *,
    zip_bytes: bytes,
    target_id: str,
    collection_methods: list[str] | None = None,
    collector_label: str | None = None,
) -> dict[str, Any]:
    archive_entries = _load_bloodhound_archive(zip_bytes)
    objects = _collect_objects(archive_entries)
    edge_records, privileged_memberships = _collect_edges(archive_entries, objects)
    attack_paths = _derive_attack_paths(objects, edge_records)
    path_edge_records = _edge_records_from_paths(attack_paths)
    choke_points = _derive_choke_points(attack_paths)

    identity_subjects = [_identity_subject_payload(entry) for entry in objects.values() if entry["kind"] == "user"]
    identity_groups = [_identity_group_payload(entry) for entry in objects.values() if entry["kind"] == "group"]
    hosts = [_host_payload(entry) for entry in objects.values() if entry["kind"] == "computer"]
    kerberoastable_accounts = [
        _kerberoastable_account_payload(entry)
        for entry in objects.values()
        if entry["kind"] == "user" and entry["enabled"] is not False and entry["service_principal_names"]
    ]
    asrep_roastable_accounts = [
        _asrep_account_payload(entry)
        for entry in objects.values()
        if entry["kind"] == "user" and entry["enabled"] is not False and entry["dontreqpreauth"]
    ]

    analysis_findings = [
        *[
            {
                "finding_type": "attack_path",
                "title": path["finding_title"],
                "severity": path["severity"],
                "target_id": path["finding_target_id"],
                "summary": path["summary"],
                "methodology_tags": [
                    "active_directory",
                    "bloodhound",
                    "attack_path_analysis",
                    "credential_access",
                    "privilege_escalation",
                    "T1069.002",
                ],
                "ptes_phase": "exploitation",
                "nist_phase": "privilege_escalation",
                "wstg_id": "WSTG-ATHZ-01",
                "control_family": "authorization",
            }
            for path in attack_paths
        ],
        *[
            {
                "finding_type": choke["kind"],
                "title": (
                    "AD choke point principal appears in 3+ BloodHound paths"
                    if choke["kind"] == "principal_choke_point"
                    else "AD choke point ACE appears in 3+ BloodHound paths"
                ),
                "severity": "high" if int(choke["path_count"]) >= 5 else "medium",
                "target_id": choke["target_id"],
                "summary": choke["summary"],
                "methodology_tags": [
                    "active_directory",
                    "bloodhound",
                    "attack_path_analysis",
                    "choke_point",
                    "T1069.002",
                ],
                "ptes_phase": "exploitation",
                "nist_phase": "privilege_escalation",
                "wstg_id": "WSTG-ATHZ-01",
                "control_family": "authorization",
            }
            for choke in choke_points
        ],
        *[
            {
                "finding_type": "kerberoastable_account",
                "title": "Kerberoastable account exposure observed",
                "severity": "medium",
                "target_id": account["account_name"],
                "summary": (
                    f"Read-only BloodHound collection observed enabled account {account['account_name']} "
                    "with service principal names. No Kerberos ticket request or cracking was performed."
                ),
                "methodology_tags": [
                    "active_directory",
                    "bloodhound",
                    "authentication",
                    "credential_access",
                    "T1558.003",
                ],
                "ptes_phase": "exploitation",
                "nist_phase": "credential_access",
                "wstg_id": "WSTG-ATHN",
                "control_family": "authentication",
            }
            for account in kerberoastable_accounts
        ],
        *[
            {
                "finding_type": "asrep_roastable_account",
                "title": "AS-REP roastable account exposure observed",
                "severity": "high",
                "target_id": account["account_name"],
                "summary": (
                    f"Read-only BloodHound collection observed enabled account {account['account_name']} "
                    "without Kerberos pre-authentication. No AS-REP request or cracking was performed."
                ),
                "methodology_tags": [
                    "active_directory",
                    "bloodhound",
                    "authentication",
                    "credential_access",
                    "T1558.004",
                ],
                "ptes_phase": "exploitation",
                "nist_phase": "credential_access",
                "wstg_id": "WSTG-ATHN",
                "control_family": "authentication",
            }
            for account in asrep_roastable_accounts
        ],
    ]

    return {
        "tool": "bloodhound-collect",
        "status": "ok",
        "read_only": True,
        "targets": [
            {
                "target": target_id,
                "status": "ok",
                "domain": _dominant_domain(objects.values()),
                "collection_methods": collection_methods or ["All"],
                "collector_label": collector_label,
                "hosts": hosts,
                "identity_subjects": identity_subjects,
                "identity_groups": identity_groups,
                "privileged_memberships": privileged_memberships,
                "bloodhound_confirmed_edges": path_edge_records,
                "bloodhound_attack_paths": attack_paths,
                "analysis_findings": analysis_findings,
                "kerberoastable_accounts": kerberoastable_accounts,
                "asrep_roastable_accounts": asrep_roastable_accounts,
                "summary": {
                    "archive_file_count": len(archive_entries),
                    "object_count": len(objects),
                    "raw_edge_count": len(edge_records),
                    "confirmed_edge_count": len(path_edge_records),
                    "attack_path_count": len(attack_paths),
                    "choke_point_count": len(choke_points),
                    "kerberoastable_account_count": len(kerberoastable_accounts),
                    "asrep_roastable_account_count": len(asrep_roastable_accounts),
                    "high_value_target_count": len(
                        [entry for entry in objects.values() if entry["high_value_category"]]
                    ),
                },
            }
        ],
        "summary": {
            "target_count": 1,
            "attack_path_count": len(attack_paths),
            "confirmed_edge_count": len(path_edge_records),
            "finding_count": len(analysis_findings),
        },
    }


def _load_bloodhound_archive(zip_bytes: bytes) -> list[dict[str, Any]]:
    try:
        with ZipFile(BytesIO(zip_bytes)) as archive:
            loaded: list[dict[str, Any]] = []
            for name in archive.namelist():
                if not name.lower().endswith(".json"):
                    continue
                payload = json.loads(archive.read(name).decode("utf-8", errors="replace"))
                if not isinstance(payload, dict):
                    continue
                loaded.append(
                    {
                        "name": name,
                        "type": _archive_type(name, payload),
                        "data": payload.get("data") if isinstance(payload.get("data"), list) else [],
                    }
                )
            return loaded
    except (BadZipFile, OSError, json.JSONDecodeError) as exc:
        raise ValueError("BloodHound collection must be a valid ZIP containing JSON payloads") from exc


def _archive_type(name: str, payload: dict[str, Any]) -> str:
    meta = payload.get("meta")
    if isinstance(meta, dict):
        value = str(meta.get("type") or "").strip().lower()
        if value:
            return value
    lowered = name.lower()
    for candidate in ("users", "groups", "computers", "domains", "gpos", "containers"):
        if candidate in lowered:
            return candidate
    return "unknown"


def _collect_objects(archive_entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    objects: dict[str, dict[str, Any]] = {}
    for archive in archive_entries:
        entry_type = str(archive.get("type") or "").strip().lower()
        for entry in archive.get("data", []):
            if not isinstance(entry, dict):
                continue
            object_id = _object_identifier(entry)
            if not object_id:
                continue
            normalized = _normalize_object(entry, entry_type)
            if normalized is None:
                continue
            objects.setdefault(object_id, normalized)
    return objects


def _normalize_object(entry: dict[str, Any], entry_type: str) -> dict[str, Any] | None:
    if entry_type not in {"users", "groups", "computers", "domains"}:
        return None
    props = dict(entry.get("Properties") or {})
    kind = {
        "users": "user",
        "groups": "group",
        "computers": "computer",
        "domains": "domain",
    }[entry_type]
    raw_name = _first_text(
        props.get("name"),
        props.get("samaccountname"),
        props.get("displayname"),
        props.get("domain"),
        entry.get("Name"),
    )
    if not raw_name:
        return None
    display_label = _display_label(raw_name, kind=kind)
    distinguished_name = _first_text(props.get("distinguishedname"), props.get("distinguishedName"))
    dns_host_name = _first_text(props.get("dnshostname"), props.get("dnsHostName"))
    service_principal_names = _string_list(
        props.get("serviceprincipalnames")
        or props.get("servicePrincipalNames")
        or props.get("spns")
    )
    high_value_category = _high_value_category(
        display_label=display_label,
        kind=kind,
        high_value=bool(props.get("highvalue")),
        distinguished_name=distinguished_name,
    )
    return {
        "object_id": _object_identifier(entry),
        "kind": kind,
        "raw_name": raw_name,
        "display_label": display_label,
        "domain": _domain_hint(raw_name, distinguished_name),
        "enabled": _bool_or_none(props.get("enabled")),
        "high_value": bool(props.get("highvalue")),
        "high_value_category": high_value_category,
        "dns_host_name": dns_host_name.lower() if dns_host_name else None,
        "distinguished_name": distinguished_name,
        "service_principal_names": service_principal_names,
        "dontreqpreauth": bool(
            props.get("dontreqpreauth")
            or props.get("dontreqpreauth")
            or props.get("DoesNotRequirePreAuth")
        ),
        "aegis_node_id": _aegis_node_id(
            kind=kind,
            display_label=display_label,
            dns_host_name=dns_host_name,
        ),
        "aegis_node_type": "host" if kind == "computer" else (
            "identity_group" if kind == "group" else "identity_subject"
        ),
    }


def _collect_edges(
    archive_entries: list[dict[str, Any]],
    objects: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    edge_records: list[dict[str, Any]] = []
    privileged_memberships: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    seen_privileged: set[tuple[str, str]] = set()

    def add_edge(
        source_id: str | None,
        target_id: str | None,
        relationship: str,
        *,
        confidence: float,
        rationale: str,
        relationship_label: str | None = None,
    ) -> None:
        if not source_id or not target_id:
            return
        source_object = objects.get(source_id)
        target_object = objects.get(target_id)
        if source_object is None or target_object is None:
            return
        if source_object["aegis_node_id"] == target_object["aegis_node_id"]:
            return
        key = (source_id, target_id, relationship)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edge_records.append(
            {
                "source_object_id": source_id,
                "target_object_id": target_id,
                "source_id": source_object["aegis_node_id"],
                "target_id": target_object["aegis_node_id"],
                "source_label": source_object["display_label"],
                "target_label": target_object["display_label"],
                "source_type": source_object["aegis_node_type"],
                "target_type": target_object["aegis_node_type"],
                "relationship": relationship,
                "relationship_label": relationship_label or relationship,
                "confidence": confidence,
                "rationale": rationale,
            }
        )

    for archive in archive_entries:
        entry_type = str(archive.get("type") or "").strip().lower()
        for entry in archive.get("data", []):
            if not isinstance(entry, dict):
                continue
            target_id = _object_identifier(entry)
            if not target_id or target_id not in objects:
                continue

            if entry_type == "groups":
                for member in _list_members(entry.get("Members")):
                    add_edge(
                        _related_object_id(member),
                        target_id,
                        "member-of",
                        confidence=0.86,
                        rationale="BloodHound group membership data confirms this principal is a member of the group.",
                        relationship_label="MemberOf",
                    )
                    target_group = objects[target_id]
                    if target_group["kind"] == "group" and _is_privileged_group(target_group["display_label"]):
                        member_object = objects.get(_related_object_id(member) or "")
                        if member_object is None:
                            continue
                        privileged_key = (member_object["display_label"], target_group["display_label"])
                        if privileged_key in seen_privileged:
                            continue
                        seen_privileged.add(privileged_key)
                        privileged_memberships.append(
                            {
                                "group": target_group["display_label"],
                                "member": member_object["display_label"],
                                "group_dn": target_group["distinguished_name"],
                                "member_dn": member_object["distinguished_name"],
                                "source": "bloodhound-collect",
                                "confidence": 0.86,
                            }
                        )

            for ace in _list_members(entry.get("Aces")):
                principal_id = _first_text(
                    ace.get("PrincipalSID"),
                    ace.get("PrincipalObjectIdentifier"),
                    ace.get("PrincipalId"),
                )
                right_name = _first_text(ace.get("RightName"), ace.get("Right"), ace.get("Name"))
                if not principal_id or not right_name or right_name.lower() not in USEFUL_ACE_RIGHTS:
                    continue
                add_edge(
                    principal_id,
                    target_id,
                    f"ace-{_slug(right_name)}",
                    confidence=0.82,
                    rationale=(
                        f"BloodHound ACL data links principal access right {right_name} to {objects[target_id]['display_label']}."
                    ),
                    relationship_label=right_name,
                )

            target_object = objects[target_id]
            for relationship_key, relationship in LIST_RELATIONSHIP_KEYS.items():
                for related in _relationship_results(entry.get(relationship_key)):
                    related_id = _related_object_id(related)
                    if relationship_key == "HasSession" and target_object["kind"] == "computer":
                        add_edge(
                            related_id,
                            target_id,
                            relationship,
                            confidence=0.76,
                            rationale=(
                                f"BloodHound session-style data shows {objects.get(related_id, {}).get('display_label', 'a principal')} "
                                f"touching {target_object['display_label']}."
                            ),
                            relationship_label=relationship_key,
                        )
                    else:
                        add_edge(
                            related_id,
                            target_id,
                            relationship,
                            confidence=0.78,
                            rationale=(
                                f"BloodHound relationship data confirms {relationship_key} context into {target_object['display_label']}."
                            ),
                            relationship_label=relationship_key,
                        )

    return edge_records, privileged_memberships


def _derive_attack_paths(
    objects: dict[str, dict[str, Any]],
    edge_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
    direct_privileged_members: set[str] = set()
    for edge in edge_records:
        adjacency[edge["source_object_id"]].append(edge)
        if edge["relationship"] == "member-of":
            target = objects.get(edge["target_object_id"])
            if target is not None and _is_privileged_group(target["display_label"]):
                direct_privileged_members.add(edge["source_object_id"])

    standard_users = [
        entry
        for entry in objects.values()
        if entry["kind"] == "user"
        and entry["enabled"] is not False
        and not entry["high_value_category"]
        and entry["object_id"] not in direct_privileged_members
    ]
    if not standard_users:
        standard_users = [
            entry
            for entry in objects.values()
            if entry["kind"] == "user" and entry["enabled"] is not False and not entry["high_value_category"]
        ]

    high_value_targets = [entry for entry in objects.values() if entry["high_value_category"]]
    high_value_target_ids = {entry["object_id"] for entry in high_value_targets}
    paths: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, tuple[str, ...]]] = set()

    for start in sorted(standard_users, key=lambda entry: entry["display_label"].lower()):
        queue: deque[tuple[str, list[str], list[dict[str, Any]]]] = deque()
        queue.append((start["object_id"], [start["object_id"]], []))
        while queue and len(paths) < MAX_ATTACK_PATHS:
            current_id, visited, traversed_edges = queue.popleft()
            if len(traversed_edges) >= MAX_PATH_DEPTH:
                continue
            for edge in adjacency.get(current_id, []):
                next_id = edge["target_object_id"]
                if next_id in visited:
                    continue
                next_visited = [*visited, next_id]
                next_edges = [*traversed_edges, edge]
                if next_id in high_value_target_ids:
                    path_key = (start["object_id"], tuple(next_visited))
                    if path_key in seen_paths:
                        continue
                    seen_paths.add(path_key)
                    target = objects[next_id]
                    labels = [objects[node_id]["display_label"] for node_id in next_visited if node_id in objects]
                    confidence = round(
                        min(
                            [float(step.get("confidence") or 0.0) for step in next_edges] or [0.45]
                        ),
                        3,
                    )
                    finding_title = (
                        f"Read-only AD attack path to {target['display_label']} observed from {start['display_label']}"
                    )
                    paths.append(
                        {
                            "path_id": f"bloodhound-path:{len(paths) + 1}",
                            "finding_title": finding_title,
                            "finding_target_id": target["display_label"],
                            "severity": "high",
                            "target_category": target["high_value_category"] or "high_value_target",
                            "source_label": start["display_label"],
                            "source_type": start["aegis_node_type"],
                            "target_label": target["display_label"],
                            "target_type": target["aegis_node_type"],
                            "node_ids": [objects[node_id]["aegis_node_id"] for node_id in next_visited if node_id in objects],
                            "node_labels": labels,
                            "edge_chain": [
                                {
                                    "source_id": step["source_id"],
                                    "target_id": step["target_id"],
                                    "relationship": step["relationship"],
                                    "relationship_label": step["relationship_label"],
                                    "source_label": step["source_label"],
                                    "target_label": step["target_label"],
                                }
                                for step in next_edges
                            ],
                            "confidence": confidence,
                            "summary": (
                                f"Read-only BloodHound analysis found a privilege path from {start['display_label']} "
                                f"to high-value target {target['display_label']} through {' -> '.join(labels[1:-1]) if len(labels) > 2 else 'direct graph relationships'}; "
                                "no exploitation, ticket requests, password spraying, or AD modification was performed."
                            ),
                        }
                    )
                    continue
                queue.append((next_id, next_visited, next_edges))
    return paths


def _edge_records_from_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for path in paths:
        for edge in path.get("edge_chain", []):
            key = (
                str(edge.get("source_id") or ""),
                str(edge.get("target_id") or ""),
                str(edge.get("relationship") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(
                {
                    "source_id": edge.get("source_id"),
                    "target_id": edge.get("target_id"),
                    "source_label": edge.get("source_label"),
                    "target_label": edge.get("target_label"),
                    "source_type": _node_type_from_id(edge.get("source_id")),
                    "target_type": _node_type_from_id(edge.get("target_id")),
                    "relationship": edge.get("relationship"),
                    "relationship_label": edge.get("relationship_label"),
                    "source": "bloodhound-collect",
                    "confidence": float(path.get("confidence") or 0.0),
                    "rationale": "Read-only BloodHound path analysis confirmed this edge inside a recorded attack path.",
                }
            )
    return deduped


def _derive_choke_points(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    principal_counter: Counter[str] = Counter()
    principal_labels: dict[str, str] = {}
    edge_counter: Counter[str] = Counter()
    edge_labels: dict[str, str] = {}
    for path in paths:
        node_ids = [str(node_id) for node_id in path.get("node_ids", []) if isinstance(node_id, str)]
        node_labels = [str(label) for label in path.get("node_labels", []) if isinstance(label, str)]
        for index, node_id in enumerate(node_ids[1:-1], start=1):
            principal_counter[node_id] += 1
            if index < len(node_labels):
                principal_labels[node_id] = node_labels[index]
        for edge in path.get("edge_chain", []):
            relationship = str(edge.get("relationship") or "")
            if not relationship.startswith("ace-"):
                continue
            label = (
                f"{edge.get('source_label')} {edge.get('relationship_label')} {edge.get('target_label')}"
            ).strip()
            edge_counter[label] += 1
            edge_labels[label] = label

    findings: list[dict[str, Any]] = []
    for node_id, count in principal_counter.items():
        if count < CHOKE_POINT_THRESHOLD:
            continue
        label = principal_labels.get(node_id) or node_id
        findings.append(
            {
                "kind": "principal_choke_point",
                "target_id": label,
                "path_count": count,
                "summary": (
                    f"Read-only BloodHound analysis found principal {label} on {count} high-value attack paths, "
                    "making it a likely choke point for privilege escalation review."
                ),
            }
        )
    for label, count in edge_counter.items():
        if count < CHOKE_POINT_THRESHOLD:
            continue
        findings.append(
            {
                "kind": "ace_choke_point",
                "target_id": label,
                "path_count": count,
                "summary": (
                    f"Read-only BloodHound analysis found ACE relationship '{edge_labels[label]}' on {count} high-value attack paths."
                ),
            }
        )
    return findings


def _identity_subject_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "account_name": entry["display_label"],
        "principal": (
            entry["raw_name"].lower()
            if entry["kind"] == "user" and "@" in entry["raw_name"]
            else None
        ),
        "dn": entry["distinguished_name"],
        "enabled": entry["enabled"],
        "source": "bloodhound-collect",
        "confidence": 0.86,
    }


def _identity_group_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": entry["display_label"],
        "dn": entry["distinguished_name"],
        "member_count": None,
        "privileged": _is_privileged_group(entry["display_label"]),
        "source": "bloodhound-collect",
        "confidence": 0.84,
    }


def _host_payload(entry: dict[str, Any]) -> dict[str, Any]:
    host = entry["dns_host_name"] or entry["display_label"].lower()
    notes: list[str] = []
    if entry["high_value_category"] == "domain_controller":
        notes.append("BloodHound classified this computer as a high-value domain controller target.")
    return {
        "host": host,
        "notes": notes,
        "source": "bloodhound-collect",
        "confidence": 0.82,
    }


def _kerberoastable_account_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "account_name": entry["display_label"],
        "user_principal_name": entry["raw_name"].lower() if "@" in entry["raw_name"] else None,
        "service_principal_names": list(entry["service_principal_names"]),
    }


def _asrep_account_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "account_name": entry["display_label"],
        "user_principal_name": entry["raw_name"].lower() if "@" in entry["raw_name"] else None,
    }


def _first_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
    return result


def _object_identifier(entry: dict[str, Any]) -> str | None:
    value = _first_text(
        entry.get("ObjectIdentifier"),
        entry.get("ObjectID"),
        entry.get("ObjectId"),
        entry.get("Id"),
    )
    return value or None


def _related_object_id(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if not isinstance(value, dict):
        return None
    return _object_identifier(value) or _first_text(
        value.get("UserSID"),
        value.get("UserId"),
        value.get("MemberId"),
        value.get("PrincipalSID"),
        value.get("PrincipalId"),
        value.get("ObjectIdentifier"),
    ) or None


def _list_members(value: Any) -> list[dict[str, Any] | str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, (dict, str))]
    return []


def _relationship_results(value: Any) -> list[dict[str, Any] | str]:
    if isinstance(value, dict):
        results = value.get("Results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, (dict, str))]
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, (dict, str))]
    return []


def _display_label(raw_name: str, *, kind: str) -> str:
    normalized = raw_name.strip()
    if kind == "computer":
        return normalized.rstrip("$").lower()
    if "@" in normalized:
        head = normalized.split("@", 1)[0]
        if kind == "group":
            return head.replace("_", " ").title()
        return normalized.lower()
    return normalized.replace("_", " ").title() if kind == "group" else normalized


def _aegis_node_id(*, kind: str, display_label: str, dns_host_name: str | None) -> str:
    if kind == "computer":
        host = (dns_host_name or display_label).strip().lower()
        return f"host:{host}"
    if kind == "group":
        return f"identity-group:{_slug(display_label)}"
    return f"identity-subject:{_slug(display_label)}"


def _high_value_category(
    *,
    display_label: str,
    kind: str,
    high_value: bool,
    distinguished_name: str | None,
) -> str | None:
    if kind == "group":
        normalized = display_label.strip().lower()
        if normalized in HIGH_VALUE_GROUP_NAMES:
            return HIGH_VALUE_GROUP_NAMES[normalized]
    if kind == "computer":
        dn = str(distinguished_name or "").lower()
        if "ou=domain controllers" in dn or high_value:
            return "domain_controller"
    return None


def _domain_hint(raw_name: str, distinguished_name: str | None) -> str | None:
    if "@" in raw_name:
        return raw_name.split("@", 1)[1].strip().lower()
    if distinguished_name:
        labels = [
            part.split("=", 1)[1].strip().lower()
            for part in distinguished_name.split(",")
            if part.strip().lower().startswith("dc=")
        ]
        if labels:
            return ".".join(labels)
    return None


def _is_privileged_group(label: str) -> bool:
    return label.strip().lower() in PRIVILEGED_GROUP_NAMES


def _dominant_domain(entries: Any) -> str | None:
    counter: Counter[str] = Counter(
        str(entry.get("domain") or "").strip().lower()
        for entry in entries
        if isinstance(entry, dict) and str(entry.get("domain") or "").strip()
    )
    if not counter:
        return None
    return counter.most_common(1)[0][0]


def _node_type_from_id(node_id: Any) -> str:
    value = str(node_id or "")
    if value.startswith("host:"):
        return "host"
    if value.startswith("identity-group:"):
        return "identity_group"
    return "identity_subject"


def _slug(value: str) -> str:
    return "-".join(part for part in "".join(ch if ch.isalnum() else " " for ch in value.lower()).split() if part)
