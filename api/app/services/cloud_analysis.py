from __future__ import annotations

import json
from typing import Any

from api.app.models import InventorySnapshot

SUPPORTED_CLOUD_PROVIDERS = {"aws"}
PUBLIC_IPV4_CIDR = "0.0.0.0/0"
PUBLIC_IPV6_CIDR = "::/0"
REMOTE_ADMIN_PORTS = {22, 3389}


def _dict_entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _normalized_provider(value: Any, *, default: str = "") -> str:
    provider = str(value or default).strip().lower()
    return provider


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item or "").strip()]


def _policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _statements(document: Any) -> list[dict[str, Any]]:
    payload = _policy_document(document)
    statements = payload.get("Statement")
    if isinstance(statements, dict):
        return [statements]
    return _dict_entries(statements)


def _field_values(statement: dict[str, Any], field: str) -> list[str]:
    value = statement.get(field)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "").strip()]
    return []


def _has_wildcard_action(actions: list[str]) -> bool:
    return any(action == "*" or action.endswith(":*") for action in actions)


def _has_wildcard_resource(resources: list[str]) -> bool:
    return any(resource == "*" for resource in resources)


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    for value in principal.values():
        if value == "*":
            return True
        if isinstance(value, list) and "*" in value:
            return True
    return False


def _metadata(entry: dict[str, Any]) -> dict[str, Any]:
    metadata = entry.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _flag(entry: dict[str, Any], *keys: str) -> bool | None:
    metadata = _metadata(entry)
    for key in keys:
        if isinstance(entry.get(key), bool):
            return entry[key]
        if isinstance(metadata.get(key), bool):
            return metadata[key]
    return None


def _cidrs_from_rule(rule: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for key in ("cidr", "cidr_ip", "cidr_block"):
        value = rule.get(key)
        if isinstance(value, str) and value.strip():
            cidrs.append(value.strip())
    cidrs.extend(_string_list(rule.get("cidr_blocks")))
    cidrs.extend(_string_list(rule.get("ipv6_cidr_blocks")))

    for range_entry in _dict_entries(rule.get("IpRanges")):
        cidr = str(range_entry.get("CidrIp") or "").strip()
        if cidr:
            cidrs.append(cidr)
    for range_entry in _dict_entries(rule.get("Ipv6Ranges")):
        cidr = str(range_entry.get("CidrIpv6") or "").strip()
        if cidr:
            cidrs.append(cidr)
    return list(dict.fromkeys(cidrs))


def _rule_protocol(rule: dict[str, Any]) -> str:
    return str(rule.get("protocol") or rule.get("IpProtocol") or "").strip().lower()


def _rule_ports(rule: dict[str, Any]) -> tuple[int | None, int | None]:
    from_port = rule.get("from_port", rule.get("FromPort"))
    to_port = rule.get("to_port", rule.get("ToPort"))
    return (
        from_port if isinstance(from_port, int) else None,
        to_port if isinstance(to_port, int) else None,
    )


def _port_label(from_port: int | None, to_port: int | None, protocol: str) -> str:
    if protocol in {"-1", "all"}:
        return "all ports"
    if from_port is None and to_port is None:
        return "unspecified ports"
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def _rule_exposes_remote_admin(
    *, protocol: str, from_port: int | None, to_port: int | None
) -> bool:
    if protocol in {"-1", "all"}:
        return True
    if from_port is None or to_port is None:
        return False
    return any(from_port <= port <= to_port for port in REMOTE_ADMIN_PORTS)


def _observed_providers(normalized: dict[str, Any]) -> list[str]:
    providers: set[str] = set()
    for collection_name in (
        "cloud_accounts",
        "cloud_resources",
        "cloud_security_groups",
        "cloud_iam_principals",
        "cloud_iam_policies",
        "cloud_collection_errors",
    ):
        for entry in _dict_entries(normalized.get(collection_name)):
            provider = _normalized_provider(entry.get("provider"))
            if provider:
                providers.add(provider)
    return sorted(providers)


def _finding(
    *,
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    provider: str,
    inventory_ref: str,
    evidence_path: str,
    evidence_value: Any,
    account_id: str | None = None,
    region: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    description: str,
    recommendation: str,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "category": category,
        "title": title,
        "severity": severity,
        "provider": provider,
        "account_id": account_id,
        "region": region,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "description": description,
        "recommendation": recommendation,
        "evidence": [
            {
                "ref": inventory_ref,
                "path": evidence_path,
                "value": evidence_value,
            }
        ],
    }


def _public_instance_findings(
    normalized: dict[str, Any], *, inventory_ref: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for resource in _dict_entries(normalized.get("cloud_resources")):
        if _normalized_provider(resource.get("provider")) != "aws":
            continue
        if resource.get("resource_type") != "ec2:instance":
            continue
        metadata = _metadata(resource)
        public_value = str(
            metadata.get("public_ip") or metadata.get("public_dns_name") or ""
        ).strip()
        if not public_value:
            continue
        resource_id = str(resource.get("resource_id") or "").strip()
        findings.append(
            _finding(
                finding_id=f"aws-public-instance:{resource_id or public_value}",
                category="public_exposure",
                title="EC2 instance has public network exposure",
                severity="medium",
                provider="aws",
                account_id=str(resource.get("account_id") or "") or None,
                region=str(resource.get("region") or "") or None,
                resource_type="ec2:instance",
                resource_id=resource_id or None,
                inventory_ref=inventory_ref,
                evidence_path="cloud_resources[].metadata.public_ip",
                evidence_value=public_value,
                description=(
                    "Stored AWS inventory shows an EC2 instance with a public IP or DNS name. "
                    "This is a review signal, not proof of reachability or exploitability."
                ),
                recommendation=(
                    "Confirm the instance is intended to be internet-reachable and restrict "
                    "security groups, routing, or load-balancer exposure where possible."
                ),
            )
        )
    return findings


def _security_group_findings(
    normalized: dict[str, Any], *, inventory_ref: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for group in _dict_entries(normalized.get("cloud_security_groups")):
        if _normalized_provider(group.get("provider")) != "aws":
            continue
        rules = _dict_entries(group.get("ingress_rules"))
        for index, rule in enumerate(rules):
            cidrs = _cidrs_from_rule(rule)
            public_cidrs = [cidr for cidr in cidrs if cidr in {PUBLIC_IPV4_CIDR, PUBLIC_IPV6_CIDR}]
            if not public_cidrs:
                continue
            protocol = _rule_protocol(rule)
            from_port, to_port = _rule_ports(rule)
            admin_exposure = _rule_exposes_remote_admin(
                protocol=protocol,
                from_port=from_port,
                to_port=to_port,
            )
            group_id = str(group.get("group_id") or "").strip()
            port_label = _port_label(from_port, to_port, protocol)
            findings.append(
                _finding(
                    finding_id=f"aws-security-group-public-ingress:{group_id}:{index}",
                    category="security_group_exposure",
                    title="Security group allows public ingress",
                    severity="high" if admin_exposure else "medium",
                    provider="aws",
                    account_id=str(group.get("account_id") or "") or None,
                    region=str(group.get("region") or "") or None,
                    resource_type="ec2:security-group",
                    resource_id=group_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path=f"cloud_security_groups[].ingress_rules[{index}]",
                    evidence_value={"cidrs": public_cidrs, "ports": port_label},
                    description=(
                        "Stored AWS inventory shows public ingress on a security group. "
                        "Remote administration or all-port exposure is treated as higher risk."
                    ),
                    recommendation=(
                        "Restrict ingress CIDRs to approved sources, remove broad public rules, "
                        "and prefer private access paths for administration."
                    ),
                )
            )
    return findings


def _iam_policy_findings(
    normalized: dict[str, Any], *, inventory_ref: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for policy in _dict_entries(normalized.get("cloud_iam_policies")):
        if _normalized_provider(policy.get("provider")) != "aws":
            continue
        policy_id = str(policy.get("policy_id") or policy.get("arn") or "").strip()
        for index, statement in enumerate(_statements(policy.get("policy_document"))):
            if str(statement.get("Effect") or "").lower() != "allow":
                continue
            actions = _field_values(statement, "Action")
            resources = _field_values(statement, "Resource")
            if not _has_wildcard_action(actions) or not _has_wildcard_resource(resources):
                continue
            findings.append(
                _finding(
                    finding_id=f"aws-iam-wildcard-policy:{policy_id}:{index}",
                    category="iam_policy_risk",
                    title="IAM policy allows wildcard actions on wildcard resources",
                    severity="high",
                    provider="aws",
                    account_id=str(policy.get("account_id") or "") or None,
                    resource_type="iam:policy",
                    resource_id=policy_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path=f"cloud_iam_policies[].policy_document.Statement[{index}]",
                    evidence_value={"actions": actions, "resources": resources},
                    description=(
                        "Stored IAM policy inventory includes an allow statement with broad "
                        "action and resource wildcards."
                    ),
                    recommendation=(
                        "Replace wildcard permissions with least-privilege actions and scoped "
                        "resources validated against the role's operational need."
                    ),
                )
            )
    return findings


def _iam_trust_findings(
    normalized: dict[str, Any], *, inventory_ref: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for principal in _dict_entries(normalized.get("cloud_iam_principals")):
        if _normalized_provider(principal.get("provider")) != "aws":
            continue
        principal_id = str(principal.get("principal_id") or principal.get("arn") or "").strip()
        for index, statement in enumerate(_statements(principal.get("trust_policy"))):
            if str(statement.get("Effect") or "").lower() != "allow":
                continue
            actions = _field_values(statement, "Action")
            action_allows_assume = any(action in {"*", "sts:AssumeRole"} for action in actions)
            if not action_allows_assume or not _principal_is_wildcard(statement.get("Principal")):
                continue
            findings.append(
                _finding(
                    finding_id=f"aws-iam-wildcard-trust:{principal_id}:{index}",
                    category="iam_trust_risk",
                    title="IAM role trust policy allows wildcard principals",
                    severity="high",
                    provider="aws",
                    account_id=str(principal.get("account_id") or "") or None,
                    resource_type="iam:principal",
                    resource_id=principal_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path=f"cloud_iam_principals[].trust_policy.Statement[{index}]",
                    evidence_value={"actions": actions, "principal": statement.get("Principal")},
                    description=(
                        "Stored IAM trust-policy inventory shows a role assumption statement "
                        "that accepts wildcard principals."
                    ),
                    recommendation=(
                        "Constrain trusted principals to approved AWS accounts, roles, or "
                        "federated identities and add external-id conditions where applicable."
                    ),
                )
            )
    return findings


def _kubernetes_findings(
    normalized: dict[str, Any], *, inventory_ref: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for cluster in _dict_entries(normalized.get("kubernetes_clusters")):
        cluster_id = str(cluster.get("cluster_id") or cluster.get("name") or "").strip()
        if _flag(cluster, "public_endpoint", "endpoint_public_access") is True:
            findings.append(
                _finding(
                    finding_id=f"kubernetes-public-endpoint:{cluster_id}",
                    category="kubernetes_configuration",
                    title="Kubernetes cluster endpoint is publicly reachable",
                    severity="medium",
                    provider=_normalized_provider(cluster.get("provider"), default="kubernetes"),
                    account_id=str(cluster.get("account_id") or "") or None,
                    region=str(cluster.get("region") or "") or None,
                    resource_type="kubernetes:cluster",
                    resource_id=cluster_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path="kubernetes_clusters[].metadata.endpoint_public_access",
                    evidence_value=True,
                    description=(
                        "Stored Kubernetes inventory indicates a public control-plane endpoint."
                    ),
                    recommendation=(
                        "Restrict control-plane endpoint access to approved networks and "
                        "confirm authentication and audit controls are enabled."
                    ),
                )
            )
        if _flag(cluster, "rbac_enabled") is False:
            findings.append(
                _finding(
                    finding_id=f"kubernetes-rbac-disabled:{cluster_id}",
                    category="kubernetes_configuration",
                    title="Kubernetes RBAC appears disabled",
                    severity="high",
                    provider=_normalized_provider(cluster.get("provider"), default="kubernetes"),
                    account_id=str(cluster.get("account_id") or "") or None,
                    region=str(cluster.get("region") or "") or None,
                    resource_type="kubernetes:cluster",
                    resource_id=cluster_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path="kubernetes_clusters[].metadata.rbac_enabled",
                    evidence_value=False,
                    description="Stored Kubernetes inventory indicates RBAC is disabled.",
                    recommendation="Enable RBAC and review cluster role bindings for least privilege.",
                )
            )
        if _flag(cluster, "anonymous_auth_enabled") is True:
            findings.append(
                _finding(
                    finding_id=f"kubernetes-anonymous-auth:{cluster_id}",
                    category="kubernetes_configuration",
                    title="Kubernetes anonymous authentication appears enabled",
                    severity="high",
                    provider=_normalized_provider(cluster.get("provider"), default="kubernetes"),
                    account_id=str(cluster.get("account_id") or "") or None,
                    region=str(cluster.get("region") or "") or None,
                    resource_type="kubernetes:cluster",
                    resource_id=cluster_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path="kubernetes_clusters[].metadata.anonymous_auth_enabled",
                    evidence_value=True,
                    description=(
                        "Stored Kubernetes inventory indicates anonymous API authentication "
                        "may be enabled."
                    ),
                    recommendation="Disable anonymous authentication unless explicitly justified.",
                )
            )
        if _flag(cluster, "secrets_encryption_enabled") is False:
            findings.append(
                _finding(
                    finding_id=f"kubernetes-secrets-encryption-disabled:{cluster_id}",
                    category="kubernetes_configuration",
                    title="Kubernetes secrets encryption appears disabled",
                    severity="medium",
                    provider=_normalized_provider(cluster.get("provider"), default="kubernetes"),
                    account_id=str(cluster.get("account_id") or "") or None,
                    region=str(cluster.get("region") or "") or None,
                    resource_type="kubernetes:cluster",
                    resource_id=cluster_id or None,
                    inventory_ref=inventory_ref,
                    evidence_path="kubernetes_clusters[].metadata.secrets_encryption_enabled",
                    evidence_value=False,
                    description=(
                        "Stored Kubernetes inventory indicates secrets encryption at rest "
                        "may be disabled."
                    ),
                    recommendation="Enable envelope encryption for Kubernetes secrets at rest.",
                )
            )

    for workload in _dict_entries(normalized.get("kubernetes_workloads")):
        metadata = _metadata(workload)
        workload_id = (
            f"{workload.get('cluster_id')}/{workload.get('namespace')}/"
            f"{workload.get('kind')}/{workload.get('name')}"
        )
        risky_flags = {
            "privileged": _flag(workload, "privileged"),
            "host_network": _flag(workload, "host_network", "hostNetwork"),
            "run_as_root": _flag(workload, "run_as_root", "runAsRoot"),
        }
        enabled_flags = sorted(flag for flag, enabled in risky_flags.items() if enabled is True)
        if not enabled_flags:
            security_context = metadata.get("security_context")
            if isinstance(security_context, dict) and security_context.get("privileged") is True:
                enabled_flags = ["privileged"]
        if not enabled_flags:
            continue
        findings.append(
            _finding(
                finding_id=f"kubernetes-risky-workload:{workload_id}",
                category="kubernetes_workload_risk",
                title="Kubernetes workload uses risky pod security settings",
                severity="high" if "privileged" in enabled_flags else "medium",
                provider=_normalized_provider(workload.get("provider"), default="kubernetes"),
                account_id=str(workload.get("account_id") or "") or None,
                resource_type="kubernetes:workload",
                resource_id=workload_id,
                inventory_ref=inventory_ref,
                evidence_path="kubernetes_workloads[].metadata",
                evidence_value={"enabled_flags": enabled_flags},
                description=(
                    "Stored Kubernetes workload inventory shows pod security settings that "
                    "can increase container breakout or node-impact risk."
                ),
                recommendation=(
                    "Remove privileged mode, host networking, and root execution unless there "
                    "is a documented exception with compensating controls."
                ),
            )
        )
    return findings


def _limitations(
    normalized: dict[str, Any],
    *,
    inventory_ref: str,
    observed_providers: list[str],
    unsupported_providers: list[str],
) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = []
    for provider in unsupported_providers:
        limitations.append(
            {
                "category": "unsupported_provider",
                "provider": provider,
                "message": (
                    f"{provider} inventory is present, but this first analysis slice only "
                    "supports AWS cloud-risk analysis."
                ),
                "evidence": [{"ref": inventory_ref, "path": "cloud_*[].provider", "value": provider}],
            }
        )

    for error in _dict_entries(normalized.get("cloud_collection_errors")):
        provider = _normalized_provider(error.get("provider"), default="aws")
        limitations.append(
            {
                "category": "missing_permission",
                "provider": provider,
                "account_id": error.get("account_id"),
                "region": error.get("region"),
                "service": error.get("service"),
                "operation": error.get("operation"),
                "error_code": error.get("error_code"),
                "message": str(error.get("message") or "collection error"),
                "evidence": [
                    {
                        "ref": inventory_ref,
                        "path": "cloud_collection_errors[]",
                        "value": error,
                    }
                ],
            }
        )

    has_kubernetes_input = bool(
        _dict_entries(normalized.get("kubernetes_clusters"))
        or _dict_entries(normalized.get("kubernetes_workloads"))
    )
    if any(provider in SUPPORTED_CLOUD_PROVIDERS for provider in observed_providers) and not has_kubernetes_input:
        limitations.append(
            {
                "category": "kubernetes_input_unavailable",
                "provider": "kubernetes",
                "message": (
                    "No safe read-only Kubernetes inventory was present, so Kubernetes "
                    "configuration signals were not analyzed."
                ),
                "evidence": [
                    {
                        "ref": inventory_ref,
                        "path": "kubernetes_clusters|kubernetes_workloads",
                        "value": [],
                    }
                ],
            }
        )
    return limitations


def _status(
    *,
    observed_providers: list[str],
    unsupported_providers: list[str],
    limitations: list[dict[str, Any]],
) -> str:
    supported_observed = [
        provider for provider in observed_providers if provider in SUPPORTED_CLOUD_PROVIDERS
    ]
    if not observed_providers:
        return "no_supported_inventory"
    if unsupported_providers and not supported_observed:
        return "unsupported_provider"
    if limitations:
        return "partial"
    return "analysis_ready"


def analyze_cloud_inventory_snapshot(snapshot: InventorySnapshot) -> dict[str, Any]:
    normalized = snapshot.normalized_inventory_json or {}
    inventory_ref = f"inventory:{snapshot.id}"
    observed_providers = _observed_providers(normalized)
    unsupported_providers = [
        provider for provider in observed_providers if provider not in SUPPORTED_CLOUD_PROVIDERS
    ]

    findings: list[dict[str, Any]] = []
    if "aws" in observed_providers:
        findings.extend(_public_instance_findings(normalized, inventory_ref=inventory_ref))
        findings.extend(_security_group_findings(normalized, inventory_ref=inventory_ref))
        findings.extend(_iam_policy_findings(normalized, inventory_ref=inventory_ref))
        findings.extend(_iam_trust_findings(normalized, inventory_ref=inventory_ref))
    findings.extend(_kubernetes_findings(normalized, inventory_ref=inventory_ref))

    limitations = _limitations(
        normalized,
        inventory_ref=inventory_ref,
        observed_providers=observed_providers,
        unsupported_providers=unsupported_providers,
    )
    status = _status(
        observed_providers=observed_providers,
        unsupported_providers=unsupported_providers,
        limitations=limitations,
    )

    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    for finding in findings:
        category = str(finding.get("category") or "unknown")
        severity = str(finding.get("severity") or "unknown")
        categories[category] = categories.get(category, 0) + 1
        severities[severity] = severities.get(severity, 0) + 1

    return {
        "inventory_snapshot_id": str(snapshot.id),
        "status": status,
        "read_only": True,
        "provider_scope": {
            "supported": sorted(SUPPORTED_CLOUD_PROVIDERS),
            "observed": observed_providers,
            "unsupported": unsupported_providers,
        },
        "evidence_basis": [
            "inventory_snapshot.normalized_inventory_json",
            inventory_ref,
        ],
        "analysis_findings": findings,
        "limitations": limitations,
        "summary": {
            "finding_count": len(findings),
            "findings_by_category": dict(sorted(categories.items())),
            "findings_by_severity": dict(sorted(severities.items())),
            "limitation_count": len(limitations),
        },
    }
