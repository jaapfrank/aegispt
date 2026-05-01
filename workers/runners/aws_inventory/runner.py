from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

AWS_INVENTORY_ARTIFACT_NAME = "aws-inventory-results.json"
AWS_INVENTORY_RUNNER_DIGEST = "workers.aws_inventory.runner:v1"


class AwsInventoryCredentialError(RuntimeError):
    pass


class AwsInventoryScopeError(RuntimeError):
    pass


def normalize_aws_account_target(target: str) -> str:
    normalized = target.strip()
    if normalized.startswith("aws://"):
        normalized = normalized.removeprefix("aws://")
    if normalized.startswith("arn:aws:iam::"):
        parts = normalized.split(":")
        if len(parts) >= 5:
            normalized = parts[4]
    normalized = normalized.strip()
    if not normalized:
        raise AwsInventoryScopeError("aws account target is required")
    if not normalized.isdigit() or len(normalized) != 12:
        raise AwsInventoryScopeError("aws account target must be a 12 digit account id")
    return normalized


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _tag_value(tags: Any, key: str = "Name") -> str | None:
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        if str(tag.get("Key") or "") == key and str(tag.get("Value") or "").strip():
            return str(tag["Value"]).strip()
    return None


def _normalized_tags(tags: Any) -> dict[str, str]:
    if not isinstance(tags, list):
        return {}
    normalized: dict[str, str] = {}
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        key = str(tag.get("Key") or "").strip()
        value = str(tag.get("Value") or "").strip()
        if key:
            normalized[key] = value
    return normalized


def _paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(operation)
        except Exception:
            paginator = None
        if paginator is not None:
            items: list[dict[str, Any]] = []
            for page in paginator.paginate(**kwargs):
                values = page.get(result_key, []) if isinstance(page, dict) else []
                if isinstance(values, list):
                    items.extend(value for value in values if isinstance(value, dict))
            return items

    method = getattr(client, operation)
    response = method(**kwargs)
    values = response.get(result_key, []) if isinstance(response, dict) else []
    return [value for value in values if isinstance(value, dict)] if isinstance(values, list) else []


def _env_credentials(
    *,
    access_key_id_env: str | None,
    secret_access_key_env: str | None,
    session_token_env: str | None,
) -> dict[str, str]:
    if not access_key_id_env or not secret_access_key_env:
        raise AwsInventoryCredentialError(
            "aws inventory requires access_key_id_env and secret_access_key_env or an injected client"
        )

    access_key_id = os.getenv(access_key_id_env)
    secret_access_key = os.getenv(secret_access_key_env)
    session_token = os.getenv(session_token_env) if session_token_env else None

    if not access_key_id or not secret_access_key:
        raise AwsInventoryCredentialError(
            "aws inventory credential environment variables are not available"
        )

    credentials = {
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_access_key,
    }
    if session_token:
        credentials["aws_session_token"] = session_token
    return credentials


def _default_client_factory(
    *,
    access_key_id_env: str | None,
    secret_access_key_env: str | None,
    session_token_env: str | None,
) -> Callable[[str, str | None], Any]:
    try:
        import boto3
    except ImportError as exc:
        raise AwsInventoryCredentialError("boto3 is required for live AWS inventory") from exc

    credentials = _env_credentials(
        access_key_id_env=access_key_id_env,
        secret_access_key_env=secret_access_key_env,
        session_token_env=session_token_env,
    )

    def factory(service_name: str, region_name: str | None = None) -> Any:
        return boto3.client(service_name, region_name=region_name, **credentials)

    return factory


def _security_group_rule_count(group: dict[str, Any]) -> int:
    ingress = group.get("IpPermissions")
    egress = group.get("IpPermissionsEgress")
    return len(ingress if isinstance(ingress, list) else []) + len(
        egress if isinstance(egress, list) else []
    )


def _normalized_security_group_rules(rules: Any) -> list[dict[str, Any]]:
    if not isinstance(rules, list):
        return []

    normalized_rules: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ip_ranges = rule.get("IpRanges")
        ipv6_ranges = rule.get("Ipv6Ranges")
        referenced_groups = rule.get("UserIdGroupPairs")
        normalized_rules.append(
            {
                "protocol": str(rule.get("IpProtocol") or ""),
                "from_port": rule.get("FromPort") if isinstance(rule.get("FromPort"), int) else None,
                "to_port": rule.get("ToPort") if isinstance(rule.get("ToPort"), int) else None,
                "cidr_blocks": [
                    str(range_entry.get("CidrIp"))
                    for range_entry in ip_ranges
                    if isinstance(range_entry, dict) and range_entry.get("CidrIp")
                ]
                if isinstance(ip_ranges, list)
                else [],
                "ipv6_cidr_blocks": [
                    str(range_entry.get("CidrIpv6"))
                    for range_entry in ipv6_ranges
                    if isinstance(range_entry, dict) and range_entry.get("CidrIpv6")
                ]
                if isinstance(ipv6_ranges, list)
                else [],
                "referenced_security_groups": [
                    str(group_entry.get("GroupId"))
                    for group_entry in referenced_groups
                    if isinstance(group_entry, dict) and group_entry.get("GroupId")
                ]
                if isinstance(referenced_groups, list)
                else [],
            }
        )
    return normalized_rules


def collect_aws_inventory(
    *,
    account_targets: list[str],
    regions: list[str] | None = None,
    access_key_id_env: str | None = None,
    secret_access_key_env: str | None = None,
    session_token_env: str | None = None,
    client_factory: Callable[[str, str | None], Any] | None = None,
) -> dict[str, Any]:
    normalized_targets = [normalize_aws_account_target(target) for target in account_targets]
    factory = client_factory or _default_client_factory(
        access_key_id_env=access_key_id_env,
        secret_access_key_env=secret_access_key_env,
        session_token_env=session_token_env,
    )

    sts = factory("sts", None)
    identity = sts.get_caller_identity()
    account_id = str(identity.get("Account") or "").strip()
    if account_id not in normalized_targets:
        raise AwsInventoryScopeError("aws caller identity is outside the approved account scope")

    regional_client = factory("ec2", regions[0] if regions else None)
    selected_regions = [region.strip() for region in (regions or []) if region.strip()]
    if not selected_regions:
        region_payload = regional_client.describe_regions(AllRegions=False)
        selected_regions = [
            str(region.get("RegionName") or "").strip()
            for region in region_payload.get("Regions", [])
            if isinstance(region, dict) and str(region.get("RegionName") or "").strip()
        ]
    selected_regions = list(dict.fromkeys(selected_regions))

    target_result: dict[str, Any] = {
        "target": account_id,
        "provider": "aws",
        "status": "ok",
        "identity": {
            "account_id": account_id,
            "arn": str(identity.get("Arn") or "") or None,
            "user_id": str(identity.get("UserId") or "") or None,
        },
        "regions": [],
        "errors": [],
    }

    for region in selected_regions:
        region_result: dict[str, Any] = {
            "name": region,
            "vpcs": [],
            "subnets": [],
            "security_groups": [],
            "instances": [],
            "errors": [],
        }
        try:
            ec2 = factory("ec2", region)
            for vpc in _paginate(ec2, "describe_vpcs", "Vpcs"):
                region_result["vpcs"].append(
                    {
                        "vpc_id": str(vpc.get("VpcId") or ""),
                        "cidr_block": str(vpc.get("CidrBlock") or "") or None,
                        "state": str(vpc.get("State") or "") or None,
                        "is_default": vpc.get("IsDefault") if isinstance(vpc.get("IsDefault"), bool) else None,
                        "name": _tag_value(vpc.get("Tags")),
                        "tags": _normalized_tags(vpc.get("Tags")),
                    }
                )

            for subnet in _paginate(ec2, "describe_subnets", "Subnets"):
                region_result["subnets"].append(
                    {
                        "subnet_id": str(subnet.get("SubnetId") or ""),
                        "vpc_id": str(subnet.get("VpcId") or "") or None,
                        "cidr_block": str(subnet.get("CidrBlock") or "") or None,
                        "availability_zone": str(subnet.get("AvailabilityZone") or "") or None,
                        "state": str(subnet.get("State") or "") or None,
                        "name": _tag_value(subnet.get("Tags")),
                        "tags": _normalized_tags(subnet.get("Tags")),
                    }
                )

            for group in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
                region_result["security_groups"].append(
                    {
                        "group_id": str(group.get("GroupId") or ""),
                        "group_name": str(group.get("GroupName") or "") or None,
                        "vpc_id": str(group.get("VpcId") or "") or None,
                        "description": str(group.get("Description") or "") or None,
                        "rule_count": _security_group_rule_count(group),
                        "ingress_rules": _normalized_security_group_rules(
                            group.get("IpPermissions")
                        ),
                        "egress_rules": _normalized_security_group_rules(
                            group.get("IpPermissionsEgress")
                        ),
                        "tags": _normalized_tags(group.get("Tags")),
                    }
                )

            reservations = _paginate(ec2, "describe_instances", "Reservations")
            for reservation in reservations:
                instances = reservation.get("Instances", [])
                if not isinstance(instances, list):
                    continue
                for instance in instances:
                    if not isinstance(instance, dict):
                        continue
                    state = instance.get("State") if isinstance(instance.get("State"), dict) else {}
                    region_result["instances"].append(
                        {
                            "instance_id": str(instance.get("InstanceId") or ""),
                            "instance_type": str(instance.get("InstanceType") or "") or None,
                            "state": str(state.get("Name") or "") or None,
                            "private_ip": str(instance.get("PrivateIpAddress") or "") or None,
                            "public_ip": str(instance.get("PublicIpAddress") or "") or None,
                            "private_dns_name": str(instance.get("PrivateDnsName") or "") or None,
                            "public_dns_name": str(instance.get("PublicDnsName") or "") or None,
                            "vpc_id": str(instance.get("VpcId") or "") or None,
                            "subnet_id": str(instance.get("SubnetId") or "") or None,
                            "security_group_ids": [
                                str(group.get("GroupId"))
                                for group in instance.get("SecurityGroups", [])
                                if isinstance(group, dict) and group.get("GroupId")
                            ],
                            "name": _tag_value(instance.get("Tags")),
                            "tags": _normalized_tags(instance.get("Tags")),
                        }
                    )
        except Exception as exc:
            region_result["errors"].append(str(exc))
            target_result["status"] = "partial"
        target_result["regions"].append(region_result)

    return {
        "tool": "aws-inventory",
        "provider": "aws",
        "status": target_result["status"],
        "read_only": True,
        "generated_at": _now_iso(),
        "targets": [target_result],
        "summary": summarize_aws_inventory_targets([target_result]),
    }


def summarize_aws_inventory_targets(targets: list[dict[str, Any]]) -> dict[str, int]:
    account_count = len(
        {
            str(target.get("target") or target.get("identity", {}).get("account_id") or "")
            for target in targets
            if isinstance(target, dict)
        }
        - {""}
    )
    region_count = 0
    instance_count = 0
    vpc_count = 0
    subnet_count = 0
    security_group_count = 0
    for target in targets:
        if not isinstance(target, dict):
            continue
        regions = target.get("regions", [])
        if not isinstance(regions, list):
            continue
        for region in regions:
            if not isinstance(region, dict):
                continue
            region_count += 1
            instance_count += len(region.get("instances", []) if isinstance(region.get("instances"), list) else [])
            vpc_count += len(region.get("vpcs", []) if isinstance(region.get("vpcs"), list) else [])
            subnet_count += len(region.get("subnets", []) if isinstance(region.get("subnets"), list) else [])
            security_group_count += len(
                region.get("security_groups", [])
                if isinstance(region.get("security_groups"), list)
                else []
            )
    return {
        "account_count": account_count,
        "region_count": region_count,
        "instance_count": instance_count,
        "vpc_count": vpc_count,
        "subnet_count": subnet_count,
        "security_group_count": security_group_count,
    }


def _execution_from_payload(payload: dict[str, Any], *, exit_code: int, stderr: str = "") -> RunnerExecution:
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    status = str(payload.get("status") or ("ok" if exit_code == 0 else "failed"))
    return RunnerExecution(
        tool="aws-inventory",
        exit_code=exit_code,
        stdout=json.dumps({"status": status, "read_only": True}),
        stderr=stderr,
        metadata={
            "status": status,
            "read_only": True,
            "tool_version": "aws-read-only-api",
            "runner_digest": AWS_INVENTORY_RUNNER_DIGEST,
        },
        artifacts=[
            EvidenceArtifact(
                name=AWS_INVENTORY_ARTIFACT_NAME,
                content_type="application/json",
                data=data,
                kind="cloud-inventory-results",
            )
        ],
    )


def execute_aws_inventory(
    targets: list[str],
    *,
    regions: list[str] | None = None,
    access_key_id_env: str | None = None,
    secret_access_key_env: str | None = None,
    session_token_env: str | None = None,
    client_factory: Callable[[str, str | None], Any] | None = None,
) -> RunnerExecution:
    try:
        payload = collect_aws_inventory(
            account_targets=targets,
            regions=regions,
            access_key_id_env=access_key_id_env,
            secret_access_key_env=secret_access_key_env,
            session_token_env=session_token_env,
            client_factory=client_factory,
        )
    except AwsInventoryCredentialError as exc:
        payload = {
            "tool": "aws-inventory",
            "provider": "aws",
            "status": "auth_failed",
            "read_only": True,
            "generated_at": _now_iso(),
            "targets": [],
            "summary": {
                "account_count": 0,
                "region_count": 0,
                "instance_count": 0,
                "vpc_count": 0,
                "subnet_count": 0,
                "security_group_count": 0,
            },
            "errors": [str(exc)],
        }
        return _execution_from_payload(payload, exit_code=2, stderr=str(exc))
    except AwsInventoryScopeError as exc:
        payload = {
            "tool": "aws-inventory",
            "provider": "aws",
            "status": "scope_failed",
            "read_only": True,
            "generated_at": _now_iso(),
            "targets": [],
            "summary": {
                "account_count": 0,
                "region_count": 0,
                "instance_count": 0,
                "vpc_count": 0,
                "subnet_count": 0,
                "security_group_count": 0,
            },
            "errors": [str(exc)],
        }
        return _execution_from_payload(payload, exit_code=3, stderr=str(exc))
    except Exception as exc:
        payload = {
            "tool": "aws-inventory",
            "provider": "aws",
            "status": "failed",
            "read_only": True,
            "generated_at": _now_iso(),
            "targets": [],
            "summary": {
                "account_count": 0,
                "region_count": 0,
                "instance_count": 0,
                "vpc_count": 0,
                "subnet_count": 0,
                "security_group_count": 0,
            },
            "errors": [str(exc)],
        }
        return _execution_from_payload(payload, exit_code=1, stderr=str(exc))

    exit_code = 0 if payload.get("status") == "ok" else 1
    return _execution_from_payload(payload, exit_code=exit_code)
