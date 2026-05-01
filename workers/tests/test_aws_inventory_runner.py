from __future__ import annotations

import json
from typing import Any

from api.app.services.inventory import (
    aws_inventory_observation_from_json,
    inventory_summary_from_normalized,
    normalize_inventory_observations,
)
from workers.runners.aws_inventory.runner import (
    AWS_INVENTORY_ARTIFACT_NAME,
    execute_aws_inventory,
    normalize_aws_account_target,
)


class StaticAwsClient:
    def __init__(self, service_name: str, region_name: str | None = None) -> None:
        self.service_name = service_name
        self.region_name = region_name

    def get_caller_identity(self) -> dict[str, str]:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/aegispt-readonly",
            "UserId": "AIDAEXAMPLE",
        }

    def describe_regions(self, AllRegions: bool = False) -> dict[str, list[dict[str, str]]]:  # noqa: N803
        return {"Regions": [{"RegionName": "us-east-1"}]}

    def describe_vpcs(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "Vpcs": [
                {
                    "VpcId": "vpc-001",
                    "CidrBlock": "10.10.0.0/16",
                    "State": "available",
                    "IsDefault": False,
                    "Tags": [{"Key": "Name", "Value": "prod-vpc"}],
                }
            ]
        }

    def describe_subnets(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "Subnets": [
                {
                    "SubnetId": "subnet-001",
                    "VpcId": "vpc-001",
                    "CidrBlock": "10.10.1.0/24",
                    "AvailabilityZone": "us-east-1a",
                    "State": "available",
                    "Tags": [{"Key": "Name", "Value": "prod-app"}],
                }
            ]
        }

    def describe_security_groups(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                    "GroupName": "web-tier",
                    "VpcId": "vpc-001",
                    "Description": "web ingress",
                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}],
                    "IpPermissionsEgress": [{"IpProtocol": "-1"}],
                }
            ]
        }

    def describe_instances(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-001",
                            "InstanceType": "t3.micro",
                            "State": {"Name": "running"},
                            "PrivateIpAddress": "10.10.1.25",
                            "PrivateDnsName": "ip-10-10-1-25.ec2.internal",
                            "VpcId": "vpc-001",
                            "SubnetId": "subnet-001",
                            "SecurityGroups": [{"GroupId": "sg-001"}],
                            "Tags": [{"Key": "Name", "Value": "app01"}],
                        }
                    ]
                }
            ]
        }


def static_client_factory(service_name: str, region_name: str | None = None) -> StaticAwsClient:
    return StaticAwsClient(service_name=service_name, region_name=region_name)


def artifact_payload(execution) -> dict[str, Any]:
    assert execution.artifacts[0].name == AWS_INVENTORY_ARTIFACT_NAME
    return json.loads(execution.artifacts[0].data.decode("utf-8"))


def test_aws_account_target_normalization_is_scope_strict() -> None:
    assert normalize_aws_account_target("123456789012") == "123456789012"
    assert normalize_aws_account_target("aws://123456789012") == "123456789012"
    assert (
        normalize_aws_account_target("arn:aws:iam::123456789012:role/AegisPTReadOnly")
        == "123456789012"
    )


def test_aws_inventory_fixture_collects_read_only_inventory() -> None:
    execution = execute_aws_inventory(
        ["123456789012"],
        regions=["us-east-1"],
        client_factory=static_client_factory,
    )
    payload = artifact_payload(execution)

    assert execution.tool == "aws-inventory"
    assert execution.exit_code == 0
    assert execution.metadata["read_only"] is True
    assert payload["read_only"] is True
    assert payload["status"] == "ok"
    assert payload["summary"]["account_count"] == 1
    assert payload["summary"]["region_count"] == 1
    assert payload["summary"]["instance_count"] == 1
    assert payload["summary"]["vpc_count"] == 1
    assert payload["summary"]["subnet_count"] == 1
    assert payload["summary"]["security_group_count"] == 1

    target = payload["targets"][0]
    assert target["identity"]["account_id"] == "123456789012"
    assert target["regions"][0]["instances"][0]["instance_id"] == "i-001"
    assert target["regions"][0]["security_groups"][0]["rule_count"] == 2
    assert target["regions"][0]["security_groups"][0]["ingress_rules"][0]["from_port"] == 443


def test_aws_inventory_normalizes_cloud_resources_into_inventory() -> None:
    execution = execute_aws_inventory(
        ["123456789012"],
        regions=["us-east-1"],
        client_factory=static_client_factory,
    )
    observation = aws_inventory_observation_from_json(
        json_bytes=execution.artifacts[0].data,
        target_id="123456789012",
    )
    normalized = normalize_inventory_observations(
        observations=[observation],
        environment_notes=[],
        assumptions=[],
    )
    summary = inventory_summary_from_normalized(normalized)

    assert summary["host_count"] >= 2
    assert summary["cloud_account_count"] == 1
    assert summary["cloud_region_count"] == 1
    assert summary["cloud_resource_count"] == 4
    assert summary["cloud_security_group_count"] == 1
    assert normalized["cloud_accounts"][0]["account_id"] == "123456789012"
    assert normalized["cloud_security_groups"][0]["ingress_rules"][0]["from_port"] == 443
    assert {resource["resource_type"] for resource in normalized["cloud_resources"]} == {
        "ec2:instance",
        "ec2:security-group",
        "ec2:subnet",
        "ec2:vpc",
    }


def test_aws_inventory_missing_env_credentials_fails_without_secret_output(monkeypatch) -> None:
    monkeypatch.delenv("AEGISPT_TEST_AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AEGISPT_TEST_AWS_SECRET_ACCESS_KEY", raising=False)

    execution = execute_aws_inventory(
        ["123456789012"],
        access_key_id_env="AEGISPT_TEST_AWS_ACCESS_KEY_ID",
        secret_access_key_env="AEGISPT_TEST_AWS_SECRET_ACCESS_KEY",
    )
    payload = artifact_payload(execution)

    assert execution.exit_code == 2
    assert execution.metadata["status"] == "auth_failed"
    assert payload["status"] == "auth_failed"
    assert payload["read_only"] is True
    assert payload["summary"]["account_count"] == 0
    assert "AEGISPT_TEST_AWS_SECRET_ACCESS_KEY" not in execution.stdout
    assert "AEGISPT_TEST_AWS_SECRET_ACCESS_KEY" not in execution.stderr
