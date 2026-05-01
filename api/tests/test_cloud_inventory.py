from __future__ import annotations


def _create_engagement(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "cloud-operator"},
        json={
            "name": "Cloud Inventory Review",
            "client": "Acme Corp",
            "roe_ref": "ROE-CLOUD-1",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_inventory(client, engagement_id: str, observation_data: dict) -> dict:
    response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "cloud-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["cloud-readonly-fixture"],
            "observations": [
                {
                    "tool": "cloud-readonly-fixture",
                    "kind": "inventory",
                    "data": observation_data,
                }
            ],
            "environment_notes": ["Read-only cloud analysis fixture"],
            "assumptions": ["No cloud mutation or exploitation was performed"],
        },
    )
    assert response.status_code == 201
    return response.json()


def test_cloud_analysis_returns_aws_iam_exposure_and_kubernetes_signals(client) -> None:
    engagement_id = _create_engagement(client)
    inventory = _create_inventory(
        client,
        engagement_id,
        {
            "confidence": 0.88,
            "cloud_accounts": [{"provider": "aws", "account_id": "123456789012"}],
            "cloud_resources": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "resource_type": "ec2:instance",
                    "resource_id": "i-public",
                    "metadata": {
                        "public_ip": "198.51.100.10",
                        "security_group_ids": ["sg-open"],
                    },
                }
            ],
            "cloud_security_groups": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "group_id": "sg-open",
                    "group_name": "open-admin",
                    "ingress_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr_blocks": ["0.0.0.0/0"],
                        }
                    ],
                    "rule_count": 1,
                }
            ],
            "cloud_iam_policies": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "policy_id": "arn:aws:iam::123456789012:policy/AdminWildcard",
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    },
                }
            ],
            "cloud_iam_principals": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "principal_type": "role",
                    "principal_id": "arn:aws:iam::123456789012:role/OpenTrust",
                    "trust_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                }
            ],
            "kubernetes_clusters": [
                {
                    "provider": "kubernetes",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "cluster_id": "prod-eks",
                    "public_endpoint": True,
                    "rbac_enabled": False,
                    "anonymous_auth_enabled": True,
                    "secrets_encryption_enabled": False,
                }
            ],
            "kubernetes_workloads": [
                {
                    "provider": "kubernetes",
                    "account_id": "123456789012",
                    "cluster_id": "prod-eks",
                    "namespace": "default",
                    "kind": "Deployment",
                    "name": "privileged-agent",
                    "privileged": True,
                    "host_network": True,
                    "run_as_root": True,
                }
            ],
        },
    )

    response = client.get(f"/api/v1/inventory/{inventory['id']}/cloud-analysis")
    assert response.status_code == 200
    analysis = response.json()

    assert analysis["status"] == "analysis_ready"
    assert analysis["read_only"] is True
    assert analysis["provider_scope"]["observed"] == ["aws"]
    assert analysis["provider_scope"]["unsupported"] == []
    assert f"inventory:{inventory['id']}" in analysis["evidence_basis"]
    assert analysis["limitations"] == []

    categories = {finding["category"] for finding in analysis["analysis_findings"]}
    assert "public_exposure" in categories
    assert "security_group_exposure" in categories
    assert "iam_policy_risk" in categories
    assert "iam_trust_risk" in categories
    assert "kubernetes_configuration" in categories
    assert "kubernetes_workload_risk" in categories
    assert all(finding["evidence"] for finding in analysis["analysis_findings"])


def test_cloud_analysis_missing_permissions_are_explicit_and_non_fatal(client) -> None:
    engagement_id = _create_engagement(client)
    inventory = _create_inventory(
        client,
        engagement_id,
        {
            "confidence": 0.7,
            "cloud_accounts": [{"provider": "aws", "account_id": "123456789012"}],
            "cloud_collection_errors": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "service": "iam",
                    "operation": "ListRoles",
                    "error_code": "AccessDenied",
                    "message": "not authorized to list roles",
                }
            ],
        },
    )

    response = client.get(f"/api/v1/inventory/{inventory['id']}/cloud-analysis")
    assert response.status_code == 200
    analysis = response.json()

    assert analysis["status"] == "partial"
    assert analysis["read_only"] is True
    assert analysis["analysis_findings"] == []
    assert any(
        limitation["category"] == "missing_permission"
        and limitation["operation"] == "ListRoles"
        and limitation["error_code"] == "AccessDenied"
        for limitation in analysis["limitations"]
    )


def test_cloud_analysis_unsupported_provider_is_explicit(client) -> None:
    engagement_id = _create_engagement(client)
    inventory = _create_inventory(
        client,
        engagement_id,
        {
            "confidence": 0.74,
            "cloud_accounts": [{"provider": "azure", "account_id": "tenant-001"}],
            "cloud_resources": [
                {
                    "provider": "azure",
                    "account_id": "tenant-001",
                    "region": "westeurope",
                    "resource_type": "compute:vm",
                    "resource_id": "vm-001",
                    "metadata": {"public_ip": "203.0.113.10"},
                }
            ],
        },
    )

    response = client.get(f"/api/v1/inventory/{inventory['id']}/cloud-analysis")
    assert response.status_code == 200
    analysis = response.json()

    assert analysis["status"] == "unsupported_provider"
    assert analysis["read_only"] is True
    assert analysis["provider_scope"]["observed"] == ["azure"]
    assert analysis["provider_scope"]["unsupported"] == ["azure"]
    assert analysis["analysis_findings"] == []
    assert any(
        limitation["category"] == "unsupported_provider"
        and limitation["provider"] == "azure"
        for limitation in analysis["limitations"]
    )
