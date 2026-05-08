from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from api.app.models import Finding, FindingRemediation, FindingValidationRecord, RunDrift


def _create_scoped_engagement(client) -> dict:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "name": "Attack Path Review",
            "client": "Acme Corp",
            "roe_ref": "ROE-ATTACK-PATH-1",
        },
    ).json()

    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "allowlist_json": {
                "hosts": ["app.example.test", "api.example.test", "10.0.1.10"],
                "urls": ["https://app.example.test/login", "https://api.example.test/v1"],
            },
            "denylist_json": {},
        },
    )
    return engagement


def _create_attack_path_run(client) -> tuple[dict, dict, dict]:
    engagement = _create_scoped_engagement(client)
    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["attack-path-fixture"],
            "observations": [
                {
                    "tool": "attack-path-fixture",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.test", "api.example.test"],
                        "services": [
                            {
                                "host": "app.example.test",
                                "port": 443,
                                "protocol": "tcp",
                                "service": "https",
                                "product": "nginx",
                                "confidence": 0.92,
                            },
                            {
                                "host": "api.example.test",
                                "port": 443,
                                "protocol": "tcp",
                                "service": "https",
                                "product": "uvicorn",
                                "confidence": 0.88,
                            },
                        ],
                        "endpoints": [
                            {
                                "url": "https://app.example.test/login",
                                "methods": ["GET"],
                                "status_code": 200,
                                "title": "Login",
                                "confidence": 0.9,
                            },
                            {
                                "url": "https://api.example.test/v1",
                                "methods": ["GET"],
                                "status_code": 200,
                                "title": "API Root",
                                "confidence": 0.86,
                            },
                        ],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    ).json()

    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": "passive-web-baseline",
                "targets": {
                    "urls": ["https://app.example.test/login", "https://api.example.test/v1"],
                },
            },
        },
    ).json()
    return engagement, inventory, run


def _seed_attack_path_findings(client, *, run_id: str, inventory_id: str) -> None:
    finding_specs = [
        (
            "Weak login throttling",
            "high",
            "https://app.example.test/login",
            "artifact://zap/app/login-throttling",
        ),
        (
            "Missing security headers",
            "medium",
            "app.example.test",
            "artifact://httpx/app/headers",
        ),
        (
            "TLS certificate nearing expiry",
            "low",
            "app.example.test:443",
            "artifact://tls/app/certificate",
        ),
        (
            "Verbose API banner",
            "medium",
            "https://api.example.test/v1",
            "artifact://httpx/api/banner",
        ),
    ]
    with client.app.state.session_factory() as session:
        for title, severity, target_id, evidence_ref in finding_specs:
            session.add(
                Finding(
                    run_id=UUID(run_id),
                    source_inventory_snapshot_id=UUID(inventory_id),
                    title=title,
                    severity=severity,
                    target_id=target_id,
                    evidence_ref=evidence_ref,
                    status="open",
                    summary=f"{title} was observed during the run.",
                )
            )
        session.commit()


def test_attack_path_summary_builds_multi_host_paths_and_choke_points(client) -> None:
    _, inventory, run = _create_attack_path_run(client)
    _seed_attack_path_findings(client, run_id=run["id"], inventory_id=inventory["id"])

    response = client.get(f"/api/v1/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["run_id"] == run["id"]
    assert payload["evaluation_model"] == "evidence-first-choke-point-v1"
    assert payload["sources"]["inventory_snapshot_id"] == inventory["id"]
    assert payload["summary"]["candidate_path_count"] == 4
    assert payload["summary"]["choke_point_count"] >= 1
    assert payload["summary"]["confirmed_edge_count"] == len(payload["edges"])
    assert payload["summary"]["inferred_edge_count"] == 0
    assert payload["inferred_edges"] == []
    assert payload["lateral_analysis"]["status"] == "confirmed_only"
    assert all(edge["classification"] == "confirmed" for edge in payload["edges"])

    node_types = {node["type"] for node in payload["nodes"]}
    assert {"host", "service", "endpoint", "finding"}.issubset(node_types)

    path_labels = [" > ".join(path["labels"]) for path in payload["candidate_paths"]]
    assert any("app.example.test" in labels and "Weak login throttling" in labels for labels in path_labels)
    assert any("api.example.test" in labels and "Verbose API banner" in labels for labels in path_labels)

    app_choke = next(
        choke
        for choke in payload["choke_points"]
        if choke["type"] == "host" and choke["label"] == "app.example.test"
    )
    assert app_choke["path_count"] == 3
    assert app_choke["finding_count"] == 3
    assert all(choke["path_count"] >= payload["choke_point_threshold"] for choke in payload["choke_points"])


def test_remediation_advisor_ranks_choke_points_and_links_proof_boundaries(client) -> None:
    _, inventory, run = _create_attack_path_run(client)
    _seed_attack_path_findings(client, run_id=run["id"], inventory_id=inventory["id"])

    with client.app.state.session_factory() as session:
        login_finding = session.query(Finding).filter_by(
            run_id=UUID(run["id"]),
            title="Weak login throttling",
        ).one()
        login_finding.replay_recipe_json = {
            "tool": "zap",
            "target": login_finding.target_id,
            "match": "login-throttling",
        }
        session.add(
            FindingRemediation(
                finding_id=login_finding.id,
                state="ready_for_retest",
                owner="app-team",
                notes="Rate-limit change staged for controlled proof.",
                created_by="advisor-test",
                updated_by="advisor-test",
            )
        )
        session.add(
            FindingValidationRecord(
                finding_id=login_finding.id,
                run_id=UUID(run["id"]),
                status="validated_confirmed",
                validator_tool="zap",
                validator_target_id=login_finding.target_id,
                evidence_ref="artifact://validation/login-throttling",
            )
        )
        session.add(
            RunDrift(
                run_id=UUID(run["id"]),
                previous_run_id=UUID(run["id"]),
                new_finding_count=1,
                resolved_finding_count=0,
                exposure_delta=12.5,
                computed_at=datetime.now(tz=UTC),
            )
        )
        session.commit()

    response = client.get(f"/api/v1/runs/{run['id']}/remediation-advisor")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["advisor_model"] == "deterministic-ai-choke-point-remediation-v1"
    assert payload["execution_contract"]["planning_only"] is True
    assert payload["execution_contract"]["dispatches_work"] is False
    assert payload["execution_contract"]["approval_gates_bypassed"] is False
    assert payload["summary"]["candidate_path_count"] == 4
    assert payload["summary"]["recommendation_count"] >= 1
    assert payload["drift_context"]["available"] is True
    assert payload["drift_context"]["new_finding_count"] == 1

    top = payload["recommendations"][0]
    assert top["label"] in {"app.example.test", "https://app.example.test/login"}
    assert top["breaks_candidate_path_count"] == 3
    assert top["breaks_candidate_path_percent"] == 75.0
    assert top["affected_finding_count"] == 3
    assert top["proof_of_resolution_plan"]
    assert any(plan["replay_recipe_available"] is True for plan in top["proof_of_resolution_plan"])
    assert any(plan["existing_validation_count"] == 1 for plan in top["proof_of_resolution_plan"])
    assert "controlled proof" in payload["proof_of_resolution"]["boundary"]
    assert payload["proof_of_resolution"]["planning_only"] is True


def test_attack_path_summary_adds_review_only_inferred_identity_cloud_edges(client) -> None:
    engagement = _create_scoped_engagement(client)
    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["attack-path-inference-fixture"],
            "observations": [
                {
                    "tool": "attack-path-inference-fixture",
                    "kind": "inventory",
                    "data": {
                        "confidence": 0.9,
                        "hosts": ["10.0.1.10"],
                        "services": [
                            {
                                "host": "10.0.1.10",
                                "port": 443,
                                "protocol": "tcp",
                                "service": "https",
                                "confidence": 0.9,
                            }
                        ],
                        "identity_subjects": [
                            {"account_name": "svc-deploy", "enabled": True, "confidence": 0.86}
                        ],
                        "identity_groups": [
                            {"name": "Domain Admins", "privileged": True, "confidence": 0.84}
                        ],
                        "privileged_memberships": [
                            {"member": "svc-deploy", "group": "Domain Admins", "confidence": 0.82}
                        ],
                        "cloud_resources": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "region": "us-east-1",
                                "resource_type": "ec2:instance",
                                "resource_id": "i-web",
                                "name": "web-instance",
                                "confidence": 0.88,
                                "metadata": {
                                    "private_ip": "10.0.1.10",
                                    "security_group_ids": ["sg-web"],
                                },
                            }
                        ],
                        "cloud_security_groups": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "region": "us-east-1",
                                "group_id": "sg-web",
                                "group_name": "web-sg",
                                "confidence": 0.87,
                            }
                        ],
                        "cloud_iam_principals": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "principal_type": "role",
                                "principal_id": "arn:aws:iam::123456789012:role/WebRole",
                                "name": "WebRole",
                                "confidence": 0.8,
                            }
                        ],
                        "cloud_iam_policies": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "policy_id": "arn:aws:iam::123456789012:policy/WebPolicy",
                                "policy_name": "WebPolicy",
                                "confidence": 0.78,
                            }
                        ],
                        "cloud_iam_attachments": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "principal_id": "arn:aws:iam::123456789012:role/WebRole",
                                "policy_id": "arn:aws:iam::123456789012:policy/WebPolicy",
                                "confidence": 0.77,
                            }
                        ],
                        "kubernetes_clusters": [
                            {
                                "provider": "kubernetes",
                                "cluster_id": "prod-eks",
                                "name": "prod-eks",
                                "confidence": 0.76,
                            }
                        ],
                        "kubernetes_workloads": [
                            {
                                "provider": "kubernetes",
                                "cluster_id": "prod-eks",
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "web-api",
                                "confidence": 0.75,
                            }
                        ],
                    },
                }
            ],
        },
    ).json()
    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"hosts": ["10.0.1.10"]},
            },
        },
    ).json()
    with client.app.state.session_factory() as session:
        session.add(
            Finding(
                run_id=UUID(run["id"]),
                source_inventory_snapshot_id=UUID(inventory["id"]),
                title="Exposed management endpoint",
                severity="high",
                target_id="10.0.1.10:443",
                evidence_ref="artifact://fixture/management-endpoint",
                status="open",
                summary="The approved host exposes a management endpoint.",
            )
        )
        session.commit()

    response = client.get(f"/api/v1/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["summary"]["confirmed_edge_count"] > 0
    assert payload["summary"]["inferred_edge_count"] >= 5
    assert len(payload["inferred_edges"]) == payload["summary"]["inferred_edge_count"]

    inferred_types = {edge["type"] for edge in payload["inferred_edges"]}
    assert "inferred-privileged-membership" in inferred_types
    assert "inferred-iam-policy-attachment" in inferred_types
    assert "inferred-security-group-association" in inferred_types
    assert "inferred-cloud-host-context" in inferred_types
    assert "inferred-kubernetes-workload-context" in inferred_types
    assert all(edge["classification"] == "inferred" for edge in payload["inferred_edges"])
    assert all(edge["operator_review_required"] is True for edge in payload["inferred_edges"])
    assert all(edge["active_pivoting_performed"] is False for edge in payload["inferred_edges"])
    assert all(edge["credential_testing_performed"] is False for edge in payload["inferred_edges"])
    assert all(edge["lateral_movement_performed"] is False for edge in payload["inferred_edges"])
    assert all(edge["scope_expansion_performed"] is False for edge in payload["inferred_edges"])
    assert all(edge["automatic_dispatch_performed"] is False for edge in payload["inferred_edges"])
    assert all(0 < edge["confidence"] <= 1 for edge in payload["inferred_edges"])
    assert all(edge["rationale"] for edge in payload["inferred_edges"])
    assert all(edge["evidence_refs"] for edge in payload["inferred_edges"])

    boundary = payload["lateral_analysis"]["boundary"]
    assert payload["lateral_analysis"]["status"] == "inferred_context_available"
    assert boundary["active_pivoting_performed"] is False
    assert boundary["credential_testing_performed"] is False
    assert boundary["lateral_movement_performed"] is False
    assert boundary["scope_expansion_performed"] is False
    assert boundary["automatic_dispatch_performed"] is False
    assert payload["lateral_analysis"]["notes"]
    assert all(note["operator_review_required"] is True for note in payload["lateral_analysis"]["notes"])

    advisor_response = client.get(f"/api/v1/runs/{run['id']}/remediation-advisor")
    assert advisor_response.status_code == 200
    advisor = advisor_response.json()
    assert advisor["cloud_context"]["available"] is True
    assert advisor["cloud_context"]["cloud_node_count"] >= 1
    assert advisor["cloud_context"]["cloud_inferred_edge_count"] >= 1
    assert "does not mutate cloud resources" in advisor["cloud_context"]["boundary"]


def test_attack_path_summary_returns_truthful_zero_data_fallback(client) -> None:
    engagement = _create_scoped_engagement(client)
    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test"]},
            },
        },
    ).json()

    response = client.get(f"/api/v1/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "empty"
    assert payload["sources"]["inventory_snapshot_id"] is None
    assert payload["sources"]["finding_count"] == 0
    assert payload["nodes"] == []
    assert payload["edges"] == []
    assert payload["inferred_edges"] == []
    assert payload["lateral_analysis"]["status"] == "confirmed_only"
    assert payload["lateral_analysis"]["boundary"]["scope_expansion_performed"] is False
    assert payload["candidate_paths"] == []
    assert payload["choke_points"] == []
    assert "No selected-run inventory or finding evidence" in payload["summary"]["reason"]


def test_attack_path_summary_retains_unmatched_findings_as_low_confidence(client) -> None:
    engagement = _create_scoped_engagement(client)
    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test/login"]},
            },
        },
    ).json()
    with client.app.state.session_factory() as session:
        session.add(
            Finding(
                run_id=UUID(run["id"]),
                title="Unmatched finding target",
                severity="medium",
                target_id="https://unmatched.example.test",
                evidence_ref="artifact://manual/unmatched",
                status="open",
                summary="The finding exists before inventory is linked.",
            )
        )
        session.commit()

    response = client.get(f"/api/v1/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "low_confidence"
    assert payload["summary"]["candidate_path_count"] == 1
    assert payload["candidate_paths"][0]["node_ids"] == [payload["nodes"][0]["id"]]
    assert payload["candidate_paths"][0]["confidence"] == 0.35
    assert payload["summary"]["inferred_edge_count"] == 0
    assert payload["lateral_analysis"]["boundary"]["scope_expansion_performed"] is False
    assert "low-confidence" in payload["summary"]["reason"]


def test_attack_path_inference_does_not_turn_context_into_candidate_scope(client) -> None:
    engagement = _create_scoped_engagement(client)
    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["cloud-context-fixture"],
            "observations": [
                {
                    "tool": "cloud-context-fixture",
                    "kind": "inventory",
                    "data": {
                        "cloud_resources": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "region": "us-east-1",
                                "resource_type": "ec2:instance",
                                "resource_id": "i-context-only",
                                "name": "context-only-instance",
                                "metadata": {"security_group_ids": ["sg-context"]},
                            }
                        ],
                        "cloud_security_groups": [
                            {
                                "provider": "aws",
                                "account_id": "123456789012",
                                "region": "us-east-1",
                                "group_id": "sg-context",
                                "group_name": "context-only-sg",
                            }
                        ],
                    },
                }
            ],
        },
    ).json()
    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test/login"]},
            },
        },
    ).json()

    response = client.get(f"/api/v1/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    payload = response.json()
    assert payload["candidate_paths"] == []
    assert payload["lateral_analysis"]["boundary"]["scope_expansion_performed"] is False
    assert payload["lateral_analysis"]["boundary"]["automatic_dispatch_performed"] is False
    assert payload["summary"]["inferred_edge_count"] == 1
    assert payload["inferred_edges"][0]["type"] == "inferred-security-group-association"


def test_attack_path_summary_404s_for_unknown_run(client) -> None:
    response = client.get("/api/v1/runs/00000000-0000-0000-0000-000000000000/attack-paths")

    assert response.status_code == 404
    assert response.json()["detail"] == "run not found"


def test_attack_path_summary_imports_bloodhound_confirmed_edges_and_candidate_paths(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "name": "BloodHound Review",
            "client": "Acme Corp",
            "roe_ref": "ROE-BLOODHOUND-1",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "allowlist_json": {
                "directory_hosts": ["dc01.corp.example"],
                "ad_domains": ["corp.example"],
            },
            "denylist_json": {},
        },
    )

    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["bloodhound-collect"],
            "observations": [
                {
                    "tool": "bloodhound-collect",
                    "kind": "inventory",
                    "data": {
                        "hosts": [{"host": "dc01.corp.example", "confidence": 0.82}],
                        "identity_subjects": [
                            {
                                "account_name": "alice@corp.example",
                                "enabled": True,
                                "confidence": 0.86,
                            }
                        ],
                        "identity_groups": [
                            {"name": "Helpdesk", "privileged": False, "confidence": 0.84},
                            {
                                "name": "Domain Admins",
                                "privileged": True,
                                "confidence": 0.84,
                            },
                        ],
                        "privileged_memberships": [],
                        "bloodhound_confirmed_edges": [
                            {
                                "source_id": "identity-subject:alice-corp-example",
                                "target_id": "identity-group:helpdesk",
                                "source_label": "alice@corp.example",
                                "target_label": "Helpdesk",
                                "source_type": "identity_subject",
                                "target_type": "identity_group",
                                "relationship": "member-of",
                                "relationship_label": "MemberOf",
                                "confidence": 0.86,
                                "rationale": "Group membership observed in BloodHound.",
                            },
                            {
                                "source_id": "identity-group:helpdesk",
                                "target_id": "identity-group:domain-admins",
                                "source_label": "Helpdesk",
                                "target_label": "Domain Admins",
                                "source_type": "identity_group",
                                "target_type": "identity_group",
                                "relationship": "ace-addmember",
                                "relationship_label": "AddMember",
                                "confidence": 0.82,
                                "rationale": "ACL path observed in BloodHound.",
                            },
                        ],
                        "bloodhound_attack_paths": [
                            {
                                "path_id": "bloodhound-path:1",
                                "finding_title": "Read-only AD attack path to Domain Admins observed from alice@corp.example",
                                "finding_target_id": "Domain Admins",
                                "severity": "high",
                                "target_category": "domain_admins",
                                "source_label": "alice@corp.example",
                                "source_type": "identity_subject",
                                "target_label": "Domain Admins",
                                "target_type": "identity_group",
                                "node_ids": [
                                    "identity-subject:alice-corp-example",
                                    "identity-group:helpdesk",
                                    "identity-group:domain-admins",
                                ],
                                "node_labels": [
                                    "alice@corp.example",
                                    "Helpdesk",
                                    "Domain Admins",
                                ],
                                "edge_chain": [
                                    {
                                        "source_id": "identity-subject:alice-corp-example",
                                        "target_id": "identity-group:helpdesk",
                                        "relationship": "member-of",
                                        "relationship_label": "MemberOf",
                                        "source_label": "alice@corp.example",
                                        "target_label": "Helpdesk",
                                    },
                                    {
                                        "source_id": "identity-group:helpdesk",
                                        "target_id": "identity-group:domain-admins",
                                        "relationship": "ace-addmember",
                                        "relationship_label": "AddMember",
                                        "source_label": "Helpdesk",
                                        "target_label": "Domain Admins",
                                    },
                                ],
                                "summary": "Read-only BloodHound analysis found a path from alice to Domain Admins.",
                                "confidence": 0.82,
                            }
                        ],
                        "confidence": 0.84,
                    },
                }
            ],
        },
    ).json()

    run = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "attack-path-operator"},
        json={
            "profile_name": "passive-identity-ldap-enum",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "targets": {"ad_domains": ["corp.example"]},
                "ldap": {"base_dn": "DC=corp,DC=example"},
            },
        },
    ).json()

    with client.app.state.session_factory() as session:
        session.add(
            Finding(
                run_id=UUID(run["id"]),
                source_inventory_snapshot_id=UUID(inventory["id"]),
                title="Read-only AD attack path to Domain Admins observed from alice@corp.example",
                severity="high",
                target_id="Domain Admins",
                evidence_ref="artifact://bloodhound/path-1",
                status="open",
                summary="BloodHound read-only analysis observed a path to Domain Admins.",
            )
        )
        session.commit()

    response = client.get(f"/api/v1/runs/{run['id']}/attack-paths")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["summary"]["confirmed_edge_count"] >= 2
    assert payload["summary"]["candidate_path_count"] >= 1
    assert any(edge["type"] == "ace-addmember" for edge in payload["edges"])
    assert any(path["finding_title"].startswith("Read-only AD attack path to Domain Admins") for path in payload["candidate_paths"])
    joined_labels = " > ".join(payload["candidate_paths"][0]["labels"])
    assert "alice@corp.example" in joined_labels
    assert "Domain Admins" in joined_labels
