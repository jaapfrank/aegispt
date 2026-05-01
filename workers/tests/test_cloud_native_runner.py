from __future__ import annotations

import json
from types import SimpleNamespace

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.cloud_native.runner import (
    CLOUD_NATIVE_INVENTORY_ARTIFACT_NAME,
    CLOUD_NATIVE_RESULTS_ARTIFACT_NAME,
    execute_cloud_native_assessment,
)


class ArtifactRecord:
    uri = "artifact://cloud-native/results"


def build_fixture_manifest(path) -> None:
    path.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-api
  namespace: production
spec:
  template:
    spec:
      hostNetwork: true
      automountServiceAccountToken: true
      volumes:
        - name: host-root
          hostPath:
            path: /
      containers:
        - name: api
          image: registry.example/api:latest
          securityContext:
            privileged: true
            runAsNonRoot: false
            capabilities:
              add: ["NET_ADMIN"]
          env:
            - name: DATABASE_PASSWORD
              value: super-secret-not-echoed
---
apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
stringData:
  password: do-not-echo
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anonymous-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: system:unauthenticated
---
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
spec:
  type: LoadBalancer
  selector:
    app: dashboard
""",
        encoding="utf-8",
    )


def test_cloud_native_static_review_creates_evidence_backed_findings(tmp_path) -> None:
    manifest_path = tmp_path / "workloads.yaml"
    build_fixture_manifest(manifest_path)

    execution = execute_cloud_native_assessment(
        [str(manifest_path), "registry.example/api:latest"],
        scope_allowlist={
            "kubernetes_manifest_paths": [str(manifest_path)],
            "container_images": ["registry.example/api:latest"],
        },
        image_metadata=[
            {
                "image": "registry.example/api:latest",
                "base_image": "ubuntu:latest",
                "user": "root",
                "cves": [{"id": "CVE-2026-0001", "severity": "critical"}],
            }
        ],
        cluster_posture={"cluster_id": "prod-aks", "rbac_enabled": False, "network_policies": False},
    )

    assert execution.exit_code == 0
    assert execution.tool == "cloud-native"
    assert execution.metadata["status"] == "completed"
    artifact_names = {artifact.name for artifact in execution.artifacts}
    assert CLOUD_NATIVE_RESULTS_ARTIFACT_NAME in artifact_names
    assert CLOUD_NATIVE_INVENTORY_ARTIFACT_NAME in artifact_names

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CLOUD_NATIVE_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    assert payload["safety"]["cluster_mutation"] is False
    assert payload["safety"]["container_execution"] is False
    assert "container_execution_not_run" in payload["unsupported_states"]
    finding_types = {finding["type"] for finding in payload["findings"]}
    assert "kubernetes_privileged_container" in finding_types
    assert "kubernetes_hostpath_volume" in finding_types
    assert "kubernetes_rbac_wildcard_permissions" in finding_types
    assert "kubernetes_manifest_secret_material" in finding_types
    assert "container_image_high_risk_cve" in finding_types
    assert any("OWASP Kubernetes Top 10" in " ".join(finding["methodology_tags"]) for finding in payload["findings"])

    task = SimpleNamespace(tool="cloud-native", target_id=str(manifest_path), params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=CLOUD_NATIVE_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="cloud-native-results",
        ),
        artifact_record=ArtifactRecord(),
    )
    assert {finding.evidence_ref for finding in findings} == {ArtifactRecord.uri}
    assert "Kubernetes workload has privileged container" in {finding.title for finding in findings}


def test_cloud_native_rejects_out_of_scope_manifest(tmp_path) -> None:
    allowed_manifest = tmp_path / "allowed.yaml"
    outside_manifest = tmp_path / "outside.yaml"
    build_fixture_manifest(allowed_manifest)
    build_fixture_manifest(outside_manifest)

    try:
        execute_cloud_native_assessment(
            [str(outside_manifest)],
            scope_allowlist={"kubernetes_manifest_paths": [str(allowed_manifest)]},
        )
    except ValueError as exc:
        assert "outside scope" in str(exc)
    else:
        raise AssertionError("out-of-scope Kubernetes manifest was accepted")


def test_cloud_native_missing_artifact_is_truthful(tmp_path) -> None:
    manifest_path = tmp_path / "missing.yaml"

    execution = execute_cloud_native_assessment(
        [str(manifest_path)],
        scope_allowlist={"kubernetes_manifest_paths": [str(manifest_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_cloud_native_artifact"


def test_cloud_native_unsupported_provider_is_truthful(tmp_path) -> None:
    manifest_path = tmp_path / "workloads.yaml"
    build_fixture_manifest(manifest_path)

    execution = execute_cloud_native_assessment(
        [str(manifest_path)],
        scope_allowlist={"kubernetes_manifest_paths": [str(manifest_path)]},
        provider="ecs",
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "unsupported_cloud_native_provider"


def test_cloud_native_missing_input_is_truthful() -> None:
    execution = execute_cloud_native_assessment([], scope_allowlist={})

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_cloud_native_input"
