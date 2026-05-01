from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

import yaml

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

CLOUD_NATIVE_RESULTS_ARTIFACT_NAME = "cloud-native-results.json"
CLOUD_NATIVE_INVENTORY_ARTIFACT_NAME = "cloud-native-inventory.json"
RUNNER_DIGEST = "workers.cloud_native.runner:v1"

SUPPORTED_PROVIDERS = {"kubernetes", "generic-kubernetes", "local", ""}
WORKLOAD_KINDS = {"CronJob", "DaemonSet", "Deployment", "Job", "Pod", "ReplicaSet", "StatefulSet"}
SECRET_NAME_PATTERN = re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)", re.I)
CONTROL_PLANE_PATTERN = re.compile(r"(dashboard|api[-_]?server|apiserver|control[-_]?plane)", re.I)


@dataclass(slots=True, frozen=True)
class ManifestResource:
    source: str
    document_index: int
    kind: str
    api_version: str | None
    name: str
    namespace: str | None
    body: dict[str, Any]


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind=kind,
    )


def _safety_contract() -> dict[str, bool]:
    return {
        "read_only": True,
        "cluster_mutation": False,
        "container_execution": False,
        "privilege_escalation": False,
        "lateral_movement": False,
        "destructive_actions": False,
    }


def _skip_execution(
    *,
    reason: str,
    targets: list[str],
    stdout: str,
    stderr: str = "",
    extra_payload: dict[str, Any] | None = None,
) -> RunnerExecution:
    payload = {
        "status": "skipped",
        "reason": reason,
        "targets": targets,
        "checks": [],
        "findings": [],
        "warnings": [],
        "unsupported_states": [reason],
        "safety": _safety_contract(),
        **(extra_payload or {}),
    }
    return RunnerExecution(
        tool="cloud-native",
        exit_code=0,
        stdout=stdout,
        stderr=stderr,
        metadata={
            "status": "skipped",
            "reason": reason,
            "runner_digest": RUNNER_DIGEST,
            "finding_count": 0,
        },
        artifacts=[
            _json_artifact(
                CLOUD_NATIVE_RESULTS_ARTIFACT_NAME,
                payload,
                kind="cloud-native-results",
            )
        ],
    )


def _finding(
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    tags: list[str],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "title": title,
        "severity": severity,
        "target": target,
        "summary": summary,
        "methodology_tags": ["cloud_native_security", "owasp_kubernetes_top_10", *tags],
        "evidence": evidence,
    }


def _safe_name(resource: dict[str, Any], fallback: str) -> str:
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    name = str(metadata.get("name") or "").strip()
    return name or fallback


def _read_manifest_documents(
    *,
    manifest_paths: list[str],
    inline_manifests: Any,
) -> tuple[list[ManifestResource], list[str], list[str]]:
    resources: list[ManifestResource] = []
    warnings: list[str] = []
    missing_paths: list[str] = []

    sources: list[tuple[str, str]] = []
    for path_value in manifest_paths:
        path = Path(path_value)
        if not path.exists():
            missing_paths.append(path_value)
            continue
        try:
            sources.append((path_value, path.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            warnings.append(f"{path_value}: could not read manifest artifact: {exc}")

    if isinstance(inline_manifests, str) and inline_manifests.strip():
        sources.append(("inline-manifest", inline_manifests))
    elif isinstance(inline_manifests, list):
        for index, manifest in enumerate(inline_manifests, start=1):
            if isinstance(manifest, str) and manifest.strip():
                sources.append((f"inline-manifest-{index}", manifest))
            elif isinstance(manifest, dict):
                resources.append(_resource_from_dict(manifest, f"inline-manifest-{index}", 1))

    for source, text in sources:
        try:
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            warnings.append(f"{source}: manifest parse error: {exc}")
            continue
        for index, document in enumerate(documents, start=1):
            if isinstance(document, list):
                for item in document:
                    if isinstance(item, dict):
                        resources.append(_resource_from_dict(item, source, index))
                continue
            if isinstance(document, dict):
                resources.append(_resource_from_dict(document, source, index))

    return resources, warnings, missing_paths


def _resource_from_dict(resource: dict[str, Any], source: str, document_index: int) -> ManifestResource:
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    return ManifestResource(
        source=source,
        document_index=document_index,
        kind=str(resource.get("kind") or "Unknown").strip() or "Unknown",
        api_version=str(resource.get("apiVersion") or "").strip() or None,
        name=str(metadata.get("name") or "").strip() or "unnamed",
        namespace=str(metadata.get("namespace") or "").strip() or None,
        body=resource,
    )


def _pod_spec_for(resource: ManifestResource) -> dict[str, Any] | None:
    body = resource.body
    spec = body.get("spec") if isinstance(body.get("spec"), dict) else {}
    if resource.kind == "Pod":
        return spec
    if resource.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
        return template.get("spec") if isinstance(template.get("spec"), dict) else None
    if resource.kind == "Job":
        template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
        return template.get("spec") if isinstance(template.get("spec"), dict) else None
    if resource.kind == "CronJob":
        job_template = spec.get("jobTemplate") if isinstance(spec.get("jobTemplate"), dict) else {}
        job_spec = job_template.get("spec") if isinstance(job_template.get("spec"), dict) else {}
        template = job_spec.get("template") if isinstance(job_spec.get("template"), dict) else {}
        return template.get("spec") if isinstance(template.get("spec"), dict) else None
    return None


def _containers_from_pod_spec(pod_spec: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(pod_spec, dict):
        return []
    containers: list[dict[str, Any]] = []
    for key in ("initContainers", "containers"):
        raw_containers = pod_spec.get(key)
        if isinstance(raw_containers, list):
            containers.extend([item for item in raw_containers if isinstance(item, dict)])
    return containers


def _resource_target(resource: ManifestResource) -> str:
    namespace = f"{resource.namespace}/" if resource.namespace else ""
    return f"{resource.kind}/{namespace}{resource.name}"


def _analyze_workloads(resources: list[ManifestResource]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for resource in resources:
        if resource.kind not in WORKLOAD_KINDS:
            continue
        target = _resource_target(resource)
        pod_spec = _pod_spec_for(resource)
        containers = _containers_from_pod_spec(pod_spec)
        checks.append(
            {
                "check": "workload_security_context",
                "status": "reviewed",
                "target": target,
                "container_count": len(containers),
                "source": resource.source,
            }
        )
        if not isinstance(pod_spec, dict):
            continue

        for field_name in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(field_name) is True:
                findings.append(
                    _finding(
                        finding_type=f"kubernetes_{field_name}_enabled",
                        title=f"Kubernetes workload enables {field_name}",
                        severity="high",
                        target=target,
                        summary=f"{target} enables {field_name}, increasing host and network isolation risk.",
                        tags=["OWASP Kubernetes Top 10 2022: K01 Insecure Workload Configurations"],
                        evidence={"field": field_name, "source": resource.source},
                    )
                )

        if pod_spec.get("automountServiceAccountToken") is True:
            findings.append(
                _finding(
                    finding_type="kubernetes_service_account_token_automount",
                    title="Kubernetes workload explicitly automounts a service account token",
                    severity="medium",
                    target=target,
                    summary=f"{target} explicitly automounts a service account token; confirm the workload needs API access.",
                    tags=["OWASP Kubernetes Top 10 2022: K05 Inadequate RBAC Controls"],
                    evidence={"source": resource.source, "field": "automountServiceAccountToken=true"},
                )
            )

        for volume in pod_spec.get("volumes", []) if isinstance(pod_spec.get("volumes"), list) else []:
            if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
                findings.append(
                    _finding(
                        finding_type="kubernetes_hostpath_volume",
                        title="Kubernetes workload mounts hostPath volume",
                        severity="high",
                        target=target,
                        summary=f"{target} mounts a hostPath volume, which can expose host filesystem data to the workload.",
                        tags=["OWASP Kubernetes Top 10 2022: K01 Insecure Workload Configurations"],
                        evidence={"volume": str(volume.get("name") or ""), "source": resource.source},
                    )
                )

        for container in containers:
            container_name = str(container.get("name") or "container").strip()
            security_context = (
                container.get("securityContext")
                if isinstance(container.get("securityContext"), dict)
                else {}
            )
            if security_context.get("privileged") is True:
                findings.append(
                    _finding(
                        finding_type="kubernetes_privileged_container",
                        title="Kubernetes workload has privileged container",
                        severity="high",
                        target=target,
                        summary=f"{target} container {container_name} runs privileged.",
                        tags=["OWASP Kubernetes Top 10 2022: K01 Insecure Workload Configurations"],
                        evidence={"container": container_name, "source": resource.source},
                    )
                )
            capabilities = (
                security_context.get("capabilities")
                if isinstance(security_context.get("capabilities"), dict)
                else {}
            )
            added_caps = capabilities.get("add") if isinstance(capabilities, dict) else []
            if isinstance(added_caps, list) and added_caps:
                findings.append(
                    _finding(
                        finding_type="kubernetes_added_capabilities",
                        title="Kubernetes workload adds Linux capabilities",
                        severity="medium",
                        target=target,
                        summary=f"{target} container {container_name} adds Linux capabilities that should be justified.",
                        tags=["OWASP Kubernetes Top 10 2022: K01 Insecure Workload Configurations"],
                        evidence={"container": container_name, "capabilities": added_caps, "source": resource.source},
                    )
                )
            run_as_user = security_context.get("runAsUser")
            if security_context.get("runAsNonRoot") is False or run_as_user in {0, "0", "root"}:
                findings.append(
                    _finding(
                        finding_type="kubernetes_root_container_user",
                        title="Kubernetes workload permits root container user",
                        severity="medium",
                        target=target,
                        summary=f"{target} container {container_name} is configured to allow a root container user.",
                        tags=["OWASP Kubernetes Top 10 2022: K01 Insecure Workload Configurations"],
                        evidence={"container": container_name, "source": resource.source},
                    )
                )

            for env in container.get("env", []) if isinstance(container.get("env"), list) else []:
                if not isinstance(env, dict):
                    continue
                name = str(env.get("name") or "").strip()
                if SECRET_NAME_PATTERN.search(name) and str(env.get("value") or "").strip():
                    findings.append(
                        _finding(
                            finding_type="kubernetes_inline_env_secret",
                            title="Kubernetes workload contains inline secret-like environment value",
                            severity="high",
                            target=target,
                            summary=f"{target} container {container_name} stores a secret-like environment variable inline. Values are not echoed.",
                            tags=["OWASP Kubernetes Top 10 2022: K08 Secrets Management Failures"],
                            evidence={"container": container_name, "env_name": name, "source": resource.source},
                        )
                    )
    return checks, findings


def _analyze_rbac(resources: list[ManifestResource]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for resource in resources:
        if resource.kind not in {"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"}:
            continue
        target = _resource_target(resource)
        checks.append({"check": "rbac", "status": "reviewed", "target": target, "source": resource.source})
        if resource.kind in {"ClusterRole", "Role"}:
            rules = resource.body.get("rules") if isinstance(resource.body.get("rules"), list) else []
            for index, rule in enumerate([item for item in rules if isinstance(item, dict)], start=1):
                verbs = rule.get("verbs") if isinstance(rule.get("verbs"), list) else []
                resources_list = rule.get("resources") if isinstance(rule.get("resources"), list) else []
                if "*" in verbs and "*" in resources_list:
                    findings.append(
                        _finding(
                            finding_type="kubernetes_rbac_wildcard_permissions",
                            title="Kubernetes RBAC role grants wildcard permissions",
                            severity="high",
                            target=target,
                            summary=f"{target} grants wildcard verbs over wildcard resources.",
                            tags=["OWASP Kubernetes Top 10 2022: K05 Inadequate RBAC Controls"],
                            evidence={"rule_index": index, "source": resource.source},
                        )
                    )
        if resource.kind in {"ClusterRoleBinding", "RoleBinding"}:
            role_ref = (
                resource.body.get("roleRef")
                if isinstance(resource.body.get("roleRef"), dict)
                else {}
            )
            subjects = resource.body.get("subjects") if isinstance(resource.body.get("subjects"), list) else []
            subject_names = [
                str(subject.get("name") or "").strip()
                for subject in subjects
                if isinstance(subject, dict)
            ]
            if str(role_ref.get("name") or "").strip() == "cluster-admin" or any(
                name in {"system:anonymous", "system:unauthenticated"} for name in subject_names
            ):
                findings.append(
                    _finding(
                        finding_type="kubernetes_rbac_sensitive_binding",
                        title="Kubernetes RBAC binding exposes sensitive cluster permissions",
                        severity="critical",
                        target=target,
                        summary=f"{target} binds sensitive cluster permissions or unauthenticated subjects.",
                        tags=["OWASP Kubernetes Top 10 2022: K05 Inadequate RBAC Controls"],
                        evidence={"role_ref": dict(role_ref), "subjects": subject_names, "source": resource.source},
                    )
                )
    return checks, findings


def _analyze_services_and_secrets(resources: list[ManifestResource]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    workload_count = sum(1 for resource in resources if resource.kind in WORKLOAD_KINDS)
    network_policy_count = sum(1 for resource in resources if resource.kind == "NetworkPolicy")
    if workload_count:
        checks.append(
            {
                "check": "network_policy_presence",
                "status": "reviewed",
                "workload_count": workload_count,
                "network_policy_count": network_policy_count,
            }
        )
    if workload_count and network_policy_count == 0:
        findings.append(
            _finding(
                finding_type="kubernetes_missing_network_policy_context",
                title="Kubernetes workloads supplied without NetworkPolicy context",
                severity="medium",
                target="kubernetes-manifests",
                summary="Workload manifests were supplied without visible NetworkPolicy coverage; confirm segmentation separately if policies live outside this input bundle.",
                tags=["Cloud Native Risk: Network segmentation"],
                evidence={"workload_count": workload_count, "network_policy_count": 0},
            )
        )

    for resource in resources:
        target = _resource_target(resource)
        if resource.kind == "Secret":
            data = resource.body.get("data") if isinstance(resource.body.get("data"), dict) else {}
            string_data = (
                resource.body.get("stringData")
                if isinstance(resource.body.get("stringData"), dict)
                else {}
            )
            if data or string_data:
                findings.append(
                    _finding(
                        finding_type="kubernetes_manifest_secret_material",
                        title="Kubernetes Secret material is present in supplied manifests",
                        severity="high",
                        target=target,
                        summary=f"{target} contains secret material in manifest input. Values are not echoed.",
                        tags=["OWASP Kubernetes Top 10 2022: K08 Secrets Management Failures"],
                        evidence={"data_keys": sorted(data.keys()), "string_data_keys": sorted(string_data.keys()), "source": resource.source},
                    )
                )
        if resource.kind == "Service":
            spec = resource.body.get("spec") if isinstance(resource.body.get("spec"), dict) else {}
            service_type = str(spec.get("type") or "ClusterIP").strip()
            labels = resource.body.get("metadata", {}).get("labels", {}) if isinstance(resource.body.get("metadata"), dict) else {}
            searchable = " ".join([resource.name, json.dumps(labels, sort_keys=True)])
            if service_type in {"LoadBalancer", "NodePort"}:
                control_plane = bool(CONTROL_PLANE_PATTERN.search(searchable))
                findings.append(
                    _finding(
                        finding_type="kubernetes_exposed_sensitive_service" if control_plane else "kubernetes_exposed_service",
                        title=(
                            "Kubernetes dashboard/control-plane service is externally exposed"
                            if control_plane
                            else "Kubernetes service is externally exposed"
                        ),
                        severity="high" if control_plane else "medium",
                        target=target,
                        summary=f"{target} is type {service_type}; confirm exposure is intended and approved.",
                        tags=[
                            "OWASP Kubernetes Top 10 2022: K03 Overly Permissive Network Exposure"
                            if control_plane
                            else "Cloud Native Risk: Exposed service"
                        ],
                        evidence={"service_type": service_type, "source": resource.source},
                    )
                )
    return checks, findings


def _image_records(image_metadata: Any, targets: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(image_metadata, list):
        for item in image_metadata:
            if isinstance(item, dict):
                image = str(item.get("image") or item.get("name") or item.get("ref") or "").strip()
                if image:
                    records.append({**item, "image": image})
            elif isinstance(item, str) and item.strip():
                records.append({"image": item.strip()})
    elif isinstance(image_metadata, dict):
        image = str(image_metadata.get("image") or image_metadata.get("name") or image_metadata.get("ref") or "").strip()
        if image:
            records.append({**image_metadata, "image": image})

    for target in targets:
        if target.endswith((".yaml", ".yml", ".json")):
            continue
        if "/" in target or ":" in target:
            if target not in {record["image"] for record in records}:
                records.append({"image": target})
    return records


def _analyze_images(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for record in records:
        image = str(record.get("image") or "").strip()
        if not image:
            continue
        checks.append({"check": "container_image_metadata", "status": "reviewed", "target": image})
        tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""
        if not tag or tag == "latest":
            findings.append(
                _finding(
                    finding_type="container_image_mutable_tag",
                    title="Container image tag is mutable or missing",
                    severity="medium",
                    target=image,
                    summary=f"{image} uses a mutable or missing tag; pin immutable versions or digests for production workloads.",
                    tags=["OWASP Kubernetes Top 10 2022: K02 Supply Chain Vulnerabilities"],
                    evidence={"image": image, "tag": tag or None},
                )
            )
        base_image = str(record.get("base_image") or "").strip()
        if base_image and (base_image.endswith(":latest") or ":" not in base_image.rsplit("/", 1)[-1]):
            findings.append(
                _finding(
                    finding_type="container_base_image_mutable_tag",
                    title="Container base image tag is mutable or missing",
                    severity="medium",
                    target=image,
                    summary=f"{image} metadata references mutable base image {base_image}.",
                    tags=["OWASP Kubernetes Top 10 2022: K02 Supply Chain Vulnerabilities"],
                    evidence={"image": image, "base_image": base_image},
                )
            )
        if str(record.get("user") or "").strip().lower() in {"root", "0"} or record.get("root_user") is True:
            findings.append(
                _finding(
                    finding_type="container_image_root_user",
                    title="Container image defaults to root user",
                    severity="medium",
                    target=image,
                    summary=f"{image} metadata indicates the container defaults to root.",
                    tags=["OWASP Kubernetes Top 10 2022: K01 Insecure Workload Configurations"],
                    evidence={"image": image, "user": record.get("user"), "root_user": record.get("root_user")},
                )
            )
        for cve in record.get("cves", []) if isinstance(record.get("cves"), list) else []:
            if not isinstance(cve, dict):
                continue
            severity = str(cve.get("severity") or "").strip().lower()
            if severity in {"critical", "high"}:
                cve_id = str(cve.get("id") or cve.get("cve") or "CVE").strip()
                findings.append(
                    _finding(
                        finding_type="container_image_high_risk_cve",
                        title=f"Container image has {severity} vulnerability metadata",
                        severity="critical" if severity == "critical" else "high",
                        target=image,
                        summary=f"{image} metadata includes {severity} vulnerability {cve_id}.",
                        tags=["OWASP Kubernetes Top 10 2022: K02 Supply Chain Vulnerabilities"],
                        evidence={"image": image, "cve_id": cve_id, "severity": severity},
                    )
                )
    return checks, findings


def _analyze_cluster_posture(cluster_posture: Any, cluster_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    posture_items: list[dict[str, Any]]
    if isinstance(cluster_posture, dict):
        posture_items = [cluster_posture]
    elif isinstance(cluster_posture, list):
        posture_items = [item for item in cluster_posture if isinstance(item, dict)]
    else:
        posture_items = []

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for index, posture in enumerate(posture_items, start=1):
        target = str(posture.get("cluster_id") or cluster_id or f"cluster-{index}").strip()
        checks.append({"check": "cluster_posture", "status": "reviewed", "target": target})
        if posture.get("rbac_enabled") is False:
            findings.append(
                _finding(
                    finding_type="kubernetes_cluster_rbac_disabled",
                    title="Kubernetes cluster posture indicates RBAC is disabled",
                    severity="high",
                    target=target,
                    summary=f"{target} posture input reports RBAC disabled.",
                    tags=["OWASP Kubernetes Top 10 2022: K05 Inadequate RBAC Controls"],
                    evidence={"cluster_id": target},
                )
            )
        if posture.get("network_policies") is False or posture.get("network_policy_count") == 0:
            findings.append(
                _finding(
                    finding_type="kubernetes_cluster_network_policy_absent",
                    title="Kubernetes cluster posture indicates no NetworkPolicy coverage",
                    severity="medium",
                    target=target,
                    summary=f"{target} posture input reports missing NetworkPolicy coverage.",
                    tags=["Cloud Native Risk: Network segmentation"],
                    evidence={"cluster_id": target},
                )
            )
    return checks, findings


def _inventory_payload(
    *,
    resources: list[ManifestResource],
    image_records: list[dict[str, Any]],
    cluster_id: str | None,
    finding_count: int,
) -> dict[str, Any]:
    workloads = [
        {
            "kind": resource.kind,
            "name": resource.name,
            "namespace": resource.namespace,
            "source": resource.source,
            "api_version": resource.api_version,
        }
        for resource in resources
        if resource.kind in WORKLOAD_KINDS
    ]
    clusters = [
        {
            "cluster_id": cluster_id or "static-cloud-native-input",
            "provider": "kubernetes",
            "source": "cloud-native",
            "workload_count": len(workloads),
            "finding_count": finding_count,
        }
    ]
    images = [{"image": record.get("image")} for record in image_records if record.get("image")]
    return {
        "tool": "cloud-native",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": [],
            "technologies": [
                {"name": "Kubernetes", "vendor": "CNCF", "version": None, "confidence": 0.82}
            ],
            "fingerprints": [
                {
                    "vendor": "CNCF",
                    "product": "Kubernetes",
                    "version": None,
                    "source": "cloud-native",
                    "confidence": 0.76,
                }
            ],
            "kubernetes_clusters": clusters,
            "kubernetes_workloads": workloads,
            "container_images": images,
            "confidence": 0.82,
        },
    }


def execute_cloud_native_assessment(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    manifest_paths: list[str] | None = None,
    manifests: Any = None,
    image_metadata: Any = None,
    cluster_posture: Any = None,
    provider: str | None = "kubernetes",
    cluster_id: str | None = None,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    selected_provider = str(provider or "kubernetes").strip().lower()
    if selected_provider not in SUPPORTED_PROVIDERS:
        return _skip_execution(
            reason="unsupported_cloud_native_provider",
            targets=normalized_targets,
            stdout=f"Cloud-native assessment skipped: provider {selected_provider} is unsupported in this slice.",
            extra_payload={"provider": selected_provider},
        )

    input_manifest_paths = [
        str(path).strip()
        for path in (manifest_paths or [])
        if isinstance(path, str) and str(path).strip()
    ]
    for target in normalized_targets:
        if target.endswith((".yaml", ".yml", ".json")) and target not in input_manifest_paths:
            input_manifest_paths.append(target)

    scope = scope_allowlist or {}
    for value in [*normalized_targets, *input_manifest_paths]:
        if scope and not target_value_is_allowed(scope, value):
            raise ValueError(f"target outside scope: {value}")

    images = _image_records(image_metadata, normalized_targets)
    has_cluster_posture = isinstance(cluster_posture, (dict, list)) and bool(cluster_posture)
    if not input_manifest_paths and not manifests and not images and not has_cluster_posture:
        return _skip_execution(
            reason="missing_cloud_native_input",
            targets=normalized_targets,
            stdout="Cloud-native assessment skipped: no manifest, image metadata, or read-only cluster posture input was supplied.",
        )

    resources, warnings, missing_paths = _read_manifest_documents(
        manifest_paths=input_manifest_paths,
        inline_manifests=manifests,
    )
    if missing_paths and not resources and not images and not has_cluster_posture:
        return _skip_execution(
            reason="missing_cloud_native_artifact",
            targets=normalized_targets,
            stdout="Cloud-native assessment skipped: manifest artifact path does not exist on this host.",
            extra_payload={"missing_paths": missing_paths},
        )
    for missing_path in missing_paths:
        warnings.append(f"{missing_path}: manifest artifact path does not exist on this host.")

    checks: list[dict[str, Any]] = [
        {
            "check": "input_summary",
            "status": "reviewed",
            "manifest_resource_count": len(resources),
            "image_metadata_count": len(images),
            "has_cluster_posture": has_cluster_posture,
            "provider": selected_provider or "kubernetes",
        }
    ]
    findings: list[dict[str, Any]] = []
    for analyzer in (_analyze_workloads, _analyze_rbac, _analyze_services_and_secrets):
        next_checks, next_findings = analyzer(resources)
        checks.extend(next_checks)
        findings.extend(next_findings)
    image_checks, image_findings = _analyze_images(images)
    checks.extend(image_checks)
    findings.extend(image_findings)
    posture_checks, posture_findings = _analyze_cluster_posture(cluster_posture, cluster_id)
    checks.extend(posture_checks)
    findings.extend(posture_findings)

    unsupported_states = [
        "live_cluster_mutation_not_run",
        "container_execution_not_run",
        "privilege_escalation_not_run",
        "lateral_movement_not_run",
    ]
    payload = {
        "status": "completed",
        "provider": selected_provider or "kubernetes",
        "cluster_id": cluster_id,
        "targets": normalized_targets,
        "inputs": {
            "manifest_paths": input_manifest_paths,
            "inline_manifest_count": len(manifests) if isinstance(manifests, list) else int(bool(manifests)),
            "image_metadata_count": len(images),
            "cluster_posture_supplied": has_cluster_posture,
        },
        "checks": checks,
        "findings": findings,
        "warnings": warnings,
        "unsupported_states": unsupported_states,
        "safety": _safety_contract(),
    }
    inventory = _inventory_payload(
        resources=resources,
        image_records=images,
        cluster_id=cluster_id,
        finding_count=len(findings),
    )
    return RunnerExecution(
        tool="cloud-native",
        exit_code=0,
        stdout=(
            "Cloud-native static/read-only assessment completed: "
            f"{len(checks)} checks, {len(findings)} finding(s)."
        ),
        stderr="\n".join(warnings),
        metadata={
            "status": "completed",
            "runner_digest": RUNNER_DIGEST,
            "finding_count": len(findings),
            "manifest_resource_count": len(resources),
            "image_metadata_count": len(images),
            "cluster_mutation_executed": False,
            "container_execution_executed": False,
        },
        artifacts=[
            _json_artifact(
                CLOUD_NATIVE_RESULTS_ARTIFACT_NAME,
                payload,
                kind="cloud-native-results",
            ),
            _json_artifact(
                CLOUD_NATIVE_INVENTORY_ARTIFACT_NAME,
                inventory,
                kind="cloud-native-inventory",
            ),
        ],
    )
