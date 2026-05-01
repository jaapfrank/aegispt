from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

import yaml

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

CICD_SECURITY_RESULTS_ARTIFACT_NAME = "cicd-security-results.json"
CICD_SECURITY_INVENTORY_ARTIFACT_NAME = "cicd-security-inventory.json"
RUNNER_DIGEST = "workers.cicd_security.runner:v1"

SUPPORTED_PIPELINE_TYPES = {"github-actions", "gitlab-ci", "jenkinsfile", "generic-yaml", ""}
SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)",
    re.I,
)
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}"
)
UNSAFE_SHELL_PATTERN = re.compile(r"(curl|wget)\s+[^|;&]+[|]\s*(sh|bash|python|ruby)", re.I)


@dataclass(slots=True, frozen=True)
class PipelineDocument:
    source: str
    pipeline_type: str
    body: dict[str, Any] | str
    raw_text: str


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
        "pipeline_execution": False,
        "repository_mutation": False,
        "credential_rotation": False,
        "exploit_chaining": False,
        "raw_secret_disclosure": False,
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
        tool="cicd-security",
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
                CICD_SECURITY_RESULTS_ARTIFACT_NAME,
                payload,
                kind="cicd-security-results",
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
        "methodology_tags": ["cicd_security", "owasp_cicd_top_10", "wrongsecrets", *tags],
        "evidence": evidence,
    }


def _detect_pipeline_type(source: str, raw_type: str | None = None) -> str:
    normalized = str(raw_type or "").strip().lower()
    if normalized:
        if normalized in SUPPORTED_PIPELINE_TYPES:
            return normalized
        return "unsupported"
    lowered = source.lower()
    name = Path(source).name.lower()
    if name.endswith((".github/workflows", ".github/workflow")) or "/.github/workflows/" in lowered:
        return "github-actions"
    if name.endswith((".yml", ".yaml")) and ("github" in lowered or "workflow" in lowered):
        return "github-actions"
    if name == ".gitlab-ci.yml" or name == ".gitlab-ci.yaml" or "gitlab-ci" in lowered:
        return "gitlab-ci"
    if name == "jenkinsfile" or name.endswith(".jenkinsfile"):
        return "jenkinsfile"
    if name.endswith((".yml", ".yaml")):
        return "generic-yaml"
    return "unsupported"


def _load_pipeline_documents(
    *,
    pipeline_paths: list[str],
    pipeline_configs: Any,
    pipeline_type: str | None,
) -> tuple[list[PipelineDocument], list[str], list[str]]:
    documents: list[PipelineDocument] = []
    warnings: list[str] = []
    missing_paths: list[str] = []

    sources: list[tuple[str, str, str | None]] = []
    for path_value in pipeline_paths:
        path = Path(path_value)
        if not path.exists():
            missing_paths.append(path_value)
            continue
        try:
            sources.append((path_value, path.read_text(encoding="utf-8", errors="replace"), pipeline_type))
        except OSError as exc:
            warnings.append(f"{path_value}: could not read pipeline config: {exc}")

    if isinstance(pipeline_configs, str) and pipeline_configs.strip():
        sources.append(("inline-pipeline", pipeline_configs, pipeline_type))
    elif isinstance(pipeline_configs, dict):
        source = str(pipeline_configs.get("source") or "inline-pipeline").strip() or "inline-pipeline"
        raw_type = str(pipeline_configs.get("pipeline_type") or pipeline_type or "").strip()
        content = pipeline_configs.get("content")
        if isinstance(content, str) and content.strip():
            sources.append((source, content, raw_type))
        else:
            documents.append(
                PipelineDocument(
                    source=source,
                    pipeline_type=_detect_pipeline_type(source, raw_type),
                    body=dict(pipeline_configs),
                    raw_text=json.dumps(pipeline_configs, sort_keys=True),
                )
            )
    elif isinstance(pipeline_configs, list):
        for index, item in enumerate(pipeline_configs, start=1):
            if isinstance(item, str) and item.strip():
                sources.append((f"inline-pipeline-{index}", item, pipeline_type))
            elif isinstance(item, dict):
                source = str(item.get("source") or f"inline-pipeline-{index}").strip()
                raw_type = str(item.get("pipeline_type") or pipeline_type or "").strip()
                content = item.get("content")
                if isinstance(content, str) and content.strip():
                    sources.append((source, content, raw_type))
                else:
                    documents.append(
                        PipelineDocument(
                            source=source,
                            pipeline_type=_detect_pipeline_type(source, raw_type),
                            body=dict(item),
                            raw_text=json.dumps(item, sort_keys=True),
                        )
                    )

    for source, text, raw_type in sources:
        detected_type = _detect_pipeline_type(source, raw_type)
        if detected_type == "unsupported":
            documents.append(
                PipelineDocument(
                    source=source,
                    pipeline_type=detected_type,
                    body=text,
                    raw_text=text,
                )
            )
            continue
        if detected_type == "jenkinsfile":
            documents.append(
                PipelineDocument(
                    source=source,
                    pipeline_type=detected_type,
                    body=text,
                    raw_text=text,
                )
            )
            continue
        try:
            parsed = yaml.safe_load(text) if text.strip() else {}
        except yaml.YAMLError as exc:
            warnings.append(f"{source}: pipeline config parse error: {exc}")
            continue
        if not isinstance(parsed, dict):
            warnings.append(f"{source}: pipeline config did not parse to an object")
            continue
        documents.append(
            PipelineDocument(
                source=source,
                pipeline_type=detected_type,
                body=parsed,
                raw_text=text,
            )
        )

    return documents, warnings, missing_paths


def _iter_nested_values(value: Any) -> list[tuple[str, Any]]:
    results: list[tuple[str, Any]] = []

    def walk(current: Any, path: str) -> None:
        if isinstance(current, dict):
            for key, nested in current.items():
                next_path = f"{path}.{key}" if path else str(key)
                results.append((next_path, nested))
                walk(nested, next_path)
        elif isinstance(current, list):
            for index, nested in enumerate(current):
                next_path = f"{path}[{index}]"
                results.append((next_path, nested))
                walk(nested, next_path)

    walk(value, "")
    return results


def _secret_exposure_findings(document: PipelineDocument) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks = [{"check": "secret_exposure", "status": "reviewed", "target": document.source}]
    findings: list[dict[str, Any]] = []
    secret_like_keys: list[str] = []
    inline_secret_paths: list[str] = []
    if isinstance(document.body, dict):
        for path, value in _iter_nested_values(document.body):
            key = path.rsplit(".", 1)[-1]
            if SECRET_NAME_PATTERN.search(key):
                secret_like_keys.append(path)
                if isinstance(value, str) and value.strip() and "${{" not in value and "$" not in value:
                    inline_secret_paths.append(path)
            if isinstance(value, str) and SECRET_VALUE_PATTERN.search(value):
                inline_secret_paths.append(path)
    elif isinstance(document.body, str):
        for line_number, line in enumerate(document.body.splitlines(), start=1):
            if SECRET_VALUE_PATTERN.search(line):
                inline_secret_paths.append(f"line:{line_number}")

    if secret_like_keys:
        checks.append(
            {
                "check": "secret_reference_names",
                "status": "reviewed",
                "count": len(secret_like_keys),
                "paths": secret_like_keys[:20],
            }
        )
    if inline_secret_paths:
        findings.append(
            _finding(
                finding_type="cicd_inline_secret_material",
                title="CI/CD pipeline contains inline secret-like material",
                severity="high",
                target=document.source,
                summary="Pipeline configuration contains secret-like inline values. Raw values are not echoed in evidence.",
                tags=[
                    "OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene",
                    "WrongSecrets: secret exposure",
                ],
                evidence={"paths": sorted(set(inline_secret_paths))[:20]},
            )
        )
    return checks, findings


def _github_actions_findings(document: PipelineDocument) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    body = document.body if isinstance(document.body, dict) else {}
    checks: list[dict[str, Any]] = [
        {"check": "github_actions", "status": "reviewed", "target": document.source}
    ]
    findings: list[dict[str, Any]] = []

    permissions = body.get("permissions")
    if permissions == "write-all" or (
        isinstance(permissions, dict)
        and any(str(value).strip().lower() == "write" for value in permissions.values())
    ):
        findings.append(
            _finding(
                finding_type="cicd_overprivileged_pipeline_token",
                title="GitHub Actions workflow grants broad write permissions",
                severity="high",
                target=document.source,
                summary="Workflow permissions grant write-capable token access; use least-privilege job or workflow permissions.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene"],
                evidence={"permissions": "write-capable"},
            )
        )

    triggers = body.get("on")
    trigger_names: set[str] = set()
    if isinstance(triggers, str):
        trigger_names.add(triggers)
    elif isinstance(triggers, list):
        trigger_names.update(str(item) for item in triggers)
    elif isinstance(triggers, dict):
        trigger_names.update(str(key) for key in triggers)
    if "pull_request_target" in trigger_names:
        findings.append(
            _finding(
                finding_type="cicd_poisoned_pipeline_prerequisite",
                title="GitHub Actions workflow uses pull_request_target",
                severity="high",
                target=document.source,
                summary="pull_request_target can expose privileged workflow context to untrusted pull request paths if checkout/build steps are not tightly constrained.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution"],
                evidence={"trigger": "pull_request_target"},
            )
        )

    jobs = body.get("jobs") if isinstance(body.get("jobs"), dict) else {}
    self_hosted_jobs: list[str] = []
    unpinned_actions: list[str] = []
    risky_shell_paths: list[str] = []
    broad_artifacts: list[str] = []
    cache_paths: list[str] = []
    checkout_persist_credentials: list[str] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on")
        runs_on_values = runs_on if isinstance(runs_on, list) else [runs_on]
        if any(str(value).strip().lower() == "self-hosted" for value in runs_on_values):
            self_hosted_jobs.append(str(job_name))
        steps = job.get("steps") if isinstance(job.get("steps"), list) else []
        for index, step in enumerate([item for item in steps if isinstance(item, dict)], start=1):
            uses = str(step.get("uses") or "").strip()
            step_path = f"jobs.{job_name}.steps[{index}]"
            if uses:
                if "@" not in uses or not re.search(r"@[a-f0-9]{40}$", uses, re.I):
                    unpinned_actions.append(uses)
                if uses.lower().startswith("actions/checkout@"):
                    with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
                    if with_config.get("persist-credentials") is True:
                        checkout_persist_credentials.append(step_path)
                if uses.lower().startswith("actions/upload-artifact@"):
                    with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
                    path_value = str(with_config.get("path") or "").strip()
                    if path_value in {".", "./", "**", "**/*"} or "*" in path_value:
                        broad_artifacts.append(step_path)
                if uses.lower().startswith("actions/cache@"):
                    with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
                    path_value = str(with_config.get("path") or "").strip()
                    if path_value:
                        cache_paths.append(step_path)
            run_script = str(step.get("run") or "")
            if UNSAFE_SHELL_PATTERN.search(run_script):
                risky_shell_paths.append(step_path)

    if self_hosted_jobs:
        findings.append(
            _finding(
                finding_type="cicd_self_hosted_runner_exposure",
                title="GitHub Actions workflow uses self-hosted runner",
                severity="medium",
                target=document.source,
                summary="Self-hosted runners increase blast radius when workflows process untrusted input; confirm isolation and runner lifecycle controls.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management"],
                evidence={"jobs": self_hosted_jobs[:20]},
            )
        )
    if unpinned_actions:
        findings.append(
            _finding(
                finding_type="cicd_unpinned_third_party_action",
                title="GitHub Actions workflow uses unpinned actions",
                severity="medium",
                target=document.source,
                summary="Workflow actions are not pinned to immutable commit SHAs, increasing supply-chain drift risk.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse"],
                evidence={"uses": unpinned_actions[:20]},
            )
        )
    if risky_shell_paths:
        findings.append(
            _finding(
                finding_type="cicd_unsafe_shell_bootstrap",
                title="CI/CD pipeline executes remote shell bootstrap pattern",
                severity="high",
                target=document.source,
                summary="Pipeline shell steps include remote download piped into an interpreter.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution"],
                evidence={"steps": risky_shell_paths[:20]},
            )
        )
    if broad_artifacts or cache_paths:
        findings.append(
            _finding(
                finding_type="cicd_artifact_cache_exposure",
                title="CI/CD workflow may expose broad artifacts or caches",
                severity="medium",
                target=document.source,
                summary="Artifact or cache configuration should be reviewed for secret, build-output, and dependency-cache leakage.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-8 Ungoverned Usage of Third Party Services"],
                evidence={"artifact_steps": broad_artifacts[:20], "cache_steps": cache_paths[:20]},
            )
        )
    if checkout_persist_credentials:
        findings.append(
            _finding(
                finding_type="cicd_checkout_persist_credentials",
                title="GitHub Actions checkout persists credentials",
                severity="medium",
                target=document.source,
                summary="actions/checkout persists repository credentials in the workspace; disable when subsequent build steps do not need git push access.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene"],
                evidence={"steps": checkout_persist_credentials[:20]},
            )
        )
    return checks, findings


def _gitlab_ci_findings(document: PipelineDocument) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    body = document.body if isinstance(document.body, dict) else {}
    checks = [{"check": "gitlab_ci", "status": "reviewed", "target": document.source}]
    findings: list[dict[str, Any]] = []
    risky_scripts: list[str] = []
    broad_artifacts: list[str] = []
    cache_paths: list[str] = []
    unpinned_includes: list[str] = []
    privileged_jobs: list[str] = []
    for include in body.get("include", []) if isinstance(body.get("include"), list) else []:
        if isinstance(include, dict) and not include.get("ref"):
            unpinned_includes.append(str(include.get("project") or include.get("remote") or "include"))
        elif isinstance(include, str) and include.startswith("http"):
            unpinned_includes.append(include)
    for job_name, job in body.items():
        if not isinstance(job, dict) or job_name.startswith("."):
            continue
        if job.get("privileged") is True:
            privileged_jobs.append(str(job_name))
        script = job.get("script")
        script_lines = script if isinstance(script, list) else [script]
        if any(isinstance(line, str) and UNSAFE_SHELL_PATTERN.search(line) for line in script_lines):
            risky_scripts.append(str(job_name))
        artifacts = job.get("artifacts") if isinstance(job.get("artifacts"), dict) else {}
        paths = artifacts.get("paths") if isinstance(artifacts.get("paths"), list) else []
        if any(str(path).strip() in {".", "./", "**", "**/*"} or "*" in str(path) for path in paths):
            broad_artifacts.append(str(job_name))
        cache = job.get("cache") if isinstance(job.get("cache"), dict) else {}
        cache_value = cache.get("paths") if isinstance(cache.get("paths"), list) else []
        if cache_value:
            cache_paths.append(str(job_name))

    if unpinned_includes:
        findings.append(
            _finding(
                finding_type="cicd_unpinned_pipeline_include",
                title="GitLab CI includes are not pinned",
                severity="medium",
                target=document.source,
                summary="Pipeline includes should pin trusted refs to reduce supply-chain drift and poisoned-template risk.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-3 Dependency Chain Abuse"],
                evidence={"includes": unpinned_includes[:20]},
            )
        )
    if privileged_jobs:
        findings.append(
            _finding(
                finding_type="cicd_privileged_runner_job",
                title="GitLab CI job requests privileged runner execution",
                severity="high",
                target=document.source,
                summary="Privileged runner jobs increase container escape and host-impact risk.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management"],
                evidence={"jobs": privileged_jobs[:20]},
            )
        )
    if risky_scripts:
        findings.append(
            _finding(
                finding_type="cicd_unsafe_shell_bootstrap",
                title="CI/CD pipeline executes remote shell bootstrap pattern",
                severity="high",
                target=document.source,
                summary="Pipeline shell steps include remote download piped into an interpreter.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution"],
                evidence={"jobs": risky_scripts[:20]},
            )
        )
    if broad_artifacts or cache_paths:
        findings.append(
            _finding(
                finding_type="cicd_artifact_cache_exposure",
                title="GitLab CI may expose broad artifacts or caches",
                severity="medium",
                target=document.source,
                summary="Artifact or cache configuration should be reviewed for secret, build-output, and dependency-cache leakage.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-8 Ungoverned Usage of Third Party Services"],
                evidence={"artifact_jobs": broad_artifacts[:20], "cache_jobs": cache_paths[:20]},
            )
        )
    return checks, findings


def _jenkinsfile_findings(document: PipelineDocument) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = document.raw_text
    checks = [{"check": "jenkinsfile", "status": "reviewed", "target": document.source}]
    findings: list[dict[str, Any]] = []
    if "agent any" in text or "label 'built-in'" in text or 'label "built-in"' in text:
        findings.append(
            _finding(
                finding_type="cicd_jenkins_broad_agent",
                title="Jenkinsfile uses broad agent selection",
                severity="medium",
                target=document.source,
                summary="Broad Jenkins agent selection can place untrusted jobs on overly privileged or shared executors.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management"],
                evidence={"signal": "broad_agent_selection"},
            )
        )
    if UNSAFE_SHELL_PATTERN.search(text):
        findings.append(
            _finding(
                finding_type="cicd_unsafe_shell_bootstrap",
                title="CI/CD pipeline executes remote shell bootstrap pattern",
                severity="high",
                target=document.source,
                summary="Pipeline shell steps include remote download piped into an interpreter.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-4 Poisoned Pipeline Execution"],
                evidence={"signal": "remote_shell_bootstrap"},
            )
        )
    if "archiveArtifacts" in text and ("**/*" in text or "artifacts: '*'" in text):
        findings.append(
            _finding(
                finding_type="cicd_artifact_cache_exposure",
                title="Jenkinsfile archives broad artifacts",
                severity="medium",
                target=document.source,
                summary="Broad archive artifact patterns should be reviewed for accidental secret or build-output disclosure.",
                tags=["OWASP CI/CD Top 10: CICD-SEC-8 Ungoverned Usage of Third Party Services"],
                evidence={"signal": "broad_archive_artifacts"},
            )
        )
    return checks, findings


def _repository_metadata_findings(repository_metadata: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    metadata_items: list[dict[str, Any]]
    if isinstance(repository_metadata, dict):
        metadata_items = [repository_metadata]
    elif isinstance(repository_metadata, list):
        metadata_items = [item for item in repository_metadata if isinstance(item, dict)]
    else:
        metadata_items = []

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(metadata_items, start=1):
        repository = str(item.get("repository") or item.get("name") or f"repository-{index}").strip()
        checks.append({"check": "repository_metadata", "status": "reviewed", "target": repository})
        if item.get("branch_protection_enabled") is False:
            findings.append(
                _finding(
                    finding_type="cicd_weak_branch_protection",
                    title="Repository metadata indicates missing branch protection",
                    severity="medium",
                    target=repository,
                    summary="Default branch protection is reported as disabled or absent in supplied repository metadata.",
                    tags=["OWASP CI/CD Top 10: CICD-SEC-5 Insufficient PBAC"],
                    evidence={"repository": repository, "branch_protection_enabled": False},
                )
            )
        if item.get("secret_scanning_enabled") is False:
            findings.append(
                _finding(
                    finding_type="cicd_secret_scanning_disabled",
                    title="Repository metadata indicates secret scanning is disabled",
                    severity="medium",
                    target=repository,
                    summary="Repository metadata reports secret scanning disabled; enable platform secret scanning where available.",
                    tags=[
                        "OWASP CI/CD Top 10: CICD-SEC-6 Insufficient Credential Hygiene",
                        "WrongSecrets: secret scanning",
                    ],
                    evidence={"repository": repository, "secret_scanning_enabled": False},
                )
            )
        runner_labels = item.get("self_hosted_runner_labels")
        if isinstance(runner_labels, list) and runner_labels:
            findings.append(
                _finding(
                    finding_type="cicd_self_hosted_runner_exposure",
                    title="Repository metadata includes self-hosted runner labels",
                    severity="medium",
                    target=repository,
                    summary="Self-hosted runner metadata should be reviewed for isolation, ephemeral lifecycle, and trust boundaries.",
                    tags=["OWASP CI/CD Top 10: CICD-SEC-2 Inadequate Identity and Access Management"],
                    evidence={"repository": repository, "runner_label_count": len(runner_labels)},
                )
            )
    return checks, findings


def _analyze_document(document: PipelineDocument) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = [
        {
            "check": "pipeline_type",
            "status": "unsupported" if document.pipeline_type == "unsupported" else "reviewed",
            "target": document.source,
            "pipeline_type": document.pipeline_type,
        }
    ]
    findings: list[dict[str, Any]] = []
    if document.pipeline_type == "unsupported":
        return checks, findings

    secret_checks, secret_findings = _secret_exposure_findings(document)
    checks.extend(secret_checks)
    findings.extend(secret_findings)
    if document.pipeline_type == "github-actions":
        next_checks, next_findings = _github_actions_findings(document)
    elif document.pipeline_type == "gitlab-ci":
        next_checks, next_findings = _gitlab_ci_findings(document)
    elif document.pipeline_type == "jenkinsfile":
        next_checks, next_findings = _jenkinsfile_findings(document)
    else:
        next_checks, next_findings = [], []
    checks.extend(next_checks)
    findings.extend(next_findings)
    return checks, findings


def _inventory_payload(
    *,
    documents: list[PipelineDocument],
    repository_metadata: Any,
    finding_count: int,
) -> dict[str, Any]:
    repositories: list[dict[str, Any]] = []
    if isinstance(repository_metadata, dict):
        repositories = [repository_metadata]
    elif isinstance(repository_metadata, list):
        repositories = [item for item in repository_metadata if isinstance(item, dict)]
    return {
        "tool": "cicd-security",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": [],
            "technologies": [
                {
                    "name": "CI/CD Pipeline",
                    "vendor": "generic",
                    "version": None,
                    "confidence": 0.8,
                }
            ],
            "fingerprints": [
                {
                    "vendor": "pipeline",
                    "product": document.pipeline_type,
                    "version": None,
                    "source": document.source,
                    "confidence": 0.78,
                }
                for document in documents
            ],
            "repositories": [
                {
                    "name": str(item.get("repository") or item.get("name") or "").strip(),
                    "default_branch": str(item.get("default_branch") or "").strip() or None,
                    "branch_protection_enabled": item.get("branch_protection_enabled"),
                    "secret_scanning_enabled": item.get("secret_scanning_enabled"),
                }
                for item in repositories
            ],
            "pipeline_configs": [
                {
                    "source": document.source,
                    "pipeline_type": document.pipeline_type,
                }
                for document in documents
            ],
            "finding_count": finding_count,
            "confidence": 0.8,
        },
    }


def execute_cicd_security_assessment(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    pipeline_paths: list[str] | None = None,
    pipeline_configs: Any = None,
    repository_metadata: Any = None,
    pipeline_type: str | None = None,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    selected_type = str(pipeline_type or "").strip().lower()
    if selected_type and selected_type not in SUPPORTED_PIPELINE_TYPES:
        return _skip_execution(
            reason="unsupported_pipeline_type",
            targets=normalized_targets,
            stdout=f"CI/CD security assessment skipped: pipeline type {selected_type} is unsupported in this slice.",
            extra_payload={"pipeline_type": selected_type},
        )

    input_paths = [
        str(path).strip()
        for path in (pipeline_paths or [])
        if isinstance(path, str) and str(path).strip()
    ]
    for target in normalized_targets:
        if target not in input_paths and not ("/" in target and ":" not in target and not target.endswith((".yml", ".yaml"))):
            input_paths.append(target)

    scope = scope_allowlist or {}
    for value in [*normalized_targets, *input_paths]:
        if scope and not target_value_is_allowed(scope, value):
            raise ValueError(f"target outside scope: {value}")

    has_repository_metadata = isinstance(repository_metadata, (dict, list)) and bool(repository_metadata)
    if not input_paths and not pipeline_configs and not has_repository_metadata:
        return _skip_execution(
            reason="missing_cicd_security_input",
            targets=normalized_targets,
            stdout="CI/CD security assessment skipped: no pipeline config or repository metadata input was supplied.",
        )

    documents, warnings, missing_paths = _load_pipeline_documents(
        pipeline_paths=input_paths,
        pipeline_configs=pipeline_configs,
        pipeline_type=selected_type or None,
    )
    if missing_paths and not documents and not has_repository_metadata:
        return _skip_execution(
            reason="missing_pipeline_config",
            targets=normalized_targets,
            stdout="CI/CD security assessment skipped: pipeline config artifact path does not exist on this host.",
            extra_payload={"missing_paths": missing_paths},
        )
    for missing_path in missing_paths:
        warnings.append(f"{missing_path}: pipeline config artifact path does not exist on this host.")

    checks: list[dict[str, Any]] = [
        {
            "check": "input_summary",
            "status": "reviewed",
            "pipeline_config_count": len(documents),
            "repository_metadata_supplied": has_repository_metadata,
        }
    ]
    findings: list[dict[str, Any]] = []
    unsupported_states = [
        "pipeline_execution_not_run",
        "repository_mutation_not_run",
        "credential_rotation_not_run",
        "exploit_chaining_not_run",
    ]
    unsupported_count = 0
    for document in documents:
        next_checks, next_findings = _analyze_document(document)
        checks.extend(next_checks)
        findings.extend(next_findings)
        if document.pipeline_type == "unsupported":
            unsupported_count += 1
    if unsupported_count:
        unsupported_states.append("unsupported_pipeline_type")

    repo_checks, repo_findings = _repository_metadata_findings(repository_metadata)
    checks.extend(repo_checks)
    findings.extend(repo_findings)
    if not has_repository_metadata:
        unsupported_states.append("repository_metadata_not_supplied")

    payload = {
        "status": "completed",
        "targets": normalized_targets,
        "inputs": {
            "pipeline_paths": input_paths,
            "inline_pipeline_count": len(pipeline_configs) if isinstance(pipeline_configs, list) else int(bool(pipeline_configs)),
            "repository_metadata_supplied": has_repository_metadata,
        },
        "checks": checks,
        "findings": findings,
        "warnings": warnings,
        "unsupported_states": unsupported_states,
        "safety": _safety_contract(),
    }
    inventory = _inventory_payload(
        documents=documents,
        repository_metadata=repository_metadata,
        finding_count=len(findings),
    )
    return RunnerExecution(
        tool="cicd-security",
        exit_code=0,
        stdout=(
            "CI/CD security static/read-only assessment completed: "
            f"{len(checks)} checks, {len(findings)} finding(s)."
        ),
        stderr="\n".join(warnings),
        metadata={
            "status": "completed",
            "runner_digest": RUNNER_DIGEST,
            "finding_count": len(findings),
            "pipeline_config_count": len(documents),
            "pipeline_execution_executed": False,
            "repository_mutation_executed": False,
            "raw_secret_disclosure": False,
        },
        artifacts=[
            _json_artifact(
                CICD_SECURITY_RESULTS_ARTIFACT_NAME,
                payload,
                kind="cicd-security-results",
            ),
            _json_artifact(
                CICD_SECURITY_INVENTORY_ARTIFACT_NAME,
                inventory,
                kind="cicd-security-inventory",
            ),
        ],
    )
