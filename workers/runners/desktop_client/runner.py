from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse
import zipfile

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME = "desktop-client-results.json"
DESKTOP_CLIENT_INVENTORY_ARTIFACT_NAME = "desktop-client-inventory.json"
RUNNER_DIGEST = "workers.desktop_client.runner:v1"

SUPPORTED_ARTIFACT_SUFFIXES = {
    ".asar",
    ".appx",
    ".dmg",
    ".exe",
    ".msi",
    ".msix",
    ".zip",
}
TEXT_SUFFIXES = {
    ".config",
    ".env",
    ".ini",
    ".json",
    ".log",
    ".properties",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
URL_PATTERN = re.compile(r"https?://[^\s'\"<>`\\]+", re.I)
SECRET_PATTERN = re.compile(
    r"(?i)['\"]?\b(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}"
)
IPC_PATTERN = re.compile(r"(?i)(\\\\\.\\pipe\\|named[_-]?pipe|pipeName|ipc://|localhost:\d+|127\.0\.0\.1:\d+)")
UPDATER_PATTERN = re.compile(r"(?i)(electron-updater|autoUpdater|latest\.yml|app-update\.yml|update\.yml)")


@dataclass(slots=True, frozen=True)
class DesktopDocument:
    source: str
    path: str
    text: str


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind=kind,
    )


def _safety_contract() -> dict[str, bool]:
    return {
        "static_artifact_review": True,
        "local_helper_probe": False,
        "kernel_driver_analysis": False,
        "memory_corruption_exploit_development": False,
        "process_injection": False,
        "malware_triage": False,
        "unrestricted_host_instrumentation": False,
        "exploit_execution": False,
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
        tool="desktop-client",
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
                DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME,
                payload,
                kind="desktop-client-results",
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
        "methodology_tags": ["desktop_client", "owasp_desktop_top_10", *tags],
        "evidence": evidence,
    }


def _read_text_bytes(data: bytes, *, limit: int = 250_000) -> str:
    return data[:limit].decode("utf-8", errors="replace")


def _load_desktop_documents(artifact_paths: list[str]) -> tuple[list[DesktopDocument], list[str], list[str]]:
    documents: list[DesktopDocument] = []
    warnings: list[str] = []
    missing_paths: list[str] = []

    for artifact_path in artifact_paths:
        path = Path(artifact_path)
        if not path.exists():
            missing_paths.append(artifact_path)
            continue
        suffix = path.suffix.lower()
        if suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in archive.infolist()[:300]:
                        member_name = member.filename
                        member_suffix = Path(member_name).suffix.lower()
                        if member.is_dir():
                            continue
                        if member.file_size > 1_000_000:
                            continue
                        if member_suffix not in TEXT_SUFFIXES and not any(
                            marker in member_name.lower()
                            for marker in ("latest.yml", "app-update.yml", "package.json", "config")
                        ):
                            continue
                        with archive.open(member) as handle:
                            documents.append(
                                DesktopDocument(
                                    source=artifact_path,
                                    path=member_name,
                                    text=_read_text_bytes(handle.read()),
                                )
                            )
            except zipfile.BadZipFile:
                warnings.append(f"{artifact_path}: zip artifact could not be opened")
            except OSError as exc:
                warnings.append(f"{artifact_path}: could not read desktop artifact: {exc}")
            continue

        if suffix in TEXT_SUFFIXES or path.name.lower() in {"latest.yml", "app-update.yml"}:
            try:
                documents.append(
                    DesktopDocument(
                        source=artifact_path,
                        path=path.name,
                        text=path.read_text(encoding="utf-8", errors="replace")[:250_000],
                    )
                )
            except OSError as exc:
                warnings.append(f"{artifact_path}: could not read desktop config artifact: {exc}")
            continue

        try:
            documents.append(
                DesktopDocument(
                    source=artifact_path,
                    path=path.name,
                    text=_read_text_bytes(path.read_bytes(), limit=350_000),
                )
            )
        except OSError as exc:
            warnings.append(f"{artifact_path}: could not sample desktop artifact: {exc}")

    return documents, warnings, missing_paths


def _extract_urls(documents: list[DesktopDocument], helper_urls: list[str]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for helper_url in helper_urls:
        if helper_url not in seen:
            seen.add(helper_url)
            endpoints.append({"url": helper_url, "source": "configured-helper", "kind": "local-helper"})
    for document in documents:
        for match in URL_PATTERN.findall(document.text):
            url = match.rstrip(".,);]")
            if url in seen:
                continue
            seen.add(url)
            parsed = urlparse(url)
            endpoints.append(
                {
                    "url": url,
                    "source": document.path,
                    "kind": "embedded-url",
                    "scheme": parsed.scheme,
                    "host": parsed.hostname,
                }
            )
    return endpoints


def _analyze_documents(
    *,
    documents: list[DesktopDocument],
    endpoints: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = [
        {
            "check": "input_summary",
            "status": "reviewed",
            "artifact_document_count": len(documents),
            "embedded_endpoint_count": len(endpoints),
        }
    ]
    findings: list[dict[str, Any]] = []

    secret_paths: list[str] = []
    ipc_paths: list[str] = []
    updater_paths: list[str] = []
    local_storage_paths: list[str] = []
    for document in documents:
        lowered_path = document.path.lower()
        if SECRET_PATTERN.search(document.text):
            secret_paths.append(document.path)
        if IPC_PATTERN.search(document.text):
            ipc_paths.append(document.path)
        if UPDATER_PATTERN.search(document.text) or "verifyupdatecodesignature: false" in document.text.lower():
            updater_paths.append(document.path)
        if any(
            marker in lowered_path
            for marker in ("localstorage", "indexeddb", "leveldb", "appdata", "/logs/", "\\logs\\")
        ) or lowered_path.endswith(".log"):
            local_storage_paths.append(document.path)

    checks.append({"check": "config_secret_review", "status": "reviewed", "paths": secret_paths[:30]})
    checks.append({"check": "ipc_helper_review", "status": "reviewed", "paths": ipc_paths[:30]})
    checks.append({"check": "updater_review", "status": "reviewed", "paths": updater_paths[:30]})
    checks.append(
        {"check": "local_storage_log_review", "status": "reviewed", "paths": local_storage_paths[:30]}
    )

    if secret_paths:
        findings.append(
            _finding(
                finding_type="desktop_embedded_secret_material",
                title="Desktop client contains embedded secret-like material",
                severity="high",
                target=documents[0].source if documents else "desktop-client",
                summary="Desktop artifact text/config contains secret-like values. Raw secret material is not echoed in evidence.",
                tags=["OWASP Desktop Top 10: Sensitive data storage"],
                evidence={"paths": sorted(set(secret_paths))[:30]},
            )
        )
    insecure_urls = [
        endpoint["url"]
        for endpoint in endpoints
        if str(endpoint.get("url") or "").lower().startswith("http://")
    ]
    if insecure_urls:
        findings.append(
            _finding(
                finding_type="desktop_insecure_transport_endpoint",
                title="Desktop client references cleartext HTTP endpoints",
                severity="medium",
                target=insecure_urls[0],
                summary="Desktop configuration or embedded strings reference cleartext HTTP endpoints; verify transport security for client-server flows.",
                tags=["OWASP Desktop Top 10: Insecure communication"],
                evidence={"url_count": len(insecure_urls), "sample_urls": insecure_urls[:10]},
            )
        )
    if ipc_paths:
        findings.append(
            _finding(
                finding_type="desktop_local_helper_ipc_exposure",
                title="Desktop client exposes local helper or IPC surface",
                severity="medium",
                target=documents[0].source if documents else "desktop-client",
                summary="Desktop artifact references local helper, localhost, or named-pipe IPC surfaces that need authorization and origin-boundary review.",
                tags=["OWASP Desktop Top 10: Insecure interprocess communication"],
                evidence={"paths": sorted(set(ipc_paths))[:30]},
            )
        )
    if updater_paths:
        findings.append(
            _finding(
                finding_type="desktop_updater_posture_review_required",
                title="Desktop updater posture needs code-signing review",
                severity="medium",
                target=documents[0].source if documents else "desktop-client",
                summary="Updater configuration or updater references were observed; verify signed update enforcement and trusted update channels.",
                tags=["OWASP Desktop Top 10: Insecure update mechanism"],
                evidence={"paths": sorted(set(updater_paths))[:30]},
            )
        )
    if local_storage_paths:
        findings.append(
            _finding(
                finding_type="desktop_local_storage_log_exposure",
                title="Desktop artifact includes local storage or log exposure signals",
                severity="low",
                target=documents[0].source if documents else "desktop-client",
                summary="Desktop artifact references local storage, IndexedDB/LevelDB, AppData, or log paths that should be reviewed for sensitive data retention.",
                tags=["OWASP Desktop Top 10: Sensitive data storage"],
                evidence={"paths": sorted(set(local_storage_paths))[:30]},
            )
        )
    if metadata.get("code_signing_verified") is False:
        findings.append(
            _finding(
                finding_type="desktop_code_signing_not_verified",
                title="Desktop code-signing metadata is not verified",
                severity="medium",
                target=str(metadata.get("artifact") or "desktop-client"),
                summary="Supplied desktop metadata reports code signing as unverified or absent; verify publisher identity and signing chain.",
                tags=["OWASP Desktop Top 10: Insecure update mechanism"],
                evidence={"code_signing_verified": False},
            )
        )

    return checks, findings


def _inventory_payload(
    *,
    artifact_paths: list[str],
    endpoints: list[dict[str, Any]],
    finding_count: int,
) -> dict[str, Any]:
    technologies = [
        {
            "name": "Desktop Client",
            "vendor": "generic",
            "version": None,
            "confidence": 0.78,
        }
    ]
    if any(path.lower().endswith(".asar") or path.lower().endswith(".zip") for path in artifact_paths):
        technologies.append(
            {
                "name": "Electron-style Desktop Client",
                "vendor": "generic",
                "version": None,
                "confidence": 0.66,
            }
        )
    return {
        "tool": "desktop-client",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": endpoints,
            "technologies": technologies,
            "fingerprints": [
                {
                    "vendor": "desktop",
                    "product": Path(path).suffix.lower().lstrip(".") or "artifact",
                    "version": None,
                    "source": path,
                    "confidence": 0.72,
                }
                for path in artifact_paths
            ],
            "desktop_apps": [{"artifact_path": path} for path in artifact_paths],
            "finding_count": finding_count,
            "confidence": 0.78,
        },
    }


def execute_desktop_client_assessment(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    artifact_paths: list[str] | None = None,
    helper_urls: list[str] | None = None,
    desktop_metadata: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    input_paths = [
        str(path).strip()
        for path in (artifact_paths or [])
        if isinstance(path, str) and str(path).strip()
    ]
    for target in normalized_targets:
        if target not in input_paths and not target.lower().startswith(("http://", "https://")):
            input_paths.append(target)

    normalized_helpers = [
        str(value).strip()
        for value in (helper_urls or [])
        if isinstance(value, str) and str(value).strip()
    ]
    scope = scope_allowlist or {}
    for value in [*normalized_targets, *input_paths, *normalized_helpers]:
        if scope and not target_value_is_allowed(scope, value):
            raise ValueError(f"target outside scope: {value}")

    if not input_paths and not normalized_helpers:
        return _skip_execution(
            reason="missing_desktop_client_input",
            targets=normalized_targets,
            stdout="Desktop client assessment skipped: no desktop artifact or local helper input was supplied.",
        )

    unsupported_paths = [
        path for path in input_paths if Path(path).suffix.lower() not in SUPPORTED_ARTIFACT_SUFFIXES
    ]
    if unsupported_paths and len(unsupported_paths) == len(input_paths):
        return _skip_execution(
            reason="unsupported_desktop_artifact_type",
            targets=normalized_targets,
            stdout="Desktop client assessment skipped: supplied artifacts are outside the supported first-slice types.",
            extra_payload={"unsupported_paths": unsupported_paths},
        )

    documents, warnings, missing_paths = _load_desktop_documents(input_paths)
    if missing_paths and not documents and not normalized_helpers:
        return _skip_execution(
            reason="missing_desktop_artifact",
            targets=normalized_targets,
            stdout="Desktop client assessment skipped: desktop artifact path does not exist on this host.",
            extra_payload={"missing_paths": missing_paths},
        )
    for missing_path in missing_paths:
        warnings.append(f"{missing_path}: desktop artifact path does not exist on this host.")

    endpoints = _extract_urls(documents, normalized_helpers)
    metadata = desktop_metadata if isinstance(desktop_metadata, dict) else {}
    checks, findings = _analyze_documents(
        documents=documents,
        endpoints=endpoints,
        metadata=metadata,
    )
    unsupported_states = [
        "kernel_driver_analysis_not_run",
        "memory_corruption_exploit_development_not_run",
        "process_injection_not_run",
        "malware_triage_not_run",
        "unrestricted_host_instrumentation_not_run",
        "live_local_helper_probe_not_run",
    ]

    payload = {
        "status": "completed",
        "targets": normalized_targets,
        "inputs": {
            "artifact_paths": input_paths,
            "helper_urls": normalized_helpers,
            "desktop_metadata_supplied": bool(metadata),
        },
        "checks": checks,
        "findings": findings,
        "warnings": warnings,
        "unsupported_states": unsupported_states,
        "safety": _safety_contract(),
    }
    inventory = _inventory_payload(
        artifact_paths=input_paths,
        endpoints=endpoints,
        finding_count=len(findings),
    )
    return RunnerExecution(
        tool="desktop-client",
        exit_code=0,
        stdout=(
            "Desktop/thick-client static assessment completed: "
            f"{len(checks)} checks, {len(findings)} finding(s)."
        ),
        stderr="\n".join(warnings),
        metadata={
            "status": "completed",
            "runner_digest": RUNNER_DIGEST,
            "finding_count": len(findings),
            "artifact_count": len(input_paths),
            "endpoint_count": len(endpoints),
            "kernel_driver_analysis_executed": False,
            "process_injection_executed": False,
            "malware_triage_executed": False,
            "raw_secret_disclosure": False,
        },
        artifacts=[
            _json_artifact(
                DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME,
                payload,
                kind="desktop-client-results",
            ),
            _json_artifact(
                DESKTOP_CLIENT_INVENTORY_ARTIFACT_NAME,
                inventory,
                kind="desktop-client-inventory",
            ),
        ],
    )
