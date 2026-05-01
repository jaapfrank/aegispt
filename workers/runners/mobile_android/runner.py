from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

MOBILE_ANDROID_RESULTS_ARTIFACT_NAME = "mobile-android-results.json"
MOBILE_ANDROID_INVENTORY_ARTIFACT_NAME = "mobile-android-inventory.json"
RUNNER_DIGEST = "workers.mobile_android.runner:v1"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("firebase_url", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com", re.I)),
    (
        "generic_api_secret",
        re.compile(
            r"(?i)\b(api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{16,}"
        ),
    ),
)


@dataclass(slots=True, frozen=True)
class ManifestContext:
    package_name: str | None
    min_sdk: str | None
    target_sdk: str | None
    permissions: tuple[str, ...]
    application_attrs: dict[str, str]
    components: tuple[dict[str, Any], ...]
    network_security_config: str | None
    manifest_format: str


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind=kind,
    )


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
        "manifest": {},
        "checks": [],
        "findings": [],
        "unsupported_states": [reason],
        "safety": _safety_contract(),
        **(extra_payload or {}),
    }
    return RunnerExecution(
        tool="mobile-android",
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
                MOBILE_ANDROID_RESULTS_ARTIFACT_NAME,
                payload,
                kind="mobile-android-results",
            )
        ],
    )


def _safety_contract() -> dict[str, bool]:
    return {
        "android_static_only": True,
        "ios_testing": False,
        "emulator_orchestration": False,
        "rooting_or_jailbreak": False,
        "malware_analysis": False,
        "destructive_exploitation": False,
    }


def _android_attr(element: ET.Element, name: str) -> str | None:
    value = element.attrib.get(f"{ANDROID_NS}{name}")
    if value is None:
        value = element.attrib.get(f"android:{name}")
    if value is None:
        value = element.attrib.get(name)
    return str(value).strip() if value is not None and str(value).strip() else None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _read_zip_member_text(
    archive: zipfile.ZipFile,
    name: str,
    *,
    max_bytes: int = 512_000,
) -> str:
    with archive.open(name) as handle:
        data = handle.read(max_bytes + 1)
    return data[:max_bytes].decode("utf-8", errors="replace")


def _parse_manifest(archive: zipfile.ZipFile) -> tuple[ManifestContext | None, list[str]]:
    warnings: list[str] = []
    try:
        manifest_text = _read_zip_member_text(archive, "AndroidManifest.xml")
    except KeyError:
        return None, ["missing AndroidManifest.xml"]

    if "<manifest" not in manifest_text[:4096]:
        return (
            ManifestContext(
                package_name=None,
                min_sdk=None,
                target_sdk=None,
                permissions=(),
                application_attrs={},
                components=(),
                network_security_config=None,
                manifest_format="android_binary_xml",
            ),
            ["AndroidManifest.xml appears to be binary AXML; plaintext static manifest parsing is unavailable without an external decoder."],
        )

    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError as exc:
        return None, [f"AndroidManifest.xml parse error: {exc}"]

    package_name = str(root.attrib.get("package") or "").strip() or None
    uses_sdk = next((child for child in root if _local_name(child.tag) == "uses-sdk"), None)
    min_sdk = _android_attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    target_sdk = _android_attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    permissions = tuple(
        dict.fromkeys(
            permission
            for child in root
            if _local_name(child.tag) in {"uses-permission", "uses-permission-sdk-23"}
            for permission in [_android_attr(child, "name")]
            if permission
        )
    )

    application = next((child for child in root if _local_name(child.tag) == "application"), None)
    application_attrs: dict[str, str] = {}
    components: list[dict[str, Any]] = []
    network_security_config: str | None = None
    if application is not None:
        for attr_name in (
            "allowBackup",
            "debuggable",
            "usesCleartextTraffic",
            "networkSecurityConfig",
            "requestLegacyExternalStorage",
        ):
            attr_value = _android_attr(application, attr_name)
            if attr_value is not None:
                application_attrs[attr_name] = attr_value
        network_security_config = application_attrs.get("networkSecurityConfig")

        for child in application:
            component_type = _local_name(child.tag)
            if component_type not in {"activity", "service", "receiver", "provider"}:
                continue
            exported = _android_attr(child, "exported")
            has_intent_filter = any(_local_name(grandchild.tag) == "intent-filter" for grandchild in child)
            components.append(
                {
                    "type": component_type,
                    "name": _android_attr(child, "name"),
                    "exported": exported,
                    "implicitly_exported": exported is None and has_intent_filter,
                    "has_intent_filter": has_intent_filter,
                    "permission": _android_attr(child, "permission"),
                }
            )

    return (
        ManifestContext(
            package_name=package_name,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            permissions=permissions,
            application_attrs=application_attrs,
            components=tuple(components),
            network_security_config=network_security_config,
            manifest_format="plaintext_xml",
        ),
        warnings,
    )


def _resolve_network_config_path(reference: str | None, archive_names: set[str]) -> str | None:
    if not reference:
        return None
    normalized = reference.strip()
    if normalized.startswith("@xml/"):
        candidates = [
            f"res/xml/{normalized.removeprefix('@xml/')}.xml",
            f"res/xml-v21/{normalized.removeprefix('@xml/')}.xml",
        ]
    else:
        candidates = [normalized.lstrip("/")]
    return next((candidate for candidate in candidates if candidate in archive_names), None)


def _analyze_network_security_config(
    archive: zipfile.ZipFile,
    manifest: ManifestContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    archive_names = set(archive.namelist())
    config_path = _resolve_network_config_path(manifest.network_security_config, archive_names)
    if not config_path:
        checks.append(
            {
                "check": "network_security_config",
                "status": "not_declared",
                "summary": "No networkSecurityConfig XML reference is visible in the manifest.",
            }
        )
        return checks, findings

    try:
        config_text = _read_zip_member_text(archive, config_path)
        root = ET.fromstring(config_text)
    except (KeyError, ET.ParseError) as exc:
        checks.append(
            {
                "check": "network_security_config",
                "status": "unsupported",
                "path": config_path,
                "summary": f"Could not parse declared network security config: {exc}",
            }
        )
        return checks, findings

    cleartext_nodes = [
        node
        for node in root.iter()
        if str(node.attrib.get("cleartextTrafficPermitted") or "").lower() == "true"
    ]
    user_trust_anchors = [
        node
        for node in root.iter()
        if _local_name(node.tag) == "certificates"
        and str(node.attrib.get("src") or "").strip().lower() == "user"
    ]
    checks.append(
        {
            "check": "network_security_config",
            "status": "reviewed",
            "path": config_path,
            "cleartext_nodes": len(cleartext_nodes),
            "user_trust_anchors": len(user_trust_anchors),
        }
    )
    if cleartext_nodes:
        findings.append(
            _finding(
                finding_type="android_network_cleartext_config",
                title="Android network security config permits cleartext traffic",
                severity="medium",
                target=manifest.package_name or config_path,
                summary=(
                    f"{config_path} explicitly permits cleartext traffic for at least one configuration block."
                ),
                tags=["OWASP MASVS v2.0: MASVS-NETWORK-1", "OWASP MASTG: MASTG-TEST-0230"],
                evidence={"path": config_path, "cleartext_node_count": len(cleartext_nodes)},
            )
        )
    if user_trust_anchors:
        findings.append(
            _finding(
                finding_type="android_user_ca_trust",
                title="Android network security config trusts user-installed CAs",
                severity="low",
                target=manifest.package_name or config_path,
                summary=(
                    f"{config_path} includes user trust anchors; confirm this is intended for production builds."
                ),
                tags=["OWASP MASVS v2.0: MASVS-NETWORK-2", "OWASP MASTG: MASTG-TEST-0231"],
                evidence={"path": config_path, "user_trust_anchor_count": len(user_trust_anchors)},
            )
        )
    return checks, findings


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
        "methodology_tags": ["mobile_security", "owasp_masvs", "owasp_mastg", *tags],
        "evidence": evidence,
    }


def _manifest_findings(manifest: ManifestContext) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    package_target = manifest.package_name or "android-apk"
    checks = [
        {
            "check": "manifest",
            "status": "reviewed",
            "manifest_format": manifest.manifest_format,
            "package_name": manifest.package_name,
            "permission_count": len(manifest.permissions),
            "component_count": len(manifest.components),
        }
    ]
    findings: list[dict[str, Any]] = []

    if manifest.application_attrs.get("debuggable", "").lower() == "true":
        findings.append(
            _finding(
                finding_type="android_debuggable_enabled",
                title="Android application is debuggable",
                severity="medium",
                target=package_target,
                summary="The APK manifest enables android:debuggable, which exposes a production build to debugging and instrumentation risk.",
                tags=["OWASP MASVS v2.0: MASVS-RESILIENCE-1", "OWASP MASTG: MASTG-TEST-0225"],
                evidence={"application_attr": "android:debuggable=true"},
            )
        )

    if manifest.application_attrs.get("allowBackup", "").lower() == "true":
        findings.append(
            _finding(
                finding_type="android_backup_allowed",
                title="Android application backup is allowed",
                severity="medium",
                target=package_target,
                summary="The APK manifest enables android:allowBackup, so application data may be extractable through platform backup paths.",
                tags=["OWASP MASVS v2.0: MASVS-STORAGE-1", "OWASP MASTG: MASTG-TEST-0218"],
                evidence={"application_attr": "android:allowBackup=true"},
            )
        )

    if manifest.application_attrs.get("usesCleartextTraffic", "").lower() == "true":
        findings.append(
            _finding(
                finding_type="android_cleartext_transport_allowed",
                title="Android application permits cleartext traffic",
                severity="medium",
                target=package_target,
                summary="The APK manifest enables android:usesCleartextTraffic, allowing plaintext network transport unless constrained elsewhere.",
                tags=["OWASP MASVS v2.0: MASVS-NETWORK-1", "OWASP MASTG: MASTG-TEST-0230"],
                evidence={"application_attr": "android:usesCleartextTraffic=true"},
            )
        )

    dangerous_permissions = sorted(
        permission for permission in manifest.permissions if permission in DANGEROUS_PERMISSIONS
    )
    if dangerous_permissions:
        findings.append(
            _finding(
                finding_type="android_dangerous_permissions",
                title="Android APK requests sensitive permissions",
                severity="low",
                target=package_target,
                summary=(
                    "The APK requests sensitive Android permissions that should be justified by the documented feature set."
                ),
                tags=["OWASP MASVS v2.0: MASVS-PRIVACY-1", "OWASP MASTG: MASTG-TEST-0200"],
                evidence={"permissions": dangerous_permissions},
            )
        )

    exported_components = [
        component
        for component in manifest.components
        if str(component.get("exported") or "").lower() == "true"
        or bool(component.get("implicitly_exported"))
    ]
    for component in exported_components[:20]:
        component_name = str(component.get("name") or component.get("type") or "component")
        permission = str(component.get("permission") or "").strip()
        findings.append(
            _finding(
                finding_type="android_exported_component",
                title="Android exported component requires review",
                severity="medium" if permission else "high",
                target=package_target,
                summary=(
                    f"{component.get('type')} {component_name} is exported"
                    f"{' with a declared permission' if permission else ' without a visible component permission'}."
                ),
                tags=["OWASP MASVS v2.0: MASVS-PLATFORM-1", "OWASP MASTG: MASTG-TEST-0201"],
                evidence=dict(component),
            )
        )

    return checks, findings


def _scan_embedded_config(archive: zipfile.ZipFile, package_target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    secret_matches: list[dict[str, str]] = []
    storage_files: list[str] = []
    for info in archive.infolist():
        name = info.filename
        if info.is_dir() or info.file_size <= 0 or info.file_size > 512_000:
            continue
        if not (
            name.startswith(("assets/", "res/raw/", "res/xml/"))
            or name.endswith((".properties", ".json", ".xml", ".txt", ".yml", ".yaml"))
        ):
            continue
        scanned_files += 1
        try:
            text = _read_zip_member_text(archive, name, max_bytes=128_000)
        except (KeyError, RuntimeError, zipfile.BadZipFile):
            continue
        lowered = text.lower()
        if "sharedpreferences" in lowered or "shared_prefs" in lowered:
            storage_files.append(name)
        for secret_type, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                secret_matches.append({"type": secret_type, "path": name})
                break

    checks.append(
        {
            "check": "embedded_config",
            "status": "reviewed",
            "scanned_file_count": scanned_files,
            "secret_match_count": len(secret_matches),
            "storage_signal_count": len(storage_files),
        }
    )
    if secret_matches:
        findings.append(
            _finding(
                finding_type="android_embedded_secret_indicator",
                title="Android APK contains embedded secret or token indicators",
                severity="high",
                target=package_target,
                summary="Static package review found token/secret-like material in APK resources or assets. Values are not echoed in findings.",
                tags=["OWASP MASVS v2.0: MASVS-STORAGE-2", "OWASP MASTG: MASTG-TEST-0219"],
                evidence={"matches": secret_matches[:20]},
            )
        )
    if storage_files:
        findings.append(
            _finding(
                finding_type="android_insecure_storage_signal",
                title="Android APK contains insecure-storage implementation signals",
                severity="low",
                target=package_target,
                summary="Static review found shared-preferences or storage-related resource signals that should be checked for sensitive data handling.",
                tags=["OWASP MASVS v2.0: MASVS-STORAGE-1", "OWASP MASTG: MASTG-TEST-0218"],
                evidence={"paths": storage_files[:20]},
            )
        )
    return checks, findings


def _inventory_payload(*, manifest: ManifestContext, artifact_path: str, finding_count: int) -> dict[str, Any]:
    package_name = manifest.package_name or Path(artifact_path).name
    return {
        "tool": "mobile-android",
        "kind": "inventory",
        "data": {
            "hosts": [],
            "endpoints": [],
            "technologies": [
                {
                    "name": "Android APK",
                    "vendor": "Android",
                    "version": manifest.target_sdk,
                    "confidence": 0.86,
                }
            ],
            "fingerprints": [
                {
                    "vendor": "Android",
                    "product": package_name,
                    "version": manifest.target_sdk,
                    "source": "mobile-android",
                    "confidence": 0.78,
                }
            ],
            "mobile_apps": [
                {
                    "platform": "android",
                    "package_name": manifest.package_name,
                    "artifact_path": artifact_path,
                    "manifest_format": manifest.manifest_format,
                    "min_sdk": manifest.min_sdk,
                    "target_sdk": manifest.target_sdk,
                    "permission_count": len(manifest.permissions),
                    "finding_count": finding_count,
                }
            ],
            "confidence": 0.82,
        },
    }


def execute_mobile_android_static(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    apk_path: str | None = None,
    proxy_metadata: dict[str, Any] | object = None,
    dynamic_prerequisites: dict[str, Any] | object = None,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    selected_apk = str(apk_path or (normalized_targets[0] if normalized_targets else "")).strip()
    if not selected_apk:
        return _skip_execution(
            reason="missing_mobile_artifact",
            targets=normalized_targets,
            stdout="Android mobile assessment skipped: no APK artifact path was supplied.",
        )

    if selected_apk not in normalized_targets:
        normalized_targets.insert(0, selected_apk)

    scope = scope_allowlist or {}
    if scope and not target_value_is_allowed(scope, selected_apk):
        raise ValueError(f"target outside scope: {selected_apk}")

    if Path(selected_apk).suffix.lower() != ".apk":
        return _skip_execution(
            reason="unsupported_mobile_artifact_type",
            targets=normalized_targets,
            stdout="Android mobile assessment skipped: only authorized .apk artifacts are supported in this slice.",
            extra_payload={"artifact_path": selected_apk},
        )

    artifact_path = Path(selected_apk)
    if not artifact_path.exists():
        return _skip_execution(
            reason="missing_mobile_artifact",
            targets=normalized_targets,
            stdout="Android mobile assessment skipped: APK artifact path does not exist on this host.",
            extra_payload={"artifact_path": selected_apk},
        )

    try:
        archive = zipfile.ZipFile(artifact_path)
    except zipfile.BadZipFile:
        return _skip_execution(
            reason="invalid_apk_archive",
            targets=normalized_targets,
            stdout="Android mobile assessment skipped: APK artifact is not a valid zip/APK archive.",
            extra_payload={"artifact_path": selected_apk},
        )

    warnings: list[str] = []
    with archive:
        manifest, manifest_warnings = _parse_manifest(archive)
        warnings.extend(manifest_warnings)
        if manifest is None:
            return _skip_execution(
                reason="missing_or_unreadable_manifest",
                targets=normalized_targets,
                stdout="Android mobile assessment skipped: APK manifest could not be reviewed.",
                stderr="\n".join(warnings),
                extra_payload={"artifact_path": selected_apk, "warnings": warnings},
            )

        checks, findings = _manifest_findings(manifest)
        network_checks, network_findings = _analyze_network_security_config(archive, manifest)
        config_checks, config_findings = _scan_embedded_config(
            archive,
            manifest.package_name or selected_apk,
        )
        checks.extend(network_checks)
        checks.extend(config_checks)
        findings.extend(network_findings)
        findings.extend(config_findings)

    proxy_payload = proxy_metadata if isinstance(proxy_metadata, dict) else {}
    dynamic_payload = dynamic_prerequisites if isinstance(dynamic_prerequisites, dict) else {}
    unsupported_states = [
        "dynamic_analysis_not_run",
        "emulator_orchestration_out_of_scope",
        "rooting_or_jailbreak_out_of_scope",
        "ios_out_of_scope",
    ]
    if dynamic_payload:
        unsupported_states.append("dynamic_prerequisites_recorded_not_executed")

    manifest_payload = {
        "package_name": manifest.package_name,
        "min_sdk": manifest.min_sdk,
        "target_sdk": manifest.target_sdk,
        "permissions": list(manifest.permissions),
        "application_attrs": manifest.application_attrs,
        "components": list(manifest.components),
        "network_security_config": manifest.network_security_config,
        "manifest_format": manifest.manifest_format,
    }
    payload = {
        "status": "completed",
        "artifact_path": selected_apk,
        "targets": normalized_targets,
        "manifest": manifest_payload,
        "checks": checks,
        "findings": findings,
        "warnings": warnings,
        "unsupported_states": unsupported_states,
        "dynamic_preparation": {
            "proxy_metadata": proxy_payload,
            "dynamic_prerequisites": dynamic_payload,
            "executed": False,
        },
        "safety": _safety_contract(),
    }
    inventory = _inventory_payload(
        manifest=manifest,
        artifact_path=selected_apk,
        finding_count=len(findings),
    )
    return RunnerExecution(
        tool="mobile-android",
        exit_code=0,
        stdout=(
            f"Android APK static review completed for {selected_apk}: "
            f"{len(checks)} checks, {len(findings)} finding(s)."
        ),
        stderr="\n".join(warnings),
        metadata={
            "status": "completed",
            "runner_digest": RUNNER_DIGEST,
            "manifest_format": manifest.manifest_format,
            "package_name": manifest.package_name,
            "finding_count": len(findings),
            "dynamic_analysis_executed": False,
        },
        artifacts=[
            _json_artifact(
                MOBILE_ANDROID_RESULTS_ARTIFACT_NAME,
                payload,
                kind="mobile-android-results",
            ),
            _json_artifact(
                MOBILE_ANDROID_INVENTORY_ARTIFACT_NAME,
                inventory,
                kind="mobile-android-inventory",
            ),
        ],
    )
