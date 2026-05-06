from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    Approval,
    CapabilityPack,
    Engagement,
    Finding,
    FindingValidationRecord,
    InventorySnapshot,
    Run,
    RunProfile,
    Scope,
    SecretRef,
    Task,
    ThreatIntelRecord,
)
from api.app.policy.engine import execution_kill_switch_enabled, normalize_profile_limits
from api.app.services.audit import write_audit_event
from api.app.services.packs import artifact_refs_for_tool
from api.app.services.task_dispatch import dispatch_task_batch, supported_execution_tools
from workers.runners.httpx.runner import normalize_http_target
from workers.runners.metasploit.module_allowlist import resolve_allowlisted_module

TARGET_KEY_MAP = {
    "domains": "domain",
    "subdomains": "domain",
    "urls": "url",
    "api_base_urls": "url",
    "paths": "path",
    "cidrs": "cidr",
    "cidr_ranges": "cidr",
    "hosts": "host",
    "ip_addresses": "host",
    "directory_hosts": "host",
    "ldap_hosts": "host",
    "ad_domains": "domain",
    "directory_domains": "domain",
    "aws_accounts": "aws-account",
    "aws_account_ids": "aws-account",
    "cloud_accounts": "aws-account",
    "apk_paths": "mobile-artifact",
    "apk_files": "mobile-artifact",
    "mobile_artifacts": "mobile-artifact",
    "android_apks": "mobile-artifact",
    "desktop_artifact_paths": "desktop-artifact",
    "desktop_artifacts": "desktop-artifact",
    "desktop_client_artifacts": "desktop-artifact",
    "windows_app_artifacts": "desktop-artifact",
    "electron_artifacts": "desktop-artifact",
    "local_helper_urls": "desktop-helper-url",
    "desktop_helper_urls": "desktop-helper-url",
    "container_images": "container-image",
    "container_image_refs": "container-image",
    "kubernetes_manifest_paths": "cloud-native-artifact",
    "k8s_manifest_paths": "cloud-native-artifact",
    "cluster_posture_paths": "cloud-native-artifact",
    "cloud_native_artifacts": "cloud-native-artifact",
    "pipeline_config_paths": "cicd-pipeline-config",
    "cicd_config_paths": "cicd-pipeline-config",
    "github_actions_workflows": "cicd-pipeline-config",
    "gitlab_ci_configs": "cicd-pipeline-config",
    "jenkinsfiles": "cicd-pipeline-config",
    "repositories": "repository",
    "repository_refs": "repository",
    "llm_endpoints": "llm-endpoint",
    "llm_api_endpoints": "llm-endpoint",
    "ai_endpoints": "llm-endpoint",
    "wireless_sites": "wireless-site",
    "wifi_sites": "wireless-site",
    "ssids": "ssid",
    "approved_ssids": "ssid",
    "bssids": "bssid",
    "approved_bssids": "bssid",
    "targets": "target",
}

STALE_RUNNING_TASK_RECOVERY_AFTER = timedelta(minutes=10)
STALE_RECOVERY_ACTIVE_RUN_STATUSES = {"running", "cancelling"}
STALE_RECOVERY_TERMINAL_TASK_STATUSES = {
    "completed",
    "completed_with_errors",
    "failed",
    "cancelled",
    "skipped",
}

BIZ_LOGIC_SECRET_BINDING_KEYS = {"password", "api_key", "bearer_token", "session"}
BROWSER_SECRET_BINDING_KEYS = {"api_key", "bearer_token", "session"}
API_ASSESSMENT_SECRET_BINDING_KEYS = {"password", "api_key", "bearer_token", "session"}
SESSION_SECURITY_SECRET_BINDING_KEYS = {"password", "session"}
AUTH_FLOW_SECRET_BINDING_KEYS = {"password", "session"}
IMPACKET_SECRET_BINDING_KEYS = {"password", "ntlm_hash"}
KERBEROAST_SECRET_BINDING_KEYS = {"password"}
METASPLOIT_SECRET_BINDING_KEYS = {"password", "ntlm_hash"}
NETEXEC_SECRET_BINDING_KEYS = {"password", "ntlm_hash"}
PRIV_ESC_LINUX_SECRET_BINDING_KEYS = {"password"}
HASHCAT_SOURCE_SECRET_KINDS = {
    "ntlmv2_hash_bundle",
    "kerberoast_tgs_hash_bundle",
    "asrep_hash_bundle",
}
DEFAULT_APPROVAL_STEP_ID = "run.launch"


def _uuid_or_none(value: object) -> UUID | None:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return UUID(value.strip())
        except ValueError:
            return None
    return None


def _normalized_domain_from_base_dn(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parts = []
    for item in value.split(","):
        normalized_item = item.strip()
        if normalized_item.lower().startswith("dc="):
            parts.append(normalized_item.split("=", 1)[1].strip())
    normalized = ".".join(part for part in parts if part)
    return normalized.lower() or None


def _secret_ref_id_from_pointer(value: object) -> UUID | None:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if normalized.startswith("aegispt://secret-ref/"):
        normalized = normalized.removeprefix("aegispt://secret-ref/").strip()
    try:
        return UUID(normalized)
    except ValueError:
        return None


def _resolve_secret_ref_pointer(
    session: Session,
    *,
    engagement_id: UUID,
    pointer: object,
    allowed_secret_kinds: set[str] | None = None,
) -> SecretRef | None:
    secret_ref_id = _secret_ref_id_from_pointer(pointer)
    if secret_ref_id is None:
        return None
    secret_ref = session.scalar(
        select(SecretRef).where(
            SecretRef.id == secret_ref_id,
            SecretRef.engagement_id == engagement_id,
        )
    )
    if secret_ref is None:
        return None
    if allowed_secret_kinds is not None and secret_ref.secret_kind not in allowed_secret_kinds:
        return None
    return secret_ref


def align_run_configuration_with_engagement(
    configuration: dict[str, object] | None,
    *,
    engagement: Engagement,
) -> dict[str, object]:
    payload = copy.deepcopy(configuration or {})
    intake = payload.get("intake")
    if not isinstance(intake, dict):
        return payload

    engagement_context = intake.get("engagement_context")
    if not isinstance(engagement_context, dict):
        return payload

    normalized_context = dict(engagement_context)
    normalized_context["engagement_id"] = str(engagement.id)
    normalized_context["engagement_name"] = (
        str(normalized_context.get("engagement_name") or "").strip() or engagement.name
    )

    if not str(normalized_context.get("client") or "").strip() and engagement.client:
        normalized_context["client"] = engagement.client
    if not str(normalized_context.get("roe_ref") or "").strip() and engagement.roe_ref:
        normalized_context["roe_ref"] = engagement.roe_ref

    intake["engagement_context"] = normalized_context
    return payload


def required_approvals(profile: RunProfile) -> int:
    normalized_limits = normalize_profile_limits(profile.run_class, profile.limits_json)
    configured = normalized_limits.get("required_approvals")
    return max(configured, 0) if isinstance(configured, int) else 0


def approval_step_id(profile: RunProfile | None) -> str:
    if profile is None:
        return DEFAULT_APPROVAL_STEP_ID
    normalized_limits = normalize_profile_limits(profile.run_class, profile.limits_json)
    configured = str(normalized_limits.get("approval_step_id") or "").strip()
    return configured or DEFAULT_APPROVAL_STEP_ID


def granted_approvals(
    run: Run,
    step_id: str | None = None,
    *,
    profile: RunProfile | None = None,
) -> int:
    effective_step_id = step_id or approval_step_id(profile or run.profile)
    return sum(
        1
        for approval in run.approvals
        if approval.step_id == effective_step_id and approval.decision == "approved"
    )


def pending_approvals(run: Run, profile: RunProfile, step_id: str | None = None) -> int:
    if run.status in {"rejected", "cancelled", "cancelling"}:
        return 0
    return max(
        required_approvals(profile) - granted_approvals(run, step_id=step_id, profile=profile),
        0,
    )


def latest_scope_query(engagement_id) -> Select[tuple[Scope]]:
    return (
        select(Scope)
        .where(Scope.engagement_id == engagement_id)
        .order_by(Scope.created_at.desc(), Scope.id.desc())
    )


def derive_targets(scope: Scope) -> list[dict[str, str]]:
    return derive_targets_from_target_map(scope.allowlist_json)


def derive_targets_from_target_map(target_map: dict[str, object] | None) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    for key, kind in TARGET_KEY_MAP.items():
        values = (target_map or {}).get(key, [])
        if not isinstance(values, list):
            continue

        for value in values:
            if not isinstance(value, str):
                continue
            normalized = value.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            targets.append({"kind": kind, "value": normalized})

    return targets


def derive_targets_for_run(scope: Scope, run: Run) -> list[dict[str, str]]:
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    configured_targets = configuration.get("targets", {})
    if isinstance(configured_targets, dict):
        derived = derive_targets_from_target_map(configured_targets)
        if derived:
            return derived
    return derive_targets(scope)


def _normalized_string_list(
    value: object,
    *,
    limit: int | None = None,
) -> list[str]:
    if not isinstance(value, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, (str, int)):
            continue
        candidate = str(item).strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
        if limit is not None and len(normalized) >= limit:
            break
    return normalized


def _normalized_bssid(value: object) -> str:
    candidate = str(value or "").strip().lower()
    compact = candidate.replace("-", "").replace(":", "")
    if len(compact) == 12 and all(char in "0123456789abcdef" for char in compact):
        return ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    return candidate


def business_logic_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in BIZ_LOGIC_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        label = str(
            raw_account.get("label")
            or raw_account.get("username")
            or raw_account.get("role")
            or "Authenticated Account"
        ).strip()
        username = str(raw_account.get("username") or "").strip()
        role = str(raw_account.get("role") or "User").strip()
        tenant = str(raw_account.get("tenant") or raw_account.get("tenant_id") or "").strip()
        marker_tokens = _normalized_string_list(raw_account.get("marker_tokens"), limit=10)
        if username and username not in marker_tokens:
            marker_tokens.append(username)
        if label and label not in marker_tokens:
            marker_tokens.append(label)
        if tenant and tenant not in marker_tokens:
            marker_tokens.append(tenant)

        auth_contexts.append(
            {
                "label": label or "Authenticated Account",
                "username": username,
                "role": role or "User",
                "tenant": tenant or None,
                "mfa_notes": str(raw_account.get("mfa_notes") or "").strip() or None,
                "marker_tokens": marker_tokens,
                "owned_object_ids": _normalized_string_list(
                    raw_account.get("owned_object_ids"),
                    limit=100,
                ),
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def business_logic_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("business_logic")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    configured_test_types = _normalized_string_list(settings.get("test_types"), limit=4)

    result: dict[str, Any] = {
        "test_types": configured_test_types
        or ["idor", "privilege_escalation", "broken_access", "cross_tenant"],
        "protected_paths": _normalized_string_list(settings.get("protected_paths"), limit=50),
        "admin_paths": _normalized_string_list(settings.get("admin_paths"), limit=50),
        "idor_paths": _normalized_string_list(settings.get("idor_paths"), limit=50),
        "cross_tenant_paths": _normalized_string_list(settings.get("cross_tenant_paths"), limit=50),
        "candidate_object_ids": _normalized_string_list(
            settings.get("candidate_object_ids"),
            limit=100,
        ),
    }

    api_key_header = str(settings.get("api_key_header") or "").strip()
    if api_key_header:
        result["api_key_header"] = api_key_header

    max_object_ids = settings.get("max_object_ids")
    if isinstance(max_object_ids, int):
        result["max_object_ids"] = min(max(max_object_ids, 1), 100)

    return result


def session_security_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in SESSION_SECURITY_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if "password" not in usable_secret_bindings:
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue

        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "role": str(raw_account.get("role") or "User").strip() or "User",
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def session_security_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("session_security")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "request_contexts",
        "candidate_paths",
        "success_markers",
        "login_markers",
        "token_parameter_names",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("request_contexts", "candidate_paths"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    for field_name in (
        "login_url",
        "logout_url",
        "protected_url",
        "pre_login_url",
        "token_sample_url",
        "username_field",
        "password_field",
    ):
        value = settings.get(field_name)
        if isinstance(value, str) and value.strip():
            result[field_name] = value.strip()
    if isinstance(settings.get("extra_form_fields"), dict):
        result["extra_form_fields"] = {
            str(key).strip(): str(value)
            for key, value in settings["extra_form_fields"].items()
            if str(key).strip()
        }
    if isinstance(settings.get("sample_count"), int):
        result["sample_count"] = min(max(int(settings["sample_count"]), 2), 10)
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def auth_flow_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in AUTH_FLOW_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if "password" not in usable_secret_bindings:
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue

        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "role": str(raw_account.get("role") or "User").strip() or "User",
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def auth_flow_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("auth_flow")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("invalid_usernames", "lockout_markers"):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in (
        "login_url",
        "password_reset_url",
        "reset_consume_url",
        "login_method",
        "reset_method",
        "username_field",
        "password_field",
        "reset_username_field",
        "reset_token_field",
        "new_password_field",
        "invalid_password",
        "reset_poison_host",
    ):
        value = settings.get(field_name)
        if isinstance(value, str) and value.strip():
            result[field_name] = value.strip()
    for field_name in ("extra_login_fields", "extra_reset_fields"):
        value = settings.get(field_name)
        if isinstance(value, dict):
            normalized = {
                str(key).strip(): str(raw_value)
                for key, raw_value in value.items()
                if str(key).strip()
            }
            if normalized:
                result[field_name] = normalized
    if isinstance(settings.get("reset_token_samples"), int):
        result["reset_token_samples"] = min(max(int(settings["reset_token_samples"]), 2), 5)
    if isinstance(settings.get("failed_login_attempts"), int):
        result["failed_login_attempts"] = min(max(int(settings["failed_login_attempts"]), 1), 10)
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def browser_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in BROWSER_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or "Browser Session").strip()
                or "Browser Session",
                "role": str(raw_account.get("role") or "User").strip() or "User",
                "tenant": str(raw_account.get("tenant") or "").strip() or None,
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def browser_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("browser_validation")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    proof_marker = str(settings.get("proof_marker") or "").strip()
    if proof_marker:
        result["proof_marker"] = proof_marker
    if isinstance(settings.get("requires_auth_context"), bool):
        result["requires_auth_context"] = bool(settings["requires_auth_context"])
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def api_assessment_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in API_ASSESSMENT_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        label = str(
            raw_account.get("label")
            or raw_account.get("username")
            or raw_account.get("role")
            or "API Access Context"
        ).strip()
        username = str(raw_account.get("username") or "").strip()
        auth_contexts.append(
            {
                "label": label or "API Access Context",
                "username": username,
                "role": str(raw_account.get("role") or "User").strip() or "User",
                "tenant": str(raw_account.get("tenant") or "").strip() or None,
                "marker_tokens": _normalized_string_list(
                    raw_account.get("marker_tokens"),
                    limit=10,
                ),
                "owned_object_ids": _normalized_string_list(
                    raw_account.get("owned_object_ids"),
                    limit=100,
                ),
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def api_assessment_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("api_assessment")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "openapi_spec",
        "postman_collection",
        "graphql_introspection",
        "graphql_endpoint_url",
    ):
        value = settings.get(field_name)
        if value not in (None, [], {}):
            result[field_name] = value
    if isinstance(settings.get("requires_auth_context"), bool):
        result["requires_auth_context"] = bool(settings["requires_auth_context"])
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    api_key_header = str(settings.get("api_key_header") or "").strip()
    if api_key_header:
        result["api_key_header"] = api_key_header
    return result


def content_discovery_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("content_discovery")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    result: dict[str, Any] = {}
    if isinstance(settings.get("wordlist_path"), str) and settings["wordlist_path"].strip():
        result["wordlist_path"] = settings["wordlist_path"].strip()
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def sqlmap_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("sqlmap")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("injectable_parameters", "zap_flagged_parameters"):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    zap_parameters = validation.get("zap_flagged_parameters")
    if (
        isinstance(zap_parameters, list)
        and zap_parameters
        and "zap_flagged_parameters" not in result
    ):
        result["zap_flagged_parameters"] = zap_parameters
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def xxe_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("xxe")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("xml_endpoints", "evidence_records", "oob_confirmation_refs"):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("xml_endpoints", "evidence_records"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def jwt_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("jwt")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "evidence_records",
        "jwt_tokens",
        "replay_contexts",
        "public_key_materials",
        "jwks_endpoints",
        "weak_secrets",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("evidence_records", "jwt_tokens", "replay_contexts", "jwks_endpoints"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def vulnerable_components_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("vulnerable_components")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    if isinstance(settings.get("dependency_paths"), list):
        result["dependency_paths"] = [
            str(item).strip() for item in settings["dependency_paths"] if str(item).strip()
        ]
    if isinstance(settings.get("local_cve_records"), list):
        result["local_cve_records"] = [
            item for item in settings["local_cve_records"] if isinstance(item, dict)
        ]
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def idor_bac_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("idor_bac")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "evidence_records",
        "request_contexts",
        "admin_paths",
        "candidate_paths",
        "candidate_object_ids",
        "method_override_paths",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("evidence_records", "request_contexts"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    max_id_delta = settings.get("max_id_delta")
    if isinstance(max_id_delta, int):
        result["max_id_delta"] = min(max(max_id_delta, 1), 20)
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def client_state_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    return business_logic_auth_contexts_from_configuration(configuration)


def client_state_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("client_state")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "form_contexts",
        "cookie_contexts",
        "request_contexts",
        "price_contexts",
        "workflow_contexts",
        "gruyere_contexts",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in (
        "form_contexts",
        "cookie_contexts",
        "request_contexts",
        "price_contexts",
        "workflow_contexts",
        "gruyere_contexts",
    ):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def headers_security_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("headers_security")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("additional_origins", "redirect_paths"):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    value = validation.get("redirect_paths")
    if isinstance(value, list) and value and "redirect_paths" not in result:
        result["redirect_paths"] = value
    attacker_origin = str(settings.get("attacker_origin") or "").strip()
    if attacker_origin:
        result["attacker_origin"] = attacker_origin
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def graphql_probe_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("graphql_probe")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("endpoint_paths", "ide_paths"):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = [
                str(item).strip() for item in value if isinstance(item, str) and str(item).strip()
            ]
    for field_name in ("endpoint_paths", "ide_paths"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = [
                str(item).strip() for item in value if isinstance(item, str) and str(item).strip()
            ]
    if isinstance(settings.get("max_depth"), int):
        result["max_depth"] = min(max(int(settings["max_depth"]), 2), 20)
    if isinstance(settings.get("max_injection_fields"), int):
        result["max_injection_fields"] = min(max(int(settings["max_injection_fields"]), 0), 10)
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def ssti_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("ssti_probe")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("parameter_names", "candidate_paths"):
        value = _normalized_string_list(settings.get(field_name), limit=40)
        if value:
            result[field_name] = value
    for field_name in ("parameter_names", "candidate_paths"):
        if field_name in result:
            continue
        value = _normalized_string_list(validation.get(field_name), limit=40)
        if value:
            result[field_name] = value
    for field_name in ("stored_form_contexts", "gruyere_contexts"):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = [dict(item) for item in value[:20] if isinstance(item, dict)]
    for field_name in ("stored_form_contexts", "gruyere_contexts"):
        if field_name in result:
            continue
        value = validation.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = [dict(item) for item in value[:20] if isinstance(item, dict)]
    if isinstance(settings.get("max_parameters"), int):
        result["max_parameters"] = min(max(int(settings["max_parameters"]), 1), 20)
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def http_smuggling_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("http_smuggling")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for source in (settings, validation):
        if "proxy_evidence" in result:
            continue
        value = source.get("proxy_evidence")
        if isinstance(value, list) and value:
            result["proxy_evidence"] = [dict(item) for item in value[:20] if isinstance(item, dict)]
    for source in (settings, validation):
        for field_name in ("timeout_seconds", "timing_threshold_seconds"):
            if field_name not in result and isinstance(source.get(field_name), (int, float)):
                result[field_name] = float(source[field_name])
    return result


def oauth_probe_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("oauth_probe")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("authorization_urls", "login_paths", "well_known_paths", "script_paths"):
        for source in (settings, validation):
            if field_name in result:
                continue
            value = _normalized_string_list(source.get(field_name), limit=40)
            if value:
                result[field_name] = value
    for source in (settings, validation):
        if "token_evidence" in result:
            continue
        value = source.get("token_evidence")
        if isinstance(value, list) and value:
            result["token_evidence"] = [dict(item) for item in value[:20] if isinstance(item, dict)]
    client_id = str(settings.get("client_id") or validation.get("client_id") or "").strip()
    if client_id:
        result["client_id"] = client_id
    for source in (settings, validation):
        if "timeout_seconds" not in result and isinstance(
            source.get("timeout_seconds"), (int, float)
        ):
            result["timeout_seconds"] = float(source["timeout_seconds"])
    return result


def logging_probe_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("logging_probe")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("admin_paths", "actuator_paths", "debug_paths", "error_paths"):
        for source in (settings, validation):
            if field_name in result:
                continue
            value = _normalized_string_list(source.get(field_name), limit=40)
            if value:
                result[field_name] = value
    for source in (settings, validation):
        if "timeout_seconds" not in result and isinstance(
            source.get("timeout_seconds"), (int, float)
        ):
            result["timeout_seconds"] = float(source["timeout_seconds"])
    return result


def ssh_brute_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("ssh_brute")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name, limit in (
        ("usernames", 10),
        ("password_candidates", 50),
        ("discovered_services", 256),
    ):
        for source in (settings, validation):
            if field_name in result:
                continue
            value = _normalized_string_list(source.get(field_name), limit=limit)
            if value:
                result[field_name] = value

    for source in (settings, validation):
        if "service_targets" in result:
            continue
        raw_targets = source.get("service_targets")
        if not isinstance(raw_targets, list):
            continue
        service_targets: list[dict[str, object]] = []
        for item in raw_targets[:256]:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or item.get("target") or item.get("value") or "").strip()
            service = str(item.get("service") or item.get("protocol") or "").strip().lower()
            port = item.get("port")
            if not host:
                continue
            service_targets.append(
                {
                    "host": host,
                    "port": int(port) if isinstance(port, int) else port,
                    "service": service,
                }
            )
        if service_targets:
            result["service_targets"] = service_targets

    numeric_fields = {
        "max_usernames": (1, 10),
        "max_custom_passwords": (0, 50),
        "max_attempts_per_service": (1, 200),
        "lockout_stop_threshold": (1, 3),
    }
    for field_name, (minimum, maximum) in numeric_fields.items():
        for source in (settings, validation):
            if field_name in result or not isinstance(source.get(field_name), int):
                continue
            result[field_name] = min(max(int(source[field_name]), minimum), maximum)

    for source in (settings, validation):
        if "rate_limit_per_second" not in result and isinstance(
            source.get("rate_limit_per_second"), (int, float)
        ):
            result["rate_limit_per_second"] = min(
                max(float(source["rate_limit_per_second"]), 0.1),
                5.0,
            )
        if "timeout_seconds" not in result and isinstance(
            source.get("timeout_seconds"), (int, float)
        ):
            result["timeout_seconds"] = min(max(float(source["timeout_seconds"]), 1.0), 60.0)
    return result


def crypto_audit_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("crypto_audit")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("tls_targets",):
        for source in (settings, validation):
            if field_name in result:
                continue
            value = _normalized_string_list(source.get(field_name), limit=64)
            if value:
                result[field_name] = value

    for source in (settings, validation):
        if "ssh_targets" in result:
            continue
        value = source.get("ssh_targets")
        if isinstance(value, list) and value:
            ssh_targets: list[Any] = []
            for item in value[:64]:
                if isinstance(item, dict):
                    host = str(item.get("host") or item.get("target") or "").strip()
                    port = item.get("port")
                    if host:
                        ssh_targets.append(
                            {"host": host, "port": int(port) if isinstance(port, int) else 22}
                        )
                elif isinstance(item, str) and item.strip():
                    ssh_targets.append(item.strip())
            if ssh_targets:
                result["ssh_targets"] = ssh_targets

    for source in (settings, validation):
        if "token_evidence" in result:
            continue
        value = source.get("token_evidence")
        if isinstance(value, list) and value:
            result["token_evidence"] = [
                dict(item) if isinstance(item, dict) else str(item)
                for item in value[:50]
                if isinstance(item, (dict, str)) and str(item).strip()
            ]

    for fixture_name in ("testssl_results", "ssh_audit_results"):
        for source in (settings, validation):
            if fixture_name in result:
                continue
            value = source.get(fixture_name)
            if isinstance(value, (dict, list, str)):
                result[fixture_name] = value
    for source in (settings, validation):
        if "http_headers_by_target" in result:
            continue
        value = source.get("http_headers_by_target")
        if isinstance(value, dict):
            result["http_headers_by_target"] = value

    mode = str(settings.get("mode") or validation.get("crypto_audit_mode") or "").strip().lower()
    if mode in {"passive", "active"}:
        result["mode"] = mode
    for source in (settings, validation):
        if "timeout_seconds" not in result and isinstance(
            source.get("timeout_seconds"), (int, float)
        ):
            result["timeout_seconds"] = min(max(float(source["timeout_seconds"]), 1.0), 60.0)
    return result


def xss_extended_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("xss_extended")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "upload_contexts",
        "ajax_contexts",
        "xssi_contexts",
        "evidence_records",
        "candidate_paths",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("upload_contexts", "ajax_contexts", "xssi_contexts", "evidence_records"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    for field_name in ("xss_payload", "ajax_payload"):
        value = settings.get(field_name)
        if isinstance(value, str) and value.strip():
            result[field_name] = value.strip()
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def ssrf_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("ssrf")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "request_contexts",
        "header_contexts",
        "candidate_paths",
        "oob_confirmation_refs",
        "internal_service_urls",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("request_contexts", "header_contexts", "oob_confirmation_refs"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    for field_name in ("callback_url", "callback_base_url", "callback_token", "cloud_provider"):
        value = settings.get(field_name)
        if isinstance(value, str) and value.strip():
            result[field_name] = value.strip()
    for field_name in ("cloud_metadata_probe_enabled", "cloud_hosted"):
        if isinstance(settings.get(field_name), bool):
            result[field_name] = bool(settings[field_name])
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def deserialization_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("deserialization")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "request_contexts",
        "evidence_records",
        "candidate_paths",
        "oob_confirmation_refs",
    ):
        value = settings.get(field_name)
        if isinstance(value, list) and value:
            result[field_name] = value
    for field_name in ("request_contexts", "evidence_records", "oob_confirmation_refs"):
        value = validation.get(field_name)
        if isinstance(value, list) and value and field_name not in result:
            result[field_name] = value
    for field_name in ("callback_url", "callback_base_url", "callback_token"):
        value = settings.get(field_name)
        if isinstance(value, str) and value.strip():
            result[field_name] = value.strip()
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def mobile_android_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("mobile_android")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "apk_path",
        "proxy_metadata",
        "dynamic_prerequisites",
    ):
        value = settings.get(field_name)
        if value not in (None, [], {}):
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def desktop_client_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("desktop_client")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "artifact_paths",
        "helper_urls",
        "desktop_metadata",
    ):
        value = settings.get(field_name)
        if value not in (None, [], {}):
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def cloud_native_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("cloud_native")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "provider",
        "manifest_paths",
        "manifests",
        "image_metadata",
        "cluster_posture",
        "cluster_id",
    ):
        value = settings.get(field_name)
        if value not in (None, [], {}):
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def cicd_security_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("cicd_security")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "pipeline_paths",
        "pipeline_configs",
        "repository_metadata",
        "pipeline_type",
    ):
        value = settings.get(field_name)
        if value not in (None, [], {}):
            result[field_name] = value
    if isinstance(settings.get("timeout_seconds"), (int, float)):
        result["timeout_seconds"] = float(settings["timeout_seconds"])
    return result


def bloodhound_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue
        password_binding = secret_bindings.get("password")
        if not isinstance(password_binding, dict):
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue
        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "domain": str(
                    raw_account.get("domain")
                    or raw_account.get("ad_domain")
                    or raw_account.get("realm")
                    or ""
                ).strip()
                or None,
                "secret_bindings": {"password": dict(password_binding)},
            }
        )

    return auth_contexts


def bloodhound_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("bloodhound")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("domain", "domain_controller", "nameserver"):
        value = str(settings.get(field_name) or "").strip()
        if value:
            result[field_name] = value

    collection_methods = _normalized_string_list(settings.get("collection_methods"), limit=12)
    if collection_methods:
        result["collection_methods"] = collection_methods

    for field_name in ("dns_tcp", "use_ldaps"):
        if isinstance(settings.get(field_name), bool):
            result[field_name] = bool(settings.get(field_name))

    return result


def credential_attack_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue
        password_binding = secret_bindings.get("password")
        if not isinstance(password_binding, dict):
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue
        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "domain": str(
                    raw_account.get("domain")
                    or raw_account.get("ad_domain")
                    or raw_account.get("realm")
                    or ""
                ).strip()
                or None,
                "secret_bindings": {"password": dict(password_binding)},
            }
        )

    return auth_contexts


def _candidate_privilege_level(
    *,
    account_name: str,
    user_principal_name: str | None,
    privileged_names: set[str],
    service_principal_names: list[str] | None = None,
) -> str:
    tokens = {
        str(account_name or "").strip().lower(),
        str(user_principal_name or "").strip().lower(),
    }
    tokens = {token for token in tokens if token}
    if any(token in privileged_names for token in tokens):
        return "privileged"
    if service_principal_names:
        return "service"
    return "standard"


def credential_attack_context_from_inventory_snapshot(
    snapshot: InventorySnapshot | None,
) -> dict[str, Any]:
    if snapshot is None:
        return {
            "domains": [],
            "kerberoastable_accounts": [],
            "asrep_roastable_accounts": [],
            "password_policy": {},
        }

    raw_inputs = snapshot.raw_inputs_json if isinstance(snapshot.raw_inputs_json, dict) else {}
    context = raw_inputs.get("credential_attack_context")
    if isinstance(context, dict):
        return {
            "domains": [
                str(item).strip().lower()
                for item in list(context.get("domains") or [])
                if str(item).strip()
            ],
            "kerberoastable_accounts": [
                dict(item)
                for item in list(context.get("kerberoastable_accounts") or [])
                if isinstance(item, dict)
            ],
            "asrep_roastable_accounts": [
                dict(item)
                for item in list(context.get("asrep_roastable_accounts") or [])
                if isinstance(item, dict)
            ],
            "password_policy": (
                dict(context.get("password_policy") or {})
                if isinstance(context.get("password_policy"), dict)
                else {}
            ),
        }

    normalized_inventory = (
        snapshot.normalized_inventory_json
        if isinstance(snapshot.normalized_inventory_json, dict)
        else {}
    )
    privileged_memberships = normalized_inventory.get("privileged_memberships")
    privileged_names: set[str] = set()
    if isinstance(privileged_memberships, list):
        for membership in privileged_memberships:
            if not isinstance(membership, dict):
                continue
            for field_name in ("member", "member_dn", "account_name"):
                value = str(membership.get(field_name) or "").strip().lower()
                if value:
                    privileged_names.add(value)

    domains: set[str] = set()
    observations = raw_inputs.get("observations")
    if isinstance(observations, list):
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            for item in list(((observation.get("data") or {}).get("identity_subjects") or [])):
                if not isinstance(item, dict):
                    continue
                principal = str(item.get("principal") or "").strip().lower()
                if "@" in principal:
                    domains.add(principal.split("@", 1)[1].strip())

    return {
        "domains": sorted(domains),
        "kerberoastable_accounts": [],
        "asrep_roastable_accounts": [],
        "password_policy": {},
        "privileged_names": sorted(privileged_names),
    }


def credential_attack_accounts_from_snapshot(
    snapshot: InventorySnapshot | None,
    *,
    mode: str,
) -> list[dict[str, Any]]:
    context = credential_attack_context_from_inventory_snapshot(snapshot)
    key = "kerberoastable_accounts" if mode == "kerberoast" else "asrep_roastable_accounts"
    privileged_names = {
        str(item).strip().lower()
        for item in list(context.get("privileged_names") or [])
        if str(item).strip()
    }

    accounts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_account in list(context.get(key) or []):
        if not isinstance(raw_account, dict):
            continue
        account_name = str(raw_account.get("account_name") or "").strip()
        principal = str(raw_account.get("user_principal_name") or "").strip()
        if not account_name and not principal:
            continue
        service_principal_names = _normalized_string_list(
            raw_account.get("service_principal_names"),
            limit=25,
        )
        privilege_level = str(
            raw_account.get("privilege_level") or ""
        ).strip() or _candidate_privilege_level(
            account_name=account_name or principal,
            user_principal_name=principal or None,
            privileged_names=privileged_names,
            service_principal_names=service_principal_names,
        )
        signature = ((account_name or principal).lower(), principal.lower())
        if signature in seen:
            continue
        seen.add(signature)
        accounts.append(
            {
                "account_name": account_name or principal,
                "user_principal_name": principal or None,
                "service_principal_names": service_principal_names,
                "privilege_level": privilege_level,
            }
        )
    return accounts


def credential_attack_named_accounts(
    snapshot: InventorySnapshot | None,
    *,
    account_names: list[str],
) -> list[dict[str, Any]]:
    context = credential_attack_context_from_inventory_snapshot(snapshot)
    privileged_names = {
        str(item).strip().lower()
        for item in list(context.get("privileged_names") or [])
        if str(item).strip()
    }
    accounts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_name in account_names:
        account_name = str(raw_name or "").strip()
        if not account_name or account_name.lower() in seen:
            continue
        seen.add(account_name.lower())
        accounts.append(
            {
                "account_name": account_name,
                "user_principal_name": account_name if "@" in account_name else None,
                "privilege_level": _candidate_privilege_level(
                    account_name=account_name,
                    user_principal_name=account_name if "@" in account_name else None,
                    privileged_names=privileged_names,
                    service_principal_names=[],
                ),
            }
        )
    return accounts


def credential_attack_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("credential_attacks")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in ("domain", "domain_controller", "wordlist_path"):
        value = str(settings.get(field_name) or "").strip()
        if value:
            result[field_name] = value

    spray_accounts = _normalized_string_list(settings.get("spray_accounts"), limit=100)
    if spray_accounts:
        result["spray_accounts"] = spray_accounts

    attempts_per_window = settings.get("attempts_per_window")
    if isinstance(attempts_per_window, int):
        result["attempts_per_window"] = min(max(attempts_per_window, 1), 10)

    window_minutes = settings.get("window_minutes")
    if isinstance(window_minutes, int):
        result["window_minutes"] = min(max(window_minutes, 1), 240)

    lockout_threshold_confirmed = settings.get("lockout_threshold_confirmed")
    if isinstance(lockout_threshold_confirmed, int):
        result["lockout_threshold_confirmed"] = lockout_threshold_confirmed

    return result


def credential_attack_hash_sources_from_configuration(
    session: Session,
    *,
    engagement_id: UUID,
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("credential_attacks")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    raw_sources = settings.get("hash_sources")
    if not isinstance(raw_sources, list):
        return []

    normalized_sources: list[dict[str, Any]] = []
    for index, raw_source in enumerate(raw_sources, start=1):
        if not isinstance(raw_source, dict):
            continue
        secret_ref = _resolve_secret_ref_pointer(
            session,
            engagement_id=engagement_id,
            pointer=raw_source.get("hash_ref") or raw_source.get("secret_ref"),
            allowed_secret_kinds=HASHCAT_SOURCE_SECRET_KINDS,
        )
        if secret_ref is None:
            continue
        normalized_sources.append(
            {
                "label": str(raw_source.get("label") or f"Hash source {index}").strip()
                or f"Hash source {index}",
                "secret_ref_id": str(secret_ref.id),
                "secret_kind": secret_ref.secret_kind,
            }
        )
    return normalized_sources


def credential_attack_password_candidates_from_configuration(
    session: Session,
    *,
    engagement_id: UUID,
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("credential_attacks")
    settings = raw_settings if isinstance(raw_settings, dict) else {}
    raw_candidates = settings.get("password_candidates")
    if not isinstance(raw_candidates, list):
        return []

    normalized_candidates: list[dict[str, Any]] = []
    for index, raw_candidate in enumerate(raw_candidates, start=1):
        if not isinstance(raw_candidate, dict):
            continue
        secret_ref = _resolve_secret_ref_pointer(
            session,
            engagement_id=engagement_id,
            pointer=raw_candidate.get("password_ref") or raw_candidate.get("secret_ref"),
            allowed_secret_kinds={"password"},
        )
        if secret_ref is None:
            continue
        normalized_candidates.append(
            {
                "label": str(raw_candidate.get("label") or f"Password candidate {index}").strip()
                or f"Password candidate {index}",
                "secret_ref_id": str(secret_ref.id),
                "secret_kind": secret_ref.secret_kind,
            }
        )
    return normalized_candidates


def netexec_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in NETEXEC_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue

        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "domain": str(
                    raw_account.get("domain")
                    or raw_account.get("ad_domain")
                    or raw_account.get("realm")
                    or ""
                ).strip()
                or None,
                "local_auth": bool(raw_account.get("local_auth", False)),
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def priv_esc_linux_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in PRIV_ESC_LINUX_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue

        auth_context: dict[str, Any] = {
            "label": str(raw_account.get("label") or username).strip() or username,
            "username": username,
            "secret_bindings": usable_secret_bindings,
        }
        ssh_port = raw_account.get("ssh_port") or raw_account.get("port")
        if isinstance(ssh_port, int) and 1 <= ssh_port <= 65535:
            auth_context["ssh_port"] = ssh_port
        auth_contexts.append(auth_context)

    return auth_contexts


def priv_esc_linux_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("priv_esc_linux")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    ssh_port = settings.get("ssh_port")
    if isinstance(ssh_port, int) and 1 <= ssh_port <= 65535:
        result["ssh_port"] = ssh_port
    return result


def metasploit_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in METASPLOIT_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue

        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "domain": str(
                    raw_account.get("domain")
                    or raw_account.get("ad_domain")
                    or raw_account.get("realm")
                    or ""
                ).strip()
                or None,
                "local_auth": bool(raw_account.get("local_auth", False)),
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def metasploit_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("metasploit")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    finding_id = str(settings.get("finding_id") or settings.get("source_finding_id") or "").strip()
    if finding_id:
        result["finding_id"] = finding_id

    requested_module = str(settings.get("module_name") or "").strip()
    if requested_module:
        result["module_name"] = requested_module

    lhost = str(settings.get("lhost") or "").strip()
    if lhost:
        result["lhost"] = lhost

    for field_name in ("lport", "rport"):
        value = settings.get(field_name)
        if isinstance(value, int):
            result[field_name] = value

    return result


def impacket_auth_contexts_from_configuration(
    configuration: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    payload = configuration if isinstance(configuration, dict) else {}
    access = payload.get("access")
    if not isinstance(access, dict):
        return []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return []

    auth_contexts: list[dict[str, Any]] = []
    for raw_account in accounts:
        if not isinstance(raw_account, dict):
            continue
        secret_bindings = raw_account.get("secret_bindings")
        if not isinstance(secret_bindings, dict):
            continue

        usable_secret_bindings = {
            key: dict(value)
            for key, value in secret_bindings.items()
            if key in IMPACKET_SECRET_BINDING_KEYS and isinstance(value, dict)
        }
        if not usable_secret_bindings:
            continue

        username = str(raw_account.get("username") or "").strip()
        if not username:
            continue

        auth_contexts.append(
            {
                "label": str(raw_account.get("label") or username).strip() or username,
                "username": username,
                "domain": str(
                    raw_account.get("domain")
                    or raw_account.get("ad_domain")
                    or raw_account.get("realm")
                    or ""
                ).strip()
                or None,
                "local_auth": bool(raw_account.get("local_auth", False)),
                "secret_bindings": usable_secret_bindings,
            }
        )

    return auth_contexts


def impacket_lateral_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("impacket")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    remote_exec_method = str(settings.get("remote_exec_method") or "").strip().lower()
    if remote_exec_method:
        result["remote_exec_method"] = remote_exec_method
    return result


def load_run_finding_for_engagement(
    session: Session,
    *,
    engagement_id: UUID,
    finding_id: UUID,
) -> Finding | None:
    finding = session.scalar(
        select(Finding).options(selectinload(Finding.run)).where(Finding.id == finding_id)
    )
    if finding is None or finding.run is None or finding.run.engagement_id != engagement_id:
        return None
    return finding


def finding_context_for_runner(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "summary": finding.summary,
        "severity": finding.severity,
        "target_id": finding.target_id,
        "methodology_tags": list(finding.methodology_tags or []),
    }


def netexec_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("netexec")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    sensitive_patterns = _normalized_string_list(settings.get("sensitive_patterns"), limit=20)
    if sensitive_patterns:
        result["sensitive_patterns"] = sensitive_patterns
    return result


def nmap_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("nmap")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    for field_name in (
        "discovery_only",
        "service_detection",
        "skip_discovery",
        "full_port_scan",
    ):
        if isinstance(settings.get(field_name), bool):
            result[field_name] = settings[field_name]

    for field_name in ("top_ports", "version_intensity", "max_retries"):
        value = settings.get(field_name)
        if isinstance(value, int):
            result[field_name] = value

    for field_name in ("host_timeout_seconds", "timeout_seconds"):
        value = settings.get(field_name)
        if isinstance(value, (int, float)):
            result[field_name] = float(value)

    scripts = _normalized_string_list(settings.get("scripts"), limit=32)
    if scripts:
        result["scripts"] = scripts
    ports = settings.get("ports")
    if isinstance(ports, str) and ports.strip():
        result["ports"] = ports.strip()
    else:
        port_list = _normalized_string_list(ports, limit=200)
        if port_list:
            result["ports"] = port_list
    script_args = settings.get("script_args")
    if isinstance(script_args, dict):
        normalized_args = {
            str(key).strip(): str(value).strip()
            for key, value in script_args.items()
            if str(key).strip() and str(value).strip()
        }
        if normalized_args:
            result["script_args"] = normalized_args

    timing_template = str(settings.get("timing_template") or "").strip().upper()
    if timing_template in {f"T{value}" for value in range(0, 6)}:
        result["timing_template"] = timing_template

    return result


def responder_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    raw_settings = payload.get("responder")
    settings = raw_settings if isinstance(raw_settings, dict) else {}

    result: dict[str, Any] = {}
    interface = str(settings.get("interface") or "").strip()
    if interface:
        result["interface"] = interface

    duration_minutes = settings.get("duration_minutes")
    if isinstance(duration_minutes, (int, float)):
        result["duration_minutes"] = min(max(float(duration_minutes), 1.0), 60.0)

    return result


def wifi_runner_params_from_configuration(
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = configuration if isinstance(configuration, dict) else {}
    settings = payload.get("wireless") if isinstance(payload.get("wireless"), dict) else {}
    targets = payload.get("targets") if isinstance(payload.get("targets"), dict) else {}
    exclusions = payload.get("exclusions") if isinstance(payload.get("exclusions"), dict) else {}

    approved_ssids = _normalized_string_list(settings.get("approved_ssids"), limit=256)
    if not approved_ssids:
        approved_ssids = _normalized_string_list(targets.get("ssids"), limit=256)
    approved_bssids = [
        _normalized_bssid(value)
        for value in _normalized_string_list(settings.get("approved_bssids"), limit=512)
    ]
    if not approved_bssids:
        approved_bssids = [
            _normalized_bssid(value)
            for value in _normalized_string_list(targets.get("bssids"), limit=512)
        ]

    result: dict[str, Any] = {
        "site": str(
            settings.get("site")
            or settings.get("location")
            or next(iter(_normalized_string_list(targets.get("wireless_sites"), limit=1)), "")
        ).strip(),
        "adapter": str(settings.get("adapter") or settings.get("interface") or "").strip(),
        "approved_ssids": approved_ssids,
        "approved_bssids": [value for value in approved_bssids if value],
        "excluded_ssids": _normalized_string_list(
            settings.get("excluded_ssids") or exclusions.get("ssids"),
            limit=256,
        ),
        "excluded_bssids": [
            _normalized_bssid(value)
            for value in _normalized_string_list(
                settings.get("excluded_bssids") or exclusions.get("bssids"),
                limit=512,
            )
            if _normalized_bssid(value)
        ],
        "roe_acknowledged": bool(
            settings.get("roe_acknowledged") or settings.get("wireless_roe_acknowledged")
        ),
        "passive_only": True,
        "rf_disruptive_actions": False,
        "handshake_capture": False,
        "credential_harvesting": False,
        "wps_pin_testing": False,
        "evil_twin": False,
        "jamming": False,
    }
    for field_name in ("fixture_iw_scan_text", "fixture_airodump_csv_text"):
        if isinstance(settings.get(field_name), str) and settings[field_name].strip():
            result[field_name] = settings[field_name]
    return result


def validate_business_logic_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not any(target["kind"] == "url" for target in targets):
        raise ValueError("active-business-logic requires at least one in-scope URL target")

    if not business_logic_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "active-business-logic requires at least one authenticated access account with stored secret bindings"
        )


def validate_playwright_web_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
    profile_limits: dict[str, Any] | None = None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not planned_targets_for_tool("playwright-web", targets):
        raise ValueError("playwright-web validation requires at least one in-scope web target")

    browser_params = browser_runner_params_from_configuration(configuration)
    limits = profile_limits if isinstance(profile_limits, dict) else {}
    requires_auth_context = bool(
        browser_params.get("requires_auth_context", limits.get("requires_auth_context", False))
    )
    if requires_auth_context and not browser_auth_contexts_from_configuration(configuration):
        return


def validate_api_assessment_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
    profile_limits: dict[str, Any] | None = None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not planned_targets_for_tool("api-assessment", targets):
        raise ValueError("api-assessment requires at least one in-scope API or URL target")

    api_params = api_assessment_runner_params_from_configuration(configuration)
    limits = profile_limits if isinstance(profile_limits, dict) else {}
    requires_auth_context = bool(
        api_params.get("requires_auth_context", limits.get("requires_auth_context", False))
    )
    if requires_auth_context and not api_assessment_auth_contexts_from_configuration(configuration):
        return


def validate_web_depth_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
    tool: str,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not planned_targets_for_tool(tool, targets):
        raise ValueError(f"{tool} requires at least one in-scope web target")


def validate_sqlmap_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(scope=scope, configuration=configuration, tool="sqlmap")
    params = sqlmap_runner_params_from_configuration(configuration)
    candidates = []
    for field_name in ("injectable_parameters", "zap_flagged_parameters"):
        value = params.get(field_name)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))
    if not candidates:
        raise ValueError(
            "sqlmap requires an explicit parameter target or ZAP-flagged injectable parameter"
        )
    for candidate in candidates:
        target = str(candidate.get("url") or candidate.get("target") or "").strip()
        parameter = str(candidate.get("parameter") or candidate.get("param") or "").strip()
        if not target or not parameter:
            raise ValueError("sqlmap parameter entries require url/target and parameter")
        if not target_value_is_allowed(scope.allowlist_json, target):
            raise ValueError(f"configured target {target} is outside the approved engagement scope")


def validate_xxe_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(scope=scope, configuration=configuration, tool="xxe-probe")
    params = xxe_runner_params_from_configuration(configuration)
    for field_name in ("xml_endpoints", "evidence_records"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                target = item
            elif isinstance(item, dict):
                target = item.get("url") or item.get("target") or item.get("endpoint")
            else:
                continue
            if target and not web_target_value_is_allowed_with_path(
                scope.allowlist_json, str(target)
            ):
                raise ValueError(
                    f"configured XML endpoint {target} is outside the approved engagement scope"
                )


def validate_jwt_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(scope=scope, configuration=configuration, tool="jwt-probe")
    params = jwt_runner_params_from_configuration(configuration)
    for endpoint in params.get("jwks_endpoints", []):
        if endpoint and not web_target_value_is_allowed_with_path(
            scope.allowlist_json, str(endpoint)
        ):
            raise ValueError(
                f"configured JWKS endpoint {endpoint} is outside the approved engagement scope"
            )
    for item in params.get("replay_contexts", []):
        if not isinstance(item, dict):
            continue
        endpoint = item.get("url") or item.get("target") or item.get("endpoint")
        if endpoint and not web_target_value_is_allowed_with_path(
            scope.allowlist_json, str(endpoint)
        ):
            raise ValueError(
                f"configured JWT replay endpoint {endpoint} is outside the approved engagement scope"
            )


def validate_vulnerable_components_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="vuln-components",
    )


def validate_idor_bac_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="idor-bac",
    )
    if not business_logic_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "idor-bac requires at least one authenticated access account with stored secret bindings"
        )
    params = idor_bac_runner_params_from_configuration(configuration)
    for field_name in ("evidence_records", "request_contexts"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                target = item
            elif isinstance(item, dict):
                target = (
                    item.get("url")
                    or item.get("target")
                    or item.get("request_url")
                    or item.get("endpoint")
                )
            else:
                continue
            if target and not web_target_value_is_allowed_with_path(
                scope.allowlist_json, str(target)
            ):
                raise ValueError(
                    f"configured IDOR/BAC endpoint {target} is outside the approved engagement scope"
                )


def validate_client_state_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="client-state",
    )
    if not client_state_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "client-state requires at least one authenticated access account with stored secret bindings"
        )
    params = client_state_runner_params_from_configuration(configuration)
    for field_name in (
        "form_contexts",
        "cookie_contexts",
        "request_contexts",
        "price_contexts",
        "workflow_contexts",
        "gruyere_contexts",
    ):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                targets = [item]
            elif isinstance(item, dict):
                targets = [
                    item.get("url") or item.get("target") or item.get("endpoint"),
                    item.get("action"),
                    item.get("final_url"),
                    item.get("prerequisite_url"),
                ]
            else:
                continue
            for target in targets:
                target_value = str(target or "").strip()
                if (
                    target_value
                    and "://" in target_value
                    and not web_target_value_is_allowed_with_path(
                        scope.allowlist_json, target_value
                    )
                ):
                    raise ValueError(
                        f"configured client-state endpoint {target_value} is outside the approved engagement scope"
                    )


def validate_headers_security_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="headers-security",
    )
    params = headers_security_runner_params_from_configuration(configuration)
    attacker_origin = params.get("attacker_origin")
    if attacker_origin is not None:
        parsed_origin = urlparse(str(attacker_origin))
        if parsed_origin.scheme not in {"http", "https"} or not parsed_origin.netloc:
            raise ValueError("headers-security attacker_origin must be an absolute HTTP(S) origin")
    for origin in params.get("additional_origins", []):
        origin_value = str(origin or "").strip()
        if origin_value == "null":
            continue
        parsed_origin = urlparse(origin_value)
        if parsed_origin.scheme not in {"http", "https"} or not parsed_origin.netloc:
            raise ValueError("headers-security additional_origins must be HTTP(S) origins or null")
    for raw_path in params.get("redirect_paths", []):
        value = str(raw_path or "").strip()
        if (
            value
            and "://" in value
            and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
        ):
            raise ValueError(
                f"configured headers-security redirect target {value} is outside the approved engagement scope"
            )


def validate_graphql_probe_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="graphql-probe",
    )
    params = graphql_probe_runner_params_from_configuration(configuration)
    for field_name in ("endpoint_paths", "ide_paths"):
        for raw_path in params.get(field_name, []):
            value = str(raw_path or "").strip()
            if (
                value
                and "://" in value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
            ):
                raise ValueError(
                    f"configured GraphQL probe target {value} is outside the approved engagement scope"
                )
    max_depth = params.get("max_depth")
    if isinstance(max_depth, int) and max_depth > 20:
        raise ValueError("graphql-probe max_depth must be capped at 20")


def _configured_context_targets(item: Any) -> list[str]:
    if isinstance(item, str):
        return [item]
    if not isinstance(item, dict):
        return []
    return [
        str(
            item.get("url")
            or item.get("action")
            or item.get("target")
            or item.get("endpoint")
            or ""
        ).strip(),
        str(item.get("render_url") or item.get("final_url") or item.get("view_url") or "").strip(),
    ]


def validate_ssti_probe_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="ssti-probe",
    )
    params = ssti_runner_params_from_configuration(configuration)
    for raw_path in params.get("candidate_paths", []):
        value = str(raw_path or "").strip()
        if (
            value
            and "://" in value
            and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
        ):
            raise ValueError(
                f"configured SSTI probe target {value} is outside the approved engagement scope"
            )
    for field_name in ("stored_form_contexts", "gruyere_contexts"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            for target_value in _configured_context_targets(item):
                if (
                    target_value
                    and "://" in target_value
                    and not web_target_value_is_allowed_with_path(
                        scope.allowlist_json, target_value
                    )
                ):
                    raise ValueError(
                        f"configured SSTI probe target {target_value} is outside the approved engagement scope"
                    )


def _is_http_smuggling_proxy_evidence_header(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return normalized in {"via", "forwarded"} or normalized.startswith("x-forwarded-")


def validate_http_smuggling_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="http-smuggling",
    )
    params = http_smuggling_runner_params_from_configuration(configuration)
    for field_name in ("timeout_seconds", "timing_threshold_seconds"):
        value = params.get(field_name)
        if isinstance(value, (int, float)) and not 0 < float(value) <= 5:
            raise ValueError(
                "http-smuggling timing and timeout values must be greater than zero and capped at 5 seconds"
            )

    proxy_evidence = params.get("proxy_evidence")
    for item in proxy_evidence if isinstance(proxy_evidence, list) else []:
        raw_target = str(item.get("target") or item.get("url") or "").strip()
        if (
            raw_target
            and "://" in raw_target
            and not web_target_value_is_allowed_with_path(scope.allowlist_json, raw_target)
        ):
            raise ValueError(
                "configured HTTP smuggling proxy evidence target "
                f"{raw_target} is outside the approved engagement scope"
            )
        headers = item.get("headers")
        if not isinstance(headers, dict) or not any(
            _is_http_smuggling_proxy_evidence_header(str(name)) and str(value or "").strip()
            for name, value in headers.items()
        ):
            raise ValueError(
                "http-smuggling proxy_evidence requires Via, Forwarded, or X-Forwarded-* header evidence"
            )


def validate_oauth_probe_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="oauth-probe",
    )
    params = oauth_probe_runner_params_from_configuration(configuration)
    timeout_value = params.get("timeout_seconds")
    if isinstance(timeout_value, (int, float)) and not 0 < float(timeout_value) <= 5:
        raise ValueError(
            "oauth-probe timeout_seconds must be greater than zero and capped at 5 seconds"
        )

    for field_name in ("authorization_urls", "login_paths", "well_known_paths", "script_paths"):
        for raw_value in params.get(field_name, []):
            value = str(raw_value or "").strip()
            if (
                value
                and "://" in value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
            ):
                raise ValueError(
                    f"configured OAuth probe target {value} is outside the approved engagement scope"
                )

    token_evidence = params.get("token_evidence")
    for item in token_evidence if isinstance(token_evidence, list) else []:
        if not isinstance(item, dict):
            continue
        for field_name in ("source_url", "target", "url", "token_endpoint"):
            value = str(item.get(field_name) or "").strip()
            if (
                value
                and "://" in value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
            ):
                raise ValueError(
                    f"configured OAuth token evidence target {value} is outside the approved engagement scope"
                )


def validate_logging_probe_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="logging-probe",
    )
    params = logging_probe_runner_params_from_configuration(configuration)
    timeout_value = params.get("timeout_seconds")
    if isinstance(timeout_value, (int, float)) and not 0 < float(timeout_value) <= 5:
        raise ValueError(
            "logging-probe timeout_seconds must be greater than zero and capped at 5 seconds"
        )

    for field_name in ("admin_paths", "actuator_paths", "debug_paths", "error_paths"):
        for raw_value in params.get(field_name, []):
            value = str(raw_value or "").strip()
            if (
                value
                and "://" in value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
            ):
                raise ValueError(
                    f"configured logging probe target {value} is outside the approved engagement scope"
                )


def _ssh_brute_service_target_host(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("host") or value.get("target") or value.get("value") or "").strip()
    return str(value or "").strip().split(":", 1)[0]


def validate_ssh_brute_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    params = ssh_brute_runner_params_from_configuration(configuration)
    if (
        not planned_targets_for_tool("ssh-brute", targets)
        and not params.get("service_targets")
        and not params.get("discovered_services")
    ):
        raise ValueError("ssh-brute requires at least one approved host, CIDR, or service target")

    if float(params.get("rate_limit_per_second") or 5.0) > 5.0:
        raise ValueError("ssh-brute rate_limit_per_second must be capped at 5")
    if int(params.get("lockout_stop_threshold") or 3) > 3:
        raise ValueError("ssh-brute lockout_stop_threshold must be capped at 3")
    if int(params.get("max_attempts_per_service") or 200) > 200:
        raise ValueError("ssh-brute max_attempts_per_service must be capped at 200")

    for field_name in ("service_targets", "discovered_services"):
        for raw_value in params.get(field_name, []):
            value = _ssh_brute_service_target_host(raw_value)
            if value and not target_value_is_allowed(scope.allowlist_json, value):
                raise ValueError(
                    f"configured ssh-brute service target {value} is outside the approved engagement scope"
                )


def validate_crypto_audit_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    params = crypto_audit_runner_params_from_configuration(configuration)
    if (
        not planned_targets_for_tool("crypto-audit", targets)
        and not params.get("tls_targets")
        and not params.get("ssh_targets")
        and not params.get("token_evidence")
    ):
        raise ValueError("crypto-audit requires at least one in-scope TLS, SSH, or token target")

    timeout_value = params.get("timeout_seconds")
    if isinstance(timeout_value, (int, float)) and not 0 < float(timeout_value) <= 60:
        raise ValueError(
            "crypto-audit timeout_seconds must be greater than zero and capped at 60 seconds"
        )

    for raw_value in params.get("tls_targets", []):
        value = str(raw_value or "").strip()
        if not value:
            continue
        allowed = (
            web_target_value_is_allowed_with_path(scope.allowlist_json, value)
            if "://" in value
            else target_value_is_allowed(scope.allowlist_json, value)
        )
        if not allowed:
            raise ValueError(
                f"configured crypto-audit TLS target {value} is outside the approved engagement scope"
            )

    for raw_value in params.get("ssh_targets", []):
        if isinstance(raw_value, dict):
            value = str(raw_value.get("host") or raw_value.get("target") or "").strip()
        else:
            value = str(raw_value or "").strip().split(":", 1)[0]
        if value and not target_value_is_allowed(scope.allowlist_json, value):
            raise ValueError(
                f"configured crypto-audit SSH target {value} is outside the approved engagement scope"
            )

    for item in params.get("token_evidence", []):
        if not isinstance(item, dict):
            continue
        for field_name in ("source_url", "target", "url", "token_endpoint"):
            value = str(item.get(field_name) or "").strip()
            if (
                value
                and "://" in value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, value)
            ):
                raise ValueError(
                    f"configured crypto-audit token evidence target {value} is outside the approved engagement scope"
                )


def validate_xss_extended_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="xss-extended",
    )
    params = xss_extended_runner_params_from_configuration(configuration)
    for field_name in ("upload_contexts", "ajax_contexts", "xssi_contexts", "evidence_records"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                targets = [item]
            elif isinstance(item, dict):
                targets = [
                    item.get("url")
                    or item.get("target")
                    or item.get("endpoint")
                    or item.get("upload_url"),
                    item.get("uploaded_url"),
                ]
            else:
                continue
            for target in targets:
                target_value = str(target or "").strip()
                if (
                    target_value
                    and "://" in target_value
                    and not web_target_value_is_allowed_with_path(
                        scope.allowlist_json, target_value
                    )
                ):
                    raise ValueError(
                        f"configured XSS endpoint {target} is outside the approved engagement scope"
                    )


def validate_ssrf_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="ssrf-probe",
    )
    params = ssrf_runner_params_from_configuration(configuration)
    for field_name in ("request_contexts", "header_contexts"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                target = item
            elif isinstance(item, dict):
                target = item.get("url") or item.get("target") or item.get("endpoint")
            else:
                continue
            target_value = str(target or "").strip()
            if (
                target_value
                and "://" in target_value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, target_value)
            ):
                raise ValueError(
                    f"configured SSRF probe endpoint {target_value} is outside the approved engagement scope"
                )
    if params.get("cloud_metadata_probe_enabled") and not params.get("cloud_hosted"):
        raise ValueError("cloud metadata SSRF probes require explicit cloud_hosted=true context")
    cloud_provider = str(params.get("cloud_provider") or "").strip().lower()
    if cloud_provider and cloud_provider not in {"aws", "gcp", "azure"}:
        raise ValueError("cloud metadata SSRF provider must be aws, gcp, or azure")


def validate_deserialization_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="deserialization-probe",
    )
    params = deserialization_runner_params_from_configuration(configuration)
    for field_name in ("request_contexts", "evidence_records"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                target = item
            elif isinstance(item, dict):
                target = item.get("url") or item.get("target") or item.get("endpoint")
            else:
                continue
            target_value = str(target or "").strip()
            if (
                target_value
                and "://" in target_value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, target_value)
            ):
                raise ValueError(
                    f"configured deserialization probe endpoint {target_value} is outside the approved engagement scope"
                )


def validate_session_security_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="session-security",
    )
    if not session_security_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "session-security requires at least one authenticated account with username and stored password binding"
        )

    params = session_security_runner_params_from_configuration(configuration)
    for field_name in (
        "login_url",
        "logout_url",
        "protected_url",
        "pre_login_url",
        "token_sample_url",
    ):
        target_value = str(params.get(field_name) or "").strip()
        if (
            target_value
            and "://" in target_value
            and not web_target_value_is_allowed_with_path(scope.allowlist_json, target_value)
        ):
            raise ValueError(
                f"configured session-security endpoint {target_value} is outside the approved engagement scope"
            )
    for field_name in ("request_contexts", "candidate_paths"):
        entries = params.get(field_name)
        for item in entries if isinstance(entries, list) else []:
            if isinstance(item, str):
                target = item
            elif isinstance(item, dict):
                target = item.get("url") or item.get("target") or item.get("endpoint")
            else:
                continue
            target_value = str(target or "").strip()
            if (
                target_value
                and "://" in target_value
                and not web_target_value_is_allowed_with_path(scope.allowlist_json, target_value)
            ):
                raise ValueError(
                    f"configured session-security endpoint {target_value} is outside the approved engagement scope"
                )


def validate_auth_flow_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    validate_web_depth_run_configuration(
        scope=scope,
        configuration=configuration,
        tool="auth-flow",
    )
    if not auth_flow_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "auth-flow requires at least one authenticated test account with username and stored password binding"
        )

    params = auth_flow_runner_params_from_configuration(configuration)
    for field_name in ("login_url", "password_reset_url", "reset_consume_url"):
        target_value = str(params.get(field_name) or "").strip()
        if (
            target_value
            and "://" in target_value
            and not web_target_value_is_allowed_with_path(scope.allowlist_json, target_value)
        ):
            raise ValueError(
                f"configured auth-flow endpoint {target_value} is outside the approved engagement scope"
            )
    reset_poison_host = str(params.get("reset_poison_host") or "").strip()
    if reset_poison_host and "://" in reset_poison_host:
        raise ValueError("auth-flow reset_poison_host must be a hostname, not a URL")


def local_cve_records_for_vulnerable_components(
    session: Session, *, limit: int = 500
) -> list[dict[str, Any]]:
    records = session.scalars(
        select(ThreatIntelRecord)
        .order_by(ThreatIntelRecord.advisory_updated_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "source": record.source,
            "advisory_id": record.advisory_id,
            "title": record.title,
            "summary": record.summary,
            "affected_products": list(record.affected_products_json or []),
            "affected_versions": list(record.affected_versions_json or []),
            "product_match_hints": list(record.product_match_hints_json or []),
            "severity": record.severity,
            "references": list(record.references_json or []),
        }
        for record in records
    ]


def validate_mobile_android_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not planned_targets_for_tool("mobile-android", targets):
        raise ValueError("mobile-android requires at least one in-scope authorized APK artifact")

    params = mobile_android_runner_params_from_configuration(configuration)
    apk_path = str(params.get("apk_path") or "").strip()
    if apk_path and not target_value_is_allowed(scope.allowlist_json, apk_path):
        raise ValueError(f"configured target {apk_path} is outside the approved engagement scope")


def validate_desktop_client_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not planned_targets_for_tool("desktop-client", targets):
        raise ValueError(
            "desktop-client requires at least one in-scope desktop artifact or local helper URL"
        )

    params = desktop_client_runner_params_from_configuration(configuration)
    artifact_paths = params.get("artifact_paths")
    if isinstance(artifact_paths, list):
        for artifact_path in artifact_paths:
            if (
                isinstance(artifact_path, str)
                and artifact_path.strip()
                and not target_value_is_allowed(scope.allowlist_json, artifact_path.strip())
            ):
                raise ValueError(
                    f"configured target {artifact_path.strip()} is outside the approved engagement scope"
                )
    helper_urls = params.get("helper_urls")
    if isinstance(helper_urls, list):
        for helper_url in helper_urls:
            if (
                isinstance(helper_url, str)
                and helper_url.strip()
                and not target_value_is_allowed(scope.allowlist_json, helper_url.strip())
            ):
                raise ValueError(
                    f"configured target {helper_url.strip()} is outside the approved engagement scope"
                )


def validate_cloud_native_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    target_map = (
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    targets = derive_targets_from_target_map(target_map)
    if not planned_targets_for_tool("cloud-native", targets):
        raise ValueError(
            "cloud-native requires at least one in-scope Kubernetes manifest, container image, or cloud-native artifact target"
        )

    params = cloud_native_runner_params_from_configuration(configuration)
    manifest_paths = params.get("manifest_paths")
    if isinstance(manifest_paths, list):
        for manifest_path in manifest_paths:
            if (
                isinstance(manifest_path, str)
                and manifest_path.strip()
                and not target_value_is_allowed(
                    scope.allowlist_json,
                    manifest_path.strip(),
                )
            ):
                raise ValueError(
                    f"configured target {manifest_path.strip()} is outside the approved engagement scope"
                )

    image_metadata = params.get("image_metadata")
    if isinstance(image_metadata, list):
        for item in image_metadata:
            if not isinstance(item, dict):
                continue
            image = str(item.get("image") or item.get("name") or item.get("ref") or "").strip()
            if image and not target_value_is_allowed(scope.allowlist_json, image):
                raise ValueError(
                    f"configured target {image} is outside the approved engagement scope"
                )


def validate_cicd_security_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    target_map = (
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    targets = derive_targets_from_target_map(target_map)
    if not planned_targets_for_tool("cicd-security", targets):
        raise ValueError(
            "cicd-security requires at least one in-scope pipeline config or repository target"
        )

    params = cicd_security_runner_params_from_configuration(configuration)
    pipeline_paths = params.get("pipeline_paths")
    if isinstance(pipeline_paths, list):
        for pipeline_path in pipeline_paths:
            if (
                isinstance(pipeline_path, str)
                and pipeline_path.strip()
                and not target_value_is_allowed(scope.allowlist_json, pipeline_path.strip())
            ):
                raise ValueError(
                    f"configured target {pipeline_path.strip()} is outside the approved engagement scope"
                )

    repository_metadata = params.get("repository_metadata")
    repository_items = (
        [repository_metadata]
        if isinstance(repository_metadata, dict)
        else (
            [item for item in repository_metadata if isinstance(item, dict)]
            if isinstance(repository_metadata, list)
            else []
        )
    )
    for item in repository_items:
        repository = str(item.get("repository") or item.get("name") or "").strip()
        if repository and not target_value_is_allowed(scope.allowlist_json, repository):
            raise ValueError(
                f"configured target {repository} is outside the approved engagement scope"
            )


def validate_bloodhound_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not any(target["kind"] in {"host", "domain"} for target in targets):
        raise ValueError(
            "active-ad-bloodhound requires at least one approved AD domain or directory host target"
        )

    if not bloodhound_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "active-ad-bloodhound requires at least one access account with username and stored password binding"
        )

    params = bloodhound_runner_params_from_configuration(configuration)
    effective_domain = str(params.get("domain") or "").strip()
    if not effective_domain:
        for context in bloodhound_auth_contexts_from_configuration(configuration):
            username = str(context.get("username") or "").strip()
            if "@" in username:
                effective_domain = username.split("@", 1)[1].strip()
                break
    if not effective_domain and not any(target["kind"] == "domain" for target in targets):
        raise ValueError(
            "active-ad-bloodhound requires bloodhound.domain or a domain-style target when usernames do not include a UPN domain"
        )


def validate_easm_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not planned_targets_for_tool("easm-discover", targets):
        raise ValueError(
            "passive-easm-discovery requires at least one approved root-domain-style target"
        )


def validate_external_infra_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    planned_targets = planned_targets_for_tool("external-infra", targets)
    if not planned_targets:
        raise ValueError(
            "External infrastructure assessment requires at least one approved host, CIDR, domain, or URL target"
        )


def validate_responder_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    if not any(target["kind"] == "cidr" for target in targets):
        raise ValueError(
            "intrusive-lan-credential-capture requires at least one approved CIDR target"
        )

    responder_params = responder_runner_params_from_configuration(configuration)
    if not str(responder_params.get("interface") or "").strip():
        raise ValueError(
            "intrusive-lan-credential-capture requires responder.interface in configuration_json"
        )


def validate_wifi_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    params = wifi_runner_params_from_configuration(configuration)
    if not params.get("site"):
        raise ValueError("passive-wifi-survey requires an explicit site/location")
    if not params.get("adapter"):
        raise ValueError("passive-wifi-survey requires a wireless adapter/interface context")
    if not params.get("approved_ssids") and not params.get("approved_bssids"):
        raise ValueError("passive-wifi-survey requires at least one approved SSID or BSSID")
    if not params.get("roe_acknowledged"):
        raise ValueError("passive-wifi-survey requires wireless ROE acknowledgement before launch")

    wireless_settings = (
        configuration.get("wireless")
        if isinstance(configuration, dict) and isinstance(configuration.get("wireless"), dict)
        else {}
    )
    for forbidden in (
        "deauth",
        "deauthentication",
        "jamming",
        "evil_twin",
        "handshake_capture",
        "credential_harvesting",
        "wps_pin_testing",
        "wps_bruteforce",
    ):
        if wireless_settings.get(forbidden) is True:
            raise ValueError(
                f"passive-wifi-survey does not allow {forbidden} in the foundation slice"
            )

    for value in [
        params["site"],
        *list(params.get("approved_ssids") or []),
        *list(params.get("approved_bssids") or []),
    ]:
        if value and not target_value_is_allowed(scope.allowlist_json, str(value)):
            raise ValueError(
                f"configured wireless target {value} is outside the approved engagement scope"
            )


def validate_netexec_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
    intrusive: bool,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    planned_targets = planned_targets_for_tool("netexec", targets)
    if not planned_targets:
        raise ValueError(
            "NetExec SMB validation requires at least one approved host or directory-host target"
        )

    if intrusive and not netexec_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "intrusive-lan-smb-auth requires at least one access account with username and stored password or NTLM hash binding"
        )


def validate_priv_esc_linux_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> None:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    planned_targets = planned_targets_for_tool("priv-esc-linux", targets)
    if not planned_targets:
        raise ValueError(
            "priv-esc-linux requires at least one approved Linux host or directory-host target"
        )

    if not priv_esc_linux_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "priv-esc-linux requires at least one low-privileged SSH account with username and stored password binding"
        )


def validate_metasploit_run_configuration(
    session: Session,
    *,
    engagement_id: UUID,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> Finding:
    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    planned_targets = planned_targets_for_tool("metasploit", targets)
    if not planned_targets:
        raise ValueError(
            "intrusive-exploitation requires at least one approved host or directory-host target"
        )

    params = metasploit_runner_params_from_configuration(configuration)
    finding_id = _uuid_or_none(params.get("finding_id"))
    if finding_id is None:
        raise ValueError(
            "intrusive-exploitation requires metasploit.finding_id in configuration_json"
        )

    finding = load_run_finding_for_engagement(
        session,
        engagement_id=engagement_id,
        finding_id=finding_id,
    )
    if finding is None:
        raise ValueError(
            "intrusive-exploitation requires a prior run-backed finding for this engagement"
        )

    normalized_targets = {target["value"] for target in planned_targets}
    if finding.target_id not in normalized_targets:
        raise ValueError(
            "intrusive-exploitation targets must include the exact target_id from the approved source finding"
        )

    lhost = str(params.get("lhost") or "127.0.0.1").strip().lower()
    if lhost not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("intrusive-exploitation requires metasploit.lhost to stay on loopback")

    allowlisted_module = resolve_allowlisted_module(
        finding_context_for_runner(finding),
        requested_module=(str(params.get("module_name") or "").strip() or None),
    )
    if allowlisted_module.requires_auth and not metasploit_auth_contexts_from_configuration(
        configuration
    ):
        raise ValueError(
            "intrusive-exploitation requires at least one access account with stored password or NTLM hash binding for the selected Metasploit module"
        )

    return finding


def validate_impacket_lateral_run_configuration(
    *,
    scope: Scope,
    configuration: dict[str, Any] | None,
    mode: str,
) -> None:
    normalized_mode = str(mode or "").strip().lower()
    if normalized_mode not in {"secretsdump", "remote_exec", "dcsync"}:
        raise ValueError("impacket-lateral requires a valid runner mode")

    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    planned_targets = planned_targets_for_tool("impacket-lateral", targets)
    if not planned_targets:
        raise ValueError(
            "Impacket lateral validation requires at least one approved host or directory-host target"
        )

    if not impacket_auth_contexts_from_configuration(configuration):
        raise ValueError(
            "Impacket lateral validation requires at least one access account with stored password or NTLM hash binding"
        )

    params = impacket_lateral_runner_params_from_configuration(configuration)
    if normalized_mode == "remote_exec":
        method = str(params.get("remote_exec_method") or "psexec").strip().lower()
        if method not in {"psexec", "wmiexec"}:
            raise ValueError(
                "intrusive-impacket-remote-exec requires impacket.remote_exec_method to be psexec or wmiexec"
            )


def validate_credential_attack_run_configuration(
    session: Session,
    *,
    engagement_id: UUID,
    scope: Scope,
    configuration: dict[str, Any] | None,
    source_inventory_snapshot_id: UUID | None,
    mode: str,
) -> None:
    normalized_mode = str(mode or "").strip().lower()
    if normalized_mode not in {"kerberoast", "asreproast", "hashcat", "spray"}:
        raise ValueError("Credential attacks require a valid runner mode")

    targets = derive_targets_from_target_map(
        configuration.get("targets")
        if isinstance(configuration, dict) and isinstance(configuration.get("targets"), dict)
        else scope.allowlist_json
    )
    planned_targets = planned_targets_for_tool("credential-attacks", targets)
    if not planned_targets:
        raise ValueError(
            "Credential attacks require at least one approved AD domain or directory host target"
        )

    snapshot = (
        session.get(InventorySnapshot, source_inventory_snapshot_id)
        if source_inventory_snapshot_id is not None
        else None
    )
    if snapshot is not None and snapshot.engagement_id != engagement_id:
        raise ValueError("source_inventory_snapshot_id does not belong to this engagement")

    if normalized_mode == "kerberoast":
        if snapshot is None:
            raise ValueError(
                "active-ad-kerberoast requires source_inventory_snapshot_id from LDAP or BloodHound enumeration"
            )
        if not credential_attack_accounts_from_snapshot(snapshot, mode="kerberoast"):
            raise ValueError(
                "active-ad-kerberoast requires roastable SPN accounts in the selected source inventory snapshot"
            )
        if not credential_attack_auth_contexts_from_configuration(configuration):
            raise ValueError(
                "active-ad-kerberoast requires at least one access account with username and stored password binding"
            )
        return

    if normalized_mode == "asreproast":
        if snapshot is None:
            raise ValueError(
                "active-ad-asreproast requires source_inventory_snapshot_id from LDAP or BloodHound enumeration"
            )
        if not credential_attack_accounts_from_snapshot(snapshot, mode="asreproast"):
            raise ValueError(
                "active-ad-asreproast requires AS-REP roastable accounts in the selected source inventory snapshot"
            )
        return

    if normalized_mode == "hashcat":
        if not credential_attack_hash_sources_from_configuration(
            session,
            engagement_id=engagement_id,
            configuration=configuration,
        ):
            raise ValueError(
                "active-offline-hash-crack requires at least one protected hash source reference"
            )
        return

    if snapshot is None:
        raise ValueError(
            "intrusive-ad-password-spray requires source_inventory_snapshot_id from LDAP enumeration with password policy context"
        )
    params = credential_attack_runner_params_from_configuration(configuration)
    spray_accounts = params.get("spray_accounts")
    if not isinstance(spray_accounts, list) or not spray_accounts:
        raise ValueError(
            "intrusive-ad-password-spray requires credential_attacks.spray_accounts in configuration_json"
        )
    if not credential_attack_password_candidates_from_configuration(
        session,
        engagement_id=engagement_id,
        configuration=configuration,
    ):
        raise ValueError(
            "intrusive-ad-password-spray requires at least one protected password candidate reference"
        )

    context = credential_attack_context_from_inventory_snapshot(snapshot)
    password_policy = (
        dict(context.get("password_policy") or {})
        if isinstance(context.get("password_policy"), dict)
        else {}
    )
    lockout_threshold = password_policy.get("lockout_threshold")
    if not isinstance(lockout_threshold, int) or lockout_threshold <= 1:
        raise ValueError(
            "intrusive-ad-password-spray requires a confirmed LDAP lockout_threshold greater than 1"
        )
    confirmed_threshold = params.get("lockout_threshold_confirmed")
    if not isinstance(confirmed_threshold, int) or confirmed_threshold != lockout_threshold:
        raise ValueError(
            "intrusive-ad-password-spray requires credential_attacks.lockout_threshold_confirmed to match the source inventory lockout threshold"
        )
    attempts_per_window = int(params.get("attempts_per_window") or 3)
    if attempts_per_window >= lockout_threshold:
        raise ValueError(
            "intrusive-ad-password-spray attempts_per_window must stay below the confirmed lockout threshold"
        )


def planned_tools(profile: RunProfile) -> list[str]:
    tools = profile.limits_json.get("tools", [])
    if not isinstance(tools, list):
        return []

    normalized_tools = [tool.strip() for tool in tools if isinstance(tool, str) and tool.strip()]
    return normalized_tools


def _target_preference(kind: str) -> int:
    order = {
        "url": 0,
        "host": 1,
        "domain": 2,
        "target": 3,
        "cidr": 4,
    }
    return order.get(kind, len(order))


def planned_targets_for_tool(tool: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    if tool == "external-infra":
        return [
            target
            for target in targets
            if target["kind"] in {"host", "cidr", "domain", "url", "target"}
        ]

    if tool == "bloodhound-collect":
        domain_targets = [target for target in targets if target["kind"] == "domain"]
        if domain_targets:
            return list(domain_targets)
        return [target for target in targets if target["kind"] == "host"]

    if tool == "metasploit":
        host_targets = [target for target in targets if target["kind"] == "host"]
        if host_targets:
            return list(host_targets)
        return [target for target in targets if target["kind"] in {"domain", "target"}]

    if tool == "impacket-lateral":
        host_targets = [target for target in targets if target["kind"] == "host"]
        if host_targets:
            return list(host_targets)
        return [target for target in targets if target["kind"] in {"domain", "target"}]

    if tool == "netexec":
        host_targets = [target for target in targets if target["kind"] == "host"]
        if host_targets:
            return list(host_targets)
        return [target for target in targets if target["kind"] in {"domain", "target"}]

    if tool == "priv-esc-linux":
        host_targets = [target for target in targets if target["kind"] == "host"]
        if host_targets:
            return list(host_targets)
        return [target for target in targets if target["kind"] in {"domain", "target"}]

    if tool == "ssh-brute":
        host_targets = [target for target in targets if target["kind"] == "host"]
        if host_targets:
            return list(host_targets)
        return [target for target in targets if target["kind"] in {"cidr", "domain", "target"}]

    if tool == "credential-attacks":
        domain_targets = [target for target in targets if target["kind"] == "domain"]
        if domain_targets:
            return list(domain_targets)
        return [target for target in targets if target["kind"] in {"host", "target"}]

    if tool == "responder":
        return [target for target in targets if target["kind"] == "cidr"]

    if tool == "easm-discover":
        domain_targets = [target for target in targets if target["kind"] == "domain"]
        if domain_targets:
            return list(domain_targets)
        return [target for target in targets if target["kind"] in {"host", "url", "target"}]

    if tool == "nmap":
        return [
            target for target in targets if target["kind"] in {"host", "cidr", "domain", "target"}
        ]

    if tool == "mdns-ssdp":
        return [target for target in targets if target["kind"] in {"host", "cidr", "target"}]

    if tool == "wifi-survey":
        site_targets = [target for target in targets if target["kind"] == "wireless-site"]
        if site_targets:
            return list(site_targets)
        return [target for target in targets if target["kind"] in {"ssid", "bssid", "target"}]

    if tool == "iot-default-creds":
        return [
            target
            for target in targets
            if target["kind"] in {"host", "cidr", "domain", "url", "target"}
        ]

    if tool == "network-segmentation":
        return [target for target in targets if target["kind"] in {"host", "cidr", "target"}]

    if tool == "snmp-enum":
        return [target for target in targets if target["kind"] in {"host", "cidr", "target"}]

    if tool == "smart-home":
        return [
            target
            for target in targets
            if target["kind"] in {"host", "cidr", "domain", "url", "target"}
        ]

    if tool == "camera-test":
        return [
            target
            for target in targets
            if target["kind"] in {"host", "cidr", "domain", "url", "target"}
        ]

    if tool == "ipv6-discovery":
        return [target for target in targets if target["kind"] in {"host", "cidr", "target"}]

    if tool == "nuclei":
        url_targets = [target for target in targets if target["kind"] == "url"]
        if url_targets:
            return list(url_targets)
        return [target for target in targets if target["kind"] in {"host", "domain", "target"}]

    if tool == "crypto-audit":
        url_targets = [target for target in targets if target["kind"] == "url"]
        if url_targets:
            return list(url_targets)
        return [target for target in targets if target["kind"] in {"host", "domain", "target"}]

    if tool in {
        "content-discovery",
        "nikto",
        "sqlmap",
        "xxe-probe",
        "jwt-probe",
        "vuln-components",
        "idor-bac",
        "client-state",
        "headers-security",
        "graphql-probe",
        "ssti-probe",
        "http-smuggling",
        "oauth-probe",
        "logging-probe",
        "xss-extended",
        "ssrf-probe",
        "deserialization-probe",
        "session-security",
        "auth-flow",
    }:
        url_targets = [target for target in targets if target["kind"] == "url"]
        if url_targets:
            return list(url_targets)
        return [target for target in targets if target["kind"] in {"host", "domain", "target"}]

    if tool == "external-osint":
        return [
            target for target in targets if target["kind"] in {"host", "domain", "url", "target"}
        ]

    if tool == "ldap-enum":
        return [target for target in targets if target["kind"] in {"host", "domain"}]

    if tool == "aws-inventory":
        return [target for target in targets if target["kind"] == "aws-account"]

    if tool == "llm-probe":
        return [target for target in targets if target["kind"] == "llm-endpoint"]

    if tool == "biz-logic-probe":
        return [target for target in targets if target["kind"] == "url"]

    if tool == "api-assessment":
        api_targets = [
            target for target in targets if target["kind"] in {"url", "host", "domain", "target"}
        ]
        return list(api_targets)

    if tool == "mobile-android":
        return [target for target in targets if target["kind"] == "mobile-artifact"]

    if tool == "desktop-client":
        return [
            target
            for target in targets
            if target["kind"] in {"desktop-artifact", "desktop-helper-url"}
        ]

    if tool == "cloud-native":
        return [
            target
            for target in targets
            if target["kind"] in {"cloud-native-artifact", "container-image"}
        ]

    if tool == "cicd-security":
        return [
            target for target in targets if target["kind"] in {"cicd-pipeline-config", "repository"}
        ]

    if tool == "playwright-web":
        url_targets = [target for target in targets if target["kind"] == "url"]
        if url_targets:
            return list(url_targets)
        return [target for target in targets if target["kind"] in {"host", "domain", "target"}]

    if tool != "zap" and tool != "burp":
        return list(targets)

    planned_targets: list[dict[str, str]] = []
    planned_indexes: dict[str, int] = {}

    for target in targets:
        normalized_value = normalize_http_target(target["value"])
        existing_index = planned_indexes.get(normalized_value)
        if existing_index is None:
            planned_indexes[normalized_value] = len(planned_targets)
            planned_targets.append(target)
            continue

        existing_target = planned_targets[existing_index]
        if _target_preference(target["kind"]) < _target_preference(existing_target["kind"]):
            planned_targets[existing_index] = target

    return planned_targets


def target_value_is_allowed(target_map: dict[str, Any] | None, target_id: str) -> bool:
    allowed_targets = derive_targets_from_target_map(target_map)
    allowed_values = {target["value"] for target in allowed_targets}
    if target_id in allowed_values:
        return True
    normalized_wireless_target = str(target_id or "").strip().lower()
    wireless_allowed_values = {
        (
            _normalized_bssid(target["value"])
            if target["kind"] == "bssid"
            else str(target["value"]).strip().lower()
        )
        for target in allowed_targets
        if target["kind"] in {"wireless-site", "ssid", "bssid"}
    }
    if (
        normalized_wireless_target in wireless_allowed_values
        or _normalized_bssid(target_id) in wireless_allowed_values
    ):
        return True

    cidr_ranges = []
    domain_like_targets: set[str] = set()
    for target in allowed_targets:
        if target["kind"] == "cidr":
            try:
                cidr_ranges.append(ip_network(target["value"], strict=False))
            except ValueError:
                continue
        elif target["kind"] in {"host", "domain", "url", "target"}:
            domain_like_targets.add(target["value"])
            parsed_target = urlparse(target["value"])
            if parsed_target.hostname:
                domain_like_targets.add(parsed_target.hostname)

    parsed = urlparse(target_id if "://" in target_id else f"//{target_id}")
    host_candidate = parsed.hostname or target_id.split(":", 1)[0]
    try:
        ip_candidate = ip_address(host_candidate)
    except ValueError:
        ip_candidate = None

    if ip_candidate is not None:
        return any(ip_candidate in network for network in cidr_ranges)

    normalized_host = str(host_candidate or "").strip().lower()
    normalized_allowed = {
        value.strip().lower() for value in domain_like_targets if isinstance(value, str)
    }
    return any(
        normalized_host == allowed or normalized_host.endswith(f".{allowed}")
        for allowed in normalized_allowed
        if allowed
    )


def _web_url_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return str(parsed.hostname or "").strip().lower()


def web_target_value_is_allowed_with_path(
    target_map: dict[str, Any] | None,
    target_id: str,
) -> bool:
    scope = target_map or {}
    if not scope:
        return True
    candidate = normalize_http_target(str(target_id or "").strip())
    candidate_host = _web_url_host(candidate)
    if not candidate_host:
        return False

    url_constraints: list[str] = []
    for key in ("urls", "api_base_urls", "targets"):
        values = scope.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            raw_value = str(value or "").strip()
            if not raw_value:
                continue
            allowed = normalize_http_target(raw_value)
            if _web_url_host(allowed) == candidate_host:
                url_constraints.append(allowed)
    if not url_constraints:
        return target_value_is_allowed(scope, candidate)

    candidate_path = urlparse(candidate).path or "/"
    for raw_allowed in url_constraints:
        allowed = urlparse(raw_allowed)
        allowed_path = allowed.path or "/"
        if (
            allowed_path == "/"
            or candidate_path == allowed_path
            or candidate_path.startswith(allowed_path.rstrip("/") + "/")
        ):
            return True
    return False


def target_is_allowed(scope: Scope, target_id: str) -> bool:
    return target_value_is_allowed(scope.allowlist_json, target_id)


def validate_configured_targets_within_scope(scope: Scope, configuration: dict[str, Any]) -> None:
    configured_targets = configuration.get("targets", {})
    if not isinstance(configured_targets, dict):
        return

    for target in derive_targets_from_target_map(configured_targets):
        if target["kind"] == "path":
            continue
        if not target_value_is_allowed(scope.allowlist_json, target["value"]):
            raise ValueError(
                f"configured target {target['value']} is outside the approved engagement scope"
            )


def queue_run_tasks(session: Session, run: Run, scope: Scope, profile: RunProfile) -> list[Task]:
    existing_tasks = session.scalars(
        select(Task).where(Task.run_id == run.id).order_by(Task.tool, Task.target_id)
    ).all()
    if existing_tasks:
        run.status = "queued"
        return list(existing_tasks)

    tasks: list[Task] = []
    targets = derive_targets_for_run(scope, run)
    tools = planned_tools(profile)
    normalized_limits = normalize_profile_limits(profile.run_class, profile.limits_json)
    run_configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    ldap_configuration = run_configuration.get("ldap")
    ldap_params = ldap_configuration if isinstance(ldap_configuration, dict) else {}
    bloodhound_params = bloodhound_runner_params_from_configuration(run_configuration)
    aws_configuration = run_configuration.get("aws")
    aws_params = aws_configuration if isinstance(aws_configuration, dict) else {}
    llm_configuration = run_configuration.get("llm")
    llm_params = llm_configuration if isinstance(llm_configuration, dict) else {}
    biz_logic_params = business_logic_runner_params_from_configuration(run_configuration)
    browser_params = browser_runner_params_from_configuration(run_configuration)
    api_assessment_params = api_assessment_runner_params_from_configuration(run_configuration)
    content_discovery_params = content_discovery_runner_params_from_configuration(run_configuration)
    sqlmap_params = sqlmap_runner_params_from_configuration(run_configuration)
    xxe_params = xxe_runner_params_from_configuration(run_configuration)
    jwt_params = jwt_runner_params_from_configuration(run_configuration)
    vulnerable_components_params = vulnerable_components_runner_params_from_configuration(
        run_configuration
    )
    idor_bac_params = idor_bac_runner_params_from_configuration(run_configuration)
    client_state_params = client_state_runner_params_from_configuration(run_configuration)
    headers_security_params = headers_security_runner_params_from_configuration(run_configuration)
    graphql_probe_params = graphql_probe_runner_params_from_configuration(run_configuration)
    ssti_params = ssti_runner_params_from_configuration(run_configuration)
    http_smuggling_params = http_smuggling_runner_params_from_configuration(run_configuration)
    oauth_probe_params = oauth_probe_runner_params_from_configuration(run_configuration)
    logging_probe_params = logging_probe_runner_params_from_configuration(run_configuration)
    ssh_brute_params = ssh_brute_runner_params_from_configuration(run_configuration)
    crypto_audit_params = crypto_audit_runner_params_from_configuration(run_configuration)
    xss_extended_params = xss_extended_runner_params_from_configuration(run_configuration)
    ssrf_params = ssrf_runner_params_from_configuration(run_configuration)
    deserialization_params = deserialization_runner_params_from_configuration(run_configuration)
    session_security_params = session_security_runner_params_from_configuration(run_configuration)
    auth_flow_params = auth_flow_runner_params_from_configuration(run_configuration)
    mobile_android_params = mobile_android_runner_params_from_configuration(run_configuration)
    desktop_client_params = desktop_client_runner_params_from_configuration(run_configuration)
    cloud_native_params = cloud_native_runner_params_from_configuration(run_configuration)
    cicd_security_params = cicd_security_runner_params_from_configuration(run_configuration)
    credential_attack_params = credential_attack_runner_params_from_configuration(run_configuration)
    impacket_params = impacket_lateral_runner_params_from_configuration(run_configuration)
    metasploit_params = metasploit_runner_params_from_configuration(run_configuration)
    nmap_params = nmap_runner_params_from_configuration(run_configuration)
    netexec_params = netexec_runner_params_from_configuration(run_configuration)
    priv_esc_linux_params = priv_esc_linux_runner_params_from_configuration(run_configuration)
    responder_params = responder_runner_params_from_configuration(run_configuration)
    wifi_params = wifi_runner_params_from_configuration(run_configuration)
    validation_configuration = run_configuration.get("validation")
    validation_params = (
        validation_configuration if isinstance(validation_configuration, dict) else {}
    )
    pack: CapabilityPack | None = None
    if run.bound_pack_id is not None:
        pack = session.scalar(
            select(CapabilityPack)
            .options(selectinload(CapabilityPack.artifacts))
            .where(CapabilityPack.id == run.bound_pack_id)
        )

    for tool in tools:
        tool_targets = planned_targets_for_tool(tool, targets)
        if tool == "biz-logic-probe":
            validate_business_logic_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "playwright-web":
            validate_playwright_web_run_configuration(
                scope=scope,
                configuration=run_configuration,
                profile_limits=normalized_limits,
            )
        if tool == "api-assessment":
            validate_api_assessment_run_configuration(
                scope=scope,
                configuration=run_configuration,
                profile_limits=normalized_limits,
            )
        if tool in {"content-discovery", "nikto", "external-osint"}:
            validate_web_depth_run_configuration(
                scope=scope,
                configuration=run_configuration,
                tool=tool,
            )
        if tool == "sqlmap":
            validate_sqlmap_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "xxe-probe":
            validate_xxe_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "jwt-probe":
            validate_jwt_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "vuln-components":
            validate_vulnerable_components_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "idor-bac":
            validate_idor_bac_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "client-state":
            validate_client_state_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "headers-security":
            validate_headers_security_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "graphql-probe":
            validate_graphql_probe_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "ssti-probe":
            validate_ssti_probe_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "http-smuggling":
            validate_http_smuggling_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "oauth-probe":
            validate_oauth_probe_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "logging-probe":
            validate_logging_probe_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "ssh-brute":
            validate_ssh_brute_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "crypto-audit":
            validate_crypto_audit_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "xss-extended":
            validate_xss_extended_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "ssrf-probe":
            validate_ssrf_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "deserialization-probe":
            validate_deserialization_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "session-security":
            validate_session_security_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "auth-flow":
            validate_auth_flow_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "mobile-android":
            validate_mobile_android_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "desktop-client":
            validate_desktop_client_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "cloud-native":
            validate_cloud_native_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "cicd-security":
            validate_cicd_security_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "bloodhound-collect":
            validate_bloodhound_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "impacket-lateral":
            validate_impacket_lateral_run_configuration(
                scope=scope,
                configuration=run_configuration,
                mode=str(normalized_limits.get("impacket_mode") or ""),
            )
        if tool == "metasploit":
            validate_metasploit_run_configuration(
                session,
                engagement_id=run.engagement_id,
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "netexec":
            validate_netexec_run_configuration(
                scope=scope,
                configuration=run_configuration,
                intrusive=profile.run_class == "intrusive",
            )
        if tool == "priv-esc-linux":
            validate_priv_esc_linux_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "credential-attacks":
            validate_credential_attack_run_configuration(
                session,
                engagement_id=run.engagement_id,
                scope=scope,
                configuration=run_configuration,
                source_inventory_snapshot_id=run.source_inventory_snapshot_id,
                mode=str(normalized_limits.get("credential_attack_mode") or ""),
            )
        if tool == "responder":
            validate_responder_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "wifi-survey":
            validate_wifi_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "easm-discover":
            validate_easm_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        if tool == "external-infra":
            validate_external_infra_run_configuration(
                scope=scope,
                configuration=run_configuration,
            )
        pack_metadata = None
        if pack is not None:
            pack_metadata = {
                "pack_id": str(pack.id),
                "version": pack.version,
                "deployment_id": (
                    str(run.bound_pack_deployment_id) if run.bound_pack_deployment_id else None
                ),
                "methodology_tags": list(pack.methodology_tags),
                "source_inventory_snapshot_id": (
                    str(pack.source_inventory_snapshot_id)
                    if pack.source_inventory_snapshot_id
                    else None
                ),
                "relevance_decision_id": (
                    str(pack.relevance_decision_id) if pack.relevance_decision_id else None
                ),
                "artifact_refs": artifact_refs_for_tool(pack, tool),
            }
        if tool in {"zap", "external-infra"}:
            if not tool_targets:
                continue

            target_values = [target["value"] for target in tool_targets]
            params_json = {
                "target_kind": (
                    tool_targets[0]["kind"] if len(tool_targets) == 1 else "multi-target"
                ),
                "targets": target_values,
                "profile_name": profile.name,
                "run_class": profile.run_class,
                "limits": normalized_limits,
                **({"validation": dict(validation_params)} if validation_params else {}),
                **({"capability_pack": pack_metadata} if pack_metadata is not None else {}),
            }
            if tool == "external-infra":
                params_json.update(
                    {
                        "mode": "active" if profile.run_class == "active" else "passive",
                        "include_passive_smb": bool(
                            normalized_limits.get("include_passive_smb", True)
                        ),
                    }
                )
            task = Task(
                run=run,
                source_finding_id=_uuid_or_none(validation_params.get("source_finding_id")),
                tool=tool,
                target_id=target_values[0],
                status="queued",
                params_json=params_json,
            )
            session.add(task)
            tasks.append(task)
            continue

        for target in tool_targets:
            task_source_finding_id = _uuid_or_none(validation_params.get("source_finding_id"))
            task_params = {
                "target_kind": target["kind"],
                "profile_name": profile.name,
                "run_class": profile.run_class,
                "limits": normalized_limits,
                **({"capability_pack": pack_metadata} if pack_metadata is not None else {}),
            }
            if tool == "ldap-enum":
                for field_name in ("base_dn", "bind_dn", "password_env", "use_ssl", "page_size"):
                    if field_name in ldap_params:
                        task_params[field_name] = ldap_params[field_name]
            if tool == "nmap":
                task_params.update(
                    {
                        key: value
                        for key, value in nmap_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "bloodhound-collect":
                task_params.update(
                    {
                        "auth_contexts": bloodhound_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in bloodhound_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "aws-inventory":
                for field_name in (
                    "regions",
                    "access_key_id_env",
                    "secret_access_key_env",
                    "session_token_env",
                ):
                    if field_name in aws_params:
                        task_params[field_name] = aws_params[field_name]
            if tool == "llm-probe":
                for field_name in (
                    "provider_mode",
                    "deterministic_profile",
                    "api_key_env",
                    "bearer_token_env",
                    "model",
                    "max_tokens",
                    "max_probes",
                ):
                    if field_name in llm_params:
                        task_params[field_name] = llm_params[field_name]
            if tool == "biz-logic-probe":
                task_params.update(
                    {
                        "auth_contexts": business_logic_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in biz_logic_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "playwright-web":
                task_params.update(
                    {
                        "auth_contexts": browser_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        "mode": str(normalized_limits.get("mode") or "passive").strip()
                        or "passive",
                        "requires_auth_context": bool(
                            browser_params.get(
                                "requires_auth_context",
                                normalized_limits.get("requires_auth_context", False),
                            )
                        ),
                        "proof_marker": str(
                            browser_params.get(
                                "proof_marker",
                                normalized_limits.get("proof_marker", ""),
                            )
                            or ""
                        ).strip()
                        or None,
                        **{
                            key: value
                            for key, value in browser_params.items()
                            if key not in {"requires_auth_context", "proof_marker"}
                            and value not in (None, [], {})
                        },
                    }
                )
            if tool == "api-assessment":
                task_params.update(
                    {
                        "auth_contexts": api_assessment_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        "requires_auth_context": bool(
                            api_assessment_params.get(
                                "requires_auth_context",
                                normalized_limits.get("requires_auth_context", False),
                            )
                        ),
                        **{
                            key: value
                            for key, value in api_assessment_params.items()
                            if key not in {"requires_auth_context"} and value not in (None, [], {})
                        },
                    }
                )
            if tool == "content-discovery":
                task_params.update(
                    {
                        key: value
                        for key, value in content_discovery_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "sqlmap":
                task_params.update(
                    {
                        key: value
                        for key, value in sqlmap_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "xxe-probe":
                task_params.update(
                    {key: value for key, value in xxe_params.items() if value not in (None, [], {})}
                )
            if tool == "jwt-probe":
                task_params.update(
                    {key: value for key, value in jwt_params.items() if value not in (None, [], {})}
                )
            if tool == "vuln-components":
                task_params.update(
                    {
                        key: value
                        for key, value in vulnerable_components_params.items()
                        if key != "local_cve_records" and value not in (None, [], {})
                    }
                )
                if vulnerable_components_params.get("local_cve_records"):
                    task_params["local_cve_records"] = vulnerable_components_params[
                        "local_cve_records"
                    ]
                else:
                    task_params["local_cve_records"] = local_cve_records_for_vulnerable_components(
                        session
                    )
            if tool == "idor-bac":
                task_params.update(
                    {
                        "auth_contexts": business_logic_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in idor_bac_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "client-state":
                task_params.update(
                    {
                        "auth_contexts": client_state_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in client_state_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "headers-security":
                task_params.update(
                    {
                        key: value
                        for key, value in headers_security_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "graphql-probe":
                task_params.update(
                    {
                        key: value
                        for key, value in graphql_probe_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "ssti-probe":
                task_params.update(
                    {
                        key: value
                        for key, value in ssti_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "http-smuggling":
                task_params.update(
                    {
                        key: value
                        for key, value in http_smuggling_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "oauth-probe":
                task_params.update(
                    {
                        key: value
                        for key, value in oauth_probe_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "logging-probe":
                task_params.update(
                    {
                        key: value
                        for key, value in logging_probe_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "ssh-brute":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "rate_limit_per_second": float(
                            normalized_limits.get("rate_limit_per_second") or 5
                        ),
                        "lockout_stop_threshold": int(
                            normalized_limits.get("lockout_stop_threshold") or 3
                        ),
                        "max_attempts_per_service": int(
                            normalized_limits.get("max_attempts_per_service") or 200
                        ),
                        "max_usernames": int(normalized_limits.get("max_usernames") or 10),
                        "max_custom_passwords": int(
                            normalized_limits.get("max_custom_passwords") or 50
                        ),
                        **{
                            key: value
                            for key, value in ssh_brute_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "crypto-audit":
                task_params.update(
                    {
                        key: value
                        for key, value in crypto_audit_params.items()
                        if value not in (None, [], {})
                    }
                )
                task_params["mode"] = (
                    str(
                        task_params.get("mode") or normalized_limits.get("mode") or "passive"
                    ).strip()
                    or "passive"
                )
                if "ssh_targets" not in task_params:
                    task_params["ssh_targets"] = (
                        [target["value"]] if target["kind"] in {"host", "target"} else []
                    )
            if tool == "xss-extended":
                task_params.update(
                    {
                        key: value
                        for key, value in xss_extended_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "ssrf-probe":
                task_params.update(
                    {
                        key: value
                        for key, value in ssrf_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "deserialization-probe":
                task_params.update(
                    {
                        key: value
                        for key, value in deserialization_params.items()
                        if value not in (None, [], {})
                    }
                )
            if tool == "session-security":
                task_params.update(
                    {
                        "auth_contexts": session_security_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in session_security_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "auth-flow":
                task_params.update(
                    {
                        "auth_contexts": auth_flow_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in auth_flow_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "mobile-android":
                task_params.update(
                    {
                        "apk_path": str(
                            mobile_android_params.get("apk_path") or target["value"]
                        ).strip()
                        or target["value"],
                        **{
                            key: value
                            for key, value in mobile_android_params.items()
                            if key != "apk_path" and value not in (None, [], {})
                        },
                    }
                )
            if tool == "desktop-client":
                artifact_paths = (
                    list(desktop_client_params.get("artifact_paths", []))
                    if isinstance(desktop_client_params.get("artifact_paths"), list)
                    else []
                )
                helper_urls = (
                    list(desktop_client_params.get("helper_urls", []))
                    if isinstance(desktop_client_params.get("helper_urls"), list)
                    else []
                )
                if target["kind"] == "desktop-artifact" and target["value"] not in artifact_paths:
                    artifact_paths = [*artifact_paths, target["value"]]
                if target["kind"] == "desktop-helper-url" and target["value"] not in helper_urls:
                    helper_urls = [*helper_urls, target["value"]]
                task_params.update(
                    {
                        "artifact_paths": artifact_paths,
                        "helper_urls": helper_urls,
                        **{
                            key: value
                            for key, value in desktop_client_params.items()
                            if key not in {"artifact_paths", "helper_urls"}
                            and value not in (None, [], {})
                        },
                    }
                )
            if tool == "cloud-native":
                manifest_paths = (
                    list(cloud_native_params.get("manifest_paths", []))
                    if isinstance(cloud_native_params.get("manifest_paths"), list)
                    else []
                )
                image_metadata = cloud_native_params.get("image_metadata")
                if (
                    target["kind"] == "cloud-native-artifact"
                    and target["value"] not in manifest_paths
                ):
                    manifest_paths = [*manifest_paths, target["value"]]
                if target["kind"] == "container-image" and not image_metadata:
                    image_metadata = [{"image": target["value"]}]
                task_params.update(
                    {
                        "manifest_paths": manifest_paths,
                        "image_metadata": image_metadata,
                        **{
                            key: value
                            for key, value in cloud_native_params.items()
                            if key not in {"manifest_paths", "image_metadata"}
                            and value not in (None, [], {})
                        },
                    }
                )
            if tool == "cicd-security":
                pipeline_paths = (
                    list(cicd_security_params.get("pipeline_paths", []))
                    if isinstance(cicd_security_params.get("pipeline_paths"), list)
                    else []
                )
                repository_metadata = cicd_security_params.get("repository_metadata")
                if (
                    target["kind"] == "cicd-pipeline-config"
                    and target["value"] not in pipeline_paths
                ):
                    pipeline_paths = [*pipeline_paths, target["value"]]
                if target["kind"] == "repository" and not repository_metadata:
                    repository_metadata = {"repository": target["value"]}
                task_params.update(
                    {
                        "pipeline_paths": pipeline_paths,
                        "repository_metadata": repository_metadata,
                        **{
                            key: value
                            for key, value in cicd_security_params.items()
                            if key not in {"pipeline_paths", "repository_metadata"}
                            and value not in (None, [], {})
                        },
                    }
                )
            if tool == "credential-attacks":
                credential_attack_mode = (
                    str(normalized_limits.get("credential_attack_mode") or "").strip().lower()
                )
                task_params.update(
                    {
                        "mode": credential_attack_mode,
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        **{
                            key: value
                            for key, value in credential_attack_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
                if credential_attack_mode in {"kerberoast", "asreproast"}:
                    snapshot = (
                        session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                        if run.source_inventory_snapshot_id is not None
                        else None
                    )
                    task_params["candidate_accounts"] = credential_attack_accounts_from_snapshot(
                        snapshot,
                        mode=credential_attack_mode,
                    )
                if credential_attack_mode == "kerberoast":
                    task_params["auth_contexts"] = (
                        credential_attack_auth_contexts_from_configuration(run_configuration)
                    )
                if credential_attack_mode == "hashcat":
                    task_params["hash_sources"] = credential_attack_hash_sources_from_configuration(
                        session,
                        engagement_id=run.engagement_id,
                        configuration=run_configuration,
                    )
                if credential_attack_mode == "spray":
                    snapshot = (
                        session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                        if run.source_inventory_snapshot_id is not None
                        else None
                    )
                    task_params["candidate_accounts"] = credential_attack_named_accounts(
                        snapshot,
                        account_names=[
                            account_name
                            for account_name in list(
                                credential_attack_params.get("spray_accounts") or []
                            )
                            if isinstance(account_name, str) and account_name.strip()
                        ],
                    )
                    task_params["password_candidates"] = (
                        credential_attack_password_candidates_from_configuration(
                            session,
                            engagement_id=run.engagement_id,
                            configuration=run_configuration,
                        )
                    )
                    context = credential_attack_context_from_inventory_snapshot(snapshot)
                    password_policy = (
                        dict(context.get("password_policy") or {})
                        if isinstance(context.get("password_policy"), dict)
                        else {}
                    )
                    if isinstance(password_policy.get("lockout_threshold"), int):
                        task_params["lockout_threshold"] = int(password_policy["lockout_threshold"])
            if tool == "metasploit":
                source_finding = validate_metasploit_run_configuration(
                    session,
                    engagement_id=run.engagement_id,
                    scope=scope,
                    configuration=run_configuration,
                )
                task_source_finding_id = source_finding.id
                allowlisted_module = resolve_allowlisted_module(
                    finding_context_for_runner(source_finding),
                    requested_module=(
                        str(metasploit_params.get("module_name") or "").strip() or None
                    ),
                )
                task_params.update(
                    {
                        "source_finding": finding_context_for_runner(source_finding),
                        "module_name": allowlisted_module.module_name,
                        "module_type": allowlisted_module.module_type,
                        "reference_label": allowlisted_module.reference_label,
                        "lhost": str(metasploit_params.get("lhost") or "127.0.0.1").strip()
                        or "127.0.0.1",
                        "lport": int(metasploit_params.get("lport") or 4444),
                        "rport": int(
                            metasploit_params.get("rport") or allowlisted_module.default_rport
                        ),
                        "precheck_module_name": allowlisted_module.precheck_module_name,
                        "precheck_module_type": allowlisted_module.precheck_module_type,
                        "auth_contexts": (
                            metasploit_auth_contexts_from_configuration(run_configuration)
                            if allowlisted_module.requires_auth
                            else []
                        ),
                    }
                )
            if tool == "impacket-lateral":
                task_params.update(
                    {
                        "mode": str(normalized_limits.get("impacket_mode") or "").strip().lower(),
                        "auth_contexts": impacket_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in impacket_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "netexec":
                task_params.update(
                    {
                        "mode": (
                            str(normalized_limits.get("netexec_mode") or "passive").strip()
                            or "passive"
                        ),
                        **{
                            key: value
                            for key, value in netexec_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
                if profile.run_class == "intrusive":
                    task_params["auth_contexts"] = netexec_auth_contexts_from_configuration(
                        run_configuration
                    )
            if tool == "priv-esc-linux":
                task_params.update(
                    {
                        "auth_contexts": priv_esc_linux_auth_contexts_from_configuration(
                            run_configuration
                        ),
                        **{
                            key: value
                            for key, value in priv_esc_linux_params.items()
                            if value not in (None, [], {})
                        },
                    }
                )
            if tool == "responder":
                task_params.update(
                    {
                        **{
                            key: value
                            for key, value in responder_params.items()
                            if value not in (None, [], {})
                        },
                        "approved_scope_cidrs": [target["value"] for target in tool_targets],
                    }
                )
            if tool == "mdns-ssdp":
                task_params.update(
                    {
                        "service_types": normalized_limits.get("service_types"),
                        "mdns_enabled": bool(normalized_limits.get("mdns_enabled", True)),
                        "ssdp_enabled": bool(normalized_limits.get("ssdp_enabled", True)),
                        "timeout_seconds": normalized_limits.get("timeout_seconds", 8),
                    }
                )
            if tool == "wifi-survey":
                task_params.update(
                    {
                        **{
                            key: value
                            for key, value in wifi_params.items()
                            if value not in (None, [], {})
                        },
                        "passive_only": True,
                        "rf_disruptive_actions": False,
                        "handshake_capture": False,
                        "credential_harvesting": False,
                        "wps_pin_testing": False,
                        "timeout_seconds": normalized_limits.get("timeout_seconds", 10),
                    }
                )
            if tool == "iot-default-creds":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "max_attempts_per_host": int(
                            normalized_limits.get("max_attempts_per_host") or 3
                        ),
                        "rate_limit_per_second": float(
                            normalized_limits.get("rate_limit_per_second") or 1
                        ),
                    }
                )
            if tool == "network-segmentation":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                reachability_ports = normalized_limits.get("reachability_ports")
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "mode": str(normalized_limits.get("mode") or "passive").strip()
                        or "passive",
                        "reachability_ports": (
                            [int(port) for port in reachability_ports if isinstance(port, int)]
                            if isinstance(reachability_ports, list)
                            else [22, 80, 443, 8080, 8123]
                        ),
                        "vlan_probe_count": int(normalized_limits.get("vlan_probe_count") or 10),
                        "native_vlan": int(
                            run_configuration.get("native_vlan")
                            or normalized_limits.get("native_vlan")
                            or 1
                        ),
                        "target_vlan": int(
                            run_configuration.get("target_vlan")
                            or normalized_limits.get("target_vlan")
                            or 2
                        ),
                        "vlan_interface": (
                            str(run_configuration.get("vlan_interface")).strip()
                            if run_configuration.get("vlan_interface")
                            else None
                        ),
                    }
                )
            if tool == "snmp-enum":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                community_strings = normalized_limits.get("community_strings")
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "read_only": True,
                        "community_strings": (
                            [
                                str(item).strip()
                                for item in community_strings
                                if isinstance(item, str) and str(item).strip()
                            ]
                            if isinstance(community_strings, list)
                            else []
                        ),
                        "max_target_hosts": int(normalized_limits.get("max_target_hosts") or 256),
                    }
                )
            if tool == "smart-home":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "read_only": True,
                        "mqtt_subscribe_only": True,
                        "mqtt_publish_performed": False,
                        "home_assistant_get_only": True,
                        "device_control_performed": False,
                        "mqtt_listen_seconds": float(
                            normalized_limits.get("mqtt_listen_seconds") or 30
                        ),
                        "timeout_seconds": normalized_limits.get("timeout_seconds", 5),
                        "max_target_hosts": int(normalized_limits.get("max_target_hosts") or 128),
                    }
                )
            if tool == "camera-test":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "read_only": True,
                        "rtsp_methods": ["OPTIONS", "DESCRIBE"],
                        "rtsp_setup_performed": False,
                        "rtsp_play_performed": False,
                        "video_frame_storage": False,
                        "video_frame_captured": False,
                        "ptz_control": False,
                        "configuration_changes": False,
                        "default_credentials_bounded": True,
                        "max_default_credential_attempts": int(
                            normalized_limits.get("max_default_credential_attempts") or 10
                        ),
                        "timeout_seconds": normalized_limits.get("timeout_seconds", 5),
                        "max_target_hosts": int(normalized_limits.get("max_target_hosts") or 128),
                    }
                )
            if tool == "ipv6-discovery":
                snapshot = (
                    session.get(InventorySnapshot, run.source_inventory_snapshot_id)
                    if run.source_inventory_snapshot_id is not None
                    else None
                )
                inventory = (
                    dict(snapshot.normalized_inventory_json)
                    if snapshot is not None and isinstance(snapshot.normalized_inventory_json, dict)
                    else {}
                )
                ports = normalized_limits.get("ports")
                task_params.update(
                    {
                        "source_inventory_snapshot_id": (
                            str(run.source_inventory_snapshot_id)
                            if run.source_inventory_snapshot_id
                            else None
                        ),
                        "inventory": inventory,
                        "interface": (
                            str(run_configuration.get("ipv6_interface")).strip()
                            if run_configuration.get("ipv6_interface")
                            else None
                        ),
                        "timeout_seconds": normalized_limits.get("timeout_seconds", 6),
                        "max_discovered_hosts": int(
                            normalized_limits.get("max_discovered_hosts") or 128
                        ),
                        "run_nmap": bool(normalized_limits.get("run_nmap", True)),
                        "ports": (
                            [str(port).strip() for port in ports if str(port).strip()]
                            if isinstance(ports, list)
                            else ports if isinstance(ports, str) else None
                        ),
                    }
                )

            task = Task(
                run=run,
                source_finding_id=task_source_finding_id,
                tool=tool,
                target_id=target["value"],
                status="queued",
                params_json=task_params,
            )
            if validation_params:
                task.params_json = {**task.params_json, "validation": dict(validation_params)}
            session.add(task)
            tasks.append(task)

    session.flush()
    validation_record_id = _uuid_or_none(validation_params.get("validation_record_id"))
    if validation_record_id is not None and tasks:
        validation_record = session.scalar(
            select(FindingValidationRecord).where(
                FindingValidationRecord.id == validation_record_id
            )
        )
        if validation_record is not None and validation_record.task_id is None:
            validation_record.task_id = tasks[0].id

    run.status = "queued"
    return tasks


def load_run(session: Session, run_id) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.assessment_chain),
            selectinload(Run.engagement),
            selectinload(Run.profile),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.artifacts),
            selectinload(Run.bound_pack_deployment),
            selectinload(Run.approvals),
            selectinload(Run.tasks),
            selectinload(Run.findings),
            selectinload(Run.drift_summary),
        )
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )


def sorted_approvals(run: Run) -> list[Approval]:
    return sorted(run.approvals, key=lambda approval: (approval.created_at, approval.id.hex))


def sorted_tasks(run: Run) -> list[Task]:
    return sorted(
        run.tasks, key=lambda task: (task.tool, task.target_id, task.created_at, task.id.hex)
    )


def sorted_findings(run: Run) -> list[Finding]:
    return sorted(
        run.findings, key=lambda finding: (finding.severity, finding.title, finding.target_id)
    )


def dispatch_queued_run_tasks(
    session: Session,
    *,
    run: Run,
    actor: str,
    settings: Settings,
    background_tasks=None,
) -> tuple[str, list[UUID]]:
    if execution_kill_switch_enabled(settings):
        raise ValueError("execution kill switch is enabled")
    if run.status in {"cancelled", "cancelling", "rejected"}:
        raise ValueError("run is not dispatchable")

    queued_tasks = [task for task in sorted_tasks(run) if task.status == "queued"]
    if not queued_tasks:
        raise ValueError("run has no queued tasks to dispatch")

    unsupported_tools = sorted(
        {task.tool for task in queued_tasks if task.tool not in supported_execution_tools()}
    )
    if unsupported_tools:
        raise ValueError(
            f"queued tasks require unsupported execution tools: {', '.join(unsupported_tools)}"
        )

    dispatch_mode = dispatch_task_batch(
        [task.id for task in queued_tasks],
        settings,
        background_tasks=background_tasks,
    )
    run.configuration_json = {
        **dict(run.configuration_json or {}),
        "runtime_dispatch": {
            **dict((run.configuration_json or {}).get("runtime_dispatch") or {}),
            "last_dispatch_mode": dispatch_mode,
            "last_dispatched_at": datetime.now(tz=UTC).isoformat(),
            "last_dispatched_by": actor,
            "queued_task_count": len(queued_tasks),
        },
    }

    write_audit_event(
        session=session,
        actor=actor,
        action="run.dispatched",
        object_type="run",
        object_id=str(run.id),
        metadata={"dispatch_mode": dispatch_mode, "task_count": len(queued_tasks)},
    )
    return dispatch_mode, [task.id for task in queued_tasks]


def _aware_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def stale_task_recovery_state(
    task: Task,
    *,
    run: Run | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now_utc = _aware_utc(now) or datetime.now(UTC)
    updated_at = _aware_utc(task.updated_at or task.created_at)
    age_seconds = max(0.0, (now_utc - updated_at).total_seconds()) if updated_at else 0.0
    age_minutes = age_seconds / 60
    run_status = str((run or task.run).status if (run or task.run) is not None else "").lower()
    task_status = str(task.status or "").lower()
    has_executions = bool(task.executions)
    blocked_reasons: list[str] = []

    if run_status not in STALE_RECOVERY_ACTIVE_RUN_STATUSES:
        blocked_reasons.append("run status is not running or cancelling")
    if task_status != "running":
        blocked_reasons.append("task is not running")
    if has_executions:
        blocked_reasons.append("task already has execution evidence")
    if age_seconds < STALE_RUNNING_TASK_RECOVERY_AFTER.total_seconds():
        blocked_reasons.append(
            f"task changed less than {int(STALE_RUNNING_TASK_RECOVERY_AFTER.total_seconds() // 60)} minutes ago"
        )

    return {
        "eligible": not blocked_reasons,
        "blocked_reasons": blocked_reasons,
        "age_minutes": round(age_minutes, 1),
        "threshold_minutes": int(STALE_RUNNING_TASK_RECOVERY_AFTER.total_seconds() // 60),
        "has_execution_evidence": has_executions,
        "operator_summary": (
            "This running task appears stale: it has no execution evidence and has not changed past the recovery threshold."
            if not blocked_reasons
            else "This task is not eligible for stale recovery through the governed path."
        ),
    }


def stale_run_recovery_state(run: Run, *, now: datetime | None = None) -> dict[str, Any]:
    states = {
        str(task.id): stale_task_recovery_state(task, run=run, now=now)
        for task in sorted_tasks(run)
    }
    running_tasks = [
        task for task in sorted_tasks(run) if str(task.status or "").lower() == "running"
    ]
    queued_tasks = [
        task for task in sorted_tasks(run) if str(task.status or "").lower() == "queued"
    ]
    eligible_task_ids = [
        str(task.id) for task in running_tasks if states.get(str(task.id), {}).get("eligible")
    ]
    blocked_running_task_ids = [
        str(task.id) for task in running_tasks if not states.get(str(task.id), {}).get("eligible")
    ]
    blocked_reasons: list[str] = []
    run_status = str(run.status or "").lower()
    if run_status not in STALE_RECOVERY_ACTIVE_RUN_STATUSES:
        blocked_reasons.append("run status is not running or cancelling")
    if queued_tasks:
        blocked_reasons.append("queued tasks remain; use normal dispatch or cancellation first")
    if blocked_running_task_ids:
        blocked_reasons.append("one or more running tasks do not meet stale safety criteria")
        task_reasons = [
            reason
            for task_id in blocked_running_task_ids
            for reason in states.get(task_id, {}).get("blocked_reasons", [])
        ]
        blocked_reasons.extend(reason for reason in task_reasons if reason not in blocked_reasons)
    if not eligible_task_ids:
        blocked_reasons.append("no running task meets stale recovery criteria")

    return {
        "available": not blocked_reasons,
        "eligible_task_ids": eligible_task_ids,
        "blocked_running_task_ids": blocked_running_task_ids,
        "queued_task_ids": [str(task.id) for task in queued_tasks],
        "blocked_reasons": blocked_reasons,
        "threshold_minutes": int(STALE_RUNNING_TASK_RECOVERY_AFTER.total_seconds() // 60),
        "operator_summary": (
            "This run has stale running task rows that can be closed with audit evidence."
            if not blocked_reasons
            else "This run is not safe for stale recovery yet; use the listed reason before force-closing anything."
        ),
        "task_states": states,
    }


def recover_stale_run_tasks(
    session: Session,
    *,
    run: Run,
    actor: str,
    reason: str,
    task_outcome: str = "cancelled",
    now: datetime | None = None,
) -> list[UUID]:
    normalized_reason = str(reason or "").strip()
    if len(normalized_reason) < 8:
        raise ValueError("recovery reason must explain why the executor is considered stale")
    if task_outcome not in {"cancelled", "failed"}:
        raise ValueError("task_outcome must be cancelled or failed")

    now_utc = _aware_utc(now) or datetime.now(UTC)
    recovery_state = stale_run_recovery_state(run, now=now_utc)
    if not recovery_state["available"]:
        raise ValueError("; ".join(recovery_state["blocked_reasons"]))

    eligible_ids = {str(task_id) for task_id in recovery_state["eligible_task_ids"]}
    recovered_tasks = [task for task in sorted_tasks(run) if str(task.id) in eligible_ids]
    previous_task_statuses = {str(task.id): task.status for task in recovered_tasks}
    previous_run_status = run.status

    for task in recovered_tasks:
        task.status = task_outcome
        task.params_json = {
            **dict(task.params_json or {}),
            "runtime_recovery": {
                "type": "stale_running_task",
                "outcome": task_outcome,
                "reason": normalized_reason,
                "recovered_by": actor,
                "recovered_at": now_utc.isoformat(),
                "threshold_minutes": recovery_state["threshold_minutes"],
                "previous_status": previous_task_statuses[str(task.id)],
            },
        }

    remaining_statuses = {str(task.status or "").lower() for task in sorted_tasks(run)}
    if "running" in remaining_statuses or "queued" in remaining_statuses:
        run.status = "cancelling"
    elif task_outcome == "failed":
        run.status = "failed"
    else:
        run.status = "cancelled"

    write_audit_event(
        session=session,
        actor=actor,
        action="run.stale_recovered",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "reason": normalized_reason,
            "task_outcome": task_outcome,
            "recovered_task_ids": [str(task.id) for task in recovered_tasks],
            "previous_task_statuses": previous_task_statuses,
            "previous_run_status": previous_run_status,
            "new_run_status": run.status,
            "safety_criteria": {
                "allowed_run_statuses": sorted(STALE_RECOVERY_ACTIVE_RUN_STATUSES),
                "required_task_status": "running",
                "requires_no_tool_executions": True,
                "threshold_minutes": recovery_state["threshold_minutes"],
                "requires_no_queued_tasks": True,
            },
        },
    )
    return [task.id for task in recovered_tasks]


def cancel_run_tasks(run: Run) -> bool:
    if run.status in {"completed", "completed_with_errors", "failed", "rejected", "cancelled"}:
        return False

    changed = False
    has_running_tasks = False

    for task in run.tasks:
        if task.status == "queued":
            task.status = "cancelled"
            changed = True
        elif task.status == "running":
            has_running_tasks = True

    desired_status = "cancelling" if has_running_tasks else "cancelled"
    if run.status != desired_status:
        run.status = desired_status
        changed = True

    return changed
