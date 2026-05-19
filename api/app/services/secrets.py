from __future__ import annotations

import copy
import uuid
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import SecretRef

ACCOUNT_SECRET_FIELDS = {
    "secret_ref": {"binding_key": "password", "secret_kind": "password"},
    "hash_ref": {"binding_key": "ntlm_hash", "secret_kind": "ntlm_hash"},
    "api_key_ref": {"binding_key": "api_key", "secret_kind": "api_key"},
    "bearer_token_ref": {"binding_key": "bearer_token", "secret_kind": "bearer_token"},
    "session_ref": {"binding_key": "session", "secret_kind": "session"},
}

EXTERNAL_REFERENCE_PREFIXES = (
    "vault://",
    "env://",
    "ref://",
    "secret://",
    "session://",
    "cookie://",
    "file://",
    "aegispt://",
)

ENCRYPTED_SECRET_BACKENDS = {"encrypted_local", "deployment_key_encrypted"}


def _fernet_for_key(key: str, *, label: str) -> Fernet:
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"{label} must be a valid Fernet key") from exc


def _normalized_secret_materialization_mode(settings: Settings) -> str:
    mode = settings.secret_materialization_mode.strip().lower().replace("-", "_")
    if mode in {"deployment_key", "deployment_key_encrypted", "deployment"}:
        return "deployment_key"
    return "encrypted_local"


def direct_secret_storage_backend(settings: Settings) -> tuple[str, bool]:
    mode = _normalized_secret_materialization_mode(settings)
    if mode != "deployment_key":
        return "encrypted_local", False

    if settings.deployment_secret_encryption_key:
        return "deployment_key_encrypted", False

    if settings.require_deployment_secret_encryption_key:
        raise ValueError("deployment secret encryption key is required for deployment-key secret materialization")

    return "encrypted_local", True


def _fernet(settings: Settings, *, storage_backend: str = "encrypted_local") -> Fernet:
    if storage_backend == "deployment_key_encrypted":
        if not settings.deployment_secret_encryption_key:
            raise ValueError("deployment secret encryption key is required to decrypt deployment-key secrets")
        return _fernet_for_key(settings.deployment_secret_encryption_key, label="deployment secret encryption key")
    return _fernet_for_key(settings.local_secret_encryption_key, label="local secret encryption key")


def encrypt_secret_value(value: str, settings: Settings, *, storage_backend: str = "encrypted_local") -> str:
    return _fernet(settings, storage_backend=storage_backend).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret_value(value: str, settings: Settings, *, storage_backend: str = "encrypted_local") -> str:
    return _fernet(settings, storage_backend=storage_backend).decrypt(value.encode("utf-8")).decode("utf-8")


def is_explicit_reference(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized.startswith(EXTERNAL_REFERENCE_PREFIXES)


def is_session_material(value: str) -> bool:
    candidate = value.strip()
    if not candidate:
        return False
    if is_explicit_reference(candidate):
        return False
    return any(marker in candidate for marker in ("=", ";", "Bearer ", "token", "cookie"))


def secret_display_label(value: str, *, secret_kind: str, storage_backend: str) -> str:
    normalized = value.strip()
    if storage_backend == "external_pointer":
        if "://" in normalized:
            suffix = normalized.rstrip("/").split("/")[-1] or secret_kind
            prefix = normalized.split("://", 1)[0]
            return f"{prefix} reference ({suffix})"
        return f"{secret_kind.replace('_', ' ')} reference ({normalized})"

    if storage_backend == "deployment_key_encrypted":
        return f"{secret_kind.replace('_', ' ')} protected by deployment key"
    return f"{secret_kind.replace('_', ' ')} protected locally"


def public_secret_binding(secret_ref: SecretRef) -> dict[str, Any]:
    return {
        "secret_ref_id": str(secret_ref.id),
        "secret_kind": secret_ref.secret_kind,
        "storage_backend": secret_ref.storage_backend,
        "display_label": secret_ref.display_label or secret_ref.secret_kind,
    }


def sanitize_run_configuration(configuration: dict[str, Any] | None) -> dict[str, Any]:
    payload = copy.deepcopy(configuration or {})
    access = payload.get("access")
    if not isinstance(access, dict):
        return payload

    accounts = access.get("accounts")
    if isinstance(accounts, list):
        for account in accounts:
            if not isinstance(account, dict):
                continue
            for field_name in ACCOUNT_SECRET_FIELDS:
                if account.get(field_name):
                    account[field_name] = "[protected]"
            secret_bindings = account.get("secret_bindings")
            if isinstance(secret_bindings, dict):
                account["secret_bindings"] = {
                    key: {
                        "secret_ref_id": str(value.get("secret_ref_id")),
                        "secret_kind": str(value.get("secret_kind")),
                        "storage_backend": str(value.get("storage_backend")),
                        "display_label": str(value.get("display_label")),
                    }
                    for key, value in secret_bindings.items()
                    if isinstance(value, dict)
                }

    return payload


def materialize_run_configuration_secrets(
    session: Session,
    *,
    engagement_id: uuid.UUID,
    configuration: dict[str, Any] | None,
    settings: Settings,
) -> tuple[dict[str, Any], list[SecretRef]]:
    payload = copy.deepcopy(configuration or {})
    access = payload.get("access")
    if not isinstance(access, dict):
        return payload, []

    accounts = access.get("accounts")
    if not isinstance(accounts, list):
        return payload, []

    created_refs: list[SecretRef] = []
    direct_storage_backend: str | None = None
    fallback_to_local = False
    for account in accounts:
        if not isinstance(account, dict):
            continue

        bindings: dict[str, dict[str, Any]] = {}
        label = str(account.get("label") or account.get("username") or "Account").strip() or "Account"

        for field_name, metadata in ACCOUNT_SECRET_FIELDS.items():
            raw_value = str(account.get(field_name) or "").strip()
            if not raw_value:
                account.pop(field_name, None)
                continue

            if field_name == "session_ref":
                needs_direct_storage = is_session_material(raw_value)
            else:
                needs_direct_storage = not is_explicit_reference(raw_value)

            if needs_direct_storage:
                if direct_storage_backend is None:
                    direct_storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
                storage_backend = direct_storage_backend
            else:
                storage_backend = "external_pointer"

            secret_ref_id = uuid.uuid4()
            secret_ref = SecretRef(
                id=secret_ref_id,
                engagement_id=engagement_id,
                vault_pointer=(
                    raw_value
                    if storage_backend == "external_pointer"
                    else f"aegispt://secret-ref/{secret_ref_id}"
                ),
                purpose=f"run.access.{metadata['binding_key']}",
                secret_kind=metadata["secret_kind"],
                storage_backend=storage_backend,
                display_label=secret_display_label(
                    raw_value,
                    secret_kind=metadata["secret_kind"],
                    storage_backend=storage_backend,
                ),
                encrypted_value=(
                    encrypt_secret_value(raw_value, settings, storage_backend=storage_backend)
                    if storage_backend in ENCRYPTED_SECRET_BACKENDS
                    else None
                ),
                metadata_json={
                    "account_label": label,
                    "raw_secret_material_exposed": False,
                    "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
                },
            )
            session.add(secret_ref)
            created_refs.append(secret_ref)
            bindings[metadata["binding_key"]] = public_secret_binding(secret_ref)
            account.pop(field_name, None)

        if bindings:
            account["secret_bindings"] = bindings

    if created_refs:
        access["secret_storage"] = {
            "mode": "indirected",
            "binding_count": len(created_refs),
            "storage_backends": sorted({secret_ref.storage_backend for secret_ref in created_refs}),
            "direct_secret_backend": direct_storage_backend or "not_used",
            "fallback_to_local_secret_key": fallback_to_local,
            "raw_secret_values_exposed": False,
        }

    return payload, created_refs


def load_secret_value(secret_ref: SecretRef, settings: Settings) -> str | None:
    if secret_ref.storage_backend not in ENCRYPTED_SECRET_BACKENDS or not secret_ref.encrypted_value:
        return None
    return decrypt_secret_value(secret_ref.encrypted_value, settings, storage_backend=secret_ref.storage_backend)
