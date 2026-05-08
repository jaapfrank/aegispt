from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Run, SecretRef, Task
from api.app.services.audit import write_audit_event
from api.app.services.secrets import (
    direct_secret_storage_backend,
    encrypt_secret_value,
    public_secret_binding,
)
from workers.runners.base.contracts import ProtectedSecretMaterial

RUN_CREDENTIAL_VAULT_PURPOSE_PREFIX = "run.ephemeral_credential_vault"
RUN_CREDENTIAL_VAULT_VERSION = "run-credential-vault-v1"
RUN_CREDENTIAL_VAULT_TERMINAL_STATUSES = {
    "cancelled",
    "failed",
    "rejected",
}
RUN_CREDENTIAL_VAULT_INJECTION_TOOLS = {
    "api-assessment",
    "auth-flow",
    "biz-logic-probe",
    "client-state",
    "content-discovery",
    "idor-bac",
    "nuclei",
    "playwright-web",
    "session-security",
    "zap",
}
RUN_CREDENTIAL_VAULT_SECRET_BINDING_KEYS = {
    "api_key": "api_key",
    "bearer_token": "bearer_token",
    "password": "password",
    "session": "session",
}


def run_uses_ai_loop(run: Run) -> bool:
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    loop_config = configuration.get("ai_assessment_loop")
    return configuration.get("run_mode") == "ai_loop" or (
        isinstance(loop_config, dict) and loop_config.get("run_mode") == "ai_loop"
    )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _vault_metadata(secret_ref: SecretRef) -> dict[str, Any]:
    metadata = secret_ref.metadata_json if isinstance(secret_ref.metadata_json, dict) else {}
    return metadata if metadata.get("ephemeral_run_vault") is True else {}


def _vault_refs_for_run(session: Session, *, run: Run) -> list[SecretRef]:
    refs = session.scalars(
        select(SecretRef)
        .where(SecretRef.engagement_id == run.engagement_id)
        .order_by(SecretRef.created_at.asc(), SecretRef.id.asc())
    ).all()
    return [
        ref
        for ref in refs
        if (metadata := _vault_metadata(ref)) and metadata.get("run_id") == str(run.id)
    ]


def _binding_key_for_secret_kind(secret_kind: str) -> str | None:
    normalized = str(secret_kind or "").strip().lower().replace("-", "_")
    if normalized in {"cookie", "session_cookie", "session_token"}:
        return "session"
    if normalized in {"token", "access_token"}:
        return "bearer_token"
    return RUN_CREDENTIAL_VAULT_SECRET_BINDING_KEYS.get(normalized)


def _safe_display_label(*, secret_kind: str, label: str | None, source_tool: str | None) -> str:
    normalized_label = str(label or "").strip()
    if normalized_label:
        return normalized_label[:255]
    source = str(source_tool or "AI run").strip() or "AI run"
    return f"{secret_kind.replace('_', ' ')} from {source}"[:255]


def _secret_ref_payload(secret_ref: SecretRef) -> dict[str, Any]:
    metadata = _vault_metadata(secret_ref)
    return {
        "id": str(secret_ref.id),
        "secret_kind": secret_ref.secret_kind,
        "display_label": secret_ref.display_label or secret_ref.secret_kind,
        "storage_backend": secret_ref.storage_backend,
        "binding": public_secret_binding(secret_ref),
        "source": {
            "source_task_id": metadata.get("source_task_id"),
            "source_tool": metadata.get("source_tool"),
            "source_finding_id": metadata.get("source_finding_id"),
            "source_artifact_name": metadata.get("source_artifact_name"),
            "target": metadata.get("target"),
            "discovery_source": metadata.get("discovery_source"),
        },
        "username": metadata.get("username"),
        "raw_secret_material_exposed": False,
        "run_scoped": True,
        "ephemeral": True,
        "created_at": secret_ref.created_at.isoformat() if secret_ref.created_at else None,
    }


def run_credential_vault_payload(session: Session, *, run: Run) -> dict[str, Any]:
    entries = [_secret_ref_payload(secret_ref) for secret_ref in _vault_refs_for_run(session, run=run)]
    return {
        "available": run_uses_ai_loop(run),
        "run_id": str(run.id),
        "run_mode": "ai_loop" if run_uses_ai_loop(run) else "standard",
        "schema": RUN_CREDENTIAL_VAULT_VERSION,
        "entry_count": len(entries),
        "entries": entries,
        "ephemeral": True,
        "run_scoped": True,
        "cleared_on_run_terminal": True,
        "raw_secret_material_exposed": False,
    }


def store_run_credential_vault_secret(
    session: Session,
    *,
    run: Run,
    settings,
    secret_kind: str,
    value: str,
    label: str | None = None,
    source_task_id: str | None = None,
    source_finding_id: str | None = None,
    source_artifact_name: str | None = None,
    target: str | None = None,
    username: str | None = None,
    actor: str = "system:ai-loop",
    discovery_source: str = "operator_or_ai_store",
    source_tool: str | None = None,
) -> SecretRef:
    if not run_uses_ai_loop(run):
        raise ValueError("run credential vault is available only for ai_loop runs")
    normalized_secret_kind = str(secret_kind or "").strip().lower().replace("-", "_")
    if not _binding_key_for_secret_kind(normalized_secret_kind):
        raise ValueError(f"unsupported run credential vault secret kind: {secret_kind}")
    secret_value = str(value or "")
    if not secret_value.strip():
        raise ValueError("run credential vault secret value must not be blank")

    storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
    secret_ref_id = uuid.uuid4()
    secret_ref = SecretRef(
        id=secret_ref_id,
        engagement_id=run.engagement_id,
        vault_pointer=f"aegispt://secret-ref/{secret_ref_id}",
        purpose=f"{RUN_CREDENTIAL_VAULT_PURPOSE_PREFIX}.{normalized_secret_kind}",
        secret_kind=normalized_secret_kind,
        storage_backend=storage_backend,
        display_label=_safe_display_label(
            secret_kind=normalized_secret_kind,
            label=label,
            source_tool=source_tool,
        ),
        encrypted_value=encrypt_secret_value(
            secret_value,
            settings,
            storage_backend=storage_backend,
        ),
        metadata_json={
            "schema": RUN_CREDENTIAL_VAULT_VERSION,
            "ephemeral_run_vault": True,
            "run_id": str(run.id),
            "source_task_id": source_task_id,
            "source_finding_id": source_finding_id,
            "source_artifact_name": source_artifact_name,
            "source_tool": source_tool,
            "target": target,
            "username": username,
            "discovery_source": discovery_source,
            "binding_key": _binding_key_for_secret_kind(normalized_secret_kind),
            "stored_at": _now_iso(),
            "raw_secret_material_exposed": False,
            "run_scoped": True,
            "ephemeral": True,
            "cleared_on_run_terminal": True,
            "roe_boundary_enforced": True,
            "approval_gates_bypassed": False,
            "runner_registry_bypassed": False,
            "fallback_to_local_secret_key": (
                fallback_to_local if storage_backend == "encrypted_local" else False
            ),
        },
    )
    session.add(secret_ref)
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action="run_credential_vault.secret_stored",
        object_type="secret_ref",
        object_id=str(secret_ref.id),
        metadata={
            "run_id": str(run.id),
            "secret_kind": normalized_secret_kind,
            "source_task_id": source_task_id,
            "source_finding_id": source_finding_id,
            "source_tool": source_tool,
            "target": target,
            "raw_secret_material_exposed": False,
            "ephemeral": True,
        },
    )
    return secret_ref


def store_protected_outputs_in_run_credential_vault(
    session: Session,
    *,
    task: Task,
    protected_outputs: list[ProtectedSecretMaterial],
    settings,
) -> list[SecretRef]:
    if task.run is None or not run_uses_ai_loop(task.run):
        return []
    stored: list[SecretRef] = []
    for output in protected_outputs:
        secret_kind = str(output.secret_kind or "").strip().lower().replace("-", "_")
        if not _binding_key_for_secret_kind(secret_kind):
            continue
        metadata = output.metadata if isinstance(output.metadata, dict) else {}
        stored.append(
            store_run_credential_vault_secret(
                session,
                run=task.run,
                settings=settings,
                secret_kind=secret_kind,
                value=output.value,
                label=output.display_label,
                source_task_id=str(task.id),
                source_artifact_name=output.artifact_name,
                target=str(metadata.get("target") or task.target_id or "").strip() or None,
                username=str(metadata.get("username") or metadata.get("account_name") or "").strip()
                or None,
                actor=f"runner:{task.tool}",
                discovery_source="runner_protected_output",
                source_tool=task.tool,
            )
        )
    return stored


def _context_from_secret_ref(secret_ref: SecretRef) -> dict[str, Any] | None:
    metadata = _vault_metadata(secret_ref)
    binding_key = str(metadata.get("binding_key") or "").strip()
    if binding_key not in RUN_CREDENTIAL_VAULT_SECRET_BINDING_KEYS.values():
        return None
    username = str(metadata.get("username") or "").strip()
    context: dict[str, Any] = {
        "label": secret_ref.display_label or "Run credential vault entry",
        "role": "AI-vaulted credential",
        "source": "run_credential_vault",
        "secret_bindings": {binding_key: public_secret_binding(secret_ref)},
        "vault_entry": {
            "secret_ref_id": str(secret_ref.id),
            "secret_kind": secret_ref.secret_kind,
            "source_task_id": metadata.get("source_task_id"),
            "source_tool": metadata.get("source_tool"),
            "target": metadata.get("target"),
            "raw_secret_material_exposed": False,
            "run_scoped": True,
        },
    }
    if username:
        context["username"] = username
    return context


def vault_auth_contexts_for_task(session: Session, *, run: Run, tool: str) -> list[dict[str, Any]]:
    if not run_uses_ai_loop(run) or tool not in RUN_CREDENTIAL_VAULT_INJECTION_TOOLS:
        return []
    contexts: list[dict[str, Any]] = []
    for secret_ref in _vault_refs_for_run(session, run=run):
        context = _context_from_secret_ref(secret_ref)
        if context is not None:
            contexts.append(context)
    return contexts


def inject_run_credential_vault_into_task(
    session: Session,
    *,
    run: Run,
    task: Task,
    actor: str = "system:ai-loop",
) -> bool:
    contexts = vault_auth_contexts_for_task(session, run=run, tool=task.tool)
    if not contexts:
        return False
    params = dict(task.params_json or {})
    existing_contexts = [
        dict(item) for item in params.get("auth_contexts", []) if isinstance(item, dict)
    ]
    existing_vault_ids = {
        str((item.get("vault_entry") or {}).get("secret_ref_id"))
        for item in existing_contexts
        if isinstance(item.get("vault_entry"), dict)
    }
    new_contexts = [
        context
        for context in contexts
        if str(context["vault_entry"]["secret_ref_id"]) not in existing_vault_ids
    ]
    if not new_contexts:
        return False
    params["auth_contexts"] = [*existing_contexts, *new_contexts]
    params["credential_vault"] = {
        "schema": RUN_CREDENTIAL_VAULT_VERSION,
        "injected": True,
        "run_id": str(run.id),
        "entry_count": len(new_contexts),
        "secret_ref_ids": [context["vault_entry"]["secret_ref_id"] for context in new_contexts],
        "raw_secret_material_exposed": False,
        "run_scoped": True,
        "ephemeral": True,
        "cleared_on_run_terminal": True,
        "scope_enforced": True,
        "approval_gates_bypassed": False,
        "runner_registry_bypassed": False,
    }
    task.params_json = params
    write_audit_event(
        session=session,
        actor=actor,
        action="run_credential_vault.injected",
        object_type="task",
        object_id=str(task.id),
        metadata={
            "run_id": str(run.id),
            "tool": task.tool,
            "target": task.target_id,
            "entry_count": len(new_contexts),
            "secret_ref_ids": [context["vault_entry"]["secret_ref_id"] for context in new_contexts],
            "raw_secret_material_exposed": False,
        },
    )
    return True


def clear_run_credential_vault(
    session: Session,
    *,
    run: Run,
    actor: str,
    reason: str,
) -> int:
    refs = _vault_refs_for_run(session, run=run)
    if not refs:
        return 0
    deleted_ids = [str(secret_ref.id) for secret_ref in refs]
    for secret_ref in refs:
        session.delete(secret_ref)
    write_audit_event(
        session=session,
        actor=actor,
        action="run_credential_vault.cleared",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "reason": reason,
            "deleted_secret_ref_ids": deleted_ids,
            "entry_count": len(deleted_ids),
            "raw_secret_material_exposed": False,
        },
    )
    return len(deleted_ids)


def clear_run_credential_vault_if_terminal(
    session: Session,
    *,
    run: Run,
    actor: str,
    reason: str | None = None,
) -> int:
    status = str(run.status or "").strip().lower()
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    loop_state = (
        configuration.get("ai_assessment_loop")
        if isinstance(configuration.get("ai_assessment_loop"), dict)
        else {}
    )
    ai_loop_stopped = run_uses_ai_loop(run) and loop_state.get("status") == "stopped"
    should_clear = status in RUN_CREDENTIAL_VAULT_TERMINAL_STATUSES or (
        status in {"completed", "completed_with_errors"} and ai_loop_stopped
    )
    if not should_clear:
        return 0
    return clear_run_credential_vault(
        session,
        run=run,
        actor=actor,
        reason=reason or f"run_status_{status}",
    )
