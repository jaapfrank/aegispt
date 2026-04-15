from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from api.app.models import CapabilityPack
from api.app.schemas.codex import (
    CodexTaskCreate,
    CodexTaskRead,
    CodexTaskResultRead,
    CodexTaskRunCreate,
)
from api.app.services.codex_lane import build_codex_context


def repo_root() -> Path:
    override = os.getenv("AEGISPT_CODEX_REPO_ROOT")
    if override:
        return Path(override).resolve()
    return Path(__file__).resolve().parents[3]


def tasks_dir() -> Path:
    path = repo_root() / "codex" / "tasks"
    path.mkdir(parents=True, exist_ok=True)
    return path


def results_dir() -> Path:
    path = repo_root() / "codex" / "results"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return normalized.strip("-") or "codex-task"


def _task_path(task_id: str) -> Path:
    return tasks_dir() / f"{task_id}.json"


def _result_path(task_id: str) -> Path:
    return results_dir() / f"{task_id}.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_codex_task(
    payload: CodexTaskCreate,
    *,
    requested_by: str,
    pack: CapabilityPack | None = None,
) -> CodexTaskRead:
    timestamp = datetime.now(tz=UTC)
    task_id = f"task-{timestamp.strftime('%Y%m%d%H%M%S')}-{_slugify(payload.task_type)}-{uuid4().hex[:8]}"
    source_context = payload.source_context.model_copy()
    if pack is not None:
        source_context.pack_id = pack.id
        source_context.pack_version = pack.version

    task = CodexTaskRead(
        id=task_id,
        task_type=payload.task_type,
        scope=payload.scope,
        inputs=payload.inputs,
        constraints=payload.constraints,
        expected_output=payload.expected_output,
        generated_by="codex",
        requested_by=requested_by,
        generation_reason=payload.generation_reason,
        source_context=source_context,
        validation_status="not_run",
        approval_status="not_requested",
        status="created",
        created_at=timestamp,
        updated_at=timestamp,
        task_file=str(_task_path(task_id).relative_to(repo_root())),
    )
    _write_json(_task_path(task.id), task.model_dump(mode="json"))
    return task


def load_codex_task(task_id: str) -> CodexTaskRead | None:
    path = _task_path(task_id)
    if not path.exists():
        return None
    return CodexTaskRead.model_validate(_load_json(path))


def list_codex_tasks() -> list[CodexTaskRead]:
    items: list[CodexTaskRead] = []
    for path in sorted(tasks_dir().glob("*.json")):
        items.append(CodexTaskRead.model_validate(_load_json(path)))
    return sorted(items, key=lambda item: (item.updated_at, item.created_at, item.id), reverse=True)


def load_codex_task_result(task_id: str) -> CodexTaskResultRead | None:
    path = _result_path(task_id)
    if not path.exists():
        return None
    return CodexTaskResultRead.model_validate(_load_json(path))


def _persist_task(task: CodexTaskRead) -> CodexTaskRead:
    task.updated_at = datetime.now(tz=UTC)
    _write_json(_task_path(task.id), task.model_dump(mode="json"))
    return task


def run_codex_task(
    task: CodexTaskRead,
    *,
    run_request: CodexTaskRunCreate,
    pack: CapabilityPack | None = None,
) -> CodexTaskResultRead:
    commands = [
        "Read AGENTS.md",
        "Read CURRENT_STATE.md",
        "Read NEXT_TASK.md",
        "Read DECISIONS.md",
    ]
    output_files = [
        "DONE_LOG.md",
        "CURRENT_STATE.md",
    ]
    validation_hooks = []
    summary_parts = [
        f"Prepared {task.task_type} task in the Codex build lane.",
        "No live runtime mutation is allowed from this task interface.",
    ]

    if pack is not None:
        context = build_codex_context(pack)
        validation_hooks = context.validation_hooks
        base_url = run_request.base_url or "<base_url>"
        workspace_root = run_request.workspace_root or f"./{context.repo_conventions.workspace_root}"
        commands.extend(
            [
                f"bash scripts/export_codex_pack_workspace.sh {base_url} {pack.id} {workspace_root}",
                f"bash scripts/validate_codex_pack.sh {base_url} {pack.id}",
            ]
        )
        output_files.extend(
            [
                f"{workspace_root}/codex-review-bundle.json",
                f"{workspace_root}/codex-context.json",
                f"{workspace_root}/operator-notes.md",
                f"{workspace_root}/codex-change-summary.md",
            ]
        )
        summary_parts.append(f"Task is linked to capability pack {pack.name} {pack.version}.")

    commands.extend(
        [
            "Append completed work to DONE_LOG.md",
            "Refresh CURRENT_STATE.md after finishing the task",
        ]
    )

    result = CodexTaskResultRead(
        task_id=task.id,
        status="prepared",
        summary=" ".join(summary_parts),
        dry_run=run_request.dry_run,
        prepared_commands=commands,
        output_files=output_files,
        guardrails=[
            "Treat Prompt 1 and Prompt 2 as authoritative.",
            "Do not self-modify the active assessment runtime.",
            "Do not bypass validation, approval, deployment, or runtime binding.",
            "Keep repository files as the source of truth for future Codex runs.",
            "Prefer additive changes and reuse existing pack, provenance, and methodology structures.",
        ],
        validation_hooks=validation_hooks,
        result_file=str(_result_path(task.id).relative_to(repo_root())),
        created_at=datetime.now(tz=UTC),
    )
    _write_json(_result_path(task.id), result.model_dump(mode="json"))

    task.status = "prepared"
    task.validation_status = "ready_for_existing_pipeline" if pack is not None else task.validation_status
    _persist_task(task)
    return result
