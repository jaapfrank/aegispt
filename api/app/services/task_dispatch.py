from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from api.app.config import Settings


def supported_execution_tools() -> set[str]:
    from workers.orchestration.tasks import SUPPORTED_TOOLS

    return set(SUPPORTED_TOOLS)


def dispatch_task_execution(task_id: UUID | str, settings: Settings) -> str:
    from workers.orchestration.tasks import execute_task, process_task_by_id

    normalized_task_id = str(task_id)
    dispatch_mode = settings.task_dispatch_mode.strip().lower()

    if dispatch_mode == "manual":
        return dispatch_mode
    if dispatch_mode == "inline":
        process_task_by_id(normalized_task_id)
        return dispatch_mode
    if dispatch_mode == "dramatiq":
        execute_task.send(normalized_task_id)
        return dispatch_mode

    raise ValueError(f"unsupported task dispatch mode: {settings.task_dispatch_mode}")


def dispatch_task_batch(task_ids: Iterable[UUID | str], settings: Settings) -> str:
    dispatch_mode = "manual"
    for task_id in task_ids:
        dispatch_mode = dispatch_task_execution(task_id, settings)
    return dispatch_mode
