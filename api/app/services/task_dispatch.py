from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from uuid import UUID

from api.app.config import Settings


def supported_execution_tools() -> set[str]:
    from workers.orchestration.tasks import SUPPORTED_TOOLS

    return set(SUPPORTED_TOOLS)


def dispatch_task_execution(
    task_id: UUID | str,
    settings: Settings,
    *,
    background_tasks=None,
) -> str:
    from workers.orchestration.tasks import execute_task, process_task_by_id

    normalized_task_id = str(task_id)
    dispatch_mode = settings.task_dispatch_mode.strip().lower()

    if dispatch_mode == "manual":
        return dispatch_mode
    if dispatch_mode == "inline":
        if background_tasks is not None:
            background_tasks.add_task(process_task_by_id, normalized_task_id)
            return "inline-background"
        process_task_by_id(normalized_task_id)
        return dispatch_mode
    if dispatch_mode == "dramatiq":
        execute_task.send(normalized_task_id)
        return dispatch_mode

    raise ValueError(f"unsupported task dispatch mode: {settings.task_dispatch_mode}")


def _inline_task_worker_count(task_count: int, settings: Settings) -> int:
    if task_count <= 1:
        return 1
    try:
        configured = int(settings.inline_task_workers)
    except (TypeError, ValueError):
        configured = 4
    return max(1, min(task_count, configured))


def _process_inline_task_batch(task_ids: list[str], settings: Settings) -> list[dict[str, object]]:
    from workers.orchestration.tasks import process_task_by_id

    if not task_ids:
        return []
    if len(task_ids) == 1:
        return [process_task_by_id(task_ids[0])]

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=_inline_task_worker_count(len(task_ids), settings)) as executor:
        futures = [executor.submit(process_task_by_id, task_id) for task_id in task_ids]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def dispatch_task_batch(
    task_ids: Iterable[UUID | str],
    settings: Settings,
    *,
    background_tasks=None,
) -> str:
    normalized_task_ids = [str(task_id) for task_id in task_ids]
    if not normalized_task_ids:
        return "manual"

    dispatch_mode_name = settings.task_dispatch_mode.strip().lower()
    if dispatch_mode_name == "inline":
        if background_tasks is not None:
            background_tasks.add_task(_process_inline_task_batch, normalized_task_ids, settings)
            return "inline-background-parallel" if len(normalized_task_ids) > 1 else "inline"
        _process_inline_task_batch(normalized_task_ids, settings)
        return "inline"

    dispatch_mode = "manual"
    for task_id in normalized_task_ids:
        dispatch_mode = dispatch_task_execution(
            task_id,
            settings,
            background_tasks=background_tasks,
        )
    return dispatch_mode
