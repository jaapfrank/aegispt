#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TASK_QUEUE_PATH = REPO_ROOT / "TASK_QUEUE.md"
NEXT_TASK_PATH = REPO_ROOT / "NEXT_TASK.md"
TASKS_DIR = REPO_ROOT / "codex" / "tasks"

QUEUE_ITEM_RE = re.compile(r"^(\d+)\.\s+(.*)$")
TASK_FILE_RE = re.compile(r"`(codex/tasks/backlog-[^`]+\.json)`")

REQUIRED_TOP_LEVEL_FIELDS = [
    "id",
    "task_file",
    "task_type",
    "title",
    "goal",
    "scope",
    "status",
    "generated_by",
    "generation_reason",
    "source_context",
    "inputs",
    "constraints",
    "success_criteria",
    "likely_touched_files",
    "must_not_touch",
    "validation",
    "promotion_requirements",
    "out_of_scope",
    "expected_output",
    "validation_status",
    "approval_status",
]

REQUIRED_SOURCE_CONTEXT_FIELDS = [
    "queue_index",
    "queue_file",
    "pack_id",
    "pack_version",
    "inventory_snapshot_id",
    "relevance_decision_id",
    "threat_intel_refs",
]

REQUIRED_CONSTRAINT_FIELDS = [
    "active_task_gate",
    "no_silent_reprioritization",
    "no_untracked_future_work",
    "scope_creep_guard",
]

REQUIRED_VALIDATION_FIELDS = [
    "required_checks",
    "acceptance_criteria",
]

REQUIRED_PROMOTION_FIELDS = [
    "before_promotion",
    "after_completion",
]


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_json(path: Path) -> dict:
    return json.loads(_load_text(path))


def _validate_next_task(errors: list[str]) -> None:
    content = _load_text(NEXT_TASK_PATH)
    if content.count("# Active Task") != 1:
        errors.append("NEXT_TASK.md must contain exactly one '# Active Task' heading.")
    if content.count("## Title") != 1:
        errors.append("NEXT_TASK.md must contain exactly one '## Title' section.")
    if content.count("## Goal") != 1:
        errors.append("NEXT_TASK.md must contain exactly one '## Goal' section.")


def _parse_queue_items(errors: list[str]) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    for raw_line in _load_text(TASK_QUEUE_PATH).splitlines():
        match = QUEUE_ITEM_RE.match(raw_line)
        if not match:
            continue
        index = int(match.group(1))
        task_files = TASK_FILE_RE.findall(match.group(2))
        if len(task_files) != 1:
            errors.append(
                f"TASK_QUEUE.md item {index} must reference exactly one backlog task file in backticks."
            )
            continue
        items.append((index, task_files[0]))

    if not items:
        errors.append("TASK_QUEUE.md does not contain any numbered backlog items.")
        return items

    expected_indexes = list(range(1, len(items) + 1))
    actual_indexes = [index for index, _ in items]
    if actual_indexes != expected_indexes:
        errors.append(
            f"TASK_QUEUE.md items must be numbered sequentially from 1. Found {actual_indexes}."
        )
    return items


def _ensure_non_empty_list(payload: dict, field_name: str, errors: list[str], task_file: str) -> None:
    value = payload.get(field_name)
    if not isinstance(value, list) or not value or not all(str(item).strip() for item in value):
        errors.append(f"{task_file} field '{field_name}' must be a non-empty list.")


def _validate_task_package(index: int, task_file: str, errors: list[str]) -> None:
    path = REPO_ROOT / task_file
    if not path.exists():
        errors.append(f"Queued task file does not exist: {task_file}")
        return

    payload = _load_json(path)
    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in payload:
            errors.append(f"{task_file} is missing required field '{field}'.")

    if errors and any(f"{task_file} is missing" in message for message in errors):
        return

    if payload.get("task_file") != task_file:
        errors.append(f"{task_file} must set task_file to '{task_file}'.")
    if payload.get("status") != "queued":
        errors.append(f"{task_file} must remain in status 'queued' until promoted.")

    source_context = payload.get("source_context", {})
    for field in REQUIRED_SOURCE_CONTEXT_FIELDS:
        if field not in source_context:
            errors.append(f"{task_file} source_context is missing '{field}'.")
    if source_context.get("queue_index") != index:
        errors.append(f"{task_file} source_context.queue_index must equal queue item {index}.")
    if source_context.get("queue_file") != "TASK_QUEUE.md":
        errors.append(f"{task_file} source_context.queue_file must be 'TASK_QUEUE.md'.")

    inputs = payload.get("inputs", {})
    if inputs.get("prerequisite_active_task") != "NEXT_TASK.md":
        errors.append(f"{task_file} must declare NEXT_TASK.md as its prerequisite_active_task.")

    constraints = payload.get("constraints", {})
    for field in REQUIRED_CONSTRAINT_FIELDS:
        if field not in constraints:
            errors.append(f"{task_file} constraints are missing '{field}'.")
    if constraints.get("no_silent_reprioritization") is not True:
        errors.append(f"{task_file} must set constraints.no_silent_reprioritization to true.")
    if constraints.get("no_untracked_future_work") is not True:
        errors.append(f"{task_file} must set constraints.no_untracked_future_work to true.")

    _ensure_non_empty_list(payload, "success_criteria", errors, task_file)
    _ensure_non_empty_list(payload, "likely_touched_files", errors, task_file)
    _ensure_non_empty_list(payload, "must_not_touch", errors, task_file)
    _ensure_non_empty_list(payload, "out_of_scope", errors, task_file)

    validation = payload.get("validation", {})
    for field in REQUIRED_VALIDATION_FIELDS:
        if field not in validation:
            errors.append(f"{task_file} validation is missing '{field}'.")
    if isinstance(validation.get("required_checks"), list):
        checks_joined = " ".join(str(item) for item in validation.get("required_checks", []))
        if "scripts/validate_backlog_tasks.py" not in checks_joined:
            errors.append(
                f"{task_file} validation.required_checks must include scripts/validate_backlog_tasks.py."
            )

    promotion = payload.get("promotion_requirements", {})
    for field in REQUIRED_PROMOTION_FIELDS:
        if field not in promotion:
            errors.append(f"{task_file} promotion_requirements are missing '{field}'.")
    for field in REQUIRED_PROMOTION_FIELDS:
        value = promotion.get(field)
        if not isinstance(value, list) or not value:
            errors.append(f"{task_file} promotion_requirements.{field} must be a non-empty list.")

    after_completion = promotion.get("after_completion", [])
    if isinstance(after_completion, list):
        joined = " ".join(str(item) for item in after_completion)
        for required_ref in ("DONE_LOG.md", "CURRENT_STATE.md", "NEXT_TASK.md"):
            if required_ref not in joined:
                errors.append(
                    f"{task_file} promotion_requirements.after_completion must reference {required_ref}."
                )


def main() -> int:
    errors: list[str] = []
    _validate_next_task(errors)
    queue_items = _parse_queue_items(errors)

    queued_paths = [task_file for _, task_file in queue_items]
    if len(set(queued_paths)) != len(queued_paths):
        errors.append("TASK_QUEUE.md must not reference the same backlog task package more than once.")

    discovered_backlog_files = sorted(
        str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        for path in TASKS_DIR.glob("backlog-*.json")
    )

    missing_from_queue = sorted(set(discovered_backlog_files) - set(queued_paths))
    missing_from_tasks_dir = sorted(set(queued_paths) - set(discovered_backlog_files))
    if missing_from_queue:
        errors.append(
            "Backlog task files exist without a TASK_QUEUE.md entry: " + ", ".join(missing_from_queue)
        )
    if missing_from_tasks_dir:
        errors.append(
            "TASK_QUEUE.md references backlog task files that are missing from codex/tasks/: "
            + ", ".join(missing_from_tasks_dir)
        )

    for index, task_file in queue_items:
        _validate_task_package(index, task_file, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print(
        "Backlog validation passed: "
        f"{len(queue_items)} queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
