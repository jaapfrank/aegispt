from __future__ import annotations

import os
from enum import StrEnum
from typing import Any


class RunClass(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


def default_run_class() -> RunClass:
    return RunClass.PASSIVE


def parse_run_class(value: str | RunClass | None) -> RunClass:
    if isinstance(value, RunClass):
        return value

    normalized = str(value or "").strip().lower()
    try:
        return RunClass(normalized)
    except ValueError:
        return default_run_class()


def default_required_approvals(run_class: str | RunClass | None) -> int:
    normalized = parse_run_class(run_class)
    if normalized == RunClass.ACTIVE:
        return 1
    if normalized == RunClass.INTRUSIVE:
        return 2
    return 0


def max_rps_cap(run_class: str | RunClass | None) -> int:
    normalized = parse_run_class(run_class)
    if normalized == RunClass.ACTIVE:
        return 2
    if normalized == RunClass.INTRUSIVE:
        return 1
    return 10


def max_concurrency_cap(run_class: str | RunClass | None) -> int:
    normalized = parse_run_class(run_class)
    if normalized == RunClass.ACTIVE:
        return 2
    if normalized == RunClass.INTRUSIVE:
        return 1
    return 5


def _normalize_positive_int(value: Any, *, default: int, maximum: int, minimum: int = 1) -> int:
    if not isinstance(value, int):
        return min(max(default, minimum), maximum)
    return min(max(value, minimum), maximum)


def normalize_profile_limits(run_class: str | RunClass | None, limits_json: dict[str, Any] | None) -> dict[str, Any]:
    normalized_run_class = parse_run_class(run_class)
    normalized_limits = dict(limits_json or {})

    normalized_limits["required_approvals"] = default_required_approvals(normalized_run_class)
    normalized_limits["max_rps"] = _normalize_positive_int(
        normalized_limits.get("max_rps"),
        default=max_rps_cap(normalized_run_class),
        maximum=max_rps_cap(normalized_run_class),
    )
    normalized_limits["max_concurrency"] = _normalize_positive_int(
        normalized_limits.get("max_concurrency"),
        default=max_concurrency_cap(normalized_run_class),
        maximum=max_concurrency_cap(normalized_run_class),
    )
    return normalized_limits


def execution_kill_switch_enabled(settings: object | None = None) -> bool:
    configured = getattr(settings, "execution_kill_switch", None)
    if isinstance(configured, bool):
        return configured
    if isinstance(configured, str):
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    return os.getenv("EXECUTION_KILL_SWITCH", "false").strip().lower() in {"1", "true", "yes", "on"}
