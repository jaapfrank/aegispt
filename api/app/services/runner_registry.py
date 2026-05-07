from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


REQUIRED_CAPABILITY_FIELDS = {
    "name",
    "category",
    "risk_tier",
    "required_approvals",
    "estimated_minutes",
    "triggers",
    "blockers",
    "prerequisites",
    "expected_evidence",
    "follow_up_tools",
    "cost",
    "false_positive_rate",
    "description",
}


class RunnerRegistryError(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def runners_root() -> Path:
    return repo_root() / "workers" / "runners"


def registered_runner_tools() -> list[str]:
    tasks_path = repo_root() / "workers" / "orchestration" / "tasks.py"
    source = tasks_path.read_text(encoding="utf-8")
    tools = sorted(set(re.findall(r'request\.tool == "([^"]+)"', source)))
    if not tools:
        raise RunnerRegistryError("no registered runner tools could be discovered")
    return tools


def _capability_files(root: Path) -> list[Path]:
    files = [root / "capabilities.json"]
    files.extend(sorted(path for path in root.glob("*/capabilities.json") if path.is_file()))
    return [path for path in files if path.is_file()]


def _entries_from_file(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RunnerRegistryError(f"invalid capability metadata JSON in {path}") from exc
    if isinstance(payload, dict) and isinstance(payload.get("capabilities"), list):
        entries = payload["capabilities"]
    elif isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = [payload]
    else:
        raise RunnerRegistryError(f"unsupported capability metadata shape in {path}")
    normalized_entries: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RunnerRegistryError(f"non-object capability metadata entry in {path}")
        normalized_entries.append({**entry, "metadata_source": str(path.relative_to(repo_root()))})
    return normalized_entries


def _normalize_capability(entry: dict[str, Any]) -> dict[str, Any]:
    name = str(entry.get("name") or "").strip()
    if not name:
        raise RunnerRegistryError("capability metadata entry is missing name")
    missing = sorted(field for field in REQUIRED_CAPABILITY_FIELDS if field not in entry)
    if missing:
        raise RunnerRegistryError(f"capability metadata for {name} missing fields: {', '.join(missing)}")
    capability = dict(entry)
    for field in (
        "triggers",
        "weak_triggers",
        "blockers",
        "prerequisites",
        "expected_evidence",
        "follow_up_tools",
    ):
        value = capability.get(field, [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise RunnerRegistryError(f"capability metadata for {name} has invalid {field}")
        capability[field] = [str(item).strip() for item in value if str(item).strip()]
    try:
        capability["required_approvals"] = int(capability["required_approvals"])
        capability["estimated_minutes"] = int(capability["estimated_minutes"])
    except (TypeError, ValueError) as exc:
        raise RunnerRegistryError(f"capability metadata for {name} has invalid numeric fields") from exc
    return capability


def load_runner_capabilities(root: Path | None = None) -> list[dict[str, Any]]:
    metadata_root = root or runners_root()
    capabilities_by_name: dict[str, dict[str, Any]] = {}
    for path in _capability_files(metadata_root):
        for entry in _entries_from_file(path):
            capability = _normalize_capability(entry)
            name = capability["name"]
            if name in capabilities_by_name:
                raise RunnerRegistryError(f"duplicate runner capability metadata for {name}")
            capabilities_by_name[name] = capability
    return [capabilities_by_name[name] for name in sorted(capabilities_by_name)]


@lru_cache(maxsize=1)
def runner_capability_registry() -> dict[str, Any]:
    registered_tools = registered_runner_tools()
    capabilities = load_runner_capabilities()
    capability_names = {capability["name"] for capability in capabilities}
    registered_names = set(registered_tools)
    missing_tools = sorted(registered_names - capability_names)
    unexpected_tools = sorted(capability_names - registered_names)
    return {
        "metadata_version": "2026-05-07",
        "registered_runner_count": len(registered_tools),
        "capability_count": len(capabilities),
        "registered_tools": registered_tools,
        "missing_tools": missing_tools,
        "unexpected_tools": unexpected_tools,
        "complete": not missing_tools and not unexpected_tools,
        "capabilities": capabilities,
    }
