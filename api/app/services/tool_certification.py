from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CERTIFICATION_MATRIX_PATH = REPO_ROOT / "codex" / "results" / "runner-tool-certification-matrix.json"


def load_runner_tool_certification_matrix(path: Path | None = None) -> dict[str, Any]:
    matrix_path = path or DEFAULT_CERTIFICATION_MATRIX_PATH
    if not matrix_path.exists():
        return {
            "kind": "aegispt.runner_tool_certification_matrix",
            "schema_version": 1,
            "generated_at": None,
            "summary": {
                "tool_count": 0,
                "status_counts": {"missing": 1},
                "certified_tool_count": 0,
                "supported_with_gap_tool_count": 0,
                "blocked_tool_count": 0,
            },
            "tools": [],
            "missing": True,
            "path": str(matrix_path.relative_to(REPO_ROOT)),
        }
    try:
        payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "kind": "aegispt.runner_tool_certification_matrix",
            "schema_version": 1,
            "generated_at": None,
            "summary": {
                "tool_count": 0,
                "status_counts": {"parse-error": 1},
                "certified_tool_count": 0,
                "supported_with_gap_tool_count": 0,
                "blocked_tool_count": 0,
            },
            "tools": [],
            "parse_error": str(exc),
            "path": str(matrix_path.relative_to(REPO_ROOT)),
        }
    if not isinstance(payload, dict):
        return {
            "kind": "aegispt.runner_tool_certification_matrix",
            "schema_version": 1,
            "generated_at": None,
            "summary": {
                "tool_count": 0,
                "status_counts": {"invalid": 1},
                "certified_tool_count": 0,
                "supported_with_gap_tool_count": 0,
                "blocked_tool_count": 0,
            },
            "tools": [],
            "invalid_payload": True,
            "path": str(matrix_path.relative_to(REPO_ROOT)),
        }
    payload["path"] = str(matrix_path.relative_to(REPO_ROOT))
    return payload


def summarize_runner_tool_certification_matrix(path: Path | None = None) -> dict[str, Any]:
    matrix = load_runner_tool_certification_matrix(path)
    tools = matrix.get("tools") if isinstance(matrix.get("tools"), list) else []
    status_counts = Counter(str(tool.get("certification_status") or "unknown") for tool in tools if isinstance(tool, dict))
    if not status_counts:
        status_counts.update(matrix.get("summary", {}).get("status_counts", {}) or {})
    blocked = int(status_counts.get("blocked", 0))
    gaps = int(status_counts.get("supported-with-gap", 0))
    certified = int(status_counts.get("certified", 0))
    hardware_blockers = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        hardware = tool.get("hardware_readiness") if isinstance(tool.get("hardware_readiness"), dict) else {}
        if hardware.get("blocker"):
            hardware_blockers.append({"id": tool.get("id"), "blocker": hardware.get("blocker")})
    hardware_blocker_ids = {str(item.get("id")) for item in hardware_blockers}
    blocked_ids = {
        str(tool.get("id"))
        for tool in tools
        if isinstance(tool, dict) and str(tool.get("certification_status") or "") == "blocked"
    }
    blocked_only_by_hardware = bool(blocked_ids) and blocked_ids.issubset(hardware_blocker_ids)
    summary_status = str(matrix.get("summary", {}).get("overall_status") or "").strip()
    if matrix.get("missing") or matrix.get("parse_error") or matrix.get("invalid_payload"):
        readiness_status = "missing"
    elif summary_status:
        readiness_status = summary_status
    elif blocked_only_by_hardware:
        readiness_status = "ready_with_hardware_limitation"
    elif blocked:
        readiness_status = "blocked"
    elif gaps:
        readiness_status = "degraded"
    else:
        readiness_status = "ready"
    return {
        "path": matrix.get("path", str(DEFAULT_CERTIFICATION_MATRIX_PATH.relative_to(REPO_ROOT))),
        "generated_at": matrix.get("generated_at"),
        "readiness_status": readiness_status,
        "tool_count": len(tools),
        "certified_tool_count": certified,
        "supported_with_gap_tool_count": gaps,
        "blocked_tool_count": blocked,
        "status_counts": dict(sorted(status_counts.items())),
        "software_ready_state_counts": matrix.get("summary", {}).get("software_ready_state_counts", {}),
        "hardware_blockers": hardware_blockers,
        "hardware_limited_tool_count": len(hardware_blockers),
        "raw_matrix_available": not (matrix.get("missing") or matrix.get("parse_error") or matrix.get("invalid_payload")),
    }
