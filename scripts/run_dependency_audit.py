#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "codex" / "results" / "dependency-audit-latest.json"


def _run(command: list[str], *, timeout: int = 120) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout",
            "command": command,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
        }

    return {
        "status": "completed" if completed.returncode == 0 else "completed_with_findings",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _parse_json_output(raw: str) -> Any | None:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _python_audit() -> dict[str, Any]:
    requirements = [
        str(path.relative_to(REPO_ROOT))
        for path in (REPO_ROOT / "requirements").glob("*.txt")
        if path.is_file()
    ]
    if not requirements:
        return {"status": "not_applicable", "reason": "no requirements/*.txt files found"}

    pip_audit = shutil.which("pip-audit")
    if pip_audit:
        command = [pip_audit]
        for requirement in requirements:
            command.extend(["-r", requirement])
        command.extend(["-f", "json"])
        result = _run(command)
        parsed = _parse_json_output(result["stdout"])
        dependencies = parsed.get("dependencies", []) if isinstance(parsed, dict) else []
        vulnerability_count = sum(
            len(item.get("vulns", []))
            for item in dependencies
            if isinstance(item, dict) and isinstance(item.get("vulns"), list)
        )
        return {
            "tool": "pip-audit",
            "requirements": requirements,
            "status": result["status"],
            "returncode": result["returncode"],
            "vulnerability_count": vulnerability_count,
            "parsed": parsed,
            "stderr": result["stderr"],
        }

    safety = shutil.which("safety")
    if safety:
        command = [safety, "check", "--json"]
        for requirement in requirements:
            command.extend(["-r", requirement])
        result = _run(command)
        parsed = _parse_json_output(result["stdout"])
        vulnerability_count = len(parsed) if isinstance(parsed, list) else None
        return {
            "tool": "safety",
            "requirements": requirements,
            "status": result["status"],
            "returncode": result["returncode"],
            "vulnerability_count": vulnerability_count,
            "parsed": parsed,
            "stderr": result["stderr"],
        }

    return {
        "status": "tool_unavailable",
        "requirements": requirements,
        "reason": "pip-audit and safety are not installed in this environment",
    }


def _frontend_audit() -> dict[str, Any]:
    package_lock = REPO_ROOT / "package-lock.json"
    package_json = REPO_ROOT / "package.json"
    if not package_lock.exists() and not package_json.exists():
        return {"status": "not_applicable", "reason": "no package.json/package-lock.json found"}
    npm = shutil.which("npm")
    if not npm:
        return {
            "status": "tool_unavailable",
            "reason": "npm is not installed in this environment",
        }
    if not package_lock.exists():
        return {
            "status": "not_applicable",
            "reason": "package.json exists but package-lock.json is absent",
        }

    result = _run([npm, "audit", "--json"], timeout=180)
    parsed = _parse_json_output(result["stdout"])
    metadata = parsed.get("metadata", {}) if isinstance(parsed, dict) else {}
    vulnerabilities = metadata.get("vulnerabilities", {}) if isinstance(metadata, dict) else {}
    return {
        "tool": "npm audit",
        "status": result["status"],
        "returncode": result["returncode"],
        "vulnerabilities": vulnerabilities,
        "parsed": parsed,
        "stderr": result["stderr"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local dependency audit probes for AegisPT.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "scope": "local dependency audit; no dependency installation performed",
        "python": _python_audit(),
        "frontend": _frontend_audit(),
    }

    output = args.output if args.output.is_absolute() else REPO_ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote dependency audit report to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
