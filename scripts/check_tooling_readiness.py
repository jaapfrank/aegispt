#!/usr/bin/env python3
"""Deterministic tool-readiness gate for AegisPT.

Reports which scanning and testing tools are installed, configured, and
safe to run locally — without contacting live targets. Output is a
review-only JSON + Markdown artifact. No auto-fix, no live scanning.

Gate categories
---------------
active_gate     Required for release (CI blocks on failure).
diagnostic_gate Checked and reported; operator reviews output.
future_optional Planned addition; not yet wired or installed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "ui-v2"
DEFAULT_OUTPUT_JSON = REPO_ROOT / "codex" / "results" / "tooling-readiness-latest.json"
DEFAULT_OUTPUT_MD = REPO_ROOT / "codex" / "results" / "tooling-readiness-latest.md"

# Proxy vars that cause Semgrep to crash when set to empty strings.
_PROXY_VARS = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]


def _clean_env() -> dict[str, str]:
    env = os.environ.copy()
    for var in _PROXY_VARS:
        env.pop(var, None)
    return env


def _run(command: list[str], *, timeout: int = 30, cwd: Path | None = None, clean_proxy: bool = False) -> dict[str, Any]:
    env = _clean_env() if clean_proxy else None
    try:
        result = subprocess.run(
            command,
            cwd=cwd or REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "stderr": "command not found"}
    except subprocess.TimeoutExpired:
        return {"returncode": -2, "stdout": "", "stderr": "timeout"}


def _which(name: str) -> str | None:
    return shutil.which(name)


def check_playwright() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "playwright",
        "gate": "active_gate",
        "description": "React v2 E2E and accessibility tests",
    }
    installed = (UI_ROOT / "node_modules" / ".bin" / "playwright").exists()
    has_axe = (UI_ROOT / "node_modules" / "@axe-core" / "playwright").exists()
    if installed:
        entry["status"] = "installed"
        entry["note"] = f"axe-core/playwright: {'installed' if has_axe else 'not installed'}"
        entry["axe_available"] = has_axe
    else:
        entry["status"] = "missing"
        entry["blocker"] = "Run `cd ui-v2 && npm install` to restore Playwright."
    return entry


def check_zap() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "zap",
        "gate": "diagnostic_gate",
        "description": "OWASP ZAP passive/baseline DAST (local fixtures and daemon API only)",
    }
    path = _which("zap.sh") or _which("zap")
    if not path:
        entry["status"] = "missing"
        entry["note"] = "ZAP not on PATH. Install OWASP ZAP and expose zap.sh."
        return entry

    # Detect running daemon before version check — avoids home directory race.
    daemon_result = _run(["curl", "-sf", "http://localhost:8080/JSON/core/view/version/"], timeout=3)
    daemon_running = daemon_result["returncode"] == 0

    if daemon_running:
        entry["status"] = "running_daemon"
        entry["daemon_api"] = "http://localhost:8080"
        entry["note"] = (
            "Existing ZAP daemon detected on :8080. "
            "Use the daemon API for automation; do not start a second instance with the same home directory."
        )
    else:
        version_result = _run([path, "-version"], timeout=15)
        if version_result["returncode"] == 0:
            entry["status"] = "installed"
            entry["version"] = version_result["stdout"].splitlines()[0] if version_result["stdout"] else "unknown"
        else:
            entry["status"] = "installed_not_running"
            entry["note"] = "ZAP binary found but version check failed. Start the daemon or use -dir to isolate home."
    return entry


def check_semgrep() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "semgrep",
        "gate": "diagnostic_gate",
        "description": "SAST review gate (proxy vars stripped; no network rules)",
    }
    path = _which("semgrep")
    if not path:
        entry["status"] = "missing"
        entry["note"] = "Install via `pip install semgrep` or system package."
        return entry

    result = _run([path, "--version"], clean_proxy=True)
    if result["returncode"] == 0:
        entry["status"] = "installed"
        entry["version"] = result["stdout"].splitlines()[0] if result["stdout"] else "unknown"
        entry["note"] = "Run with proxy vars unset; network-dependent rulesets require internet access."
    else:
        entry["status"] = "installed_degraded"
        entry["blocker"] = result["stderr"] or "semgrep --version failed"
    return entry


def check_schemathesis() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "schemathesis",
        "gate": "future_optional",
        "description": "OpenAPI property-based fuzzing against local FastAPI (not yet installed)",
    }
    path = _which("schemathesis") or _which("st")
    if path:
        result = _run([path, "--version"])
        entry["status"] = "installed"
        entry["version"] = result["stdout"].splitlines()[0] if result["stdout"] else "unknown"
        entry["note"] = "Run: schemathesis run http://localhost:8000/openapi.json --base-url http://localhost:8000"
    else:
        entry["status"] = "missing"
        entry["note"] = "Install via `pip install schemathesis`. Target local FastAPI only: http://localhost:8000"
    return entry


def check_trivy() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "trivy",
        "gate": "future_optional",
        "description": "Container and dependency vulnerability scanning (review only)",
    }
    path = _which("trivy")
    if path:
        result = _run([path, "--version"])
        entry["status"] = "installed"
        entry["version"] = result["stdout"].splitlines()[0] if result["stdout"] else "unknown"
    else:
        entry["status"] = "missing"
        entry["note"] = "Install from https://aquasecurity.github.io/trivy/. Use `trivy fs --exit-code 0` for review-only output."
    return entry


def check_gitleaks() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "gitleaks",
        "gate": "future_optional",
        "description": "Git secret scanning (review-only, no auto-purge)",
    }
    path = _which("gitleaks")
    if path:
        result = _run([path, "version"])
        entry["status"] = "installed"
        entry["version"] = result["stdout"].splitlines()[0] if result["stdout"] else "unknown"
    else:
        entry["status"] = "missing"
        entry["note"] = "Install from https://github.com/zricethezav/gitleaks. Run: gitleaks detect --no-git --exit-code 0"
    return entry


def check_pip_audit() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "pip-audit",
        "gate": "future_optional",
        "description": "Python dependency vulnerability review (no auto-fix)",
    }
    path = _which("pip-audit")
    if path:
        result = _run([path, "--version"])
        entry["status"] = "installed"
        entry["version"] = result["stdout"].strip()
    else:
        entry["status"] = "missing"
        entry["note"] = "Install via `pip install pip-audit`. Run: pip-audit --no-fix -o json > codex/results/pip-audit.json"
    return entry


def check_npm_audit() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "npm-audit",
        "gate": "diagnostic_gate",
        "description": "npm dependency advisory scan (review only, no auto-fix)",
    }
    result = _run(["npm", "audit", "--audit-level=high", "--json"], cwd=UI_ROOT, timeout=60)
    if result["returncode"] == -1:
        entry["status"] = "missing"
        entry["note"] = "npm not found on PATH."
        return entry
    try:
        audit_data = json.loads(result["stdout"] or "{}")
        metadata = audit_data.get("metadata", {})
        vulnerabilities = metadata.get("vulnerabilities", {})
        entry["status"] = "completed"
        entry["high"] = vulnerabilities.get("high", 0)
        entry["critical"] = vulnerabilities.get("critical", 0)
        entry["moderate"] = vulnerabilities.get("moderate", 0)
        entry["gate_result"] = "pass" if (entry["high"] == 0 and entry["critical"] == 0) else "fail"
        if entry["gate_result"] == "pass" and entry["moderate"] > 0:
            entry["note"] = (
                f"{entry['moderate']} moderate advisory(ies) present. "
                "Vite/esbuild dev-server advisories require a breaking upgrade; "
                "tracked as planned future work — do not apply `npm audit fix --force` blindly."
            )
    except (json.JSONDecodeError, KeyError):
        entry["status"] = "completed_unstructured"
        entry["note"] = "Could not parse npm audit JSON output."
        entry["gate_result"] = "unknown"
    return entry


def check_lighthouse_ci() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": "lighthouse-ci",
        "gate": "future_optional",
        "description": "Operator-console performance and accessibility budgets",
    }
    path = _which("lhci")
    if path:
        result = _run([path, "--version"])
        entry["status"] = "installed"
        entry["version"] = result["stdout"].strip()
    else:
        entry["status"] = "missing"
        entry["note"] = "Install via `npm install -g @lhci/cli`. Target local dev server only: http://localhost:5173"
    return entry


def run_all() -> dict[str, Any]:
    checks = [
        check_playwright(),
        check_zap(),
        check_semgrep(),
        check_schemathesis(),
        check_trivy(),
        check_gitleaks(),
        check_pip_audit(),
        check_npm_audit(),
        check_lighthouse_ci(),
    ]

    active_gate_fail = [c for c in checks if c.get("gate") == "active_gate" and c.get("status") == "missing"]
    overall = "blocked" if active_gate_fail else "pass"

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "repo_root": str(REPO_ROOT),
        "overall": overall,
        "safety_boundaries": {
            "live_target_scan": False,
            "credential_materialization": False,
            "auto_fix_applied": False,
            "scope_mutation": False,
            "kill_switch_bypass": False,
        },
        "checks": checks,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# AegisPT Tooling Readiness Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Overall: **{report['overall'].upper()}**",
        "",
        "## Safety Boundaries",
        "",
        "- No live target scan performed",
        "- No credentials materialized",
        "- No auto-fix applied",
        "- No scope mutation",
        "- No kill-switch bypass",
        "",
        "## Tool Status",
        "",
        "| Tool | Gate | Status | Note |",
        "|------|------|--------|------|",
    ]
    for check in report["checks"]:
        status = check.get("status", "unknown")
        note = check.get("note", check.get("blocker", check.get("version", "")))
        lines.append(f"| {check['tool']} | {check['gate']} | {status} | {note} |")

    lines += [
        "",
        "## Gate Categories",
        "",
        "- **active_gate**: Required green for release. CI blocks on failure.",
        "- **diagnostic_gate**: Operator-reviewed output; does not block release.",
        "- **future_optional**: Planned addition; install when ready.",
        "",
        "## npm Audit Advisory Note",
        "",
        "Vite/esbuild dev-server moderate advisories are present. The suggested",
        "`npm audit fix --force` applies a breaking major Vite upgrade. This is",
        "tracked as planned future work and must not be applied blindly.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    report = run_all()

    DEFAULT_OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT_JSON.write_text(json.dumps(report, indent=2))
    DEFAULT_OUTPUT_MD.write_text(render_markdown(report))

    print(render_markdown(report))
    print(f"\nJSON: {DEFAULT_OUTPUT_JSON}")
    print(f"Markdown: {DEFAULT_OUTPUT_MD}")

    return 0 if report["overall"] != "blocked" else 1


if __name__ == "__main__":
    sys.exit(main())
