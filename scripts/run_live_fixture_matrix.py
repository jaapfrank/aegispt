#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from workers.orchestration.tasks import SUPPORTED_TOOLS  # noqa: E402

DEFAULT_OUTPUT = REPO_ROOT / "codex" / "results" / "live-fixture-matrix-latest.json"
DEFAULT_MARKDOWN = REPO_ROOT / "codex" / "results" / "live-fixture-matrix-latest.md"


@dataclass(frozen=True)
class FixtureDefinition:
    id: str
    title: str
    fixture_type: str
    image: str | None
    tools: tuple[str, ...]
    safest_next_step: str


FIXTURES: tuple[FixtureDefinition, ...] = (
    FixtureDefinition(
        id="webgoat-local",
        title="OWASP WebGoat local Docker fixture",
        fixture_type="docker",
        image="webgoat/webgoat:2023.8",
        tools=(
            "auth-flow",
            "client-state",
            "deserialization-probe",
            "idor-bac",
            "jwt-probe",
            "logging-probe",
            "oauth-probe",
            "session-security",
            "ssrf-probe",
            "vuln-components",
            "xxe-probe",
        ),
        safest_next_step="Pre-pull the approved WebGoat image locally, then run the matrix with collected runner evidence.",
    ),
    FixtureDefinition(
        id="dvwa-local",
        title="DVWA local Docker fixture",
        fixture_type="docker",
        image="vulnerables/web-dvwa:latest",
        tools=(
            "content-discovery",
            "headers-security",
            "http-smuggling",
            "nikto",
            "sqlmap",
            "ssti-probe",
            "xss-extended",
            "zap",
        ),
        safest_next_step="Pre-pull the approved DVWA image locally, then run the relevant web runner profiles.",
    ),
    FixtureDefinition(
        id="dvga-local",
        title="DVGA local GraphQL fixture",
        fixture_type="local_service",
        image=None,
        tools=("graphql-probe", "graphql-command-injection"),
        safest_next_step="Start the approved local DVGA service on 127.0.0.1:5013 and collect runner evidence.",
    ),
    FixtureDefinition(
        id="gruyere-local",
        title="Google Gruyere local Docker fixture",
        fixture_type="docker",
        image="karthequian/gruyere:latest",
        tools=("api-assessment", "playwright-web"),
        safest_next_step="Pre-pull the approved Gruyere image locally and run only loopback Gruyere scenarios.",
    ),
    FixtureDefinition(
        id="local-lan-fixture",
        title="Local LAN lab fixture",
        fixture_type="local_lab",
        image=None,
        tools=(
            "ai-shell",
            "bloodhound-collect",
            "credential-attacks",
            "easm-discover",
            "external-infra",
            "impacket-lateral",
            "iot-default-creds",
            "ldap-enum",
            "mdns-ssdp",
            "metasploit",
            "netexec",
            "network-capture",
            "network-segmentation",
            "nmap",
            "priv-esc-linux",
            "responder",
            "smart-home",
            "snmp-enum",
            "ssh-brute",
            "wifi-survey",
        ),
        safest_next_step="Attach an approved isolated LAN lab with explicit ROE and collect runner artifacts.",
    ),
    FixtureDefinition(
        id="imported-evidence-fixture",
        title="Imported evidence fixture",
        fixture_type="imported_evidence",
        image=None,
        tools=(
            "c2-ingest",
            "cicd-security",
            "cloud-native",
            "crypto-audit",
            "desktop-client",
            "external-osint",
            "leak-check",
            "malware-sim",
            "mobile-android",
            "semgrep",
            "waf-detect",
        ),
        safest_next_step="Provide approved local/imported evidence files and runner output artifacts for correlation.",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the AegisPT local live-fixture runner matrix.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="JSON output path.")
    parser.add_argument("--markdown", default=str(DEFAULT_MARKDOWN), help="Markdown output path.")
    parser.add_argument("--collected-results", help="Optional JSON file with collected local runner evidence.")
    return parser.parse_args()


def docker_image_available(image: str) -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "Docker CLI is not available on this host."
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        return True, "Docker image is present locally."
    return False, f"Docker image {image} is not present locally; remote pulls are not performed by this matrix."


def load_collected_results(path: str | Path | None) -> dict[str, dict[str, Any]]:
    if not path:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    items = payload.get("results") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise ValueError("collected results must be a list or an object with a results list")
    results: dict[str, dict[str, Any]] = {}
    for item in items:
        if isinstance(item, dict) and item.get("tool"):
            results[str(item["tool"])] = item
    return results


def fixture_for_tool(tool: str) -> FixtureDefinition:
    for fixture in FIXTURES:
        if tool in fixture.tools:
            return fixture
    return FixtureDefinition(
        id="unmapped-local-fixture",
        title="Unmapped local fixture",
        fixture_type="unmapped",
        image=None,
        tools=(tool,),
        safest_next_step="Map this runner family to an approved local fixture before claiming live coverage.",
    )


def verify_collected_result(tool: str, result: dict[str, Any]) -> tuple[str, list[str]]:
    artifacts = result.get("artifacts")
    findings = result.get("findings")
    failures: list[str] = []
    if not isinstance(artifacts, list) or not artifacts:
        failures.append("missing runner artifacts")
    if not isinstance(findings, list):
        failures.append("findings must be a list")
    else:
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                failures.append(f"finding {index} is not an object")
                continue
            if not str(finding.get("evidence_ref") or finding.get("evidence") or "").strip():
                failures.append(f"finding {index} has no evidence reference")
    return ("failed" if failures else "passed", failures)


def build_live_fixture_matrix(
    *,
    collected_results: dict[str, dict[str, Any]] | None = None,
    image_checker: Callable[[str], tuple[bool, str]] = docker_image_available,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    results = collected_results or {}
    generated = generated_at or datetime.now(tz=UTC)
    entries: list[dict[str, Any]] = []
    for tool in sorted(SUPPORTED_TOOLS):
        fixture = fixture_for_tool(tool)
        collected = results.get(tool)
        if collected is not None:
            status, failures = verify_collected_result(tool, collected)
            entries.append(
                {
                    "tool": tool,
                    "fixture_id": fixture.id,
                    "fixture_type": fixture.fixture_type,
                    "status": status,
                    "artifact_count": len(collected.get("artifacts") or []),
                    "finding_count": len(collected.get("findings") or []),
                    "failures": failures,
                    "evidence_source": "collected_local_runner_evidence",
                }
            )
            continue

        if fixture.fixture_type == "docker" and fixture.image:
            available, reason = image_checker(fixture.image)
            status = "ready_missing_collected_evidence" if available else "blocked_fixture_unavailable"
            entries.append(
                {
                    "tool": tool,
                    "fixture_id": fixture.id,
                    "fixture_type": fixture.fixture_type,
                    "status": status,
                    "blocker": None
                    if available
                    else {
                        "type": "docker_image_missing",
                        "reason": reason,
                        "safest_next_step": fixture.safest_next_step,
                    },
                    "evidence_source": None,
                }
            )
            continue

        entries.append(
            {
                "tool": tool,
                "fixture_id": fixture.id,
                "fixture_type": fixture.fixture_type,
                "status": "blocked_fixture_unavailable",
                "blocker": {
                    "type": f"{fixture.fixture_type}_fixture_required",
                    "reason": "No collected local runner evidence was supplied for this fixture family.",
                    "safest_next_step": fixture.safest_next_step,
                },
                "evidence_source": None,
            }
        )

    counts = {
        "tools": len(entries),
        "passed": sum(1 for item in entries if item["status"] == "passed"),
        "failed": sum(1 for item in entries if item["status"] == "failed"),
        "blocked": sum(1 for item in entries if str(item["status"]).startswith("blocked")),
        "ready_missing_collected_evidence": sum(
            1 for item in entries if item["status"] == "ready_missing_collected_evidence"
        ),
    }
    if counts["failed"]:
        status = "failed"
    elif counts["passed"] == counts["tools"]:
        status = "passed"
    else:
        status = "blocked"

    return {
        "kind": "aegispt.live_fixture_matrix",
        "generated_at": generated.isoformat(),
        "status": status,
        "summary": counts,
        "safety": {
            "local_fixtures_only": True,
            "external_live_infrastructure_touched": False,
            "docker_remote_pull_performed": False,
            "automatic_approval_performed": False,
            "scope_roe_bypass_performed": False,
            "credential_materialization_performed": False,
            "kill_switch_bypassed": False,
        },
        "fixtures": [
            {
                "id": fixture.id,
                "title": fixture.title,
                "fixture_type": fixture.fixture_type,
                "image": fixture.image,
                "tool_count": len(fixture.tools),
            }
            for fixture in FIXTURES
        ],
        "runner_families": entries,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Live Fixture Matrix",
        "",
        f"Status: `{report['status']}`",
        "",
        "This matrix is local-fixture only. Missing Docker images or local lab evidence are recorded as blocked, not passed.",
        "",
        "## Summary",
        "",
    ]
    for key, value in report["summary"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Runner Families", ""])
    for item in report["runner_families"]:
        lines.append(f"- `{item['tool']}` -> `{item['fixture_id']}`: `{item['status']}`")
        blocker = item.get("blocker")
        if isinstance(blocker, dict):
            lines.append(f"  - blocker: {blocker.get('reason')}")
    lines.append("")
    return "\n".join(lines)


def write_outputs(report: dict[str, Any], *, output: str | Path, markdown: str | Path) -> tuple[Path, Path]:
    output_path = Path(output)
    markdown_path = Path(markdown)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return output_path, markdown_path


def main() -> int:
    args = parse_args()
    report = build_live_fixture_matrix(collected_results=load_collected_results(args.collected_results))
    output_path, markdown_path = write_outputs(report, output=args.output, markdown=args.markdown)
    print(json.dumps({"status": report["status"], "output": str(output_path), "markdown": str(markdown_path)}, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
