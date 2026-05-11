#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import shutil
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TASK_PACKAGE = "codex/tasks/backlog-240-runner-tool-certification-matrix.json"
SUPPORTED_TOOLS_SOURCE = "workers/orchestration/tasks.py"
RUN_PROFILES_SOURCE = "api/app/services/run_profiles.py"
FINDINGS_SOURCE = "workers/orchestration/findings.py"
INVENTORY_SOURCE = "api/app/services/inventory.py"
SETTINGS_SOURCE = "api/app/services/settings.py"

STATUS_CERTIFIED = "certified"
STATUS_GAP = "supported-with-gap"
STATUS_BLOCKED = "blocked"

TOOL_GROUP_BY_RUNNER_TOOL = {
    "ai-shell": "ssh-client",
    "bloodhound-collect": "bloodhound",
    "content-discovery": "content-discovery",
    "credential-attacks": "hashcat",
    "crypto-audit": "crypto-audit",
    "httpx": "httpx",
    "impacket-lateral": "impacket",
    "metasploit": "metasploit",
    "netexec": "netexec",
    "network-capture": "network-capture",
    "nikto": "nikto",
    "nmap": "nmap",
    "nuclei": "nuclei",
    "responder": "responder",
    "semgrep": "semgrep",
    "snmp-enum": "snmp",
    "sqlmap": "sqlmap",
    "ssh-brute": "hydra",
    "wifi-survey": "wifi",
    "zap": "zap",
}

REQUIRED_BINARY_GROUPS = {
    "bloodhound": [["bloodhound-python"]],
    "content-discovery": [["ffuf"]],
    "crypto-audit": [["testssl.sh", "testssl"], ["ssh-audit"]],
    "hashcat": [["hashcat"]],
    "hydra": [["hydra"]],
    "httpx": [["httpx-toolkit", "httpx"]],
    "impacket": [
        ["secretsdump.py", "impacket-secretsdump"],
        ["psexec.py", "impacket-psexec"],
        ["wmiexec.py", "impacket-wmiexec"],
        ["GetUserSPNs.py"],
        ["GetNPUsers.py"],
    ],
    "metasploit": [["msfconsole"], ["msfrpcd"]],
    "netexec": [["nxc", "netexec", "crackmapexec"]],
    "network-capture": [["tcpdump"], ["arping"], ["arpspoof"]],
    "nikto": [["nikto"]],
    "nmap": [["nmap"]],
    "nuclei": [["nuclei"]],
    "responder": [["responder"]],
    "semgrep": [["semgrep"]],
    "snmp": [["snmpwalk"]],
    "sqlmap": [["sqlmap"]],
    "ssh-client": [["ssh"]],
    "wifi": [["iw"], ["airodump-ng"], ["aircrack-ng"]],
    "zap": [["zaproxy", "zap.sh", "zap-baseline.py"]],
}

ARTIFACT_NAMES_BY_TOOL = {
    "ai-shell": ["ai-shell-results.json"],
    "api-assessment": ["api-assessment-results.json", "api-assessment-inventory.json"],
    "auth-flow": ["auth-flow-results.json"],
    "aws-inventory": ["aws-inventory-results.json"],
    "biz-logic-probe": ["biz-logic-results.json"],
    "bloodhound-collect": [
        "bloodhound-results.json",
        "bloodhound-collection.zip",
        "bloodhound-session.log",
    ],
    "burp": ["burp-results.json"],
    "camera-test": ["camera-test-results.json"],
    "cicd-security": ["cicd-security-results.json", "cicd-security-inventory.json"],
    "client-state": ["client-state-results.json"],
    "cloud-native": ["cloud-native-results.json", "cloud-native-inventory.json"],
    "content-discovery": ["content-discovery-results.json"],
    "credential-attacks": ["credential-attack-results.json", "credential-attack-session.log"],
    "crypto-audit": ["crypto-audit-results.json"],
    "desktop-client": ["desktop-client-results.json", "desktop-client-inventory.json"],
    "deserialization-probe": ["deserialization-results.json"],
    "easm-discover": ["easm-results.json"],
    "external-infra": ["external-infra-results.json"],
    "external-osint": ["external-osint-results.json"],
    "graphql-probe": ["graphql-probe-results.json"],
    "headers-security": ["headers-security-results.json"],
    "http-smuggling": ["http-smuggling-results.json"],
    "httpx": ["httpx-results.jsonl"],
    "idor-bac": ["idor-bac-results.json"],
    "impacket-lateral": ["impacket-lateral-results.json", "impacket-lateral-session.log"],
    "iot-default-creds": ["iot-default-creds-results.json"],
    "ipv6-discovery": ["ipv6-discovery-results.json"],
    "jwt-probe": ["jwt-results.json"],
    "ldap-enum": ["ldap-enum-results.json"],
    "llm-probe": ["llm-probe-results.json"],
    "logging-probe": ["logging-probe-results.json"],
    "mdns-ssdp": ["mdns-ssdp-results.json"],
    "metasploit": ["metasploit-results.json", "metasploit-session.log"],
    "mobile-android": ["mobile-android-results.json", "mobile-android-inventory.json"],
    "network-capture": ["network-capture-results.json"],
    "network-segmentation": ["network-segmentation-results.json"],
    "nmap": ["nmap-results.xml"],
    "netexec": ["netexec-results.json", "netexec-session.log"],
    "nikto": ["nikto-results.json"],
    "nuclei": ["nuclei-results.jsonl"],
    "oauth-probe": ["oauth-probe-results.json"],
    "playwright-web": [
        "playwright-web-results.json",
        "playwright-web-network.jsonl",
        "playwright-web-console.jsonl",
        "playwright-web-dom.html",
        "playwright-web-screenshot.png",
    ],
    "priv-esc-linux": ["priv-esc-linux-results.json"],
    "responder": ["responder-results.json", "responder-session.log"],
    "semgrep": ["semgrep-results.json"],
    "session-security": ["session-security-results.json"],
    "smart-home": ["smart-home-results.json"],
    "snmp-enum": ["snmp-enum-results.json"],
    "sqlmap": ["sqlmap-results.json"],
    "ssh-brute": ["ssh-brute-results.json"],
    "ssrf-probe": ["ssrf-results.json"],
    "ssti-probe": ["ssti-probe-results.json"],
    "vuln-components": ["vuln-components-results.json"],
    "wifi-survey": ["wifi-survey-results.json"],
    "xss-extended": ["xss-extended-results.json"],
    "xxe-probe": ["xxe-results.json"],
    "zap": ["zap-results.json"],
}

RUNNER_MODULE_BY_TOOL = {
    "bloodhound-collect": "workers.runners.bloodhound.runner",
    "biz-logic-probe": "workers.runners.biz_logic.runner",
    "content-discovery": "workers.runners.web_depth.runner",
    "credential-attacks": "workers.runners.credential_attacks.runner",
    "crypto-audit": "workers.runners.crypto_audit.runner",
    "easm-discover": "workers.runners.easm.runner",
    "external-osint": "workers.runners.web_depth.runner",
    "idor-bac": "workers.runners.idor_bac.runner",
    "impacket-lateral": "workers.runners.impacket.runner",
    "iot-default-creds": "workers.runners.iot_default_creds.runner",
    "jwt-probe": "workers.runners.web_depth.runner",
    "llm-probe": "workers.runners.llm_probe",
    "mdns-ssdp": "workers.runners.mdns_ssdp.runner",
    "network-capture": "workers.runners.network_capture.runner",
    "priv-esc-linux": "workers.runners.priv_esc_linux.runner",
    "session-security": "workers.runners.session_security.runner",
    "snmp-enum": "workers.runners.snmp_enum.runner",
    "ssh-brute": "workers.runners.ssh_brute.runner",
    "ssrf-probe": "workers.runners.ssrf_probe.runner",
    "ssti-probe": "workers.runners.ssti_probe.runner",
    "vuln-components": "workers.runners.web_depth.runner",
    "xss-extended": "workers.runners.xss_extended.runner",
    "xxe-probe": "workers.runners.web_depth.runner",
}

HARDWARE_REQUIREMENTS = {
    "wifi-survey": {
        "required": True,
        "kind": "wireless_adapter",
        "blocker": "No deterministic hardware lab or monitor-mode adapter proof is recorded in this task.",
    }
}

SAFETY_GUARDRAILS = {
    "ai-shell": [
        "AI shell execution is SSH-only and requires an exact operator-reviewed command plus a credential reference.",
        "The runner blocks loopback/AegisPT host execution, banned destructive command patterns, and out-of-scope curl/wget URLs before execution.",
        "Runner output is capped at 8000 characters and every executed command records a command hash and output hash in audit metadata.",
    ],
    "credential-attacks": [
        "Spray and offline cracking modes remain approval-gated and bounded by lockout policy inputs.",
        "Plaintext credentials and captured secrets must remain encrypted or redacted outside evidence custody.",
    ],
    "metasploit": [
        "Only curated safe modules and bounded whoami/sysinfo proof are allowed through existing approval gates.",
        "No persistence, lateral expansion, or unmanaged sessions are certified here.",
    ],
    "responder": [
        "LLMNR/NBT-NS capture remains time-limited, CIDR-scoped, and intrusive approval-gated.",
        "This matrix does not authorize poisoning on live networks.",
    ],
    "network-capture": [
        "Passive capture is bounded by approved interface, host/CIDR filter, time, and packet count limits.",
        "Captured cleartext credential values are redacted from stored artifacts; ARP spoof proof remains fail-closed without explicit intrusive authorization.",
    ],
    "ssh-brute": [
        "Hydra execution is approval-gated, scoped to approved LAN service targets, capped at five attempts per second, and stopped after lockout signals.",
        "Only the built-in top-50 password tier plus explicitly configured bounded candidates are certified; large wordlists remain out of scope.",
    ],
    "wifi-survey": [
        "Passive wireless survey support does not enable deauth, rogue AP, WPS brute force, or RF jamming.",
        "Hardware proof remains separate from software installation readiness.",
    ],
}

REPO_EVIDENCE_PATTERNS = [
    "workers/tests",
    "api/tests",
    "scripts/tests",
]


@dataclass(frozen=True)
class ProfileUse:
    name: str
    run_class: str
    required_approvals: int
    approval_step_id: str | None


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _read_text(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8", errors="replace")


def _literal_set_from_assignment(relative_path: str, assignment_name: str) -> set[str]:
    tree = ast.parse(_read_text(relative_path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == assignment_name for target in node.targets
        ):
            continue
        value = ast.literal_eval(node.value)
        return {str(item) for item in value}
    raise RuntimeError(f"{assignment_name} not found in {relative_path}")


def _profile_node_value(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_profile_node_value(item) for item in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_profile_node_value(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        values: dict[str, Any] = {}
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                continue
            try:
                values[str(_profile_node_value(key))] = _profile_node_value(value)
            except ValueError:
                values[str(_profile_node_value(key))] = "<computed>"
        return values
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return "<computed>"
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "value"
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "RunClass"
    ):
        return node.value.attr.lower()
    raise ValueError(f"unsupported profile literal node: {ast.dump(node)}")


def _default_run_profiles() -> list[dict[str, Any]]:
    tree = ast.parse(_read_text(RUN_PROFILES_SOURCE))
    for node in tree.body:
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "DEFAULT_RUN_PROFILES"
            for target in node.targets
        ):
            value_node = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "DEFAULT_RUN_PROFILES"
        ):
            value_node = node.value
        if value_node is None:
            continue
        profiles = _profile_node_value(value_node)
        return [dict(profile) for profile in profiles]
    raise RuntimeError("DEFAULT_RUN_PROFILES not found")


def _profiles_by_tool() -> dict[str, list[ProfileUse]]:
    uses: dict[str, list[ProfileUse]] = defaultdict(list)
    for profile in _default_run_profiles():
        limits = profile.get("limits_json")
        if not isinstance(limits, dict):
            continue
        tools = limits.get("tools")
        if not isinstance(tools, list):
            continue
        run_class = str(profile.get("run_class") or "passive")
        required_approvals = int(
            limits.get("required_approvals")
            or (2 if run_class == "intrusive" else 1 if run_class == "active" else 0)
        )
        approval_step_id = limits.get("approval_step_id")
        for tool in tools:
            if isinstance(tool, str) and tool.strip():
                uses[tool.strip()].append(
                    ProfileUse(
                        name=str(profile.get("name") or "unnamed-profile"),
                        run_class=run_class,
                        required_approvals=required_approvals,
                        approval_step_id=str(approval_step_id) if approval_step_id else None,
                    )
                )
    return uses


def _evidence_paths_for_tool(tool: str, artifact_names: list[str]) -> dict[str, list[str]]:
    tokens = {
        tool,
        tool.replace("-", "_"),
        tool.replace("-", " "),
        *(artifact_names or []),
    }
    deterministic: list[str] = []
    for root in REPO_EVIDENCE_PATTERNS:
        for path in sorted((REPO_ROOT / root).rglob("*.py")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if any(token and token in text for token in tokens):
                deterministic.append(str(path.relative_to(REPO_ROOT)))

    result_evidence: list[str] = []
    result_root = REPO_ROOT / "codex" / "results"
    if result_root.exists():
        for path in sorted(result_root.glob("*")):
            if not path.is_file():
                continue
            if tool in path.name or tool.replace("-", "_") in path.name:
                result_evidence.append(str(path.relative_to(REPO_ROOT)))
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except UnicodeDecodeError:
                continue
            if any(token and token in text for token in tokens):
                result_evidence.append(str(path.relative_to(REPO_ROOT)))
    return {
        "deterministic_tests": sorted(dict.fromkeys(deterministic)),
        "fixture_or_lab_evidence": sorted(dict.fromkeys(result_evidence)),
    }


def _has_finding_mapping(tool: str) -> bool:
    text = _read_text(FINDINGS_SOURCE)
    return (
        f'task.tool == "{tool}"' in text
        or f'"{tool}"' in text
        and "extract_standard_json_findings" in text
    )


def _has_inventory_mapping(tool: str) -> bool:
    text = _read_text(INVENTORY_SOURCE)
    return f'"tool": "{tool}"' in text or "source_tools_json" in text and f"{tool}" in text


def _host_binary_state(binary_groups: list[list[str]]) -> dict[str, Any]:
    if not binary_groups:
        return {
            "state": "not-required",
            "required_binary_groups": [],
            "detected_paths": {},
            "missing_binary_groups": [],
        }
    detected_paths = {
        binary: path
        for group in binary_groups
        for binary in group
        if (path := shutil.which(binary))
    }
    missing = [
        group for group in binary_groups if not any(binary in detected_paths for binary in group)
    ]
    return {
        "state": "ready" if not missing else "missing",
        "required_binary_groups": binary_groups,
        "detected_paths": detected_paths,
        "missing_binary_groups": missing,
    }


def _runner_module_for(tool: str) -> str:
    if tool in RUNNER_MODULE_BY_TOOL:
        return RUNNER_MODULE_BY_TOOL[tool]
    return f"workers.runners.{tool.replace('-', '_')}.runner"


def _authorization_tier(profile_uses: list[ProfileUse]) -> dict[str, Any]:
    if not profile_uses:
        return {
            "run_classes": [],
            "max_required_approvals": None,
            "approval_step_ids": [],
            "status": "not-in-default-profile",
        }
    classes = sorted({use.run_class for use in profile_uses})
    return {
        "run_classes": classes,
        "max_required_approvals": max(use.required_approvals for use in profile_uses),
        "approval_step_ids": sorted(
            {use.approval_step_id for use in profile_uses if use.approval_step_id}
        ),
        "status": classes[-1] if classes else "unknown",
    }


def _guardrails(tool: str, profile_uses: list[ProfileUse], finding_mapping: bool) -> list[str]:
    items = [
        "Execution still goes through existing scope, ROE, approval, runtime binding, credential, and kill-switch gates.",
        "Certification records evidence only and does not dispatch tools or authorize live target actions.",
    ]
    if any(use.required_approvals for use in profile_uses):
        items.append(
            "Mapped default profiles require explicit approval before active or intrusive execution."
        )
    if finding_mapping:
        items.append(
            "Findings are only reportable after the existing normalized artifact parser accepts the expected artifact name."
        )
    else:
        items.append(
            "No normalized finding parser is claimed; output is treated as inventory/raw evidence unless another mapping is recorded."
        )
    items.extend(SAFETY_GUARDRAILS.get(tool, []))
    return items


def _status_for_entry(
    *,
    tool: str,
    deterministic_tests: list[str],
    artifact_names: list[str],
    finding_mapping: bool,
    inventory_mapping: bool,
    hardware: dict[str, Any],
) -> tuple[str, str]:
    if hardware.get("required") and hardware.get("blocker"):
        return STATUS_BLOCKED, str(hardware["blocker"])
    missing: list[str] = []
    if not deterministic_tests:
        missing.append("deterministic runner or dispatch test evidence")
    if not artifact_names:
        missing.append("declared output artifact contract")
    if not (finding_mapping or inventory_mapping):
        missing.append("finding, inventory, or report mapping proof")
    if missing:
        return STATUS_GAP, "Missing " + ", ".join(missing) + "."
    return (
        STATUS_CERTIFIED,
        "Deterministic evidence, output contract, and reportable mapping are present.",
    )


def build_matrix() -> dict[str, Any]:
    supported_tools = sorted(
        _literal_set_from_assignment(SUPPORTED_TOOLS_SOURCE, "SUPPORTED_TOOLS")
    )
    profiles_by_tool = _profiles_by_tool()
    tools: list[dict[str, Any]] = []
    for tool in supported_tools:
        artifact_names = ARTIFACT_NAMES_BY_TOOL.get(tool, [f"{tool}-results.json"])
        evidence = _evidence_paths_for_tool(tool, artifact_names)
        finding_mapping = _has_finding_mapping(tool)
        inventory_mapping = _has_inventory_mapping(tool)
        profile_uses = profiles_by_tool.get(tool, [])
        group_id = TOOL_GROUP_BY_RUNNER_TOOL.get(tool)
        binary_groups = REQUIRED_BINARY_GROUPS.get(group_id or "", [])
        software_state = _host_binary_state(binary_groups)
        hardware = {
            "required": False,
            "kind": None,
            "blocker": None,
            **HARDWARE_REQUIREMENTS.get(tool, {}),
        }
        certification_status, gap_reason = _status_for_entry(
            tool=tool,
            deterministic_tests=evidence["deterministic_tests"],
            artifact_names=artifact_names,
            finding_mapping=finding_mapping,
            inventory_mapping=inventory_mapping,
            hardware=hardware,
        )
        limitations = []
        if certification_status != STATUS_CERTIFIED:
            limitations.append(gap_reason)
        if software_state["state"] == "missing":
            limitations.append("Required host binaries were not fully detected on this build host.")
        if not profile_uses:
            limitations.append(
                "Runner is supported by the dispatcher but not mapped to a default run profile."
            )
        tools.append(
            {
                "id": tool,
                "title": tool.replace("-", " ").title(),
                "runner_module": _runner_module_for(tool),
                "default_run_profiles": [
                    {
                        "name": use.name,
                        "run_class": use.run_class,
                        "required_approvals": use.required_approvals,
                        "approval_step_id": use.approval_step_id,
                    }
                    for use in profile_uses
                ],
                "authorization_tier": _authorization_tier(profile_uses),
                "software_readiness": {
                    "settings_tool_group_id": group_id,
                    "software_installable": bool(group_id),
                    **software_state,
                },
                "hardware_readiness": hardware,
                "validation_evidence": evidence,
                "output_contract": {
                    "artifact_names": artifact_names,
                    "artifact_schema": "RunnerExecution artifacts with JSON/JSONL/XML contracts recorded by runner tests or parser mapping.",
                    "normalized_output_verified": bool(artifact_names),
                },
                "finding_mapping": {
                    "verified": finding_mapping,
                    "source": FINDINGS_SOURCE if finding_mapping else None,
                },
                "inventory_mapping": {
                    "verified": inventory_mapping,
                    "source": INVENTORY_SOURCE if inventory_mapping else None,
                },
                "report_mapping": {
                    "verified": bool(finding_mapping or inventory_mapping),
                    "source": "api/app/services/reports.py",
                    "note": "Reports consume stored findings, tasks, evidence artifacts, and inventory snapshots rather than raw runner output directly.",
                },
                "false_positive_guardrails": _guardrails(tool, profile_uses, finding_mapping),
                "limitations": limitations,
                "certification_status": certification_status,
                "gap_reason": gap_reason if certification_status != STATUS_CERTIFIED else None,
                "diagnostics_reference": {
                    "settings_capability_id": "runner_tool_certification",
                    "diagnostics_subsystem_id": "runner_tool_certification",
                },
                "release_readiness_reference": {
                    "claim_id": "runner_tool_readiness",
                    "matrix_path": "codex/results/runner-tool-certification-matrix.json",
                },
            }
        )

    status_counts = Counter(tool["certification_status"] for tool in tools)
    software_counts = Counter(tool["software_readiness"]["state"] for tool in tools)
    hardware_blockers = [tool["id"] for tool in tools if tool["hardware_readiness"].get("blocker")]
    non_hardware_blocked = [
        tool["id"]
        for tool in tools
        if tool["certification_status"] == STATUS_BLOCKED
        and not tool["hardware_readiness"].get("blocker")
    ]
    overall_status = (
        "blocked"
        if non_hardware_blocked
        else (
            "ready_with_hardware_limitation"
            if hardware_blockers
            else "supported-with-gap" if status_counts.get(STATUS_GAP, 0) else "ready"
        )
    )
    return {
        "kind": "aegispt.runner_tool_certification_matrix",
        "schema_version": 1,
        "generated_at": _now_iso(),
        "source_task": TASK_PACKAGE,
        "support_boundary": {
            "scope": "Evidence matrix only. It does not add runners, install tools, dispatch scans, approve actions, expand scope, or weaken runtime gates.",
            "live_target_actions": False,
            "runtime_mutation": False,
            "uncontrolled_plugin_installation": False,
        },
        "inputs": {
            "supported_tools": SUPPORTED_TOOLS_SOURCE,
            "run_profiles": RUN_PROFILES_SOURCE,
            "finding_mapping": FINDINGS_SOURCE,
            "inventory_mapping": INVENTORY_SOURCE,
            "settings_readiness": SETTINGS_SOURCE,
        },
        "summary": {
            "overall_status": overall_status,
            "tool_count": len(tools),
            "status_counts": dict(sorted(status_counts.items())),
            "software_ready_state_counts": dict(sorted(software_counts.items())),
            "hardware_blocker_tool_ids": hardware_blockers,
            "non_hardware_blocked_tool_ids": non_hardware_blocked,
            "certified_tool_count": status_counts.get(STATUS_CERTIFIED, 0),
            "supported_with_gap_tool_count": status_counts.get(STATUS_GAP, 0),
            "blocked_tool_count": status_counts.get(STATUS_BLOCKED, 0),
            "hardware_limited_tool_count": len(hardware_blockers),
        },
        "tools": tools,
    }


def render_markdown(matrix: dict[str, Any]) -> str:
    summary = matrix["summary"]
    lines = [
        "# Runner and Tool Certification Matrix",
        "",
        f"- Generated: `{matrix['generated_at']}`",
        f"- Source task: `{matrix['source_task']}`",
        f"- Tool count: `{summary['tool_count']}`",
        f"- Overall status: `{summary.get('overall_status', 'unknown')}`",
        f"- Certified: `{summary['certified_tool_count']}`",
        f"- Supported with gap: `{summary['supported_with_gap_tool_count']}`",
        f"- Blocked: `{summary['blocked_tool_count']}`",
        f"- Hardware-limited: `{summary.get('hardware_limited_tool_count', 0)}`",
        "",
        "This artifact is evidence-only. It does not dispatch tools, install software, grant approval, expand scope, or mutate runtime state.",
        "",
        "## Tool Matrix",
        "",
        "| Tool | Status | Software state | Auth tier | Evidence | Output/report mapping | Limitation |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for tool in matrix["tools"]:
        evidence_count = len(tool["validation_evidence"]["deterministic_tests"]) + len(
            tool["validation_evidence"]["fixture_or_lab_evidence"]
        )
        mapping = []
        if tool["finding_mapping"]["verified"]:
            mapping.append("finding")
        if tool["inventory_mapping"]["verified"]:
            mapping.append("inventory")
        mapping_text = ", ".join(mapping) if mapping else "gap"
        limitation = (
            "; ".join(tool["limitations"])
            if tool["limitations"]
            else "No recorded certification gap."
        )
        auth = tool["authorization_tier"]["status"]
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{tool['id']}`",
                    f"`{tool['certification_status']}`",
                    f"`{tool['software_readiness']['state']}`",
                    f"`{auth}`",
                    str(evidence_count),
                    mapping_text,
                    limitation.replace("|", "/"),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Hardware Blockers",
            "",
        ]
    )
    blockers = [tool for tool in matrix["tools"] if tool["hardware_readiness"].get("blocker")]
    if blockers:
        for tool in blockers:
            lines.append(f"- `{tool['id']}`: {tool['hardware_readiness']['blocker']}")
    else:
        lines.append("- No hardware-only blockers are recorded.")
    lines.append("")
    return "\n".join(lines)


def write_matrix(matrix: dict[str, Any], *, output_json: Path, output_md: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_md.write_text(render_markdown(matrix), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the AegisPT runner/tool certification matrix."
    )
    parser.add_argument(
        "--output-json",
        default=str(REPO_ROOT / "codex" / "results" / "runner-tool-certification-matrix.json"),
        help="Path for machine-readable certification matrix.",
    )
    parser.add_argument(
        "--output-md",
        default=str(REPO_ROOT / "codex" / "results" / "runner-tool-certification-matrix.md"),
        help="Path for human-readable certification matrix.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    matrix = build_matrix()
    write_matrix(matrix, output_json=Path(args.output_json), output_md=Path(args.output_md))


if __name__ == "__main__":
    main()
