from __future__ import annotations

import json
import re
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.nuclei.rce_catalog import (
    GENERIC_RCE_DETECTION_TEMPLATE,
    GENERIC_RCE_TEMPLATE_FILENAME,
    GENERIC_RCE_TEMPLATE_ID,
    RCE_SELECTION_TEMPLATE_ID,
    RCE_TEMPLATE_SOURCE,
    select_rce_template_ids,
    template_repository_status,
    template_roots,
)

DEFAULT_NUCLEI_TEMPLATE = """id: aegispt-http-status-200
info:
  name: AegisPT HTTP Status 200 Baseline
  author: aegispt
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
"""
CURATED_TEMPLATE_SOURCE = "aegispt-curated"
DEFAULT_TEMPLATE_ID = "aegispt-http-status-200"
DEFAULT_TEMPLATE_FILENAME = "aegispt-http-status-200.yaml"

INFRASTRUCTURE_NUCLEI_TEMPLATE = """id: aegispt-infrastructure-management-surfaces
info:
  name: AegisPT Infrastructure Management Surface Baseline
  author: aegispt
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "Remote Desktop"
          - "OpenSSH"
          - "VPN"
          - "Fortinet"
          - "Citrix"
          - "VMware"
      - type: word
        part: header
        words:
          - "Server"
"""
INFRASTRUCTURE_TEMPLATE_ID = "aegispt-infrastructure-management-surfaces"
INFRASTRUCTURE_TEMPLATE_FILENAME = "aegispt-infrastructure-management-surfaces.yaml"
INFRASTRUCTURE_TEMPLATE_SOURCE = "aegispt-curated-infrastructure"


def curated_nuclei_template_sha256(template_body: str = DEFAULT_NUCLEI_TEMPLATE) -> str:
    return sha256(template_body.encode("utf-8")).hexdigest()


def build_nuclei_command(
    binary: str,
    targets_file: Path,
    output_file: Path,
    template_file: Path | None = None,
    template_paths: list[Path | str] | None = None,
    rate_limit: int = 1,
    timeout_seconds: float = 10.0,
    template_ids: list[str] | None = None,
    disable_interactsh: bool = False,
    interactsh_server: str | None = None,
) -> list[str]:
    if not binary.strip():
        raise ValueError("binary must not be blank")
    if template_file is None and not template_ids and not template_paths:
        raise ValueError("template_file or template_ids must be provided")
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    command = [
        binary,
        "-duc",
        "-l",
        str(targets_file),
    ]
    if template_file is not None:
        command.extend(["-t", str(template_file)])
    for template_path in template_paths or []:
        command.extend(["-t", str(template_path)])
    command.extend(
        [
        "-jsonl",
        "-jsonl-export",
        str(output_file),
        "-rl",
        str(rate_limit),
        "-timeout",
        str(max(int(timeout_seconds), 1)),
        "-retries",
        "0",
        "-no-stdin",
        "-nc",
        ]
    )
    if template_ids:
        command.extend(["-id", ",".join(sorted({item for item in template_ids if item}))])
    if disable_interactsh:
        command.append("-no-interactsh")
    elif interactsh_server:
        command.extend(["-iserver", interactsh_server])
    return command


def run_template_update(
    *,
    binary: str,
    approved: bool,
    update_templates: bool,
    template_update_dir: str | None = None,
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    if not update_templates:
        return {"status": "skipped", "reason": "not_requested"}
    if not approved:
        return {"status": "blocked", "reason": "template_update_not_approved"}

    command = [binary, "-update-templates", "-duc"]
    if template_update_dir:
        command.extend(["-update-template-dir", template_update_dir])
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(float(timeout_seconds), 1.0),
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout",
            "command": _redacted_command(command),
            "timeout_seconds": timeout_seconds,
            "stdout": (exc.stdout or "")[:1000],
            "stderr": (exc.stderr or "")[:1000],
        }
    return {
        "status": "ok" if process.returncode == 0 else "failed",
        "exit_code": process.returncode,
        "command": _redacted_command(command),
        "stdout": (process.stdout or "")[:1000],
        "stderr": (process.stderr or "")[:1000],
    }


def get_nuclei_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    version_output = (result.stdout or result.stderr).strip()
    if not version_output:
        return "nuclei"

    cleaned_output = re.sub(r"\x1b\[[0-9;]*m", "", version_output)
    for line in cleaned_output.splitlines():
        if "Version:" in line:
            return line.split("Version:", maxsplit=1)[1].strip()

    first_line = cleaned_output.splitlines()[0].strip()
    return first_line or "nuclei"


def execute_nuclei_scan(
    targets: list[str],
    rate_limit: int = 1,
    timeout_seconds: float = 10.0,
    binary: str = "nuclei",
    template_body: str | None = DEFAULT_NUCLEI_TEMPLATE,
    template_id: str | None = DEFAULT_TEMPLATE_ID,
    template_source: str | None = CURATED_TEMPLATE_SOURCE,
    template_filename: str | None = DEFAULT_TEMPLATE_FILENAME,
    rce_template_selection: bool = False,
    service_evidence: list[dict[str, Any]] | None = None,
    inventory: dict[str, Any] | None = None,
    requested_template_ids: list[str] | None = None,
    oob_enabled: bool = False,
    interactsh_server: str | None = None,
    update_templates: bool = False,
    template_update_approved: bool = False,
    template_update_dir: str | None = None,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")

    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("targets must not be blank")

    with tempfile.TemporaryDirectory(prefix="aegispt-nuclei-") as temp_dir_name:
        plan: dict[str, Any] | None = None
        selected_template_ids: list[str] = []
        effective_template_body = template_body or DEFAULT_NUCLEI_TEMPLATE
        effective_template_id = template_id or DEFAULT_TEMPLATE_ID
        effective_template_source = template_source or CURATED_TEMPLATE_SOURCE
        effective_template_filename = template_filename or DEFAULT_TEMPLATE_FILENAME
        oob_status = {
            "enabled": bool(oob_enabled and str(interactsh_server or "").strip()),
            "mode": "self_hosted_interactsh" if oob_enabled and interactsh_server else "blocked",
            "reason": None
            if oob_enabled and interactsh_server
            else "interactsh_server_not_configured",
        }
        if rce_template_selection:
            plan = select_rce_template_ids(
                targets=normalized_targets,
                service_evidence=service_evidence,
                inventory=inventory,
                requested_template_ids=requested_template_ids,
                oob_enabled=bool(oob_status["enabled"]),
            )
            selected_template_ids = list(plan["selected_template_ids"])
            effective_template_body = GENERIC_RCE_DETECTION_TEMPLATE
            effective_template_id = RCE_SELECTION_TEMPLATE_ID
            effective_template_source = RCE_TEMPLATE_SOURCE
            effective_template_filename = GENERIC_RCE_TEMPLATE_FILENAME

        temp_dir = Path(temp_dir_name)
        targets_file = temp_dir / "targets.txt"
        template_file = temp_dir / effective_template_filename
        output_file = temp_dir / "nuclei-results.jsonl"

        targets_file.write_text("\n".join(normalized_targets) + "\n", encoding="utf-8")
        template_file.write_text(effective_template_body, encoding="utf-8")

        update_status = run_template_update(
            binary=binary,
            approved=template_update_approved,
            update_templates=update_templates,
            template_update_dir=template_update_dir,
            timeout_seconds=min(max(timeout_seconds, 30.0), 120.0),
        )
        repository_status = template_repository_status() if rce_template_selection else []
        blocked_template_ids = _blocked_template_ids(repository_status)
        blocked_selected_template_ids = [
            template_id for template_id in selected_template_ids if template_id in blocked_template_ids
        ]
        selected_template_ids = [
            template_id for template_id in selected_template_ids if template_id not in blocked_template_ids
        ]

        command = build_nuclei_command(
            binary=binary,
            targets_file=targets_file,
            output_file=output_file,
            template_file=template_file,
            template_paths=_existing_template_roots() if selected_template_ids else None,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            template_ids=(
                [GENERIC_RCE_TEMPLATE_ID, *selected_template_ids]
                if selected_template_ids
                else None
            ),
            disable_interactsh=bool(rce_template_selection and not oob_status["enabled"]),
            interactsh_server=interactsh_server if bool(oob_status["enabled"]) else None,
        )
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        artifact_data = output_file.read_bytes() if output_file.exists() else b""
        artifact = EvidenceArtifact(
            name="nuclei-results.jsonl",
            content_type="application/x-ndjson",
            data=artifact_data,
            kind="scan-results",
        )
        artifacts = [artifact]
        if plan is not None:
            plan_payload = {
                "schema": "aegispt.nuclei.rce_plan.v1",
                "rce_template_selection": True,
                "normalized_targets": normalized_targets,
                "template_update": update_status,
                "oob": oob_status,
                "template_repository_status": repository_status,
                "candidate_template_ids": plan["selected_template_ids"],
                "selected_template_ids": selected_template_ids,
                "blocked_template_ids": blocked_selected_template_ids,
                **plan,
            }
            plan_payload["candidate_template_ids"] = plan["selected_template_ids"]
            plan_payload["selected_template_ids"] = selected_template_ids
            plan_payload["blocked_template_ids"] = blocked_selected_template_ids
            artifacts.append(
                EvidenceArtifact(
                    name="nuclei-rce-plan.json",
                    content_type="application/json",
                    data=json.dumps(plan_payload, indent=2, sort_keys=True).encode("utf-8"),
                    kind="scan-plan",
                )
            )

        return RunnerExecution(
            tool="nuclei",
            exit_code=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            metadata={
                "status": "ok" if process.returncode == 0 else "failed",
                "normalized_targets": normalized_targets,
                "rate_limit": rate_limit,
                "timeout_seconds": timeout_seconds,
                "tool_version": get_nuclei_version(binary),
                "runner_digest": "workers.nuclei.runner:v1",
                "template_id": effective_template_id,
                "template_source": effective_template_source,
                "template_sha256": curated_nuclei_template_sha256(effective_template_body),
                "template_update_status": update_status,
                "rce_template_selection": rce_template_selection,
                "selected_template_ids": selected_template_ids,
                "oob_status": oob_status,
                "template_repository_status": repository_status,
            },
            artifacts=artifacts,
        )


def _redacted_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for item in command:
        if skip_next:
            skip_next = False
            continue
        if item == "-interactsh-token" or item == "-itoken":
            redacted.extend([item, "[REDACTED]"])
            skip_next = True
            continue
        redacted.append(item)
    return redacted


def _existing_template_roots() -> list[Path]:
    roots: list[Path] = []
    for root_value in template_roots():
        root = Path(root_value).expanduser()
        if root.exists():
            roots.append(root)
    return roots


def _blocked_template_ids(repository_status: list[dict[str, Any]]) -> set[str]:
    blocked: set[str] = set()
    for item in repository_status:
        template_id = str(item.get("template_id") or "").strip()
        safety = item.get("safety") if isinstance(item.get("safety"), dict) else {}
        if not template_id:
            continue
        if item.get("status") != "present" or safety.get("status") != "safe_detection_only":
            blocked.add(template_id)
    return blocked
