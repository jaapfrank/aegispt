from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from api.app.services.runs import target_value_is_allowed

AI_SHELL_TOOL_ID = "ai-shell"
AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS = 8000
AI_SHELL_MAX_COMMAND_CHARS = 4096
AI_SHELL_DEFAULT_PORT = 22
AI_SHELL_SUPPORTED_VIA = "ssh"

_BLOCKED_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "banned_rm_rf",
        re.compile(
            r"\brm\s+(?:-[^\s]*[rf][^\s]*[rf][^\s]*\s+|.*\s-[^\s]*[rf][^\s]*[rf][^\s]*\b)",
            re.IGNORECASE,
        ),
    ),
    ("banned_dd", re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?dd\b", re.IGNORECASE)),
    ("banned_mkfs", re.compile(r"\bmkfs(?:\.[A-Za-z0-9_-]+)?\b", re.IGNORECASE)),
    ("banned_shutdown", re.compile(r"\bshutdown\b", re.IGNORECASE)),
    ("banned_reboot", re.compile(r"\breboot\b", re.IGNORECASE)),
    ("banned_iptables_flush", re.compile(r"\biptables\s+.*(?:\s-F\b|--flush\b)", re.IGNORECASE)),
    ("banned_passwd", re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?passwd\b", re.IGNORECASE)),
    ("banned_useradd", re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?useradd\b", re.IGNORECASE)),
    ("banned_crontab_remove", re.compile(r"\bcrontab\s+.*(?:\s-r\b|--remove\b)", re.IGNORECASE)),
    (
        "banned_block_device_redirect",
        re.compile(r">\s*/dev/(?:sd[a-z]|vd[a-z]|xvd[a-z]|nvme\d+n\d+)\b", re.IGNORECASE),
    ),
)


class AiShellSafetyError(ValueError):
    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class AiShellContract:
    command: str
    via: str
    credentials_ref: str
    target: str
    username: str | None
    ssh_port: int
    output_cap_chars: int

    @property
    def command_sha256(self) -> str:
        return ai_shell_command_sha256(self.command)


def ai_shell_command_sha256(command: str) -> str:
    return hashlib.sha256(str(command or "").encode("utf-8")).hexdigest()


def normalize_ai_shell_params(
    *,
    params: dict[str, Any] | None,
    proposed_target: str,
    scope_allowlist: dict[str, Any] | None = None,
    allowed_target_entries: list[Any] | None = None,
    require_runtime_scope: bool = False,
) -> AiShellContract:
    payload = params if isinstance(params, dict) else {}
    command = str(payload.get("command") or "").strip()
    if not command:
        raise AiShellSafetyError(
            "ai-shell proposals must include an exact command", reason="missing_command"
        )
    if len(command) > AI_SHELL_MAX_COMMAND_CHARS:
        raise AiShellSafetyError(
            "ai-shell command exceeds the bounded command length", reason="command_too_long"
        )

    via = str(payload.get("via") or AI_SHELL_SUPPORTED_VIA).strip().lower()
    if via != AI_SHELL_SUPPORTED_VIA:
        raise AiShellSafetyError(
            "ai-shell only supports SSH execution", reason="unsupported_transport"
        )

    credentials_ref = str(payload.get("credentials_ref") or "").strip()
    if not credentials_ref:
        raise AiShellSafetyError(
            "ai-shell requires a credential reference", reason="missing_credentials_ref"
        )

    explicit_target = str(payload.get("target") or "").strip()
    normalized_proposed_target = str(proposed_target or "").strip()
    if (
        explicit_target
        and normalized_proposed_target
        and explicit_target != normalized_proposed_target
    ):
        raise AiShellSafetyError(
            "ai-shell command target must match the approved proposal target",
            reason="target_mismatch",
        )
    target = str(explicit_target or normalized_proposed_target).strip()
    if not target:
        raise AiShellSafetyError("ai-shell requires an approved target", reason="missing_target")
    host, port_from_target = _host_port(target)
    if not host:
        raise AiShellSafetyError("ai-shell target must resolve to a host", reason="invalid_target")
    if _is_local_host(host):
        raise AiShellSafetyError(
            "ai-shell may not execute on the AegisPT host or loopback targets",
            reason="local_target_blocked",
        )

    if require_runtime_scope and not target_value_is_allowed(scope_allowlist or {}, target):
        raise AiShellSafetyError(
            "ai-shell target is outside the approved engagement scope",
            reason="out_of_scope_target",
        )

    _assert_command_is_allowed(
        command,
        scope_allowlist=scope_allowlist,
        allowed_target_entries=allowed_target_entries,
    )

    ssh_port = _bounded_port(payload.get("ssh_port") or payload.get("port") or port_from_target)
    username = str(payload.get("username") or "").strip() or None
    output_cap_chars = _bounded_output_cap(payload.get("output_cap_chars"))
    return AiShellContract(
        command=command,
        via=via,
        credentials_ref=credentials_ref,
        target=target,
        username=username,
        ssh_port=ssh_port,
        output_cap_chars=output_cap_chars,
    )


def build_ai_shell_ssh_command(
    *,
    contract: AiShellContract,
    ssh_binary: str = "ssh",
) -> list[str]:
    host, _port = _host_port(contract.target)
    destination = f"{contract.username}@{host}" if contract.username else host
    return [
        ssh_binary,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-p",
        str(contract.ssh_port),
        destination,
        contract.command,
    ]


def ai_shell_command_preview(
    *,
    contract: AiShellContract,
    ssh_binary: str = "ssh",
) -> str:
    command = build_ai_shell_ssh_command(contract=contract, ssh_binary=ssh_binary)
    return "$ " + " ".join(shlex.quote(part) for part in command)


def _assert_command_is_allowed(
    command: str,
    *,
    scope_allowlist: dict[str, Any] | None,
    allowed_target_entries: list[Any] | None,
) -> None:
    normalized = _strip_shell_comments(command)
    for reason, pattern in _BLOCKED_COMMAND_PATTERNS:
        if pattern.search(normalized):
            raise AiShellSafetyError(
                "ai-shell command matches a banned command pattern",
                reason=reason,
            )
    for url in _download_urls(normalized):
        if not _url_is_in_scope(
            url,
            scope_allowlist=scope_allowlist,
            allowed_target_entries=allowed_target_entries,
        ):
            raise AiShellSafetyError(
                "ai-shell wget/curl URL is outside the approved scope",
                reason="out_of_scope_download_url",
            )


def _download_urls(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise AiShellSafetyError(
            "ai-shell command must be shell-parseable", reason="invalid_shell_syntax"
        ) from exc

    urls: list[str] = []
    previous_download_tool = False
    for token in tokens:
        lower = token.strip().lower()
        basename = lower.rsplit("/", 1)[-1]
        if basename in {"curl", "wget"}:
            previous_download_tool = True
            continue
        if lower.startswith(("http://", "https://")):
            urls.append(token)
            previous_download_tool = False
            continue
        if previous_download_tool and token.startswith("-"):
            continue
        if previous_download_tool:
            previous_download_tool = False
    return urls


def _url_is_in_scope(
    url: str,
    *,
    scope_allowlist: dict[str, Any] | None,
    allowed_target_entries: list[Any] | None,
) -> bool:
    parsed = urlparse(url)
    host = str(parsed.hostname or "").strip()
    candidates = [url]
    if host:
        candidates.append(host)
    if scope_allowlist:
        return any(target_value_is_allowed(scope_allowlist, candidate) for candidate in candidates)
    if allowed_target_entries:
        return any(
            _entry_allows_value(entry, candidate)
            for entry in allowed_target_entries
            for candidate in candidates
        )
    return False


def _entry_allows_value(entry: Any, candidate: str) -> bool:
    if not isinstance(entry, dict):
        return False
    allowed_value = str(entry.get("value") or "").strip()
    if not allowed_value:
        return False
    if candidate == allowed_value:
        return True
    candidate_host = _host_candidate(candidate)
    allowed_host = _host_candidate(allowed_value)
    if candidate_host and allowed_host:
        if candidate_host == allowed_host:
            return True
        if candidate_host.endswith(f".{allowed_host}"):
            return True
    try:
        candidate_ip = ipaddress.ip_address(candidate_host or candidate.split(":", 1)[0])
    except ValueError:
        return False
    try:
        return candidate_ip in ipaddress.ip_network(allowed_value, strict=False)
    except ValueError:
        return False


def _host_candidate(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return str(parsed.hostname or value.split(":", 1)[0]).strip().lower()


def _host_port(value: str) -> tuple[str, int | None]:
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = str(parsed.hostname or "").strip()
    if not host and "/" not in value:
        host = value.split(":", 1)[0].strip()
    try:
        port = parsed.port
    except ValueError:
        port = None
    return host, port


def _bounded_port(value: Any) -> int:
    try:
        port = int(value or AI_SHELL_DEFAULT_PORT)
    except (TypeError, ValueError):
        return AI_SHELL_DEFAULT_PORT
    return port if 0 < port <= 65535 else AI_SHELL_DEFAULT_PORT


def _bounded_output_cap(value: Any) -> int:
    try:
        cap = int(value or AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS)
    except (TypeError, ValueError):
        return AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS
    return min(max(cap, 1), AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS)


def _is_local_host(host: str) -> bool:
    normalized = str(host or "").strip().lower().rstrip(".")
    if normalized in {
        "localhost",
        "ip6-localhost",
        socket.gethostname().lower(),
        socket.getfqdn().lower(),
    }:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _strip_shell_comments(command: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in command.splitlines())
