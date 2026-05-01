from __future__ import annotations

from typing import Any

from workers.runners.impacket.secretsdump import EMPTY_LM_HASH

BOUNDED_REMOTE_COMMAND = "cmd.exe /Q /c whoami && hostname"


def _credential_target(target: str, auth_context: dict[str, Any]) -> str:
    username = str(auth_context.get("username") or "").strip()
    password = str(auth_context.get("password") or "").strip()
    domain = str(auth_context.get("domain") or "").strip()
    account = (
        f"{domain}/{username}"
        if domain and "\\" not in username and "@" not in username
        else username
    )
    if password:
        return f"{account}:{password}@{target}"
    return f"{account}@{target}"


def build_remote_exec_command(
    binary: str,
    *,
    method: str,
    target: str,
    auth_context: dict[str, Any],
) -> list[str]:
    normalized_binary = str(binary or "").strip()
    if not normalized_binary:
        raise ValueError("remote execution binary must not be blank")
    normalized_method = str(method or "").strip().lower()
    if normalized_method not in {"psexec", "wmiexec"}:
        raise ValueError("remote execution method must be psexec or wmiexec")

    ntlm_hash = str(auth_context.get("ntlm_hash") or "").strip()
    command = [normalized_binary]
    if ntlm_hash:
        command.extend(["-hashes", f"{EMPTY_LM_HASH}:{ntlm_hash}"])
    command.append(_credential_target(target, auth_context))
    command.append(BOUNDED_REMOTE_COMMAND)
    return command


def parse_remote_exec_output(value: str) -> dict[str, str | None]:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    whoami_value = lines[0] if lines else None
    hostname_value = lines[1] if len(lines) > 1 else None
    return {
        "whoami": whoami_value,
        "hostname": hostname_value,
    }
