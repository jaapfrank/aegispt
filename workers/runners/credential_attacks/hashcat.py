from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

HASHCAT_MODE_BY_SECRET_KIND = {
    "ntlmv2_hash_bundle": 5600,
    "kerberoast_tgs_hash_bundle": 13100,
    "asrep_hash_bundle": 18200,
}


def resolve_wordlist_path(configured_path: str | None = None) -> str:
    candidates = [
        configured_path,
        os.getenv("HASHCAT_WORDLIST_PATH"),
        "/usr/share/wordlists/rockyou.txt",
    ]
    for candidate in candidates:
        normalized = str(candidate or "").strip()
        if normalized and Path(normalized).exists():
            return normalized
    raise ValueError("Hashcat cracking requires an existing wordlist path")


def build_hashcat_command(
    *,
    binary: str,
    hash_mode: int,
    hash_file: Path,
    wordlist_path: str,
    output_file: Path,
) -> list[str]:
    return [
        binary,
        "-m",
        str(hash_mode),
        "-a",
        "0",
        str(hash_file),
        wordlist_path,
        "--quiet",
        "--potfile-disable",
        "--outfile",
        str(output_file),
        "--outfile-format",
        "2",
    ]


def extract_hash_records(
    *,
    source_label: str,
    source_kind: str,
    bundle_value: str,
) -> list[dict[str, Any]]:
    normalized_kind = str(source_kind or "").strip()
    if normalized_kind not in HASHCAT_MODE_BY_SECRET_KIND:
        raise ValueError(f"Unsupported hash source kind for hashcat: {source_kind}")

    stripped = str(bundle_value or "").strip()
    if not stripped:
        return []

    records: list[dict[str, Any]] = []
    parsed_json = None
    try:
        parsed_json = json.loads(stripped)
    except json.JSONDecodeError:
        parsed_json = None

    if isinstance(parsed_json, dict):
        raw_records = parsed_json.get("records", [])
        if isinstance(raw_records, list):
            for raw_record in raw_records:
                if not isinstance(raw_record, dict):
                    continue
                hash_value = str(raw_record.get("hash") or "").strip()
                if not hash_value:
                    continue
                records.append(
                    {
                        "source_label": source_label,
                        "source_kind": normalized_kind,
                        "hashcat_mode": int(
                            raw_record.get("hashcat_mode")
                            or HASHCAT_MODE_BY_SECRET_KIND[normalized_kind]
                        ),
                        "hash": hash_value,
                        "account_name": str(raw_record.get("account_name") or "").strip() or None,
                        "user_principal_name": (
                            str(raw_record.get("user_principal_name") or "").strip() or None
                        ),
                        "privilege_level": str(
                            raw_record.get("privilege_level") or "standard"
                        ).strip()
                        or "standard",
                        "source": str(raw_record.get("source") or source_label).strip()
                        or source_label,
                    }
                )
            return records

    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        account_name = None
        if normalized_kind == "ntlmv2_hash_bundle" and "::" in line:
            account_name = line.split("::", 1)[0].strip() or None
        records.append(
            {
                "source_label": source_label,
                "source_kind": normalized_kind,
                "hashcat_mode": HASHCAT_MODE_BY_SECRET_KIND[normalized_kind],
                "hash": line,
                "account_name": account_name,
                "user_principal_name": None,
                "privilege_level": "standard",
                "source": source_label,
            }
        )
    return records


def parse_hashcat_output(
    output_lines: list[str],
    *,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    cracked: list[dict[str, Any]] = []
    known_hashes = sorted(
        [str(record.get("hash") or "") for record in records if str(record.get("hash") or "").strip()],
        key=len,
        reverse=True,
    )
    record_by_hash = {
        str(record.get("hash") or ""): record
        for record in records
        if str(record.get("hash") or "").strip()
    }

    for raw_line in output_lines:
        line = str(raw_line or "").strip()
        if not line:
            continue
        matched_hash = None
        for hash_value in known_hashes:
            prefix = f"{hash_value}:"
            if line.startswith(prefix):
                matched_hash = hash_value
                password = line[len(prefix) :].strip()
                break
        if not matched_hash:
            continue
        base_record = record_by_hash.get(matched_hash)
        if base_record is None or not password:
            continue
        cracked.append({**base_record, "password": password})
    return cracked
