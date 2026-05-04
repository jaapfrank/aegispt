from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AllowlistedMetasploitModule:
    key: str
    module_type: str
    module_name: str
    reference_label: str
    payload: str
    default_rport: int
    requires_auth: bool = False
    auth_scheme: str = "none"
    precheck_module_type: str | None = None
    precheck_module_name: str | None = None
    title_hint: str | None = None
    match_any_patterns: tuple[str, ...] = ()
    required_tags: tuple[str, ...] = ()
    persistence_allowed: bool = False

    def matches(self, finding_context: dict[str, Any]) -> bool:
        title = str(finding_context.get("title") or "").strip()
        summary = str(finding_context.get("summary") or "").strip()
        methodology_tags = {
            str(tag).strip().lower()
            for tag in list(finding_context.get("methodology_tags") or [])
            if str(tag).strip()
        }
        haystack = f"{title}\n{summary}".lower()

        if self.required_tags and set(self.required_tags).issubset(methodology_tags):
            return True
        return any(
            re.search(pattern, haystack, re.IGNORECASE) for pattern in self.match_any_patterns
        )


ALLOWLISTED_METASPLOIT_MODULES: tuple[AllowlistedMetasploitModule, ...] = (
    AllowlistedMetasploitModule(
        key="ms17_010_psexec",
        module_type="exploit",
        module_name="windows/smb/ms17_010_psexec",
        reference_label="CVE-2017-0143 / MS17-010",
        payload="windows/x64/meterpreter/reverse_tcp",
        default_rport=445,
        precheck_module_type="auxiliary",
        precheck_module_name="scanner/smb/smb_ms17_010",
        title_hint="Confirmed RCE",
        match_any_patterns=(
            r"\bms17-010\b",
            r"\bcve-2017-014[3-8]\b",
            r"\beternalblue\b",
        ),
    ),
    AllowlistedMetasploitModule(
        key="windows_smb_psexec",
        module_type="exploit",
        module_name="windows/smb/psexec",
        reference_label="credentialed SMB remote code execution",
        payload="windows/x64/meterpreter/reverse_tcp",
        default_rport=445,
        requires_auth=True,
        auth_scheme="smb",
        title_hint="Confirmed RCE",
        match_any_patterns=(
            r"pass[- ]the[- ]hash",
            r"\bpsexec\b",
            r"credential(?:ed)? smb",
            r"administrative smb",
        ),
        required_tags=("smb", "pass_the_hash"),
    ),
)


def allowlisted_modules_by_name() -> dict[str, AllowlistedMetasploitModule]:
    mapping: dict[str, AllowlistedMetasploitModule] = {}
    for entry in ALLOWLISTED_METASPLOIT_MODULES:
        mapping[entry.module_name] = entry
    return mapping


def resolve_allowlisted_module(
    finding_context: dict[str, Any],
    *,
    requested_module: str | None = None,
) -> AllowlistedMetasploitModule:
    by_name = allowlisted_modules_by_name()
    normalized_requested = str(requested_module or "").strip()
    if normalized_requested:
        entry = by_name.get(normalized_requested)
        if entry is None:
            raise ValueError("Requested Metasploit module is not in the curated allowlist")
        if not entry.matches(finding_context):
            raise ValueError(
                "Requested Metasploit module does not match the approved source finding context"
            )
        return entry

    for entry in ALLOWLISTED_METASPLOIT_MODULES:
        if entry.matches(finding_context):
            return entry
    raise ValueError(
        "No curated Metasploit module matches the approved source finding; exploitation is allowlist-only"
    )
