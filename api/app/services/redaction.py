from __future__ import annotations

import json
import re
from dataclasses import dataclass

REDACTION_MASK = "[REDACTED]"
SENSITIVE_FIELD_NAMES = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "x-api-key",
}
TEXTUAL_CONTENT_TYPES = (
    "application/json",
    "application/problem+json",
    "application/x-ndjson",
    "application/xml",
    "text/",
)
TEXTUAL_FILE_EXTENSIONS = (".json", ".jsonl", ".log", ".md", ".txt", ".xml", ".yaml", ".yml")
REDACTION_PATTERNS = (
    re.compile(r"(?i)(apikey=)([^&\s]+)"),
    re.compile(r"(?i)(token=)([^&\s]+)"),
    re.compile(r"(?i)(password=)([^&\s]+)"),
    re.compile(r"(?i)(secret=)([^&\s]+)"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b(\s*[:=]\s*[\"'])([^\"']+)([\"'])"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)([^\s\"']+)"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]+)"),
    re.compile(r"(?i)(cookie:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(set-cookie:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(NTLMv2(?:-SSP)?\s+Hash\s*:\s*)([^\r\n]+)"),
    re.compile(
        r"(?i)([A-Za-z0-9._$-]+::[A-Za-z0-9._$ -]*:)([A-Fa-f0-9]{16,}:[A-Fa-f0-9]{16,}:[^\r\n]+)"
    ),
)


@dataclass(slots=True, frozen=True)
class RedactedText:
    text: str | None
    changed: bool
    redaction_count: int


@dataclass(slots=True, frozen=True)
class RedactedBytes:
    data: bytes
    redaction_state: str
    redaction_count: int


def _redact_string_patterns(value: str) -> RedactedText:
    redaction_count = 0
    redacted_value = value

    for pattern in REDACTION_PATTERNS:
        if pattern.groups == 4:
            redacted_value, replacements = pattern.subn(rf"\1\2{REDACTION_MASK}\4", redacted_value)
        else:
            redacted_value, replacements = pattern.subn(rf"\1{REDACTION_MASK}", redacted_value)
        redaction_count += replacements

    return RedactedText(
        text=redacted_value,
        changed=redacted_value != value,
        redaction_count=redaction_count,
    )


def _redact_json_value(value):
    if isinstance(value, dict):
        changed = False
        redaction_count = 0
        redacted_mapping: dict[object, object] = {}
        for key, item in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in SENSITIVE_FIELD_NAMES and item not in {None, REDACTION_MASK}:
                redacted_mapping[key] = REDACTION_MASK
                changed = True
                redaction_count += 1
                continue

            redacted_item, item_changed, item_redaction_count = _redact_json_value(item)
            redacted_mapping[key] = redacted_item
            changed = changed or item_changed
            redaction_count += item_redaction_count

        return redacted_mapping, changed, redaction_count

    if isinstance(value, list):
        changed = False
        redaction_count = 0
        redacted_items: list[object] = []
        for item in value:
            redacted_item, item_changed, item_redaction_count = _redact_json_value(item)
            redacted_items.append(redacted_item)
            changed = changed or item_changed
            redaction_count += item_redaction_count
        return redacted_items, changed, redaction_count

    if isinstance(value, str):
        redacted_text = _redact_string_patterns(value)
        return redacted_text.text, redacted_text.changed, redacted_text.redaction_count

    return value, False, 0


def redact_text(value: str | None) -> RedactedText:
    if value is None:
        return RedactedText(text=None, changed=False, redaction_count=0)
    if not value:
        return RedactedText(text="", changed=False, redaction_count=0)

    try:
        parsed_json = json.loads(value)
    except json.JSONDecodeError:
        parsed_json = None

    if parsed_json is not None:
        redacted_json, changed, redaction_count = _redact_json_value(parsed_json)
        if changed:
            return RedactedText(
                text=json.dumps(redacted_json, indent=2, sort_keys=True),
                changed=True,
                redaction_count=redaction_count,
            )

    lines = value.splitlines()
    if lines and all(line.strip() == "" or line.lstrip().startswith(("{", "[")) for line in lines):
        redacted_lines: list[str] = []
        changed = False
        redaction_count = 0
        parse_failed = False

        for line in lines:
            if not line.strip():
                redacted_lines.append(line)
                continue
            try:
                parsed_line = json.loads(line)
            except json.JSONDecodeError:
                parse_failed = True
                break

            redacted_line, line_changed, line_redaction_count = _redact_json_value(parsed_line)
            redacted_lines.append(json.dumps(redacted_line, sort_keys=True))
            changed = changed or line_changed
            redaction_count += line_redaction_count

        if not parse_failed and changed:
            return RedactedText(
                text="\n".join(redacted_lines) + ("\n" if value.endswith("\n") else ""),
                changed=True,
                redaction_count=redaction_count,
            )

    return _redact_string_patterns(value)


def redact_jsonl_text(value: str) -> RedactedText:
    lines = value.splitlines()
    redacted_lines: list[str] = []
    changed = False
    redaction_count = 0

    for line in lines:
        if not line.strip():
            redacted_lines.append(line)
            continue

        parsed_line = json.loads(line)
        redacted_line, line_changed, line_redaction_count = _redact_json_value(parsed_line)
        redacted_lines.append(json.dumps(redacted_line, sort_keys=True))
        changed = changed or line_changed
        redaction_count += line_redaction_count

    return RedactedText(
        text="\n".join(redacted_lines) + ("\n" if value.endswith("\n") else ""),
        changed=changed,
        redaction_count=redaction_count,
    )


def is_textual_artifact(*, name: str, content_type: str) -> bool:
    normalized_name = name.strip().lower()
    normalized_content_type = content_type.strip().lower()
    return normalized_content_type.startswith(TEXTUAL_CONTENT_TYPES) or normalized_name.endswith(
        TEXTUAL_FILE_EXTENSIONS
    )


def redact_artifact_bytes(*, name: str, content_type: str, data: bytes) -> RedactedBytes:
    if not data or not is_textual_artifact(name=name, content_type=content_type):
        return RedactedBytes(data=data, redaction_state="not_required", redaction_count=0)

    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return RedactedBytes(data=data, redaction_state="not_required", redaction_count=0)

    normalized_name = name.strip().lower()
    normalized_content_type = content_type.strip().lower()

    if normalized_content_type == "application/x-ndjson" or normalized_name.endswith(".jsonl"):
        redacted_text = redact_jsonl_text(decoded)
    else:
        redacted_text = redact_text(decoded)

    if not redacted_text.changed:
        return RedactedBytes(data=data, redaction_state="not_required", redaction_count=0)

    return RedactedBytes(
        data=redacted_text.text.encode("utf-8"),
        redaction_state="redacted",
        redaction_count=redacted_text.redaction_count,
    )
