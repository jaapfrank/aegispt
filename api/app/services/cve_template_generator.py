from __future__ import annotations

import difflib
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

import yaml
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import CapabilityPack, CapabilityPackArtifact, ThreatIntelRecord
from api.app.services.chatgpt_oauth import (
    ChatGPTOAuthError,
    send_chatgpt_backend_streaming_json_request,
)
from api.app.services.packs import stage_generated_nuclei_template_pack

CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CODE_FENCE_PATTERN = re.compile(r"^```(?:yaml|yml)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)
BLOCKED_TOP_LEVEL_PROTOCOLS = {
    "dns",
    "ssl",
    "tcp",
    "network",
    "headless",
    "javascript",
    "code",
    "file",
    "flow",
    "websocket",
}
BLOCKED_KEYS = {
    "attack",
    "body",
    "payload",
    "payloads",
    "race",
    "raw",
    "unsafe",
}
BLOCKED_TEXT_PATTERNS = (
    "interactsh",
    "reverse shell",
    "bash -i",
    "bash -c",
    "cmd.exe",
    "powershell",
    "nc -e",
    "netcat",
    "rm -rf",
    "wget ",
    "curl ",
    "python -c",
    "perl -e",
)
ALLOWED_HTTP_METHODS = {"GET", "HEAD"}


class CveTemplateGenerationError(RuntimeError):
    pass


class CveTemplateUnavailable(CveTemplateGenerationError):
    pass


class UnsafeNucleiTemplateError(CveTemplateGenerationError):
    pass


class NucleiTemplateValidationError(CveTemplateGenerationError):
    pass


def generate_cve_nuclei_template_pack(
    *,
    session: Session,
    record: ThreatIntelRecord,
    engagement_id,
    actor: str,
    settings: Settings,
) -> dict[str, Any]:
    if not is_cve_record(record):
        raise NucleiTemplateValidationError("threat-intel record is not a CVE record")

    instructions, input_items = build_generation_prompt(record)
    try:
        response_payload = send_chatgpt_backend_streaming_json_request(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
            model=settings.chatgpt_oauth_model,
            instructions=instructions,
            input_items=input_items,
        )
    except ChatGPTOAuthError as exc:
        raise CveTemplateUnavailable(str(exc)) from exc

    template_yaml = extract_template_yaml(response_payload)
    validation = validate_detection_only_nuclei_template(template_yaml)
    prompt_digest = hashlib.sha256(
        json.dumps(
            {
                "record_id": str(record.id),
                "advisory_id": record.advisory_id,
                "instructions": instructions,
                "input_items": input_items,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    yaml_diff = unified_yaml_diff(template_yaml)
    pack, artifact = stage_generated_nuclei_template_pack(
        session,
        engagement_id=engagement_id,
        requested_by=actor,
        record=record,
        template_yaml=template_yaml,
        validation_summary=validation,
        model=settings.chatgpt_oauth_model,
        prompt_digest=prompt_digest,
        generation_metadata={
            "provider": "chatgpt_oauth",
            "token_exposed": False,
            "model_response_keys": sorted(str(key) for key in response_payload.keys()),
            "rationale": str(response_payload.get("rationale") or ""),
            "detection_strategy": str(response_payload.get("detection_strategy") or ""),
            "safety_notes": _string_list(response_payload.get("safety_notes")),
            "yaml_diff": yaml_diff,
        },
    )
    return generation_response_payload(
        record=record,
        status="generated",
        message="Detection-only Nuclei template staged as a generated capability pack.",
        pack=pack,
        artifact=artifact,
        template_yaml=template_yaml,
        yaml_diff=yaml_diff,
        validation=validation,
    )


def existing_template_generation_payload(record: ThreatIntelRecord) -> dict[str, Any] | None:
    metadata = dict(record.metadata_json or {})
    existing = metadata.get("generated_nuclei_template")
    if not isinstance(existing, dict) or not existing.get("pack_id"):
        return None
    return {
        "record_id": record.id,
        "status": "already_exists",
        "message": "A generated Nuclei template is already linked to this CVE record.",
        "pack_id": existing.get("pack_id"),
        "artifact_id": existing.get("artifact_id"),
        "pack_status": existing.get("status") or "pending_review",
        "review_url": existing.get("review_url") or _review_url(existing.get("pack_id")),
        "template_yaml": None,
        "yaml_diff": existing.get("yaml_diff"),
        "validation": existing.get("validation") if isinstance(existing.get("validation"), dict) else {},
        "generated_template": existing,
        "lifecycle_note": _lifecycle_note(),
    }


def generation_response_payload(
    *,
    record: ThreatIntelRecord,
    status: str,
    message: str,
    pack: CapabilityPack | None = None,
    artifact: CapabilityPackArtifact | None = None,
    template_yaml: str | None = None,
    yaml_diff: str | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    generated_template = dict((record.metadata_json or {}).get("generated_nuclei_template") or {})
    return {
        "record_id": record.id,
        "status": status,
        "message": message,
        "pack_id": pack.id if pack is not None else generated_template.get("pack_id"),
        "artifact_id": artifact.id if artifact is not None else generated_template.get("artifact_id"),
        "pack_status": pack.status if pack is not None else generated_template.get("status"),
        "review_url": _review_url(str(pack.id)) if pack is not None else generated_template.get("review_url"),
        "template_yaml": template_yaml,
        "yaml_diff": yaml_diff,
        "validation": validation or {},
        "generated_template": generated_template,
        "lifecycle_note": _lifecycle_note(),
    }


def unavailable_generation_payload(*, record: ThreatIntelRecord, message: str) -> dict[str, Any]:
    return generation_response_payload(
        record=record,
        status="unavailable",
        message=message,
        validation={
            "provider": "chatgpt_oauth",
            "connected": False,
            "token_exposed": False,
            "generated_at": datetime.now(UTC).isoformat(),
        },
    )


def is_cve_record(record: ThreatIntelRecord) -> bool:
    values = [
        record.advisory_id,
        record.title,
        record.summary,
        *(record.product_match_hints_json or []),
        *(record.suggested_test_patterns_json or []),
    ]
    metadata = dict(record.metadata_json or {})
    values.append(metadata.get("cve_id"))
    return any(CVE_ID_PATTERN.search(str(value or "")) for value in values)


def build_generation_prompt(record: ThreatIntelRecord) -> tuple[str, list[dict[str, Any]]]:
    metadata = dict(record.metadata_json or {})
    cve_context = {
        "record_id": str(record.id),
        "cve_id": metadata.get("cve_id") or record.advisory_id,
        "source": record.source,
        "title": record.title,
        "description": record.summary,
        "severity": record.severity,
        "cvss_score": metadata.get("cvss_score"),
        "cvss_severity": metadata.get("cvss_severity"),
        "cwe_ids": metadata.get("cwe_ids") or [],
        "affected_products": list(record.affected_products_json or []),
        "affected_versions": list(record.affected_versions_json or []),
        "product_match_hints": list(record.product_match_hints_json or []),
        "references": list(record.references_json or []),
    }
    instructions = (
        "You generate review-only Nuclei YAML templates for AegisPT. "
        "Return a single JSON object with keys template_yaml, detection_strategy, rationale, and safety_notes. "
        "The template must be detection-only: use only GET or HEAD HTTP requests against {{BaseURL}}, "
        "include id, info.name, info.severity, and at least one matcher, and avoid payload delivery, raw requests, "
        "interactsh, destructive operations, command execution, static external targets, or exploitation. "
        "Do not generate credentials, shells, reverse callbacks, destructive methods, or out-of-scope hostnames. "
        "Use Nuclei HTTP template structure with an http list, paths under {{BaseURL}}, and matchers grounded in "
        "the CVE metadata. If the CVE cannot be safely detected, return a conservative GET matcher template that "
        "requires operator review instead of exploit logic."
    )
    examples = [
        {
            "id": "cve-2026-example-product-version-detection",
            "info": {"name": "Example product CVE detection", "severity": "high", "tags": "cve,detection"},
            "http": [
                {
                    "method": "GET",
                    "path": ["{{BaseURL}}/"],
                    "matchers": [{"type": "word", "words": ["ExampleProduct"]}],
                }
            ],
        },
        {
            "id": "cve-2026-example-header-detection",
            "info": {"name": "Example header exposure detection", "severity": "medium", "tags": "cve,detection"},
            "http": [
                {
                    "method": "HEAD",
                    "path": ["{{BaseURL}}/"],
                    "matchers": [{"type": "word", "part": "header", "words": ["X-Example-Version"]}],
                }
            ],
        },
    ]
    return instructions, [
        {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": json.dumps(
                        {
                            "task": "generate_detection_only_nuclei_template",
                            "nuclei_schema_expectations": {
                                "required_top_level": ["id", "info", "http"],
                                "required_info": ["name", "severity"],
                                "http_request_methods_allowed": sorted(ALLOWED_HTTP_METHODS),
                                "review_gate": "Generated pack must be validated, approved, deployed, and runtime-bound through existing lifecycle.",
                            },
                            "safe_examples": examples,
                            "cve_record": cve_context,
                        },
                        sort_keys=True,
                    ),
                }
            ],
        }
    ]


def extract_template_yaml(payload: dict[str, Any]) -> str:
    for key in ("template_yaml", "nuclei_yaml", "yaml", "template"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return CODE_FENCE_PATTERN.sub("", value).strip()
    raise NucleiTemplateValidationError("AI response did not include template_yaml")


def validate_detection_only_nuclei_template(template_yaml: str) -> dict[str, Any]:
    text = str(template_yaml or "").strip()
    if not text:
        raise NucleiTemplateValidationError("generated template is empty")
    _reject_blocked_text(text)
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise NucleiTemplateValidationError("generated template is not valid YAML") from exc
    if not isinstance(parsed, dict):
        raise NucleiTemplateValidationError("generated template must be a YAML mapping")

    top_keys = {str(key).strip() for key in parsed}
    blocked_protocols = sorted(top_keys.intersection(BLOCKED_TOP_LEVEL_PROTOCOLS))
    if blocked_protocols:
        raise UnsafeNucleiTemplateError(f"blocked active protocol section: {', '.join(blocked_protocols)}")
    if not str(parsed.get("id") or "").strip():
        raise NucleiTemplateValidationError("generated template must include id")
    info = parsed.get("info")
    if not isinstance(info, dict):
        raise NucleiTemplateValidationError("generated template must include info mapping")
    if not str(info.get("name") or "").strip():
        raise NucleiTemplateValidationError("generated template info.name is required")
    if not str(info.get("severity") or "").strip():
        raise NucleiTemplateValidationError("generated template info.severity is required")

    _reject_blocked_keys(parsed)
    requests = _http_requests(parsed)
    if not requests:
        raise NucleiTemplateValidationError("generated template must include http requests")

    matcher_count = 0
    for request in requests:
        method = str(request.get("method") or "GET").strip().upper()
        if method not in ALLOWED_HTTP_METHODS:
            raise UnsafeNucleiTemplateError(f"blocked HTTP method for detection-only template: {method}")
        paths = request.get("path") or request.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths:
            raise NucleiTemplateValidationError("each HTTP request must include path entries")
        for path in paths:
            _validate_path(str(path or ""))
        matchers = request.get("matchers")
        if not isinstance(matchers, list) or not matchers:
            raise NucleiTemplateValidationError("each HTTP request must include at least one matcher")
        matcher_count += len(matchers)

    return {
        "schema": "nuclei-http-detection-subset",
        "template_id": str(parsed.get("id")),
        "severity": str(info.get("severity")),
        "http_request_count": len(requests),
        "matcher_count": matcher_count,
        "allowed_methods": sorted(ALLOWED_HTTP_METHODS),
        "blocked_protocols": sorted(BLOCKED_TOP_LEVEL_PROTOCOLS),
        "detection_only": True,
        "operator_review_required": True,
        "auto_deploy": False,
        "validated_at": datetime.now(UTC).isoformat(),
    }


def unified_yaml_diff(template_yaml: str) -> str:
    return "".join(
        difflib.unified_diff(
            [],
            [f"{line}\n" for line in template_yaml.splitlines()],
            fromfile="empty-reviewed-template.yaml",
            tofile="generated-detection-template.yaml",
        )
    )


def _http_requests(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    section = parsed.get("http")
    if section is None:
        section = parsed.get("requests")
    if isinstance(section, dict):
        section = [section]
    if not isinstance(section, list):
        return []
    return [item for item in section if isinstance(item, dict)]


def _reject_blocked_keys(value: Any, *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in BLOCKED_KEYS:
                raise UnsafeNucleiTemplateError(f"blocked key in detection-only template: {path}{normalized}")
            _reject_blocked_keys(nested, path=f"{path}{normalized}.")
    elif isinstance(value, list):
        for item in value:
            _reject_blocked_keys(item, path=path)


def _reject_blocked_text(text: str) -> None:
    lowered = text.lower()
    for pattern in BLOCKED_TEXT_PATTERNS:
        if pattern in lowered:
            raise UnsafeNucleiTemplateError(f"blocked unsafe template content: {pattern.strip()}")


def _validate_path(path: str) -> None:
    clean = path.strip()
    if not clean:
        raise NucleiTemplateValidationError("HTTP path cannot be empty")
    if ("http://" in clean.lower() or "https://" in clean.lower()) and "{{baseurl}}" not in clean.lower():
        raise UnsafeNucleiTemplateError("generated template contains a static out-of-scope URL")


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item or "").strip()]


def _review_url(pack_id: Any) -> str | None:
    if not pack_id:
        return None
    return f"/app/?screen=pack-forge&pack_id={pack_id}"


def _lifecycle_note() -> str:
    return (
        "Generated template is staged only. Operators must use the existing pack validation, approval, "
        "deployment, and runtime-binding lifecycle before any run can use it."
    )
