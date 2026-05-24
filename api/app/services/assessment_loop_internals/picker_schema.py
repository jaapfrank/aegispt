"""Picker output-schema variants + prompt-injection safety helpers.

Extracted from assessment_loop.py (O4 step 5). Pure module: 3 enum
constants, the per-action schema variants (pick/level_up/stop/exec_plan),
the master _picker_output_schema builder + its eagerly-computed
_PICKER_OUTPUT_SCHEMA fallback, the agent-tool name list, plus the
prompt-injection scanner/sanitizer used to neutralise target-derived
text before it hits the picker prompt.

All names kept underscore-prefixed (re-imported under the same names in
assessment_loop.py) so call sites do not move.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("api.app.services.assessment_loop")


_PICKER_TIER_ENUM = ["passive", "active", "intrusive"]
_PICKER_ACTIVE_INTRUSIVE = ["active", "intrusive"]
_PICKER_STOP_REASONS = ["admin_compromise_proven", "exhausted", "scope_complete"]


def _picker_tool_field(available_tools: list[str] | None) -> dict[str, Any]:
    """Build the `tool` field constraint. When ``available_tools`` is provided
    (per-call dynamic schema), emit an ``enum`` so Claude is hard-constrained
    to that exact list — no more hallucinated tool names like ``memory`` or
    ``http_fetch`` (Anthropic built-in tool names that Claude picked when
    the field was just ``{"type":"string"}``). ``exec-plan`` is filtered
    out: tool=exec-plan must go through action=exec_plan (or level_up with
    plan body), not action=pick.

    Anthropic accepts ``enum`` (unlike ``not``, which is rejected per
    ced6030 regression). Empty list = fall back to generic string so the
    schema is still valid in pathological "no tools" scenarios.
    """
    if available_tools is None:
        return {"type": "string"}
    filtered = [t for t in available_tools if t and t != "exec-plan"]
    if not filtered:
        return {"type": "string"}
    return {"type": "string", "enum": sorted(set(filtered))}


def _picker_variant_pick(available_tools: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "action", "tool", "target", "tier",
            "reasoning", "expected_evidence", "confidence",
        ],
        "properties": {
            "action": {"type": "string", "const": "pick"},
            "tool": _picker_tool_field(available_tools),
            "target": {"type": "string"},
            "tier": {"type": "string", "enum": _PICKER_TIER_ENUM},
            "reasoning": {"type": "string"},
            "expected_evidence": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"},
        },
    }


def _picker_variant_level_up(*, with_plan: bool, available_tools: list[str] | None = None) -> dict[str, Any]:
    base_required = [
        "action", "previous_phase_summary", "new_phase_label",
        "tool", "target", "tier",
        "reasoning", "expected_evidence", "confidence",
    ]
    base_properties: dict[str, Any] = {
        "action": {"type": "string", "const": "level_up"},
        "previous_phase_summary": {"type": "string"},
        "new_phase_label": {"type": "string"},
        "tool": _picker_tool_field(available_tools),
        "target": {"type": "string"},
        "tier": {"type": "string", "enum": _PICKER_TIER_ENUM},
        "reasoning": {"type": "string"},
        "expected_evidence": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    }
    if with_plan:
        base_required.extend(["plan_name", "plan"])
        base_properties["tool"] = {"type": "string", "const": "exec-plan"}
        base_properties["tier"] = {"type": "string", "enum": _PICKER_ACTIVE_INTRUSIVE}
        base_properties["plan_name"] = {"type": "string"}
        # Same proper-object plan schema as _picker_variant_exec_plan
        # (HTTP-step grammar, matching exec_plan runner's actual contract).
        base_properties["plan"] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "steps"],
            "properties": {
                "name": {"type": "string"},
                "steps": {
                    "type": "array",
                    "minItems": 1,
                    "items": _exec_plan_step_schema(),
                },
            },
        }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": base_required,
        "properties": base_properties,
    }


def _picker_variant_stop() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["action", "stop_reason", "summary", "confidence"],
        "properties": {
            "action": {"type": "string", "const": "stop"},
            "stop_reason": {"type": "string", "enum": _PICKER_STOP_REASONS},
            "summary": {"type": "string"},
            "confidence": {"type": "number"},
        },
    }


_AGENT_TOOL_NAMES = (
    # Reserved for future tools= API use; the exec-plan runner does NOT
    # consume agent_tool steps — it consumes HTTP-step plans. Removed from
    # the schema in the same commit as this comment because forcing
    # steps[].tool to an agent_tool enum made every plan invalid against
    # the actual runner contract (which uses method/url/expect/capture).
    "bash", "code_exec", "web_fetch", "web_search",
    "file_read", "file_write", "subagent_spawn",
)


def _exec_plan_step_schema() -> dict[str, Any]:
    """Minimal exec-plan step schema. The earlier 10-field version caused
    Anthropic to return "Grammar compilation timed out" (the schema +
    big tool enum combined was too complex for the strict-mode grammar
    compiler). Pared back to the 5 fields that cover the critical
    use-cases for proving a vulnerability:

      name, method, url       — mandatory request shape
      json                    — JSON-encoded body (covers POST data too)
      expect_and_finding      — JSON-encoded combined block holding
                                  {expect: {...}, on_success: {create_finding: ...}}
                                so we transport the assertion + finding-
                                emission decision in one field instead of two

    Other runner-supported fields (headers, params, cookies, capture)
    can be tacked on the JSON body when needed or via subsequent calls.
    _decode_picker_plan unwraps the JSON-encoded fields server-side.
    """
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "url"],
        "properties": {
            "name": {"type": "string"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            },
            "url": {"type": "string"},
            "json": {"type": "string", "description": "JSON-encoded request body (use empty string for GET)"},
            "expect_and_finding": {
                "type": "string",
                "description": (
                    "JSON-encoded combined assertion+finding block. Shape: "
                    "{\"expect\": {\"status\": 200 | [200,302], \"body_contains\": \"text\"}, "
                    "\"on_success\": {\"create_finding\": {\"severity\": \"high\", "
                    "\"title\": \"...\", \"summary\": \"...\"}}}. "
                    "Either or both sub-keys can be omitted."
                ),
            },
        },
    }


# ---------------- Prompt-injection sentinel (OWASP LLM01) ----------------
#
# AegisPT's picker reads HTTP response bodies / stderr from the target. A
# malicious target can stuff prompt-injection into a 404 page, a JSON error,
# or even HTML comments, then have Claude exfiltrate, exit, or emit a
# false "admin_compromise_proven" stop — without any actual exploit. This
# scanner runs on every stdout/stderr excerpt BEFORE it reaches the picker
# prompt. Detected payloads are redacted (replaced with a tag) and audit-
# logged so the operator can see what the target tried to do.

_PROMPT_INJECTION_PATTERNS = [
    # Instruction overrides
    (r"\bignore\s+(?:the\s+)?(?:above|previous|prior|preceding|earlier|all)\s+(?:instructions?|prompts?|rules?|context)\b", "instruction_override"),
    (r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior|preceding|earlier|all)\b", "instruction_override"),
    (r"\b(?:from\s+now\s+on|starting\s+now)[,:\s]+you\s+(?:are|must|will|should)\b", "role_override"),
    (r"\byou\s+are\s+now\b", "role_override"),
    (r"\bnew\s+(?:instructions?|task|role|persona|system\s+prompt)[\s:.\-]+", "instruction_override"),
    # Chat-format markers (Claude / GPT)
    (r"<\|im_(?:start|end)\|>", "chat_marker"),
    (r"\[/?INST\]", "chat_marker"),
    (r"<\|(?:system|user|assistant)\|>", "chat_marker"),
    (r"</?\s*system\s*>", "chat_marker"),
    # Picker-action injection — most dangerous because it mirrors our own schema
    (r"\bemit\s+action\s*[=:]\s*[\"']?(?:stop|exec_plan|pick|level_up)\b", "picker_action_injection"),
    (r"\baction\s*[=:]\s*[\"']?stop[\"']?\b.*\bstop_reason\s*[=:]", "picker_action_injection"),
    (r"\bstop_reason\s*[=:]\s*[\"']?admin_compromise_proven\b", "picker_action_injection"),
    (r"\bset\s+stop_reason\s+to\b", "picker_action_injection"),
    # "Pretend that" / role-play takeover
    (r"\bpretend\s+(?:that\s+)?you\s+(?:are|have)\b", "role_override"),
    (r"\bact\s+as\s+(?:if\s+)?you\s+(?:are|have)\b", "role_override"),
]

_PROMPT_INJECTION_REDACTION = "[REDACTED_PROMPT_INJECTION:{tag}]"


def _scan_for_prompt_injection(text: str) -> tuple[str, list[str]]:
    """Scan target-derived text for prompt-injection patterns. Returns
    (sanitized_text, list_of_detected_tags). When patterns are detected,
    the matching span is replaced with a redaction marker so the picker
    sees only sanitized text. Empty list = clean."""
    if not text:
        return text, []
    import re
    detected: list[str] = []
    sanitized = text
    for pattern, tag in _PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, sanitized, flags=re.IGNORECASE)
        if not match:
            continue
        detected.append(tag)
        sanitized = re.sub(
            pattern,
            _PROMPT_INJECTION_REDACTION.format(tag=tag),
            sanitized,
            flags=re.IGNORECASE,
        )
    return sanitized, detected


def _sanitize_target_text_for_picker(text: str, *, source: str, run_id: str | None = None) -> str:
    """Wrapper that scans + redacts AND emits an audit log line per
    detection so the operator can see what the target tried. ``source`` is
    a short tag like "task_stdout" / "task_stderr" so the audit trail says
    where the injection landed."""
    if not text:
        return text
    sanitized, detected = _scan_for_prompt_injection(text)
    if detected:
        logger.warning(
            "prompt_injection_sentinel: redacted %s from %s (run=%s) — target appears to be injecting picker instructions",
            sorted(set(detected)),
            source,
            (str(run_id)[:8] if run_id else "?"),
        )
    return sanitized


def _picker_variant_exec_plan() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["action", "plan_name", "tier", "reasoning", "confidence", "plan"],
        "properties": {
            "action": {"type": "string", "const": "exec_plan"},
            "plan_name": {"type": "string"},
            "tier": {"type": "string", "enum": _PICKER_ACTIVE_INTRUSIVE},
            "reasoning": {"type": "string"},
            "confidence": {"type": "number"},
            # Proper object schema for `plan` (replaces the pre-2026-05-21
            # JSON-encoded-string-in-JSON gymnastics). The decoder
            # _decode_picker_plan handles both string and dict shapes so
            # this is backwards-compatible. Each step matches the actual
            # exec-plan runner contract: HTTP method/url/expect/capture,
            # NOT agent_tool dispatch (that was an incorrect schema in
            # bf9940d — the runner doesn't consume agent_tool steps).
            "plan": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "steps"],
                "properties": {
                    "name": {"type": "string"},
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "items": _exec_plan_step_schema(),
                    },
                },
            },
        },
    }


def _picker_output_schema(
    available_tools: list[str] | None = None,
    *,
    force_exec_plan: bool = False,
) -> dict[str, Any]:
    """Discriminated schema for the picker action shapes.

    Two modes:
      - Default: full 5-variant anyOf (pick / level_up / level_up+plan /
        stop / exec_plan). Claude chooses.
      - ``force_exec_plan=True``: only exec_plan + level_up-with-plan +
        stop are accepted. The prompt-side forcing rule (added 078e9b9)
        ASKED Claude to pivot to exec_plan after catalog exhaustion;
        empirically Claude ignored it. With force_exec_plan the schema
        REJECTS any action=pick or action=level_up-without-plan at the
        Anthropic API boundary, so Claude cannot avoid pivoting.

    When ``available_tools`` is provided AND force_exec_plan is False,
    the pick + level_up-without-plan variants get an enum-constrained
    ``tool`` field.
    """
    if force_exec_plan:
        return {
            "anyOf": [
                _picker_variant_level_up(with_plan=True),
                _picker_variant_stop(),
                _picker_variant_exec_plan(),
            ],
        }
    return {
        "anyOf": [
            _picker_variant_pick(available_tools),
            _picker_variant_level_up(with_plan=False, available_tools=available_tools),
            _picker_variant_level_up(with_plan=True),
            _picker_variant_stop(),
            _picker_variant_exec_plan(),
        ],
    }


# Static fallback used when no available_tools list is supplied. The dynamic
# enum-constrained variant is built per-call at the messages.create site to
# keep Claude on the actual runner registry.
_PICKER_OUTPUT_SCHEMA: dict[str, Any] = _picker_output_schema()
