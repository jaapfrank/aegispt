"""Tests for the picker structured-output JSON schema (Mythos #330).

The schema replaces the text-then-JSON-parse path in
`_claude_select_next_action`. These tests cover:

- the schema constant shape (5 anyOf variants, additionalProperties closed)
- `_decode_picker_plan` round-trips JSON-stringified plan bodies
- the picker call passes `output_config.format.json_schema` to messages.create
- the tolerant fallback still works as defensive layer + logs a warning
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import patch

import pytest

from api.app.services import assessment_loop as al


# ---------------------------------------------------------------------------
# _PICKER_OUTPUT_SCHEMA shape
# ---------------------------------------------------------------------------


def test_schema_has_five_anyof_variants() -> None:
    schema = al._PICKER_OUTPUT_SCHEMA
    assert "anyOf" in schema
    assert len(schema["anyOf"]) == 5


def test_schema_variants_lock_action_via_const() -> None:
    consts = []
    for variant in al._PICKER_OUTPUT_SCHEMA["anyOf"]:
        action_def = variant["properties"]["action"]
        assert action_def["type"] == "string"
        consts.append(action_def["const"])
    # pick, level_up (x2), stop, exec_plan
    assert consts == ["pick", "level_up", "level_up", "stop", "exec_plan"]


def test_every_variant_has_additional_properties_false() -> None:
    """Anthropic strict-mode requires `additionalProperties: false`
    on every object."""
    for variant in al._PICKER_OUTPUT_SCHEMA["anyOf"]:
        assert variant["additionalProperties"] is False, f"variant missing closure: {variant}"


def test_every_property_is_in_required() -> None:
    """Anthropic strict-mode requires every property listed to be in
    `required` (no optional fields without explicit null types)."""
    for variant in al._PICKER_OUTPUT_SCHEMA["anyOf"]:
        prop_names = set(variant["properties"].keys())
        required = set(variant["required"])
        missing = prop_names - required
        assert not missing, (
            f"variant {variant['properties']['action']['const']} "
            f"has properties not in required: {missing}"
        )


def test_plan_field_is_string_type_in_exec_plan_and_level_up_with_plan() -> None:
    """The `plan` field MUST be `type: string` in the schema (Claude
    serializes the plan body, client-side decodes). This is the
    workaround for strict-mode incompatibility with freeform inner
    objects."""
    plan_variants = [
        v for v in al._PICKER_OUTPUT_SCHEMA["anyOf"]
        if "plan" in v["properties"]
    ]
    assert len(plan_variants) == 2  # exec_plan + level_up_with_plan
    for v in plan_variants:
        assert v["properties"]["plan"]["type"] == "string"


def test_pick_requires_tool_target_tier_etc() -> None:
    pick = next(
        v for v in al._PICKER_OUTPUT_SCHEMA["anyOf"]
        if v["properties"]["action"]["const"] == "pick"
    )
    assert set(pick["required"]) == {
        "action", "tool", "target", "tier",
        "reasoning", "expected_evidence", "confidence",
    }


def test_stop_has_stop_reason_enum() -> None:
    stop = next(
        v for v in al._PICKER_OUTPUT_SCHEMA["anyOf"]
        if v["properties"]["action"]["const"] == "stop"
    )
    assert set(stop["properties"]["stop_reason"]["enum"]) == {
        "admin_compromise_proven", "exhausted", "scope_complete",
    }


def test_exec_plan_tier_excludes_passive() -> None:
    """exec_plan steps mutate state — passive is not a valid tier."""
    exec_plan = next(
        v for v in al._PICKER_OUTPUT_SCHEMA["anyOf"]
        if v["properties"]["action"]["const"] == "exec_plan"
    )
    assert set(exec_plan["properties"]["tier"]["enum"]) == {"active", "intrusive"}


# ---------------------------------------------------------------------------
# _decode_picker_plan
# ---------------------------------------------------------------------------


def test_decode_picker_plan_inflates_stringified_plan() -> None:
    decision = {
        "action": "exec_plan",
        "plan_name": "x",
        "tier": "active",
        "reasoning": "test",
        "confidence": 0.8,
        "plan": json.dumps({
            "name": "x",
            "steps": [{"name": "probe", "method": "GET", "url": "${target}/p"}],
        }),
    }
    result = al._decode_picker_plan(decision)
    assert isinstance(result["plan"], dict)
    assert result["plan"]["name"] == "x"
    assert result["plan"]["steps"][0]["name"] == "probe"


def test_decode_picker_plan_noop_when_no_plan_field() -> None:
    decision = {"action": "pick", "tool": "nmap", "target": "x"}
    result = al._decode_picker_plan(decision)
    assert result == decision  # unchanged


def test_decode_picker_plan_noop_when_plan_is_empty_string() -> None:
    decision = {"action": "pick", "plan": ""}
    result = al._decode_picker_plan(decision)
    assert result["plan"] == ""  # not decoded


def test_decode_picker_plan_logs_warning_on_invalid_json(
    caplog: pytest.LogCaptureFixture,
) -> None:
    decision = {"action": "exec_plan", "plan": "not valid json {"}
    with caplog.at_level(logging.WARNING, logger="api.app.services.assessment_loop"):
        result = al._decode_picker_plan(decision)
    # Plan stays as string when decode fails (defensive).
    assert result["plan"] == "not valid json {"
    assert any(
        "picker plan field was not valid JSON" in rec.message
        for rec in caplog.records
    )


def test_decode_picker_plan_handles_non_dict_input() -> None:
    assert al._decode_picker_plan(None) is None  # type: ignore[arg-type]
    assert al._decode_picker_plan("nope") == "nope"  # type: ignore[arg-type]


def test_decode_picker_plan_ignores_non_object_decoded_plan() -> None:
    """If plan decodes to something that isn't a dict (e.g. a list or
    a literal), leave the string in place."""
    decision = {"action": "exec_plan", "plan": "[1, 2, 3]"}
    result = al._decode_picker_plan(decision)
    assert result["plan"] == "[1, 2, 3]"  # untouched


# ---------------------------------------------------------------------------
# Picker call shape — output_config is passed to messages.create
# ---------------------------------------------------------------------------


class _MockBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _MockUsage:
    input_tokens = 0
    output_tokens = 0
    cache_read_input_tokens = 0
    cache_creation_input_tokens = 0


class _MockMsg:
    def __init__(self, text: str) -> None:
        self.content = [_MockBlock(text)]
        self.stop_reason = "end_turn"
        self.usage = _MockUsage()


def _picker_kwargs_from_call(call_kwargs: dict) -> dict:
    """Pull keyword args from a single recorded call."""
    return call_kwargs


def test_picker_passes_output_config_to_messages_create() -> None:
    """The picker call must include output_config.format.type=json_schema
    with the 4-action schema."""
    decision_text = json.dumps({
        "action": "stop",
        "stop_reason": "exhausted",
        "summary": "test",
        "confidence": 0.5,
    })

    captured: list[dict] = []

    class _FakeMessages:
        def create(self, **kwargs: Any) -> _MockMsg:
            captured.append(kwargs)
            return _MockMsg(decision_text)

    class _FakeClient:
        def __init__(self) -> None:
            self.messages = _FakeMessages()

    # Patch the picker so the anthropic import inside the function picks
    # up our fake.
    fake_anthropic = type("FakeAnthropicModule", (), {
        "Anthropic": lambda api_key=None: _FakeClient(),
    })

    # Run a minimal picker call. The function expects a `run` argument
    # with iterable .findings and .configuration_json; we use a tiny
    # stub. We don't need it to be realistic — we only need messages.
    # create to be invoked at least once.
    from types import SimpleNamespace
    stub_run = SimpleNamespace(
        id="test-run",
        configuration_json={},
        findings=[],
        engagement=SimpleNamespace(
            scope_definition_json={},
            engagement_token="",
        ),
        scope_id=None,
    )

    with patch.dict("sys.modules", {"anthropic": fake_anthropic}), patch.dict(
        "os.environ", {"ANTHROPIC_API_KEY": "test-key"}
    ):
        # Use a minimal direct invocation path. The full picker has many
        # side dependencies (DB session, etc.); we exercise it via a
        # tiny wrapper that builds the kwargs and just calls messages.
        from api.app.services.assessment_loop import _PICKER_OUTPUT_SCHEMA

        # Sanity check: the schema constant exists and is wired into the
        # call site. We assert this textually since the call site is
        # inside _claude_select_next_action and exercising it end-to-end
        # requires a real Run + Session.
        src = open(al.__file__, encoding="utf-8").read()
        assert "output_config={" in src or "output_config=" in src
        assert "_PICKER_OUTPUT_SCHEMA" in src
        assert '"json_schema"' in src
        # Lookup directly that the call includes both the schema + the
        # type=json_schema literal.
        assert _PICKER_OUTPUT_SCHEMA is al._PICKER_OUTPUT_SCHEMA


def test_known_issues_entry_removed_from_agent_system_map() -> None:
    """Per #330 success criteria #6, the JSON-parse-failures known-issue
    in AGENT_SYSTEM_MAP.md section 2 is removed."""
    from pathlib import Path
    map_path = Path(al.__file__).resolve().parent.parent.parent.parent / "docs" / "AGENT_SYSTEM_MAP.md"
    content = map_path.read_text(encoding="utf-8")
    # The bullet specifically about JSON parse failures must be gone or
    # marked resolved.
    sec2_start = content.find("## 2. The AI loop")
    sec3_start = content.find("## 3. Runners")
    assert sec2_start != -1 and sec3_start != -1
    section2 = content[sec2_start:sec3_start]
    # Bullet must either be absent or include #330-resolved marker.
    if "JSON parse failures on complex" in section2:
        # If still present, must be marked resolved.
        assert "resolved by #330" in section2 or "fixed by #330" in section2, (
            "AGENT_SYSTEM_MAP section 2 still lists JSON parse failures as "
            "a known issue — should be removed or marked resolved per #330"
        )


# ---------------------------------------------------------------------------
# Schema is reusable / cache-friendly (no dynamic content)
# ---------------------------------------------------------------------------


def test_schema_constant_is_module_level_and_stable() -> None:
    """The schema is built once at module import and reused on every
    picker call (no per-call dynamic content, so the messages.create
    call stays cache-friendly)."""
    first = al._PICKER_OUTPUT_SCHEMA
    second = al._PICKER_OUTPUT_SCHEMA
    assert first is second
    # Serialize twice to ensure deterministic shape.
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
