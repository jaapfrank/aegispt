"""Picker plan decoder — extracted from assessment_loop.py (O4 step 6).

Pure deserialization helpers. The Anthropic strict-mode picker schema
constrains certain nested-dict fields to come back as JSON-encoded
strings (grammar complexity budget). This module unwraps them in place
into the dicts downstream runners expect.

Two public helpers:

- ``_decode_step_stringified_fields`` — for one step dict; unwraps the
  step's stringified nested fields and (if present) splits the combined
  ``expect_and_finding`` blob into separate ``expect`` + ``on_success``.
- ``_decode_picker_plan`` — for a full picker decision; if the decision
  carries an ``exec_plan`` / ``level_up`` plan, decode the plan blob and
  then call ``_decode_step_stringified_fields`` on every step.

Names kept underscore-prefixed and re-imported in assessment_loop.py so
no call site moves.
"""
from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("api.app.services.assessment_loop")


# Step fields whose values arrive as JSON-encoded strings per the
# Anthropic-strict-mode + grammar-complexity budget. _decode_picker_plan
# unwraps them into the dicts the runner expects.
# ``expect_and_finding`` is a combined field: a single JSON-encoded
# string containing ``{expect: ..., on_success: ...}`` — split here
# back into the two top-level fields the runner reads.
_STEP_STRINGIFIED_FIELDS = ("json",)


def _decode_step_stringified_fields(step: dict[str, Any]) -> dict[str, Any]:
    """Unwrap step's JSON-encoded fields into dicts the runner expects."""
    if not isinstance(step, dict):
        return step
    for field in _STEP_STRINGIFIED_FIELDS:
        value = step.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        if not value.strip().startswith(("{", "[")):
            continue
        try:
            step[field] = json.loads(value)
        except json.JSONDecodeError:
            pass
    # expect_and_finding → split into {expect, on_success}
    combined = step.get("expect_and_finding")
    if isinstance(combined, str) and combined.strip():
        try:
            parsed = json.loads(combined)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            if isinstance(parsed.get("expect"), dict):
                step["expect"] = parsed["expect"]
            if isinstance(parsed.get("on_success"), dict):
                step["on_success"] = parsed["on_success"]
        # Drop the combined wrapper; runner doesn't read it.
        step.pop("expect_and_finding", None)
    return step


def _decode_picker_plan(decision: dict[str, Any]) -> dict[str, Any]:
    """If the decision is an exec_plan (or level_up + plan) variant, the
    `plan` field arrives as a JSON-encoded string (per the schema). Decode
    it in place so downstream consumers see the same dict shape they used
    to before #330. ALSO unwraps each step's stringified nested fields
    (headers/params/expect/capture/etc.) added 2026-05-21 as Anthropic
    strict-mode workaround. No-op for actions without a `plan` field.

    Returns the (possibly mutated) decision dict for chaining.
    """
    if not isinstance(decision, dict):
        return decision
    plan = decision.get("plan")
    if isinstance(plan, str) and plan:
        try:
            decoded = json.loads(plan)
        except json.JSONDecodeError as exc:
            logger.warning(
                "AI loop: picker plan field was not valid JSON despite schema "
                "constraint — raw=%r (%s)",
                plan[:240], exc,
            )
            return decision
        if isinstance(decoded, dict):
            decision["plan"] = decoded
        plan = decision.get("plan")
    # Unwrap stringified nested fields in each step
    if isinstance(plan, dict):
        steps = plan.get("steps")
        if isinstance(steps, list):
            for i, step in enumerate(steps):
                if isinstance(step, dict):
                    steps[i] = _decode_step_stringified_fields(step)
    return decision
