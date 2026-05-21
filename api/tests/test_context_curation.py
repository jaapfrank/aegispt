"""Unit tests for backlog-411 context curation."""
from __future__ import annotations

from api.app.services.context_curation import (
    CURATE_TRIGGER_FRACTION,
    LARGE_STDOUT_BYTES,
    RECENT_TURN_FLOOR,
    CurationEvent,
    curate_for_picker,
    estimate_tokens,
)

# --- token estimation -----------------------------------------------------


def test_estimate_tokens_handles_string_messages() -> None:
    n = estimate_tokens(["a" * 4000])  # ~1000 tokens at 4 chars/token
    assert 900 <= n <= 1100


def test_estimate_tokens_handles_anthropic_content_list() -> None:
    msg = {
        "role": "user",
        "content": [
            {"type": "text", "text": "x" * 800},
            {"type": "tool_result", "content": [{"text": "y" * 800}]},
        ],
    }
    n = estimate_tokens([msg])
    assert n >= 350  # ~400 tokens roughly


def test_estimate_tokens_empty_is_zero() -> None:
    assert estimate_tokens([]) == 0


# --- no-op when below trigger --------------------------------------------


def test_curator_is_noop_when_well_below_trigger() -> None:
    msgs = [{"role": "user", "content": "small message"}] * 3
    curated, event = curate_for_picker(msgs, max_tokens=120_000)
    assert event.triggered is False
    assert event.summarized_count == 0
    assert event.dropped_count == 0
    assert curated == msgs


# --- triggers above 60% --------------------------------------------------


def _bulky_message(text_len: int) -> dict:
    return {"role": "user", "content": "x" * text_len}


def test_curator_summarizes_older_turns_above_60pct() -> None:
    # Build a message list well past 60% of a small max so the trigger fires.
    msgs = [_bulky_message(4000) for _ in range(20)]  # ~20k chars = ~5k tokens
    curated, event = curate_for_picker(msgs, max_tokens=8000)
    assert event.triggered is True
    # The most recent N turns are preserved as-is; older ones get folded into
    # one synthetic summary at the start.
    assert event.summarized_count == 20 - RECENT_TURN_FLOOR
    assert len(curated) == 1 + RECENT_TURN_FLOOR
    head_text = curated[0]["content"]
    assert head_text.startswith("[curated summary of")


def test_curator_preserves_finding_carriers_even_if_old() -> None:
    msgs = []
    for i in range(20):
        # Embed a "finding" marker in the 3rd message; it must survive.
        content = "x" * 3000 if i != 3 else '{"finding": {"title": "RCE", "severity": "critical"}}'
        msgs.append({"role": "user", "content": content})
    curated, event = curate_for_picker(msgs, max_tokens=8000)
    assert event.triggered is True
    assert event.preserved_finding_count >= 1
    joined = " ".join(
        str(m.get("content")) if isinstance(m, dict) else str(m) for m in curated
    )
    assert '"finding"' in joined
    assert '"RCE"' in joined


def test_curator_preserves_captured_value_carriers() -> None:
    msgs = []
    for i in range(20):
        content = "x" * 3000 if i != 5 else '{"captured_value": {"kind": "credential", "value": "test:test"}}'
        msgs.append({"role": "user", "content": content})
    curated, event = curate_for_picker(msgs, max_tokens=8000)
    assert event.preserved_captured_value_count >= 1
    joined = " ".join(
        str(m.get("content")) if isinstance(m, dict) else str(m) for m in curated
    )
    assert '"captured_value"' in joined


# --- hard trigger (80%) shrinks large stdouts ----------------------------


def test_curator_shrinks_large_raw_stdouts_at_hard_trigger() -> None:
    # Build 9 bulky non-evidence messages that drive both 60% and 80%
    # triggers; one carries a finding marker and must escape the shrinker.
    msgs = []
    for i in range(9):
        if i == 4:
            msgs.append({"role": "user", "content": '{"finding": {"title": "X"}}'})
        else:
            msgs.append({"role": "user", "content": "y" * (LARGE_STDOUT_BYTES * 4)})
    # Force the hard trigger by setting a tiny max_tokens budget.
    curated, event = curate_for_picker(msgs, max_tokens=4000)
    assert event.triggered is True
    # Some messages should be shrunk into the [curated: ...] envelope.
    envelopes = [m for m in curated if isinstance(m, dict) and "[curated:" in str(m.get("content", ""))]
    assert envelopes, "expected at least one curated envelope after hard trigger"
    # Finding-carrier survives.
    assert any('"finding"' in str(m.get("content", "")) for m in curated if isinstance(m, dict))


# --- CurationEvent shape -------------------------------------------------


def test_curation_event_carries_telemetry_attributes() -> None:
    msgs = [_bulky_message(3000) for _ in range(15)]
    _, event = curate_for_picker(msgs, max_tokens=8000)
    assert isinstance(event, CurationEvent)
    assert event.before_tokens >= event.after_tokens
    assert event.before_tokens > 0
    assert event.notes  # at least one note explaining the triggers


# --- sanity: configuration constants ------------------------------------


def test_constants_form_valid_threshold_pair() -> None:
    assert 0 < CURATE_TRIGGER_FRACTION < 1
    assert CURATE_TRIGGER_FRACTION < 1.0
    assert RECENT_TURN_FLOOR >= 1
    assert LARGE_STDOUT_BYTES >= 256
