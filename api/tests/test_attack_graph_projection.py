"""Unit tests for backlog-405 — RECENT_CHAINS attack-graph projection.

The picker prompt now includes a RECENT_CHAINS section that projects each
captured_value entity as a causal chain string (lineage on the left, generic
consumer-class hint on the right). This complements the existing
RECENT_CAPTURES section (#334) which lists captures flat.

Per `feedback_no_prescriptive_recipes` + `feedback_live_proof_must_be_diverse_real_targets`:
the consumer hint is generic ("next HTTP step needing session auth"), NOT
per-runner ("POST /admin with cookie=${sid}"). The picker decides specific
next-step; this projection narrows his decision space.
"""
from __future__ import annotations

from api.app.services.assessment_graph import (
    _PROJECTION_LINE_CHAR_CAP,
    _PROJECTION_RECENT_CHAINS_LIMIT,
    _consumer_hint_for_kind,
    _project_chains,
    project_graph_for_picker,
)


def _capture_node(
    *,
    var_name: str = "sid",
    value_kind: str = "cookie",
    origin_step: str = "login_post",
    created_at: str = "2026-05-20T10:00:00Z",
    label: str | None = None,
) -> dict:
    return {
        "type": "captured_value",
        "subtype": value_kind,
        "label": label or var_name,
        "attributes": {
            "var_name": var_name,
            "value_kind": value_kind,
            "origin_step_name": origin_step,
            "created_at": created_at,
            "redacted_preview": "…abcd",
        },
    }


def test_project_chains_empty_returns_empty() -> None:
    """No captures → no chain lines (section omitted by caller)."""
    assert _project_chains([]) == []


def test_project_chains_emits_one_line_per_capture() -> None:
    """Single cookie capture produces one chain line with correct lineage."""
    captures = [_capture_node(var_name="sid", value_kind="cookie", origin_step="login_post")]
    lines = _project_chains(captures)
    assert len(lines) == 1
    line = lines[0]
    assert "[step=login_post]" in line
    assert "captured cookie=sid" in line
    assert "${login_post.sid}" in line
    assert "session auth" in line


def test_project_chains_caps_at_5() -> None:
    """Max chains projected is _PROJECTION_RECENT_CHAINS_LIMIT."""
    captures = [
        _capture_node(var_name=f"var{i}", origin_step=f"step{i}", created_at=f"2026-05-20T10:{i:02d}:00Z")
        for i in range(8)
    ]
    lines = _project_chains(captures)
    assert len(lines) == _PROJECTION_RECENT_CHAINS_LIMIT == 5


def test_project_chains_sorts_by_created_at_desc() -> None:
    """Most-recent captures appear first."""
    captures = [
        _capture_node(var_name="old", created_at="2026-05-20T08:00:00Z"),
        _capture_node(var_name="new", created_at="2026-05-20T10:00:00Z"),
        _capture_node(var_name="middle", created_at="2026-05-20T09:00:00Z"),
    ]
    lines = _project_chains(captures)
    assert "captured cookie=new" in lines[0]
    assert "captured cookie=middle" in lines[1]
    assert "captured cookie=old" in lines[2]


def test_project_chains_truncates_per_line_cap() -> None:
    """Pathologically long values don't blow past the per-line cap."""
    captures = [_capture_node(var_name="x" * 200, origin_step="y" * 200)]
    lines = _project_chains(captures)
    assert len(lines) == 1
    assert len(lines[0]) <= _PROJECTION_LINE_CHAR_CAP


def test_project_chains_handles_missing_attributes() -> None:
    """Capture node with no attributes dict shouldn't crash; falls back
    to safe defaults."""
    bare = {"type": "captured_value", "label": "raw_label"}
    lines = _project_chains([bare])
    assert len(lines) == 1
    assert "raw_label" in lines[0]
    assert "other" in lines[0]  # default value_kind


def test_consumer_hint_for_kind_known_kinds() -> None:
    assert "session auth" in _consumer_hint_for_kind("cookie")
    assert "bearer" in _consumer_hint_for_kind("bearer_token")
    assert "CSRF token" in _consumer_hint_for_kind("csrf_token")
    assert "host" in _consumer_hint_for_kind("hostname")
    assert "vault" in _consumer_hint_for_kind("credential_ref")


def test_consumer_hint_for_kind_unknown_falls_back() -> None:
    hint = _consumer_hint_for_kind("totally_unknown_kind")
    assert "needing this value" in hint


def test_consumer_hint_for_kind_case_insensitive() -> None:
    """Mixed-case value_kinds still match the table."""
    assert _consumer_hint_for_kind("COOKIE") == _consumer_hint_for_kind("cookie")
    assert _consumer_hint_for_kind("Bearer_Token") == _consumer_hint_for_kind("bearer_token")


def test_project_graph_for_picker_emits_recent_chains_section() -> None:
    """End-to-end: when the graph carries captured_value nodes, the
    picker projection contains a RECENT_CHAINS section."""
    graph = {
        "nodes": [
            {
                "type": "asset",
                "label": "example.test",
                "confidence": 0.9,
            },
            _capture_node(var_name="sid", value_kind="cookie", origin_step="login_post"),
        ],
    }
    text = project_graph_for_picker(graph)
    assert "RECENT_CHAINS (1):" in text
    assert "[step=login_post] captured cookie=sid" in text
    # RECENT_CAPTURES still present below (raw-data view kept for compat)
    assert "RECENT_CAPTURES (1):" in text


def test_project_graph_for_picker_omits_chains_when_no_captures() -> None:
    """Graph with assets but no captured_value → no RECENT_CHAINS section."""
    graph = {
        "nodes": [
            {"type": "asset", "label": "example.test", "confidence": 0.9},
        ],
    }
    text = project_graph_for_picker(graph)
    assert "RECENT_CHAINS" not in text


def test_recent_chains_precedes_recent_captures_in_projection() -> None:
    """The strategic chain view must appear BEFORE the raw-data captures
    so the picker reads decision-narrowing context first."""
    graph = {
        "nodes": [_capture_node(var_name="sid", origin_step="login_post")],
    }
    text = project_graph_for_picker(graph)
    chains_pos = text.find("RECENT_CHAINS")
    captures_pos = text.find("RECENT_CAPTURES")
    assert chains_pos > 0
    assert captures_pos > 0
    assert chains_pos < captures_pos


def test_no_app_specific_seeds_in_consumer_hints() -> None:
    """Per feedback_no_prescriptive_recipes: hints are GENERIC, no
    per-target paths or per-runner names."""
    forbidden = (
        "wp-login", "phpmyadmin", "/admin", "is_admin=true", "/api/v1",
        "google-gruyere", "juice-shop", "testfire", "mantis", "mediawiki",
        "roundcube", "gitea", "etherpad", "/dump.gtl", "/elmah.axd",
    )
    for kind, hint in [
        ("cookie", _consumer_hint_for_kind("cookie")),
        ("token", _consumer_hint_for_kind("token")),
        ("csrf_token", _consumer_hint_for_kind("csrf_token")),
        ("bearer_token", _consumer_hint_for_kind("bearer_token")),
        ("hostname", _consumer_hint_for_kind("hostname")),
        ("credential_ref", _consumer_hint_for_kind("credential_ref")),
        ("url", _consumer_hint_for_kind("url")),
        ("unknown", _consumer_hint_for_kind("unknown")),
    ]:
        lowered = hint.lower()
        for token in forbidden:
            assert token.lower() not in lowered, (
                f"hint for {kind!r} contains forbidden seed {token!r}: {hint!r}"
            )


def test_chain_line_includes_reference_syntax_picker_can_use() -> None:
    """The ${origin_step.var_name} interpolation syntax must appear
    verbatim in the chain line so the picker prompt addendum (#343)
    can teach Claude to reference captures by name."""
    captures = [_capture_node(var_name="session_id", origin_step="auth_register")]
    line = _project_chains(captures)[0]
    assert "${auth_register.session_id}" in line
