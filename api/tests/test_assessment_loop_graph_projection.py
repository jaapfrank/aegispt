"""Tests for project_graph_for_picker — backlog-373 (Mythos #323).

These tests exercise the projection helper directly with synthetic graph
payloads. End-to-end picker integration is exercised by existing
test_assessment_loop.py suites and live runs at the Phase 1 review
checkpoint (#324).
"""

from __future__ import annotations

import pytest

from api.app.services.assessment_graph import project_graph_for_picker


def _make_node(
    *,
    node_id: str,
    node_type: str,
    label: str,
    confidence: float = 0.7,
    subtype: str | None = None,
) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "subtype": subtype,
        "label": label,
        "confidence": confidence,
        "evidence_refs": [],
        "source_ids": [node_id],
        "data": {},
    }


def test_empty_graph_returns_empty_string() -> None:
    assert project_graph_for_picker({}) == ""
    assert project_graph_for_picker({"nodes": []}) == ""
    assert project_graph_for_picker({"nodes": [], "edges": []}) == ""


def test_non_dict_input_returns_empty_string() -> None:
    assert project_graph_for_picker(None) == ""  # type: ignore[arg-type]
    assert project_graph_for_picker([]) == ""  # type: ignore[arg-type]
    assert project_graph_for_picker("nope") == ""  # type: ignore[arg-type]


def test_only_finding_nodes_returns_empty_projection() -> None:
    # Findings are surfaced separately by the picker via its existing
    # findings block. The graph projection intentionally omits them so the
    # picker prompt doesn't duplicate the info.
    graph = {
        "nodes": [
            _make_node(
                node_id="finding:1",
                node_type="finding",
                label="Stored XSS via comment field",
                confidence=0.95,
            )
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    # Either fully empty (no asset/api/identity/credential/permission/saas/path)
    # or non-empty without the finding label.
    assert "Stored XSS via comment field" not in out


def test_single_asset_renders_minimal_block() -> None:
    graph = {
        "nodes": [
            _make_node(
                node_id="asset:host:example.test",
                node_type="asset",
                subtype="host",
                label="example.test",
                confidence=0.9,
            )
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    assert out
    assert "=== EVIDENCE GRAPH" in out
    assert "ASSETS (1):" in out
    assert "[host] example.test" in out
    assert "conf=0.90" in out


def test_multi_type_block_orders_groups_consistently() -> None:
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="asset", label="a.test"),
            _make_node(node_id="api1", node_type="api", label="/api/v1"),
            _make_node(node_id="id1", node_type="identity", label="alice"),
            _make_node(node_id="c1", node_type="credential_ref", label="session"),
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    # Group ordering: ASSETS, APIS, IDENTITIES, CREDENTIALS
    assets_pos = out.index("ASSETS")
    apis_pos = out.index("APIS")
    id_pos = out.index("IDENTITIES")
    cred_pos = out.index("CREDENTIALS")
    assert assets_pos < apis_pos < id_pos < cred_pos


def test_confidence_descending_within_group() -> None:
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="api", label="/low", confidence=0.3),
            _make_node(node_id="a2", node_type="api", label="/high", confidence=0.95),
            _make_node(node_id="a3", node_type="api", label="/mid", confidence=0.6),
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    # High-confidence entries appear first within the APIS group.
    assert out.index("/high") < out.index("/mid") < out.index("/low")


def test_truncation_caps_per_group_and_emits_more_suffix() -> None:
    graph = {
        "nodes": [
            _make_node(
                node_id=f"api:{i}",
                node_type="api",
                label=f"/path-{i}",
                confidence=0.5 + (i / 100.0),
            )
            for i in range(50)
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    assert "APIS (50):" in out
    # +N more suffix appears when group exceeds cap.
    assert "+25 more" in out


def test_overall_char_budget_respected() -> None:
    # 200 nodes with long-ish labels; ensure total output stays bounded.
    graph = {
        "nodes": [
            _make_node(
                node_id=f"a:{i}",
                node_type="api",
                label="/api/" + ("x" * 50) + f"/{i}",
                confidence=0.5,
            )
            for i in range(200)
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph, max_tokens=400)
    # max_tokens=400 → ~1600 char budget. Output should be under ~2 KB.
    assert len(out) <= 2048


def test_per_line_char_cap_for_pathological_labels() -> None:
    long_label = "x" * 5000  # 5 KB label
    graph = {
        "nodes": [
            _make_node(
                node_id="api:huge",
                node_type="api",
                label=long_label,
                confidence=0.5,
            )
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    assert out
    # No single line should contain anywhere near the full 5 KB label.
    for line in out.split("\n"):
        assert len(line) < 800


def test_edges_summary_appears_when_run_relationships_present() -> None:
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="asset", label="a.test"),
            _make_node(node_id="api1", node_type="api", label="/api"),
        ],
        "edges": [
            {
                "source": "run:1",
                "target": "a1",
                "relationship": "has_asset",
                "confidence": 0.9,
                "evidence_refs": [],
            },
            {
                "source": "run:1",
                "target": "api1",
                "relationship": "has_api",
                "confidence": 0.9,
                "evidence_refs": [],
            },
        ],
    }
    out = project_graph_for_picker(graph)
    assert "RUN_RELATIONSHIPS" in out
    assert "has_asset=1" in out
    assert "has_api=1" in out


def test_has_finding_edges_excluded_from_relationship_summary() -> None:
    # has_finding is intentionally excluded since findings have their own
    # picker block.
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="asset", label="a.test"),
        ],
        "edges": [
            {
                "source": "run:1",
                "target": "f1",
                "relationship": "has_finding",
                "confidence": 0.9,
                "evidence_refs": [],
            },
            {
                "source": "run:1",
                "target": "a1",
                "relationship": "has_asset",
                "confidence": 0.9,
                "evidence_refs": [],
            },
        ],
    }
    out = project_graph_for_picker(graph)
    assert "has_finding" not in out
    assert "has_asset=1" in out


def test_deterministic_output_for_same_input() -> None:
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="asset", label="b.test", confidence=0.5),
            _make_node(node_id="a2", node_type="asset", label="a.test", confidence=0.5),
            _make_node(node_id="api1", node_type="api", label="/x"),
        ],
        "edges": [],
    }
    out_1 = project_graph_for_picker(graph)
    out_2 = project_graph_for_picker(graph)
    out_3 = project_graph_for_picker(dict(graph))
    assert out_1 == out_2 == out_3


def test_unknown_node_types_are_silently_ignored() -> None:
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="asset", label="legit.test"),
            _make_node(node_id="x1", node_type="not_in_taxonomy", label="weird"),
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    assert "legit.test" in out
    assert "weird" not in out


def test_subtype_optional() -> None:
    graph = {
        "nodes": [
            _make_node(node_id="a1", node_type="asset", label="example.test"),  # no subtype
        ],
        "edges": [],
    }
    out = project_graph_for_picker(graph)
    assert "example.test" in out
    assert "[]" not in out


def test_50_plus_entities_within_budget(measure: callable = len) -> None:  # noqa: B008
    nodes = []
    for t in ("asset", "api", "identity", "credential_ref", "permission"):
        for i in range(15):
            nodes.append(
                _make_node(
                    node_id=f"{t}:{i}",
                    node_type=t,
                    label=f"{t}-{i}",
                    confidence=0.7,
                )
            )
    graph = {"nodes": nodes, "edges": []}
    out = project_graph_for_picker(graph)
    assert out
    # 75 nodes across 5 types. Each group caps at 25 lines, so all groups
    # render fully but truncate is not triggered for any group.
    assert "+" not in out.split("RUN_RELATIONSHIPS")[0] or "more" not in out  # no truncation triggered


def test_high_confidence_nodes_kept_when_truncating() -> None:
    nodes = [
        _make_node(
            node_id=f"api:{i}",
            node_type="api",
            label=f"/low-{i}",
            confidence=0.1,
        )
        for i in range(30)
    ]
    # Add high-confidence nodes that MUST appear after sorting.
    for i in range(3):
        nodes.append(
            _make_node(
                node_id=f"api:high-{i}",
                node_type="api",
                label=f"/critical-{i}",
                confidence=0.99,
            )
        )
    graph = {"nodes": nodes, "edges": []}
    out = project_graph_for_picker(graph)
    assert "/critical-0" in out
    assert "/critical-1" in out
    assert "/critical-2" in out
