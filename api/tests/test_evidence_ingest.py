"""Tests for evidence_ingest helpers (backlog-372 deliverable)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from api.app.models import Engagement, EvidenceObservation, Run, RunProfile, Scope, Task
from api.app.services.assessment_graph import build_normalized_evidence_graph
from api.app.services.evidence_ingest import (
    ACCEPTED_ENTITY_TYPES,
    load_run_observations,
    make_observation,
    persist_runner_observations,
)


def _ensure_profiles(client) -> None:
    """Trigger ensure_default_run_profiles via the public endpoint."""
    response = client.get("/api/v1/run-profiles")
    assert response.status_code == 200


def _make_run(session) -> tuple[Run, Task]:
    """Create a minimal engagement + scope + run + task for ingestion tests."""
    profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
    assert profile is not None
    engagement = Engagement(
        name="Evidence Ingest Test",
        client="Acme",
        roe_ref="ROE-INGEST-2026",
        status="active",
    )
    Scope(
        engagement=engagement,
        allowlist_json={"urls": ["https://ingest.example.test"]},
        denylist_json={},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        status="running",
        configuration_json={"targets": {"urls": ["https://ingest.example.test"]}},
        requested_by="ingest-test",
        autonomous_mode=True,
        autonomous_intrusive_allowed=False,
    )
    task = Task(
        run=run,
        tool="target-intel",
        target_id="https://ingest.example.test",
        status="completed",
        params_json={},
    )
    session.add(engagement)
    session.add(run)
    session.add(task)
    session.flush()
    return run, task


def test_make_observation_returns_normalized_dict() -> None:
    obs = make_observation(
        entity_type="asset",
        entity_source_id="example.test",
        entity_label="example.test",
        entity_subtype="host",
        attributes={"server": "nginx"},
        confidence=0.85,
        evidence_refs=["https://example.test"],
    )
    assert obs["entity_type"] == "asset"
    assert obs["entity_source_id"] == "example.test"
    assert obs["entity_label"] == "example.test"
    assert obs["entity_subtype"] == "host"
    assert obs["confidence"] == pytest.approx(0.85)
    assert obs["attributes"] == {"server": "nginx"}
    assert obs["evidence_refs"] == ["https://example.test"]


def test_make_observation_rejects_unknown_entity_type() -> None:
    with pytest.raises(ValueError, match="entity_type"):
        make_observation(
            entity_type="not_a_real_type",
            entity_source_id="x",
            entity_label="x",
        )


def test_make_observation_rejects_empty_required_fields() -> None:
    with pytest.raises(ValueError, match="entity_source_id"):
        make_observation(entity_type="asset", entity_source_id="", entity_label="x")
    with pytest.raises(ValueError, match="entity_label"):
        make_observation(entity_type="asset", entity_source_id="x", entity_label="")


def test_make_observation_clamps_confidence_range() -> None:
    with pytest.raises(ValueError, match="confidence"):
        make_observation(
            entity_type="asset",
            entity_source_id="x",
            entity_label="x",
            confidence=1.5,
        )


def test_accepted_entity_types_match_graph_taxonomy() -> None:
    # The accepted types must be a subset of those that
    # build_normalized_evidence_graph already handles. This guards against
    # accidentally introducing a new entity type via #322 (out_of_scope).
    expected_supported = {
        "asset",
        "api",
        "identity",
        "credential_ref",
        "permission",
        "saas_connector",
    }
    assert ACCEPTED_ENTITY_TYPES == expected_supported


def test_persist_runner_observations_writes_rows_and_loads_back(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, task = _make_run(session)
        observations = [
            make_observation(
                entity_type="asset",
                entity_source_id="ingest.example.test",
                entity_label="ingest.example.test",
                entity_subtype="host",
                confidence=0.8,
            ),
            make_observation(
                entity_type="api",
                entity_source_id="https://ingest.example.test/api/v1",
                entity_label="/api/v1",
                entity_subtype="endpoint",
                confidence=0.7,
            ),
        ]
        written = persist_runner_observations(
            session, run=run, task=task, tool="target-intel", observations=observations
        )
        session.commit()
        assert written == 2

        loaded = load_run_observations(session, run_id=run.id)
        assert len(loaded) == 2
        kinds = sorted(o.entity_type for o in loaded)
        assert kinds == ["api", "asset"]
        # All rows tagged with emitting tool.
        assert {o.emitted_by_tool for o in loaded} == {"target-intel"}


def test_persist_runner_observations_filters_invalid_rows(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, task = _make_run(session)
        # Mix valid + invalid observations. Bad rows are silently dropped.
        observations = [
            make_observation(
                entity_type="asset",
                entity_source_id="valid.example.test",
                entity_label="valid",
            ),
            {"entity_type": "asset"},  # missing source_id/label
            {"entity_type": "nope", "entity_source_id": "x", "entity_label": "x"},  # bad type
            "not_a_dict",  # type error
        ]
        written = persist_runner_observations(
            session, run=run, task=task, tool="t", observations=observations
        )
        session.commit()
        assert written == 1


def test_persist_runner_observations_caps_total(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, task = _make_run(session)
        observations = [
            make_observation(
                entity_type="api",
                entity_source_id=f"https://t.example/{i}",
                entity_label=f"/{i}",
            )
            for i in range(250)
        ]
        written = persist_runner_observations(
            session, run=run, task=task, tool="t", observations=observations
        )
        session.commit()
        # Helper caps at MAX_OBSERVATIONS_PER_TASK = 200.
        assert written == 200


def test_observations_appear_in_normalized_evidence_graph(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, task = _make_run(session)
        observations = [
            make_observation(
                entity_type="asset",
                entity_source_id="graph.example.test",
                entity_label="graph.example.test",
                entity_subtype="host",
                attributes={"server": "test-server"},
                confidence=0.9,
            ),
            make_observation(
                entity_type="identity",
                entity_source_id="graph.example.test#user:alice",
                entity_label="alice",
                entity_subtype="registered_test_user",
                confidence=0.85,
            ),
        ]
        persist_runner_observations(
            session, run=run, task=task, tool="target-intel", observations=observations
        )
        session.commit()

        graph = build_normalized_evidence_graph(session, run_id=run.id)

    node_types = {node["type"] for node in graph["nodes"]}
    assert "asset" in node_types
    assert "identity" in node_types

    asset_nodes = [
        n for n in graph["nodes"]
        if n["type"] == "asset" and n.get("label") == "graph.example.test"
    ]
    assert asset_nodes, "Observation-emitted asset must surface in normalized graph"
    asset = asset_nodes[0]
    assert asset["confidence"] == pytest.approx(0.9)
    assert "observation_id" in asset["data"]
    assert asset["data"]["emitted_by_tool"] == "target-intel"

    identity_nodes = [n for n in graph["nodes"] if n["type"] == "identity" and n["label"] == "alice"]
    assert identity_nodes

    # No regression: graph still emits the run-level structural nodes.
    assert any(n["type"] == "run" for n in graph["nodes"])

    # Observations do not duplicate inventory-derived nodes — each observation
    # is identified by its own source_id prefix.
    asset_ids = [n["id"] for n in graph["nodes"] if n["type"] == "asset"]
    assert len(asset_ids) == len(set(asset_ids))


def test_persist_runner_observations_empty_input_is_noop(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, task = _make_run(session)
        written = persist_runner_observations(
            session, run=run, task=task, tool="x", observations=None
        )
        assert written == 0
        written = persist_runner_observations(
            session, run=run, task=task, tool="x", observations=[]
        )
        assert written == 0


def test_load_run_observations_scoped_by_run(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run_a, task_a = _make_run(session)
        run_b, task_b = _make_run(session)
        persist_runner_observations(
            session,
            run=run_a,
            task=task_a,
            tool="a",
            observations=[
                make_observation(
                    entity_type="asset",
                    entity_source_id="a.example.test",
                    entity_label="a",
                )
            ],
        )
        persist_runner_observations(
            session,
            run=run_b,
            task=task_b,
            tool="b",
            observations=[
                make_observation(
                    entity_type="asset",
                    entity_source_id="b.example.test",
                    entity_label="b",
                )
            ],
        )
        session.commit()

        for_a = load_run_observations(session, run_id=run_a.id)
        for_b = load_run_observations(session, run_id=run_b.id)
        assert len(for_a) == 1 and for_a[0].entity_label == "a"
        assert len(for_b) == 1 and for_b[0].entity_label == "b"
