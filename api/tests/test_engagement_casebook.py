from __future__ import annotations

from uuid import UUID

import pytest
from sqlalchemy import select

from api.app.models import Engagement, InventorySnapshot, Run, RunProfile, Scope
from api.app.services.ai_planner import ensure_context_document
from api.app.services.engagement_casebook import (
    CasebookSecretRejectedError,
    build_casebook_from_engagement,
    casebook_context_for_run,
    create_casebook_entry,
    list_casebook_entries,
)


def _create_engagement_run(client, *, tenant_id: str = "tenant-casebook") -> tuple[str, str]:
    client.get("/api/v1/run-profiles")
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        engagement = Engagement(
            name=f"{tenant_id} engagement",
            client=f"{tenant_id} client",
            tenant_id=tenant_id,
            roe_ref=f"ROE-{tenant_id}",
            status="active",
        )
        scope = Scope(
            engagement=engagement,
            allowlist_json={"urls": [f"https://{tenant_id}.example.test"]},
            denylist_json={},
        )
        run = Run(
            engagement=engagement,
            profile=profile,
            requested_by="casebook-tester",
            status="requested",
            autonomous_mode=True,
            configuration_json={
                "run_mode": "ai_loop",
                "targets": {"urls": [f"https://{tenant_id}.example.test"]},
            },
        )
        session.add_all([engagement, scope, run])
        session.commit()
        return str(engagement.id), str(run.id)


def test_casebook_records_evidence_linked_non_secret_memory(client) -> None:
    engagement_id, run_id = _create_engagement_run(client)

    with client.app.state.session_factory() as session:
        engagement = session.get(Engagement, UUID(engagement_id))
        run = session.get(Run, UUID(run_id))
        assert engagement is not None
        assert run is not None

        entry = create_casebook_entry(
            session,
            engagement=engagement,
            tenant_id="tenant-casebook",
            entry_type="architecture_note",
            title="Public API and admin portal observed",
            summary="Prior runs observed a public API and an admin portal behind the same approved host.",
            source_refs=[{"type": "target_context_document", "id": "ctx-001"}],
            created_by="casebook-tester",
            data={"surfaces": ["public-api", "admin-portal"]},
        )
        session.commit()

        assert entry.tenant_id == "tenant-casebook"
        assert entry.source_refs_json == [{"type": "target_context_document", "id": "ctx-001"}]
        assert entry.provenance_json["planning_input_only"] is True
        assert entry.provenance_json["secrets_stored"] is False

        context = casebook_context_for_run(session, run=run)

    assert context["tenant_id"] == "tenant-casebook"
    assert context["planning_input_only"] is True
    assert context["not_evidence"] is True
    assert context["secret_material_stored"] is False
    assert context["entries"][0]["title"] == "Public API and admin portal observed"
    assert context["entries"][0]["source_refs"] == [{"type": "target_context_document", "id": "ctx-001"}]


def test_casebook_rejects_secret_like_text_and_keys(client) -> None:
    engagement_id, _run_id = _create_engagement_run(client)

    with client.app.state.session_factory() as session:
        engagement = session.get(Engagement, UUID(engagement_id))
        assert engagement is not None

        with pytest.raises(CasebookSecretRejectedError):
            create_casebook_entry(
                session,
                engagement=engagement,
                entry_type="operator_constraint",
                title="Do not reuse this credential",
                summary="Bearer abcdefghijklmnopqrstuvwxyz should never be stored.",
                source_refs=[{"type": "operator_note", "id": "note-1"}],
                created_by="casebook-tester",
            )

        with pytest.raises(CasebookSecretRejectedError):
            create_casebook_entry(
                session,
                engagement=engagement,
                entry_type="operator_constraint",
                title="Allowed testing window",
                summary="Only test during the approved weekly window.",
                source_refs=[{"type": "operator_note", "id": "note-2"}],
                created_by="casebook-tester",
                data={"session_cookie": "redacted"},
            )


def test_casebook_entries_are_tenant_isolated(client) -> None:
    engagement_a_id, run_a_id = _create_engagement_run(client, tenant_id="tenant-a")
    engagement_b_id, run_b_id = _create_engagement_run(client, tenant_id="tenant-b")

    with client.app.state.session_factory() as session:
        engagement_a = session.get(Engagement, UUID(engagement_a_id))
        engagement_b = session.get(Engagement, UUID(engagement_b_id))
        run_a = session.get(Run, UUID(run_a_id))
        run_b = session.get(Run, UUID(run_b_id))
        assert engagement_a is not None and engagement_b is not None
        assert run_a is not None and run_b is not None

        create_casebook_entry(
            session,
            engagement=engagement_a,
            tenant_id="tenant-a",
            entry_type="blocked_path",
            title="Tenant A blocked path",
            summary="A route was blocked by missing operator approval.",
            source_refs=[{"type": "rationale_ledger_entry", "id": "rle-a"}],
            created_by="casebook-tester",
        )
        create_casebook_entry(
            session,
            engagement=engagement_b,
            tenant_id="tenant-b",
            entry_type="blocked_path",
            title="Tenant B blocked path",
            summary="A route was blocked by missing prerequisite evidence.",
            source_refs=[{"type": "rationale_ledger_entry", "id": "rle-b"}],
            created_by="casebook-tester",
        )
        session.commit()

        assert list_casebook_entries(session, engagement_id=engagement_a.id, tenant_id="tenant-b") == []
        context_a = casebook_context_for_run(session, run=run_a)
        context_b = casebook_context_for_run(session, run=run_b)

    assert [entry["title"] for entry in context_a["entries"]] == ["Tenant A blocked path"]
    assert [entry["title"] for entry in context_b["entries"]] == ["Tenant B blocked path"]


def test_ai_planner_reads_casebook_only_as_planning_input(client) -> None:
    engagement_id, run_id = _create_engagement_run(client)

    with client.app.state.session_factory() as session:
        engagement = session.get(Engagement, UUID(engagement_id))
        run = session.get(Run, UUID(run_id))
        assert engagement is not None
        assert run is not None
        scope = run.engagement.scopes[-1]

        entry = create_casebook_entry(
            session,
            engagement=engagement,
            entry_type="target_context",
            title="GraphQL surface previously observed",
            summary="Prior evidence showed a GraphQL endpoint on the approved application host.",
            source_refs=[{"type": "inventory_snapshot", "id": "inventory-graphql"}],
            created_by="casebook-tester",
            data={"surface": "graphql", "confidence": 0.82},
        )
        context_document = ensure_context_document(
            session,
            run=run,
            scope=scope,
            targets=[{"kind": "url", "value": "https://tenant-casebook.example.test"}],
            plan={},
        )
        session.commit()

        casebook_context = context_document.provenance_json["casebook_context"]
        evidence_refs = list(context_document.evidence_refs_json or [])

    assert casebook_context["planning_input_only"] is True
    assert casebook_context["not_evidence"] is True
    assert casebook_context["entries"][0]["id"] == str(entry.id)
    assert casebook_context["entries"][0]["source_refs"] == [
        {"type": "inventory_snapshot", "id": "inventory-graphql"}
    ]
    assert {"type": "inventory_snapshot", "id": "inventory-graphql"} not in evidence_refs


def test_casebook_can_build_summaries_from_existing_engagement_evidence(client) -> None:
    engagement_id, _run_id = _create_engagement_run(client)

    with client.app.state.session_factory() as session:
        engagement = session.get(Engagement, UUID(engagement_id))
        assert engagement is not None
        snapshot = InventorySnapshot(
            engagement=engagement,
            requested_by="casebook-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://tenant-casebook.example.test"],
                "tech_stack_profile": {
                    "language": ["python"],
                    "api_endpoints": ["https://tenant-casebook.example.test/api"],
                },
            },
            summary_json={"url_count": 1},
            confidence_score=0.91,
        )
        session.add(snapshot)
        session.flush()
        snapshot_id = str(snapshot.id)

        created = build_casebook_from_engagement(
            session,
            engagement=engagement,
            actor="casebook-tester",
        )
        created_payload = [
            {
                "entry_type": entry.entry_type,
                "source_refs": list(entry.source_refs_json or []),
                "summary": entry.summary,
            }
            for entry in created
        ]
        session.commit()

    assert len(created_payload) == 1
    assert created_payload[0]["entry_type"] == "architecture_note"
    assert created_payload[0]["source_refs"] == [{"type": "inventory_snapshot", "id": snapshot_id}]
    assert "Observed targets" in created_payload[0]["summary"]
