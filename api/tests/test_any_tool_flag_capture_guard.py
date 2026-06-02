"""E#10: a grader-matchable flag captured by ANY tool must become a canonical
`Flag captured` finding, not only when interactive-exploit captures it.

Found 2026-06-02 on XBEN-020 (SSRF): `smart-web-probe` extracted the flag, the
harness marked solved=true, but NO `Flag captured` finding was persisted, the
solve invariant passed vacuously, and no early-stop fired. `persist_any_tool_flag_capture`
closes that gap; `check_early_stop_on_flag` then early-stops on the new finding.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Finding, Run, Scope, Task, ToolExecution
from api.app.services.assessment_loop_internals.guards import (
    check_early_stop_on_flag,
    persist_any_tool_flag_capture,
)
from api.tests.test_assessment_loop import (
    _create_engagement_and_scope,
    _create_loop_run,
)

FLAG = "xbow-3437878f9302985e6813cd9235d03817"


def _seed_run_with_flag_in_tool_output(client, *, tool: str, stdout: str):
    eng_id = _create_engagement_and_scope(client, {"urls": ["http://127.0.0.176"]})
    run_id = _create_loop_run(client, eng_id, targets={"urls": ["http://127.0.0.176"]})
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        task = Task(
            run_id=run.id, tool=tool, target_id="http://127.0.0.176", status="completed",
        )
        session.add(task)
        session.flush()
        session.add(ToolExecution(
            task_id=task.id, runner_digest="d", tool_version="1", exit_code=0,
            stdout_text=stdout,
        ))
        session.commit()
    return eng_id, run_id


def _scope_for(session, eng_id):
    return session.scalar(select(Scope).where(Scope.engagement_id == UUID(eng_id)))


def test_non_interactive_tool_flag_becomes_canonical_finding(client) -> None:
    # smart-web-probe captured the flag inside a structured-JSON evidence excerpt.
    eng_id, run_id = _seed_run_with_flag_in_tool_output(
        client, tool="smart-web-probe",
        stdout=f'{{"finding_count": 1, "evidence_excerpt": "Internal Service\\nFLAG: {FLAG}\\n"}}',
    )
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        new_flags = persist_any_tool_flag_capture(
            run=run, session=session, scope=_scope_for(session, eng_id),
        )
        session.commit()
    assert FLAG in new_flags
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        finding = session.scalar(
            select(Finding).where(Finding.run_id == run.id, Finding.title.ilike("Flag captured%"))
        )
        assert finding is not None
        assert FLAG in finding.title
        assert finding.severity == "critical"
        assert finding.evidence_ref  # transcript provenance
        assert finding.target_id == "http://127.0.0.176"  # scope provenance
        # and the EXISTING early-stop now fires on this finding
        loop_state: dict = {}
        check_early_stop_on_flag(
            run=run, loop_state=loop_state, configuration={},
            store_loop_state=lambda _c, _s: None,
            build_state=lambda *a, **k: {"ok": True},
            session=session, scope=_scope_for(session, eng_id),
        )
        assert loop_state.get("stop_reason") == "flag_extracted"


def test_idempotent_no_duplicate_flag_finding(client) -> None:
    eng_id, run_id = _seed_run_with_flag_in_tool_output(
        client, tool="ssrf-probe", stdout=f"FLAG: {FLAG}",
    )
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        first = persist_any_tool_flag_capture(run=run, session=session, scope=_scope_for(session, eng_id))
        session.commit()
    assert FLAG in first
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        second = persist_any_tool_flag_capture(run=run, session=session, scope=_scope_for(session, eng_id))
        session.commit()
    assert second == []  # flag already carried by a finding


def test_no_flag_in_output_creates_nothing(client) -> None:
    eng_id, run_id = _seed_run_with_flag_in_tool_output(
        client, tool="nuclei", stdout='{"finding_count": 0, "note": "no flag here"}',
    )
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        new_flags = persist_any_tool_flag_capture(run=run, session=session, scope=_scope_for(session, eng_id))
        assert new_flags == []
