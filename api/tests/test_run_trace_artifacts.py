from __future__ import annotations

import json

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import AuditEvent, Engagement, Run, Scope, Task, ToolExecution
from api.app.services.artifact_storage import (
    artifact_storage_config_from_settings,
    load_artifact_content,
)
from api.app.services.run_trace_artifacts import (
    RUN_TRACE_ARTIFACT_KIND,
    persist_run_trace_artifact,
)


def _create_run_with_execution(session, *, enabled: bool) -> Run:
    engagement = Engagement(name="Trace Artifact", client="ACME", status="active")
    session.add(engagement)
    session.flush()
    session.add(
        Scope(
            engagement_id=engagement.id,
            allowlist_json={"urls": ["https://lab.example.test"]},
            denylist_json={},
        )
    )
    run = Run(
        engagement_id=engagement.id,
        requested_by="pytest",
        status="completed",
        configuration_json={
            "run_trace_artifact": {
                "enabled": enabled,
                "lab_truth": "known_vulnerable",
            },
            "targets": {"urls": ["https://lab.example.test"]},
        },
    )
    session.add(run)
    session.flush()
    task = Task(
        run_id=run.id,
        tool="interactive-exploit",
        target_id="https://lab.example.test",
        params_json={"scenario_id": "non-held-out-demo"},
        status="completed",
    )
    session.add(task)
    session.flush()
    session.add(
        ToolExecution(
            task_id=task.id,
            runner_digest="workers.interactive-exploit.runner:v1",
            tool_version="interactive-exploit",
            exit_code=0,
            stdout_text="attempted chain, no marker",
            stderr_text="",
        )
    )
    session.flush()
    return run


def test_opt_in_run_trace_artifact_persists_jsonl_on_latest_execution(inline_client, tmp_path, monkeypatch):
    monkeypatch.setenv("ARTIFACTS_INLINE_DIR", str(tmp_path / "artifacts"))
    get_settings.cache_clear()

    with inline_client.app.state.session_factory() as session:
        run = _create_run_with_execution(session, enabled=True)
        artifact = persist_run_trace_artifact(session=session, run=run, actor="pytest")
        assert artifact is not None
        assert artifact.kind == RUN_TRACE_ARTIFACT_KIND
        assert artifact.metadata_json["derived_run_artifact"] is True
        assert artifact.metadata_json["lab_truth"] == "known_vulnerable"

        second = persist_run_trace_artifact(session=session, run=run, actor="pytest")
        assert second is not None
        assert second.id == artifact.id

        config = artifact_storage_config_from_settings(get_settings())
        content = load_artifact_content(config=config, uri=artifact.uri)
        assert content is not None
        rows = [json.loads(line) for line in content.data.decode("utf-8").splitlines()]
        assert rows[-1]["final_outcome"] == "no_confirmed_finding"
        assert rows[-1]["no_finding"]["lab_truth"] == "known_vulnerable"

        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "run.trace_artifact.persisted",
                AuditEvent.object_id == str(run.id),
            )
        )
        assert audit is not None
        session.commit()


def test_run_trace_artifact_is_disabled_by_default(inline_client):
    with inline_client.app.state.session_factory() as session:
        run = _create_run_with_execution(session, enabled=False)
        assert persist_run_trace_artifact(session=session, run=run, actor="pytest") is None
