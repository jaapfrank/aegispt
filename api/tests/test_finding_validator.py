from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app.config import Settings, get_settings
from api.app.models import (
    Engagement,
    EvidenceArtifact,
    Finding,
    FindingValidationRecord,
    Run,
    RunProfile,
    Scope,
    Task,
    ToolExecution,
)
from api.app.services.finding_validator import queue_automatic_validations
from api.app.services.run_profiles import ensure_default_run_profiles
from workers.runners.base.contracts import EvidenceArtifact as RunnerArtifact
from workers.runners.base.contracts import RunnerExecution


@contextmanager
def _build_client(
    tmp_path,
    monkeypatch,
    *,
    dispatch_mode: str = "inline",
    auto_validate_findings: bool = False,
) -> Iterator[TestClient]:
    database_path = tmp_path / f"aegispt-finding-validator-{dispatch_mode}-{auto_validate_findings}.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", dispatch_mode)
    monkeypatch.setenv("AUTO_VALIDATE_FINDINGS", "true" if auto_validate_findings else "false")

    from api.app.main import create_app

    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as test_client:
            yield test_client
    finally:
        get_settings.cache_clear()


def _nuclei_result_artifact(*, target: str, title: str) -> RunnerArtifact:
    payload = json.dumps(
        {
            "template-id": "template-validation",
            "matched-at": target,
            "info": {
                "name": title,
                "severity": "medium",
            },
        }
    )
    return RunnerArtifact(
        name="nuclei-results.jsonl",
        content_type="application/x-ndjson",
        data=f"{payload}\n".encode("utf-8"),
        kind="scan-result",
    )


def _seed_source_finding(client: TestClient, *, target: str = "https://app.example.test") -> tuple[UUID, UUID]:
    with client.app.state.session_factory() as session:
        ensure_default_run_profiles(session)
        engagement = Engagement(name="Validator Engagement", client="Acme", roe_ref="ROE-VAL-1")
        session.add(engagement)
        session.flush()
        session.add(
            Scope(
                engagement_id=engagement.id,
                allowlist_json={"urls": [target]},
                denylist_json={},
            )
        )
        session.flush()
        run_profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "passive-web-nuclei-audit")
        )
        assert run_profile is not None

        run = Run(
            engagement_id=engagement.id,
            profile_id=run_profile.id,
            requested_by="validator-tester",
            status="completed",
            configuration_json={
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": run_profile.name,
                "targets": {"urls": [target]},
            },
        )
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id,
            tool="nuclei",
            target_id=target,
            status="completed",
            params_json={
                "profile_name": run_profile.name,
                "run_class": run_profile.run_class,
                "limits": dict(run_profile.limits_json or {}),
            },
        )
        session.add(task)
        session.flush()

        execution = ToolExecution(
            task_id=task.id,
            runner_digest="sha256:source-nuclei",
            tool_version="nuclei test",
            exit_code=0,
            stdout_text="Template validation matched at the approved URL.",
            stderr_text="",
        )
        session.add(execution)
        session.flush()

        artifact = EvidenceArtifact(
            tool_execution_id=execution.id,
            kind="scan-result",
            uri="artifact://source/template-validation",
            sha256="a" * 64,
            redaction_state="clean",
            metadata_json={"name": "nuclei-results.jsonl", "content_type": "application/x-ndjson"},
        )
        session.add(artifact)
        session.flush()

        finding = Finding(
            run_id=run.id,
            title="Template validation",
            severity="medium",
            target_id=target,
            evidence_ref=artifact.uri,
            status="open",
            summary="Template validation matched during the source run.",
        )
        session.add(finding)
        session.commit()
        return finding.id, engagement.id


def test_auto_validation_is_disabled_by_default(tmp_path, monkeypatch) -> None:
    with _build_client(tmp_path, monkeypatch, dispatch_mode="manual", auto_validate_findings=False) as client:
        finding_id, _engagement_id = _seed_source_finding(client)

        with client.app.state.session_factory() as session:
            finding = session.scalar(select(Finding).where(Finding.id == finding_id))
            assert finding is not None

            queued = queue_automatic_validations(
                session=session,
                finding_ids=[finding.id],
                settings=Settings(auto_validate_findings=False, task_dispatch_mode="manual"),
            )
            session.commit()

            refreshed = session.scalar(select(Finding).where(Finding.id == finding_id))
            records = session.scalars(
                select(FindingValidationRecord).where(FindingValidationRecord.finding_id == finding_id)
            ).all()

        assert queued == []
        assert refreshed is not None
        assert refreshed.validation_status == "unvalidated"
        assert records == []


def test_auto_validation_confirms_reproduced_finding(tmp_path, monkeypatch) -> None:
    def fake_dispatch_runner(request):
        validation = request.params.get("validation")
        title = "Template validation"
        if isinstance(validation, dict):
            title = str(validation.get("original_finding_title") or title)
        return RunnerExecution(
            tool=request.tool,
            exit_code=0,
            stdout="Template validation matched at the approved URL.",
            stderr="",
            metadata={
                "runner_digest": "sha256:fake-nuclei",
                "tool_version": "nuclei test",
            },
            artifacts=[_nuclei_result_artifact(target=request.targets[0], title=title)],
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)
    with _build_client(tmp_path, monkeypatch, dispatch_mode="inline", auto_validate_findings=True) as client:
        engagement = client.post(
            "/api/v1/engagements",
            headers={"X-Actor": "validator-operator"},
            json={"name": "Auto Validation Engagement", "client": "Acme", "roe_ref": "ROE-AUTO-1"},
        ).json()
        scope_response = client.post(
            f"/api/v1/engagements/{engagement['id']}/scope",
            headers={"X-Actor": "validator-operator"},
            json={"allowlist_json": {"urls": ["https://app.example.test"]}, "denylist_json": {}},
        )
        assert scope_response.status_code == 201
        run_response = client.post(
            f"/api/v1/engagements/{engagement['id']}/runs",
            headers={"X-Actor": "validator-operator"},
            json={
                "profile_name": "passive-web-nuclei-audit",
                "configuration_json": {
                    "assessment_type": "Website / Web App",
                    "test_profile": "Standard",
                    "execution_profile": "passive-web-nuclei-audit",
                    "targets": {"urls": ["https://app.example.test"]},
                },
            },
        )
        assert run_response.status_code == 201
        run_id = run_response.json()["id"]

        dispatch_response = client.post(
            f"/api/v1/runs/{run_id}/dispatch",
            headers={"X-Actor": "validator-operator"},
        )
        assert dispatch_response.status_code == 200

        with client.app.state.session_factory() as session:
            finding = session.scalar(select(Finding).where(Finding.run_id == UUID(run_id)))
            assert finding is not None
            validation_records = session.scalars(
                select(FindingValidationRecord)
                .where(FindingValidationRecord.finding_id == finding.id)
                .order_by(FindingValidationRecord.created_at.desc(), FindingValidationRecord.id.desc())
            ).all()
            validation_runs = session.scalars(
                select(Run)
                .where(Run.engagement_id == UUID(engagement["id"]))
                .order_by(Run.created_at.desc(), Run.id.desc())
            ).all()

        assert finding.validation_status == "validated_confirmed"
        assert finding.status == "open"
        assert finding.severity == "medium"
        assert finding.evidence_ref
        assert len(validation_records) == 1
        assert validation_records[0].status == "validated_confirmed"
        assert "reproduced" in str(validation_records[0].note).lower()
        assert len(validation_runs) == 2
        theater = client.get(f"/api/v1/findings/{finding.id}/theater")
        assert theater.status_code == 200
        payload = theater.json()
        assert payload["validation"]["label"] == "Verified"
        assert payload["validation"]["status"] == "validated_confirmed"
        assert "reproduced" in payload["validation"]["note"].lower()


def test_auto_validation_marks_not_reproduced_without_mutating_finding(tmp_path, monkeypatch) -> None:
    def fake_dispatch_runner(request):
        validation = request.params.get("validation")
        artifacts = [_nuclei_result_artifact(target=request.targets[0], title="Template validation")]
        stdout = "Template validation matched at the approved URL."
        if isinstance(validation, dict):
            artifacts = [
                RunnerArtifact(
                    name="nuclei-results.jsonl",
                    content_type="application/x-ndjson",
                    data=b"",
                    kind="scan-result",
                )
            ]
            stdout = "Validation completed without a matching template result."
        return RunnerExecution(
            tool=request.tool,
            exit_code=0,
            stdout=stdout,
            stderr="",
            metadata={
                "runner_digest": "sha256:fake-nuclei",
                "tool_version": "nuclei test",
            },
            artifacts=artifacts,
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)
    with _build_client(tmp_path, monkeypatch, dispatch_mode="inline", auto_validate_findings=True) as client:
        engagement = client.post(
            "/api/v1/engagements",
            headers={"X-Actor": "validator-operator"},
            json={"name": "Auto Validation Engagement", "client": "Acme", "roe_ref": "ROE-AUTO-2"},
        ).json()
        client.post(
            f"/api/v1/engagements/{engagement['id']}/scope",
            headers={"X-Actor": "validator-operator"},
            json={"allowlist_json": {"urls": ["https://app.example.test"]}, "denylist_json": {}},
        )
        run_response = client.post(
            f"/api/v1/engagements/{engagement['id']}/runs",
            headers={"X-Actor": "validator-operator"},
            json={
                "profile_name": "passive-web-nuclei-audit",
                "configuration_json": {
                    "assessment_type": "Website / Web App",
                    "test_profile": "Standard",
                    "execution_profile": "passive-web-nuclei-audit",
                    "targets": {"urls": ["https://app.example.test"]},
                },
            },
        )
        run_id = run_response.json()["id"]
        client.post(f"/api/v1/runs/{run_id}/dispatch", headers={"X-Actor": "validator-operator"})

        with client.app.state.session_factory() as session:
            finding = session.scalar(select(Finding).where(Finding.run_id == UUID(run_id)))
            assert finding is not None
            validation_record = session.scalar(
                select(FindingValidationRecord)
                .where(FindingValidationRecord.finding_id == finding.id)
                .order_by(FindingValidationRecord.created_at.desc(), FindingValidationRecord.id.desc())
            )
            validation_run = session.scalar(
                select(Run)
                .where(Run.engagement_id == UUID(engagement["id"]))
                .where(Run.id != UUID(run_id))
            )

        assert finding.validation_status == "validated_not_reproduced"
        assert finding.status == "open"
        assert finding.severity == "medium"
        assert finding.evidence_ref
        assert validation_record is not None
        assert validation_record.status == "validated_not_reproduced"
        assert "did not reproduce" in str(validation_record.note).lower()
        assert validation_run is not None
        assert client.get(f"/api/v1/runs/{validation_run.id}").json()["findings"]["finding_count"] == 0


def test_validation_skips_when_target_leaves_scope(tmp_path, monkeypatch) -> None:
    with _build_client(tmp_path, monkeypatch, dispatch_mode="manual", auto_validate_findings=True) as client:
        finding_id, engagement_id = _seed_source_finding(client)

        with client.app.state.session_factory() as session:
            session.add(
                Scope(
                    engagement_id=engagement_id,
                    allowlist_json={"urls": ["https://other.example.test"]},
                    denylist_json={},
                    created_at=datetime.now(tz=UTC) + timedelta(seconds=5),
                    updated_at=datetime.now(tz=UTC) + timedelta(seconds=5),
                )
            )
            session.commit()

        with client.app.state.session_factory() as session:
            queued = queue_automatic_validations(
                session=session,
                finding_ids=[finding_id],
                settings=Settings(auto_validate_findings=True, task_dispatch_mode="manual"),
            )
            session.commit()
            finding = session.scalar(select(Finding).where(Finding.id == finding_id))
            records = session.scalars(
                select(FindingValidationRecord)
                .where(FindingValidationRecord.finding_id == finding_id)
                .order_by(FindingValidationRecord.created_at.desc(), FindingValidationRecord.id.desc())
            ).all()
            validation_runs = session.scalars(
                select(Run).where(Run.engagement_id == engagement_id)
            ).all()

        assert queued == []
        assert finding is not None
        assert finding.validation_status == "validation_skipped"
        assert len(records) == 1
        assert records[0].status == "validation_skipped"
        assert "outside the current approved scope" in str(records[0].note)
        assert len(validation_runs) == 1
