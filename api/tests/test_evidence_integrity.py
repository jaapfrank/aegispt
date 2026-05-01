from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import AuditEvent, Engagement, EvidenceArtifact, Finding, Run, Scope, Task, ToolExecution
from api.app.services.artifact_storage import (
    artifact_storage_config_from_settings,
    store_artifact_bytes_with_fallback,
)
from api.app.services import evidence_integrity
from workers.orchestration.findings import store_findings
from workers.runners.base.contracts import EvidenceArtifact as ContractEvidenceArtifact


@pytest.fixture
def integrity_client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ARTIFACTS_INLINE_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("EVIDENCE_TIMESTAMPING_ENABLED", "false")
    from api.tests.conftest import _build_client

    yield from _build_client(tmp_path, monkeypatch, dispatch_mode="inline")


def _create_run(session) -> tuple[Engagement, Run, Task, ToolExecution]:
    engagement = Engagement(name="Evidence Integrity", client="ACME", status="active")
    session.add(engagement)
    session.flush()
    session.add(
        Scope(
            engagement_id=engagement.id,
            allowlist_json={"cidr_ranges": ["10.0.20.0/24"]},
            denylist_json={},
        )
    )
    run = Run(
        engagement_id=engagement.id,
        requested_by="pytest",
        status="completed",
        configuration_json={"targets": {"cidr_ranges": ["10.0.20.0/24"]}},
    )
    session.add(run)
    session.flush()
    task = Task(
        run_id=run.id,
        tool="nuclei",
        target_id="https://shop.example.test",
        params_json={"templates": ["cves/2021/CVE-2021-41773.yaml"]},
        status="completed",
    )
    session.add(task)
    session.flush()
    execution = ToolExecution(
        task_id=task.id,
        runner_digest="sha256:test-runner",
        tool_version="nuclei 3.2.0",
        exit_code=0,
        stdout_text=("warmup\n" * 250)
        + "Apache path traversal matched https://shop.example.test/cgi-bin/.%2e/%2e%2e/etc/passwd\n"
        + ("tail\n" * 250),
    )
    session.add(execution)
    session.flush()
    return engagement, run, task, execution


def _store_artifact(
    *,
    session,
    task: Task,
    execution: ToolExecution,
    name: str,
    data: bytes,
    sha256_override: str | None = None,
) -> EvidenceArtifact:
    settings = get_settings()
    config = artifact_storage_config_from_settings(settings)
    digest = hashlib.sha256(data).hexdigest()
    stored = store_artifact_bytes_with_fallback(
        config=config,
        artifact_name=name,
        artifact_kind="nuclei-jsonl",
        artifact_digest=digest,
        content_type="application/jsonl",
        data=data,
        run_id=str(task.run_id),
        task_id=str(task.id),
        execution_id=str(execution.id),
    )
    artifact = EvidenceArtifact(
        tool_execution_id=execution.id,
        kind="nuclei-jsonl",
        uri=stored.uri,
        sha256=sha256_override or digest,
        redaction_state="clean",
        metadata_json={
            "name": name,
            "content_type": "application/jsonl",
            "hash_status": "sha256-recorded" if sha256_override is None else "sha256-recorded",
            "timestamp_status": "timestamp-disabled",
            **stored.metadata,
        },
    )
    session.add(artifact)
    session.flush()
    return artifact


def test_inline_artifact_verify_evidence_and_audit_event(integrity_client: TestClient) -> None:
    payload = (
        json.dumps(
            {
                "template-id": "CVE-2021-41773",
                "info": {"name": "Apache path traversal", "severity": "critical"},
                "matched-at": "https://shop.example.test/cgi-bin/.%2e/%2e%2e/etc/passwd",
            }
        )
        + "\n"
    ).encode()

    with integrity_client.app.state.session_factory() as session:
        _, run, task, execution = _create_run(session)
        artifact = _store_artifact(
            session=session,
            task=task,
            execution=execution,
            name="nuclei-results.jsonl",
            data=payload,
        )
        finding = Finding(
            run_id=run.id,
            title="Apache path traversal",
            severity="critical",
            target_id="https://shop.example.test/cgi-bin/.%2e/%2e%2e/etc/passwd",
            evidence_ref=artifact.uri,
            status="open",
            summary="Template CVE-2021-41773 matched.",
            methodology_tags=["owasp-wstg"],
            replay_recipe_json={
                "tool": "nuclei",
                "tool_version": "nuclei 3.2.0",
                "target": "https://shop.example.test",
                "params_json": {"templates": ["cves/2021/CVE-2021-41773.yaml"]},
                "scope_allowlist": ["10.0.20.0/24"],
                "expected_match_pattern": "Apache path traversal",
            },
        )
        session.add(finding)
        session.commit()
        finding_id = str(finding.id)

    response = integrity_client.post(f"/api/v1/findings/{finding_id}/evidence/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verified"
    assert body["current_sha256"] == hashlib.sha256(payload).hexdigest()
    assert body["timestamp_status"] == "timestamp-disabled"

    with integrity_client.app.state.session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == finding_id,
                AuditEvent.action == "finding.evidence_integrity.verified",
            )
        )
        assert audit is not None
        assert audit.metadata_json["status"] == "verified"


def test_hash_mismatch_returns_integrity_failure(integrity_client: TestClient) -> None:
    data = b'{"finding":"tamper-test"}\n'
    with integrity_client.app.state.session_factory() as session:
        _, run, task, execution = _create_run(session)
        artifact = _store_artifact(
            session=session,
            task=task,
            execution=execution,
            name="nuclei-results.jsonl",
            data=data,
            sha256_override="0" * 64,
        )
        finding = Finding(
            run_id=run.id,
            title="Tamper test",
            severity="medium",
            target_id="https://shop.example.test",
            evidence_ref=artifact.uri,
            status="open",
            summary="Synthetic mismatch.",
            methodology_tags=[],
            replay_recipe_json={
                "tool": "nuclei",
                "tool_version": "nuclei 3.2.0",
                "target": "https://shop.example.test",
                "params_json": {},
                "scope_allowlist": ["10.0.20.0/24"],
                "expected_match_pattern": "tamper-test",
            },
        )
        session.add(finding)
        session.commit()
        finding_id = str(finding.id)

    response = integrity_client.post(f"/api/v1/findings/{finding_id}/evidence/verify")
    assert response.status_code == 200
    assert response.json()["status"] == "integrity-failure"


def test_store_findings_persists_replay_recipe(integrity_client: TestClient) -> None:
    data = (
        json.dumps(
            {
                "template-id": "CVE-2021-41773",
                "info": {
                    "name": "Apache path traversal",
                    "severity": "critical",
                    "classification": {
                        "cvss-score": 9.8,
                        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                },
                "matched-at": "https://shop.example.test",
            }
        )
        + "\n"
    ).encode()

    with integrity_client.app.state.session_factory() as session:
        _, _run, task, execution = _create_run(session)
        artifact_record = _store_artifact(
            session=session,
            task=task,
            execution=execution,
            name="nuclei-results.jsonl",
            data=data,
        )
        contract_artifact = ContractEvidenceArtifact(
            name="nuclei-results.jsonl",
            content_type="application/jsonl",
            data=data,
            kind="nuclei-jsonl",
        )
        findings = store_findings(
            session=session,
            task=task,
            artifact_pairs=[(contract_artifact, artifact_record)],
        )
        session.commit()
        assert len(findings) == 1
        recipe = findings[0].replay_recipe_json
        assert recipe["tool"] == "nuclei"
        assert recipe["tool_version"] == "nuclei 3.2.0"
        assert recipe["target"] == "https://shop.example.test"
        assert recipe["params_json"]["templates"] == ["cves/2021/CVE-2021-41773.yaml"]
        assert recipe["scope_allowlist"] == ["10.0.20.0/24"]
        assert recipe["artifact"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert findings[0].cvss_score == 9.8
        assert findings[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == str(findings[0].id),
                AuditEvent.action == "finding.created",
            )
        )
        assert audit is not None
        assert audit.metadata_json["cvss_score"] == 9.8


def test_artifact_integrity_metadata_sets_timestamp_columns(
    integrity_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with integrity_client.app.state.session_factory() as session:
        _, _run, task, execution = _create_run(session)
        artifact = _store_artifact(
            session=session,
            task=task,
            execution=execution,
            name="nuclei-results.jsonl",
            data=b'{"finding":"timestamp-test"}\n',
        )

        def fake_store_timestamp_response(**_kwargs):
            return {
                "timestamp_status": "stored",
                "timestamp_response_uri": "inline://tasks/timestamp/test.tsr",
            }

        monkeypatch.setattr(
            evidence_integrity,
            "_store_timestamp_response",
            fake_store_timestamp_response,
        )
        evidence_integrity.apply_artifact_integrity_metadata(
            settings=get_settings(),
            storage_config=artifact_storage_config_from_settings(get_settings()),
            artifact_record=artifact,
            artifact_name="nuclei-results.jsonl",
            data=b'{"finding":"timestamp-test"}\n',
            run_id=str(task.run_id),
            task_id=str(task.id),
            execution_id=str(execution.id),
        )
        session.flush()
        assert artifact.timestamp_token_uri == "inline://tasks/timestamp/test.tsr"
        assert artifact.metadata_json["timestamp_response_uri"] == "inline://tasks/timestamp/test.tsr"


def test_evidence_replay_returns_matched_excerpt_and_integrity_context(
    integrity_client: TestClient,
) -> None:
    data = b'{"finding":"apache path traversal"}\n'
    with integrity_client.app.state.session_factory() as session:
        _, run, task, execution = _create_run(session)
        artifact = _store_artifact(
            session=session,
            task=task,
            execution=execution,
            name="nuclei-results.jsonl",
            data=data,
        )
        finding = Finding(
            run_id=run.id,
            title="Apache path traversal",
            severity="critical",
            target_id="https://shop.example.test",
            evidence_ref=artifact.uri,
            status="open",
            summary="Apache path traversal matched.",
            methodology_tags=[],
            replay_recipe_json={
                "tool": "nuclei",
                "tool_version": "nuclei 3.2.0",
                "target": "https://shop.example.test",
                "params_json": {},
                "scope_allowlist": ["10.0.20.0/24"],
                "expected_match_pattern": "Apache path traversal",
            },
        )
        session.add(finding)
        session.commit()
        finding_id = str(finding.id)

    theater = integrity_client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater.status_code == 200
    theater_body = theater.json()
    assert theater_body["evidence_integrity"]["ready_for_replay"] is True
    assert theater_body["verification_status"] == "evidence-linked and ready for replay"

    evidence = integrity_client.get(f"/api/v1/findings/{finding_id}/evidence")
    assert evidence.status_code == 200
    stdout_excerpt = evidence.json()["related_executions"][0]["stdout_excerpt"]
    assert "Apache path traversal matched" in stdout_excerpt
    assert len(stdout_excerpt) <= 4000


def test_bulk_verify_run_evidence(integrity_client: TestClient) -> None:
    with integrity_client.app.state.session_factory() as session:
        _, run, task, execution = _create_run(session)
        for index in range(2):
            data = f'{{"finding":"bulk-{index}"}}\n'.encode()
            artifact = _store_artifact(
                session=session,
                task=task,
                execution=execution,
                name=f"nuclei-results-{index}.jsonl",
                data=data,
            )
            session.add(
                Finding(
                    run_id=run.id,
                    title=f"Bulk finding {index}",
                    severity="low",
                    target_id=f"https://shop.example.test/{index}",
                    evidence_ref=artifact.uri,
                    status="open",
                    summary="Synthetic bulk evidence.",
                    methodology_tags=[],
                    replay_recipe_json={
                        "tool": "nuclei",
                        "tool_version": "nuclei 3.2.0",
                        "target": f"https://shop.example.test/{index}",
                        "params_json": {},
                        "scope_allowlist": ["10.0.20.0/24"],
                        "expected_match_pattern": f"bulk-{index}",
                    },
                )
            )
        session.commit()
        run_id = str(run.id)

    response = integrity_client.post(f"/api/v1/runs/{run_id}/evidence/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 2
    assert body["verified"] == 2
    assert body["status"] == "verified"
