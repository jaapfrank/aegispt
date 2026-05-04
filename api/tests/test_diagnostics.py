from __future__ import annotations

from datetime import UTC, datetime, timedelta

from api.app.models import (
    CveFeedSyncLog,
    Engagement,
    InstanceSetting,
    Run,
    SecretRef,
    Task,
    ToolExecution,
)
from api.app.services.diagnostics import redact_payload, redact_text


def test_diagnostics_surfaces_subsystems_and_actionable_failures(client, monkeypatch) -> None:
    def fake_which(binary: str) -> str | None:
        if binary in {"nmap", "nuclei", "httpx"}:
            return f"/usr/bin/{binary}"
        return None

    monkeypatch.setattr("api.app.services.settings.shutil.which", fake_which)

    with client.app.state.session_factory() as session:
        engagement = Engagement(name="Diagnostics Engagement", client="Acme", roe_ref="ROE-DIAG", status="active")
        session.add(engagement)
        session.flush()
        stale_run = Run(
            engagement_id=engagement.id,
            requested_by="diagnostics-test",
            status="running",
            configuration_json={"targets": {"urls": ["https://example.test"]}},
        )
        stale_run.updated_at = datetime.now(tz=UTC) - timedelta(hours=2)
        failed_run = Run(
            engagement_id=engagement.id,
            requested_by="diagnostics-test",
            status="failed",
            configuration_json={},
        )
        session.add_all([stale_run, failed_run])
        session.flush()
        failed_task = Task(
            run_id=failed_run.id,
            tool="nuclei",
            target_id="https://example.test",
            params_json={"api_token": "raw-token-value"},
            status="failed",
        )
        session.add(failed_task)
        session.flush()
        session.add(
            CveFeedSyncLog(
                tenant_id="default",
                source="nvd",
                status="failed",
                started_at=datetime.now(tz=UTC) - timedelta(minutes=3),
                error_text="HTTP 429 token=raw-feed-token",
                metadata_json={},
            )
        )
        session.commit()

    response = client.get("/api/v1/diagnostics")

    assert response.status_code == 200
    payload = response.json()
    subsystems = {item["id"]: item for item in payload["subsystems"]}
    assert payload["overall_status"] in {"degraded", "missing", "blocked"}
    assert subsystems["app_health"]["status"] == "ready"
    assert subsystems["database_migrations"]["operator_next_step"]
    assert subsystems["worker_dispatch"]["metadata"]["task_dispatch_mode"] == "manual"
    assert subsystems["queue_state"]["metadata"]["task_status_counts"]["failed"] == 1
    assert subsystems["run_stuck"]["metadata"]["stuck_run_ids"]
    assert subsystems["tool_readiness"]["metadata"]["missing_tools"]
    assert subsystems["ai_provider"]["operator_next_step"]
    assert subsystems["deployment_hardening"]["operator_next_step"]
    assert subsystems["deployment_hardening"]["metadata"]["secrets_plaintext_exposed"] is False
    assert subsystems["feed_sync"]["status"] == "blocked"
    assert "raw-feed-token" not in str(payload)
    assert any(item["subsystem"] == "feed_sync" and item["operator_next_step"] for item in payload["recent_failures"])


def test_support_bundle_redacts_secrets_hashes_and_raw_evidence_payloads(client, monkeypatch, tmp_path) -> None:
    secret = "super-secret-value"
    hash_value = "a" * 64
    log_path = tmp_path / "aegispt.log"
    log_path.write_text(
        f"ERROR password={secret} digest={hash_value} Bearer abc.def.ghi\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AEGISPT_LOG_FILE", str(log_path))

    with client.app.state.session_factory() as session:
        engagement = Engagement(name="Bundle Engagement", client="Acme", roe_ref="ROE-BUNDLE", status="active")
        session.add(engagement)
        session.flush()
        run = Run(
            engagement_id=engagement.id,
            requested_by="diagnostics-test",
            status="failed",
            configuration_json={"password": secret},
        )
        session.add(run)
        session.flush()
        task = Task(
            run_id=run.id,
            tool="httpx",
            target_id="https://example.test",
            params_json={"password": secret},
            status="failed",
        )
        session.add(task)
        session.flush()
        session.add(
            ToolExecution(
                task_id=task.id,
                runner_digest=hash_value,
                tool_version="fixture",
                exit_code=1,
                stdout_text=f"raw evidence payload {secret}",
                stderr_text=f"stack trace {hash_value}",
            )
        )
        session.add(
            SecretRef(
                engagement_id=engagement.id,
                vault_pointer="vault://aegispt/bundle-secret",
                purpose="bundle secret",
                encrypted_value=secret,
                metadata_json={"token": secret},
            )
        )
        session.add(
            InstanceSetting(
                tenant_id="default",
                setting_key="diagnostics.secret",
                value_json={"value": True},
                sensitive=True,
                encrypted_value=secret,
                metadata_json={"api_key": secret},
            )
        )
        session.commit()

    response = client.get("/api/v1/diagnostics/support-bundle", headers={"X-Actor": "support-admin"})

    assert response.status_code == 200
    payload = response.json()
    serialized = str(payload)
    assert payload["kind"] == "aegispt.support_bundle"
    assert payload["redaction"]["plaintext_secrets_included"] is False
    assert payload["redaction"]["raw_evidence_payloads_included"] is False
    assert payload["redaction"]["task_stdout_included"] is False
    assert payload["redaction"]["hashes_redacted"] is True
    assert "raw evidence payload" not in serialized
    assert secret not in serialized
    assert hash_value not in serialized
    assert "<redacted" in serialized
    assert payload["runtime_ids"]["recent_tasks"][0]["stdout_included"] is False
    assert payload["recent_logs"][0]["redacted_excerpt"]


def test_diagnostics_redaction_helpers_cover_common_secret_shapes() -> None:
    assert "secret-value" not in redact_text("Authorization: Bearer secret-value")
    assert "user:pass" not in redact_text("proxy=http://user:pass@proxy.example.test:8080")
    assert "http://<redacted>@proxy.example.test:8080" in redact_text("proxy=http://user:pass@proxy.example.test:8080")
    assert "a" * 64 not in redact_text("sha256=" + "a" * 64)
    assert redact_payload({"nested": {"api_key": "secret"}})["nested"]["api_key"] == "<redacted>"
