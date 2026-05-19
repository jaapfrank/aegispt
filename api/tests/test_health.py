from __future__ import annotations

from dataclasses import asdict


def test_live(client) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["detail"] == "service is running"
    assert payload["runtime_state"] == "healthy"
    assert any("runtime_state=healthy" in item for item in payload["diagnostics"])


def test_ready(client) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["detail"] == "database connection verified"


def test_api_docs_available(client) -> None:
    response = client.get("/api/docs")

    assert response.status_code == 200
    assert "swagger-ui" in response.text
    assert "/openapi.json" in response.text


def test_live_reports_shutting_down_state(client) -> None:
    client.app.state.runtime_state = "shutting_down"

    response = client.get("/health/live")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["detail"] == "service is shutting_down"
    assert payload["runtime_state"] == "shutting_down"


def test_full_system_audit_partial_artifacts_include_health_failure(tmp_path) -> None:
    from scripts.run_full_system_acceptance_audit import (
        AuditResult,
        Defect,
        _write_result_artifacts,
    )

    output_json = tmp_path / "partial.json"
    output_md = tmp_path / "partial.md"
    result = AuditResult(
        generated_at="2026-05-02T00:00:00+00:00",
        base_url="http://127.0.0.1:8000",
        duration_seconds=0.1,
        live_environment_relevant=True,
        health={"ok": False, "status": None, "error": "timed out"},
    )
    result.defects.append(
        asdict(
            Defect(
                "critical",
                "local_runtime_unreachable",
                "bootstrap",
                "control_plane",
                "Local runtime health check failed before browser audit",
                "timed out",
                recommended_backlog_target="backlog-181",
            )
        )
    )

    _write_result_artifacts(result, output_json, output_md)

    assert output_json.exists()
    assert output_md.exists()
    assert "local_runtime_unreachable" in output_json.read_text(encoding="utf-8")
    assert "timed out" in output_md.read_text(encoding="utf-8")
