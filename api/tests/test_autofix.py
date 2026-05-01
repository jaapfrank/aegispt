from __future__ import annotations

import json
from collections.abc import Iterator

from fastapi.testclient import TestClient

from api.app.config import Settings, get_settings
from api.app.models import (
    Engagement,
    EvidenceArtifact,
    Finding,
    FindingRemediation,
    InventorySnapshot,
    Run,
    RunProfile,
    Task,
    ToolExecution,
)
from api.app.services.autofix import DeterministicAutoFixProvider, ensure_autofix_for_finding


def _build_autofix_client(
    tmp_path,
    monkeypatch,
    *,
    enabled: bool,
    provider: str = "disabled",
) -> Iterator[TestClient]:
    database_path = tmp_path / f"aegispt-autofix-{provider}.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "manual")
    monkeypatch.setenv("AI_AUTOFIX_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("AI_AUTOFIX_PROVIDER", provider)

    from api.app.main import create_app

    get_settings.cache_clear()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


def _seed_finding(
    session,
    *,
    title: str,
    summary: str | None,
    with_inventory: bool = True,
    stdout_text: str = "https://portal.example.test/login [sql injection: interpolated email query]",
    technology_vendor: str = "Python Software Foundation",
    technology_product: str = "FastAPI",
    technology_version: str = "0.111",
) -> Finding:
    engagement = Engagement(
        name="Autofix Engagement",
        client="Acme Corp",
        roe_ref="ROE-AUTOFIX",
        status="active",
    )
    profile = RunProfile(
        name="autofix-profile",
        run_class="active",
        limits_json={"tools": ["httpx"], "approval_required": False},
    )
    inventory_snapshot = None
    if with_inventory:
        inventory_snapshot = InventorySnapshot(
            engagement=engagement,
            requested_by="autofix-tester",
            normalized_inventory_json={
                "vendor_product_fingerprints": [
                    {
                        "vendor": technology_vendor,
                        "product": technology_product,
                        "version": technology_version,
                        "source": "httpx",
                        "confidence": 0.92,
                        "host": "portal.example.test",
                    }
                ],
                "services": [
                    {
                        "host": "portal.example.test",
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "product": "uvicorn",
                        "source": "httpx",
                    }
                ],
                "http_endpoints": [
                    {
                        "url": "https://portal.example.test/login",
                        "methods": ["GET"],
                        "source": "httpx",
                    }
                ],
            },
            summary_json={"technology_count": 1},
            confidence_score=0.92,
        )
    run = Run(
        engagement=engagement,
        profile=profile,
        source_inventory_snapshot=inventory_snapshot,
        requested_by="autofix-tester",
        status="completed",
        configuration_json={"targets": {"urls": ["https://portal.example.test/login"]}},
    )
    task = Task(
        run=run,
        tool="httpx",
        target_id="https://portal.example.test/login",
        params_json={"profile_name": "safe-web"},
        status="completed",
    )
    execution = ToolExecution(
        task=task,
        runner_digest="sha256:autofix",
        tool_version="httpx 1.7",
        exit_code=0,
        stdout_text=stdout_text,
        stderr_text="",
    )
    artifact = EvidenceArtifact(
        execution=execution,
        kind="http-response",
        uri="artifact://autofix-evidence",
        sha256="a" * 64,
        redaction_state="clean",
        metadata_json={"name": "httpx.txt"},
    )
    finding = Finding(
        run=run,
        source_inventory_snapshot=inventory_snapshot,
        title=title,
        severity="high",
        target_id="https://portal.example.test/login",
        evidence_ref="artifact://autofix-evidence",
        status="open",
        summary=summary,
        finding_origin="standard",
        methodology_tags=["WSTG-INPV-05"],
        ptes_phase="exploitation",
        nist_phase="analysis",
        wstg_id="WSTG-INPV-05",
        wstg_version="4.2",
        control_family="input_validation",
    )
    session.add_all([engagement, profile, run, task, execution, artifact, finding])
    session.commit()
    session.refresh(finding)
    return finding


def test_autofix_is_disabled_by_default_and_theater_stays_readable(client) -> None:
    with client.app.state.session_factory() as session:
        finding = _seed_finding(
            session,
            title="SQL Injection in login lookup",
            summary="User input is concatenated into a SQL query during login lookup.",
        )
        finding_id = finding.id

    response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert response.status_code == 200
    payload = response.json()
    assert payload["autofix"]["available"] is False
    assert payload["autofix"]["enabled"] is False
    assert payload["autofix"]["detail"] == "AutoFix is disabled for this deployment."

    with client.app.state.session_factory() as session:
        stored = session.get(Finding, finding_id)
        assert stored is not None
        assert stored.autofix_json is None


def test_enabled_deterministic_autofix_is_generated_and_persisted(tmp_path, monkeypatch) -> None:
    client_iter = _build_autofix_client(tmp_path, monkeypatch, enabled=True, provider="deterministic")
    client = next(client_iter)
    try:
        with client.app.state.session_factory() as session:
            finding = _seed_finding(
                session,
                title="SQL Injection in login lookup",
                summary="User input is concatenated into a SQL query during login lookup.",
            )
            finding_id = finding.id

        response = client.get(f"/api/v1/findings/{finding_id}/theater")

        assert response.status_code == 200
        payload = response.json()
        assert payload["autofix"]["available"] is True
        assert payload["autofix"]["advisory_only"] is True
        assert payload["autofix"]["provider"] == "deterministic"
        assert payload["autofix"]["confidence"] == "high"
        assert "SELECT * FROM users WHERE email = :email" in payload["autofix"]["patch_after"]
        assert "parameterized query" in payload["autofix"]["patch_explanation"].lower()

        with client.app.state.session_factory() as session:
            stored = session.get(Finding, finding_id)
            assert stored is not None
            assert isinstance(stored.autofix_json, dict)
            assert stored.autofix_json["auto_apply_allowed"] is False
            assert stored.autofix_json["advisory_only"] is True
    finally:
        client_iter.close()
        get_settings.cache_clear()


def test_sparse_evidence_autofix_falls_back_to_low_confidence_guidance(client) -> None:
    with client.app.state.session_factory() as session:
        finding = _seed_finding(
            session,
            title="Weak validation path requires review",
            summary=None,
            with_inventory=False,
            stdout_text="https://portal.example.test/login [manual review required]",
        )
        settings = Settings(ai_autofix_enabled=True, ai_autofix_provider="deterministic")

        generated = ensure_autofix_for_finding(
            session=session,
            finding=finding,
            settings=settings,
            provider=DeterministicAutoFixProvider(),
        )
        session.commit()

        assert generated is not None
        assert generated["confidence"] == "low"
        assert generated["patch_language"] == "text"
        assert "too sparse" in generated["patch_explanation"].lower()


def test_autofix_provider_failure_does_not_mutate_finding(client) -> None:
    class FailingAutoFixProvider:
        name = "failing-test"

        def generate(self, context: dict) -> object:
            raise RuntimeError("provider unavailable")

    with client.app.state.session_factory() as session:
        finding = _seed_finding(
            session,
            title="Missing X-Frame-Options Header",
            summary="Responses are missing frame protection headers.",
        )
        finding_id = finding.id
        settings = Settings(ai_autofix_enabled=True, ai_autofix_provider="deterministic")

        generated = ensure_autofix_for_finding(
            session=session,
            finding=finding,
            settings=settings,
            provider=FailingAutoFixProvider(),
        )
        session.commit()

        assert generated is None
        stored = session.get(Finding, finding_id)
        assert stored is not None
        assert stored.autofix_json is None


def test_chatgpt_autofix_generates_stack_specific_suggestion_and_stores_remediation(
    tmp_path,
    monkeypatch,
) -> None:
    def fake_streaming_autofix(**kwargs):
        input_text = kwargs["input_items"][0]["content"][0]["text"]
        payload = json.loads(input_text)
        stack = payload["stack"]
        assert stack["framework"] == "Express"
        assert payload["finding"]["cwe"] == "CWE-89"
        assert "interpolated email query" in payload["evidence_excerpt"]
        return {
            "patch_language": "javascript",
            "patch_before": "const sql = `SELECT * FROM users WHERE email = '${email}'`;",
            "patch_after": (
                "const sql = \"SELECT * FROM users WHERE email = ?\";\n"
                "const [rows] = await db.execute(sql, [email]);"
            ),
            "patch_explanation": "Use Express database parameter binding for the login lookup.",
            "verification_command": "npm test -- --runInBand security",
            "confidence": "high",
            "model": "gpt-5.4",
            "status": "ok",
        }

    monkeypatch.setattr(
        "api.app.services.autofix.send_chatgpt_backend_streaming_json_request",
        fake_streaming_autofix,
    )
    client_iter = _build_autofix_client(tmp_path, monkeypatch, enabled=True, provider="chatgpt_oauth")
    client = next(client_iter)
    try:
        with client.app.state.session_factory() as session:
            finding = _seed_finding(
                session,
                title="CWE-89 SQL Injection in login lookup",
                summary="User input is concatenated into a SQL query during login lookup.",
                technology_vendor="Node.js",
                technology_product="Express",
                technology_version="4.18",
            )
            finding_id = finding.id

        response = client.get(f"/api/v1/findings/{finding_id}/theater")

        assert response.status_code == 200
        payload = response.json()
        assert payload["autofix"]["available"] is True
        assert payload["autofix"]["provider"] == "chatgpt_oauth"
        assert payload["autofix"]["ai_generated"] is True
        assert "AI-generated suggestion" in payload["autofix"]["disclaimer"]
        assert "db.execute(sql, [email])" in payload["autofix"]["ai_fix_suggestion"]
        assert "Express database parameter binding" in payload["autofix"]["patch_explanation"]

        with client.app.state.session_factory() as session:
            stored = session.get(Finding, finding_id)
            remediation = session.query(FindingRemediation).filter_by(finding_id=finding_id).one()
            assert stored is not None
            assert stored.autofix_json["provider"] == "chatgpt_oauth"
            assert "db.execute(sql, [email])" in remediation.ai_fix_suggestion
    finally:
        client_iter.close()
        get_settings.cache_clear()


def test_chatgpt_autofix_failure_degrades_to_deterministic_fallback(tmp_path, monkeypatch) -> None:
    def failing_streaming_autofix(**kwargs):
        raise RuntimeError("ChatGPT OAuth disconnected")

    monkeypatch.setattr(
        "api.app.services.autofix.send_chatgpt_backend_streaming_json_request",
        failing_streaming_autofix,
    )
    client_iter = _build_autofix_client(tmp_path, monkeypatch, enabled=True, provider="chatgpt_oauth")
    client = next(client_iter)
    try:
        with client.app.state.session_factory() as session:
            finding = _seed_finding(
                session,
                title="Missing X-Frame-Options Header",
                summary="Responses are missing frame protection headers.",
                stdout_text="https://portal.example.test/login [header missing: X-Frame-Options]",
            )
            finding_id = finding.id

        response = client.get(f"/api/v1/findings/{finding_id}/theater")

        assert response.status_code == 200
        payload = response.json()
        assert payload["autofix"]["available"] is True
        assert payload["autofix"]["provider"] == "deterministic"
        assert payload["autofix"]["ai_generated"] is False
        assert "fallback_from_provider" in payload["autofix"]["metadata"]
        assert "X-Frame-Options" in payload["autofix"]["patch_after"]

        with client.app.state.session_factory() as session:
            remediation = session.query(FindingRemediation).filter_by(finding_id=finding_id).first()
            assert remediation is None
    finally:
        client_iter.close()
        get_settings.cache_clear()
