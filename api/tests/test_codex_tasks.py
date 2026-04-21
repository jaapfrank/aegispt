from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]


def _create_engagement_with_scope(client: TestClient) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Codex Task Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-011",
        },
    )
    engagement_id = response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"domains": ["app.example.com"], "urls": ["https://app.example.com"]},
            "denylist_json": {},
        },
    )
    return engagement_id


def _create_pack(client: TestClient, engagement_id: str) -> str:
    inventory_response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.com"],
                        "technologies": [{"name": "Grafana", "vendor": "Grafana Labs", "confidence": 0.9}],
                        "auth_mechanisms": [{"type": "session-cookie", "confidence": 0.8}],
                        "fingerprints": [{"vendor": "Grafana Labs", "product": "Grafana", "version": "10.4.0"}],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    )
    inventory_id = inventory_response.json()["id"]

    intel_response = client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "intel-operator"},
        json={
            "records": [
                {
                    "source": "vendor-advisory",
                    "advisory_id": "CVE-2026-1001",
                    "title": "Grafana pack refinement candidate",
                    "summary": "Grafana authorization control regression.",
                    "affected_products": ["grafana"],
                    "product_match_hints": ["grafana labs"],
                    "attack_surface_type": "auth",
                    "suggested_test_patterns": ["playwright", "zap"],
                    "confidence": 0.9,
                    "severity": "high",
                }
            ]
        },
    )
    intel_id = intel_response.json()[0]["id"]

    relevance_response = client.post(
        "/api/v1/relevance/analyze",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "inventory_snapshot_id": inventory_id,
            "threat_intel_ids": [intel_id],
            "include_prior_findings": False,
        },
    )
    decision_id = relevance_response.json()["id"]

    pack_response = client.post(
        "/api/v1/packs/generate",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "relevance_decision_id": decision_id,
            "name": "codex-task-pack",
        },
    )
    return pack_response.json()["id"]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_http(url: str, *, timeout_seconds: int = 30) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except URLError as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}") from last_error


def _api_json(base_url: str, path: str, *, method: str = "GET", actor: str = "tester", body: dict | None = None):
    headers = {"X-Actor": actor}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


@contextmanager
def _start_live_server(tmp_path: Path) -> Iterator[str]:
    database_path = tmp_path / "aegispt-codex-live.db"
    codex_repo_root = tmp_path / "codex-repo-root"
    codex_repo_root.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "AEGISPT_CODEX_REPO_ROOT": str(codex_repo_root),
            "DATABASE_URL": f"sqlite+pysqlite:///{database_path}",
            "AUTO_CREATE_TABLES": "true",
            "TASK_DISPATCH_MODE": "inline",
            "APP_PUBLIC_BASE_URL": base_url,
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "api.app.main:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_http(f"{base_url}/health/live")
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _create_pack_via_http(base_url: str) -> tuple[str, str]:
    engagement = _api_json(
        base_url,
        "/api/v1/engagements",
        method="POST",
        actor="tester",
        body={
            "name": "Codex Script Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-012",
        },
    )
    engagement_id = engagement["id"]
    _api_json(
        base_url,
        f"/api/v1/engagements/{engagement_id}/scope",
        method="POST",
        actor="tester",
        body={
            "allowlist_json": {"domains": ["app.example.com"], "urls": ["https://app.example.com"]},
            "denylist_json": {},
        },
    )
    inventory = _api_json(
        base_url,
        "/api/v1/inventory/runs",
        method="POST",
        actor="inventory-operator",
        body={
            "engagement_id": engagement_id,
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.com"],
                        "technologies": [{"name": "Grafana", "vendor": "Grafana Labs", "confidence": 0.9}],
                        "auth_mechanisms": [{"type": "session-cookie", "confidence": 0.8}],
                        "fingerprints": [{"vendor": "Grafana Labs", "product": "Grafana", "version": "10.4.0"}],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    )
    intel = _api_json(
        base_url,
        "/api/v1/threat-intel/ingest",
        method="POST",
        actor="intel-operator",
        body={
            "records": [
                {
                    "source": "vendor-advisory",
                    "advisory_id": "CVE-2026-1002",
                    "title": "Grafana build-lane export validation",
                    "summary": "Validate Codex workspace export and validation handoff.",
                    "affected_products": ["grafana"],
                    "product_match_hints": ["grafana labs"],
                    "attack_surface_type": "auth",
                    "suggested_test_patterns": ["playwright", "zap"],
                    "confidence": 0.9,
                    "severity": "high",
                }
            ]
        },
    )
    relevance = _api_json(
        base_url,
        "/api/v1/relevance/analyze",
        method="POST",
        actor="planner",
        body={
            "engagement_id": engagement_id,
            "inventory_snapshot_id": inventory["id"],
            "threat_intel_ids": [intel[0]["id"]],
            "include_prior_findings": False,
        },
    )
    pack = _api_json(
        base_url,
        "/api/v1/packs/generate",
        method="POST",
        actor="planner",
        body={
            "engagement_id": engagement_id,
            "relevance_decision_id": relevance["id"],
            "name": "codex-workspace-pack",
        },
    )
    return engagement_id, pack["id"]


def test_codex_task_api_creates_and_reads_repo_backed_task(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    response = client.post(
        "/api/v1/codex/tasks",
        headers={"X-Actor": "codex-planner"},
        json={
            "task_type": "pack_refinement",
            "scope": "Refine adaptive pack artifacts inside the controlled build lane.",
            "inputs": {"base_url": "http://127.0.0.1:8000"},
            "constraints": {"touch_runtime": False},
            "expected_output": {"artifacts": ["playwright_flow", "zap_job"]},
            "generation_reason": "Prepare customer-specific refinement without changing runtime behavior.",
            "source_context": {"pack_id": pack_id},
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["generated_by"] == "codex"
    assert payload["source_context"]["pack_id"] == pack_id
    assert payload["task_file"].startswith("codex/tasks/")

    read_response = client.get(f"/api/v1/codex/tasks/{payload['id']}")
    assert read_response.status_code == 200
    assert read_response.json()["id"] == payload["id"]


def test_codex_task_run_returns_safe_commands_and_result(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    create_response = client.post(
        "/api/v1/codex/tasks",
        headers={"X-Actor": "codex-planner"},
        json={
            "task_type": "pack_refinement",
            "scope": "Prepare a Codex workspace and validation handoff for an existing pack.",
            "inputs": {},
            "constraints": {"runtime_mutation": "forbidden"},
            "expected_output": {"workspace_export": True},
            "generation_reason": "Create a controlled Codex build-lane task.",
            "source_context": {"pack_id": pack_id},
        },
    )
    task_id = create_response.json()["id"]

    run_response = client.post(
        f"/api/v1/codex/tasks/{task_id}/run",
        headers={"X-Actor": "codex-runner"},
        json={"base_url": "http://127.0.0.1:8000", "workspace_root": "./codex-workspaces/test-pack"},
    )

    assert run_response.status_code == 200
    result = run_response.json()
    assert result["status"] == "prepared"
    assert result["dry_run"] is True
    assert any("export_codex_pack_workspace.sh" in command for command in result["prepared_commands"])
    assert any("validate_codex_pack.sh" in command for command in result["prepared_commands"])
    assert any(
        command.endswith("./codex-workspaces/test-pack/validation-result.json")
        for command in result["prepared_commands"]
    )
    assert any(hook["path"].endswith(f"/packs/{pack_id}/validate") for hook in result["validation_hooks"])
    playwright_hook = next(hook for hook in result["validation_hooks"] if hook["name"] == "artifact.playwright_flow.validate")
    assert playwright_hook["expected_checks"] == ["has steps array"]
    zap_hook = next(hook for hook in result["validation_hooks"] if hook["name"] == "artifact.zap_job.validate")
    assert zap_hook["expected_checks"] == ["has tool", "has targets or note"]
    assert "./codex-workspaces/test-pack/validation-result.json" in result["output_files"]
    assert result["result_file"].startswith("codex/results/")

    stored_result = client.get(f"/api/v1/codex/tasks/{task_id}/result")
    assert stored_result.status_code == 200
    assert stored_result.json()["task_id"] == task_id


def test_codex_task_list_normalizes_legacy_repo_task_files(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    task_dir = tmp_path / "codex" / "tasks"
    task_dir.mkdir(parents=True, exist_ok=True)
    legacy_task_path = task_dir / "ACTIVE-TASK-20260415-controlled-artifact-reimport.json"
    legacy_task_path.write_text(
        json.dumps(
            {
                "task_type": "codex_artifact_reimport",
                "scope": "Add a supervised mechanism to re-import reviewed Codex workspace artifacts.",
                "inputs": {"build_lane_only": True},
                "constraints": {"no_runtime_mutation": True},
                "expected_output": {"validation_required": True},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    response = client.get("/api/v1/codex/tasks")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["id"] == "ACTIVE-TASK-20260415-controlled-artifact-reimport"
    assert payload[0]["status"] == "legacy"
    assert payload[0]["generated_by"] == "codex"
    assert payload[0]["requested_by"] == "repository"


def test_codex_task_list_skips_catalog_only_json_files(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    task_dir = tmp_path / "codex" / "tasks"
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "product_acceptance_matrix.json").write_text(
        json.dumps(
            {
                "catalog_only": True,
                "matrix_id": "product_acceptance_matrix_v1",
                "scenarios": [{"id": "ui-flow"}],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    response = client.get("/api/v1/codex/tasks")

    assert response.status_code == 200
    assert response.json() == []


def test_codex_workspace_scripts_export_bundle_and_capture_validation_against_live_host(tmp_path) -> None:
    with _start_live_server(tmp_path) as base_url:
        _, pack_id = _create_pack_via_http(base_url)
        task = _api_json(
            base_url,
            "/api/v1/codex/tasks",
            method="POST",
            actor="codex-planner",
            body={
                "task_type": "pack_refinement",
                "scope": "Prepare workspace export and validation handoff for the selected pack.",
                "inputs": {"review_bundle": True},
                "constraints": {"runtime_mutation": False},
                "expected_output": {"workspace_export": True, "validation_required": True},
                "generation_reason": "Exercise the real Codex workspace shell scripts against a live host.",
                "source_context": {"pack_id": pack_id},
            },
        )
        workspace_root = tmp_path / "codex-workspace"
        prepared = _api_json(
            base_url,
            f"/api/v1/codex/tasks/{task['id']}/run",
            method="POST",
            actor="codex-runner",
            body={
                "base_url": base_url,
                "workspace_root": str(workspace_root),
                "dry_run": True,
            },
        )

        assert str(workspace_root / "validation-result.json") in prepared["output_files"]

        export_completed = subprocess.run(
            ["bash", "scripts/export_codex_pack_workspace.sh", base_url, pack_id, str(workspace_root)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        assert "Exported Codex workspace" in export_completed.stdout
        assert (workspace_root / "codex-review-bundle.json").exists()
        assert (workspace_root / "codex-context.json").exists()
        assert (workspace_root / "pack.json").exists()
        assert (workspace_root / "artifacts.json").exists()
        assert (workspace_root / "operator-notes.md").exists()
        assert (workspace_root / "codex-change-summary.md").exists()
        assert (workspace_root / "README.md").exists()

        context_payload = json.loads((workspace_root / "codex-context.json").read_text(encoding="utf-8"))
        assert context_payload["pack_id"] == pack_id
        playwright_hook = next(
            hook for hook in context_payload["validation_hooks"] if hook["name"] == "artifact.playwright_flow.validate"
        )
        assert playwright_hook["expected_checks"] == ["has steps array"]
        assert any(path.endswith("validation-result.json") for path in playwright_hook["workspace_files"])
        zap_hook = next(hook for hook in context_payload["validation_hooks"] if hook["name"] == "artifact.zap_job.validate")
        assert zap_hook["expected_checks"] == ["has tool", "has targets or note"]
        readme_text = (workspace_root / "README.md").read_text(encoding="utf-8")
        assert "validation-result.json" in readme_text
        assert f"bash scripts/validate_codex_pack.sh {base_url} {pack_id} {workspace_root}/validation-result.json" in readme_text

        validation_output = workspace_root / "validation-result.json"
        validate_completed = subprocess.run(
            ["bash", "scripts/validate_codex_pack.sh", base_url, pack_id, str(validation_output)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        assert '"status": "passed"' in validate_completed.stdout
        validation_payload = json.loads(validation_output.read_text(encoding="utf-8"))
        assert validation_payload["status"] == "passed"
        assert validation_payload["executed_by"] == "codex-validator"

        refreshed_bundle = _api_json(base_url, f"/api/v1/packs/{pack_id}/codex-review-bundle")
        assert refreshed_bundle["validations"]
        assert refreshed_bundle["validations"][-1]["status"] == "passed"
