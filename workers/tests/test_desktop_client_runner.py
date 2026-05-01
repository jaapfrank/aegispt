from __future__ import annotations

import json
from types import SimpleNamespace
import zipfile

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.desktop_client.runner import (
    DESKTOP_CLIENT_INVENTORY_ARTIFACT_NAME,
    DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME,
    execute_desktop_client_assessment,
)


class ArtifactRecord:
    uri = "artifact://desktop-client/results"


def build_desktop_fixture(path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "resources/app/package.json",
            json.dumps(
                {
                    "name": "operator-desktop",
                    "main": "main.js",
                    "build": {"publish": [{"provider": "generic", "url": "http://updates.example.test"}]},
                }
            ),
        )
        archive.writestr(
            "resources/app/config/production.json",
            """
{
  "apiBaseUrl": "http://api.example.test/v1",
  "clientSecret": "desktopsecretvalue123456",
  "helper": "http://127.0.0.1:4372",
  "pipeName": "\\\\.\\pipe\\aegispt-helper"
}
""",
        )
        archive.writestr(
            "resources/app/app-update.yml",
            "provider: generic\nurl: http://updates.example.test\nverifyUpdateCodeSignature: false\n",
        )
        archive.writestr(
            "AppData/Roaming/operator/logs/runtime.log",
            "cached session written to local log",
        )


def test_desktop_client_static_review_creates_safe_evidence_backed_findings(tmp_path) -> None:
    artifact_path = tmp_path / "operator-desktop.zip"
    build_desktop_fixture(artifact_path)

    execution = execute_desktop_client_assessment(
        [str(artifact_path)],
        scope_allowlist={"desktop_artifact_paths": [str(artifact_path)]},
        desktop_metadata={"artifact": str(artifact_path), "code_signing_verified": False},
    )

    assert execution.exit_code == 0
    assert execution.tool == "desktop-client"
    assert execution.metadata["status"] == "completed"
    assert execution.metadata["kernel_driver_analysis_executed"] is False
    assert execution.metadata["process_injection_executed"] is False
    assert execution.metadata["malware_triage_executed"] is False
    assert execution.metadata["raw_secret_disclosure"] is False
    artifact_names = {artifact.name for artifact in execution.artifacts}
    assert DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME in artifact_names
    assert DESKTOP_CLIENT_INVENTORY_ARTIFACT_NAME in artifact_names

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME
    )
    raw_results = results_artifact.data.decode("utf-8")
    assert "desktopsecretvalue123456" not in raw_results
    payload = json.loads(raw_results)
    assert payload["safety"]["kernel_driver_analysis"] is False
    assert payload["safety"]["process_injection"] is False
    assert payload["safety"]["malware_triage"] is False
    assert payload["safety"]["raw_secret_disclosure"] is False
    assert "live_local_helper_probe_not_run" in payload["unsupported_states"]
    finding_types = {finding["type"] for finding in payload["findings"]}
    assert "desktop_embedded_secret_material" in finding_types
    assert "desktop_insecure_transport_endpoint" in finding_types
    assert "desktop_local_helper_ipc_exposure" in finding_types
    assert "desktop_updater_posture_review_required" in finding_types
    assert "desktop_local_storage_log_exposure" in finding_types
    assert "desktop_code_signing_not_verified" in finding_types

    task = SimpleNamespace(tool="desktop-client", target_id=str(artifact_path), params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=DESKTOP_CLIENT_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="desktop-client-results",
        ),
        artifact_record=ArtifactRecord(),
    )
    assert {finding.evidence_ref for finding in findings} == {ArtifactRecord.uri}
    assert "Desktop client contains embedded secret-like material" in {
        finding.title for finding in findings
    }


def test_desktop_client_rejects_out_of_scope_artifact(tmp_path) -> None:
    allowed_path = tmp_path / "allowed.zip"
    outside_path = tmp_path / "outside.zip"
    build_desktop_fixture(allowed_path)
    build_desktop_fixture(outside_path)

    with pytest.raises(ValueError, match="outside scope"):
        execute_desktop_client_assessment(
            [str(outside_path)],
            scope_allowlist={"desktop_artifact_paths": [str(allowed_path)]},
        )


def test_desktop_client_skips_missing_artifact(tmp_path) -> None:
    missing_path = tmp_path / "missing.zip"

    execution = execute_desktop_client_assessment(
        [str(missing_path)],
        scope_allowlist={"desktop_artifact_paths": [str(missing_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_desktop_artifact"


def test_desktop_client_skips_unsupported_artifact_type(tmp_path) -> None:
    artifact_path = tmp_path / "notes.txt"
    artifact_path.write_text("apiBaseUrl=http://api.example.test", encoding="utf-8")

    execution = execute_desktop_client_assessment(
        [str(artifact_path)],
        scope_allowlist={"desktop_artifact_paths": [str(artifact_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "unsupported_desktop_artifact_type"
