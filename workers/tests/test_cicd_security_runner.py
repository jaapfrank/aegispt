from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.cicd_security.runner import (
    CICD_SECURITY_INVENTORY_ARTIFACT_NAME,
    CICD_SECURITY_RESULTS_ARTIFACT_NAME,
    execute_cicd_security_assessment,
)


class ArtifactRecord:
    uri = "artifact://cicd-security/results"


def build_github_actions_fixture(path) -> None:
    path.write_text(
        """
name: vulnerable
"on": [pull_request_target]
permissions: write-all
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
      - uses: third-party/action@v1
      - run: curl https://example.test/install.sh | bash
      - uses: actions/upload-artifact@v4
        with:
          path: "**/*"
      - name: Secret
        env:
          DEPLOY_TOKEN: supersecretvalue123456
""",
        encoding="utf-8",
    )


def test_cicd_security_static_review_creates_safe_evidence_backed_findings(tmp_path) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "build.yml"
    workflow_path.parent.mkdir(parents=True)
    build_github_actions_fixture(workflow_path)

    execution = execute_cicd_security_assessment(
        [str(workflow_path), "acme/repo"],
        scope_allowlist={
            "pipeline_config_paths": [str(workflow_path)],
            "repositories": ["acme/repo"],
        },
        repository_metadata={
            "repository": "acme/repo",
            "branch_protection_enabled": False,
            "secret_scanning_enabled": False,
            "self_hosted_runner_labels": ["prod"],
        },
    )

    assert execution.exit_code == 0
    assert execution.tool == "cicd-security"
    assert execution.metadata["status"] == "completed"
    assert execution.metadata["pipeline_execution_executed"] is False
    assert execution.metadata["repository_mutation_executed"] is False
    assert execution.metadata["raw_secret_disclosure"] is False
    artifact_names = {artifact.name for artifact in execution.artifacts}
    assert CICD_SECURITY_RESULTS_ARTIFACT_NAME in artifact_names
    assert CICD_SECURITY_INVENTORY_ARTIFACT_NAME in artifact_names

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CICD_SECURITY_RESULTS_ARTIFACT_NAME
    )
    raw_results = results_artifact.data.decode("utf-8")
    assert "supersecretvalue123456" not in raw_results
    payload = json.loads(raw_results)
    assert payload["safety"]["pipeline_execution"] is False
    assert payload["safety"]["repository_mutation"] is False
    assert payload["safety"]["raw_secret_disclosure"] is False
    finding_types = {finding["type"] for finding in payload["findings"]}
    assert "cicd_overprivileged_pipeline_token" in finding_types
    assert "cicd_poisoned_pipeline_prerequisite" in finding_types
    assert "cicd_unpinned_third_party_action" in finding_types
    assert "cicd_inline_secret_material" in finding_types
    assert "cicd_self_hosted_runner_exposure" in finding_types
    assert "cicd_artifact_cache_exposure" in finding_types
    assert "cicd_weak_branch_protection" in finding_types
    assert "pipeline_execution_not_run" in payload["unsupported_states"]

    task = SimpleNamespace(tool="cicd-security", target_id=str(workflow_path), params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=CICD_SECURITY_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="cicd-security-results",
        ),
        artifact_record=ArtifactRecord(),
    )
    assert {finding.evidence_ref for finding in findings} == {ArtifactRecord.uri}
    assert "GitHub Actions workflow grants broad write permissions" in {
        finding.title for finding in findings
    }


def test_cicd_security_rejects_out_of_scope_pipeline_path(tmp_path) -> None:
    allowed_path = tmp_path / "allowed.yml"
    outside_path = tmp_path / "outside.yml"
    build_github_actions_fixture(allowed_path)
    build_github_actions_fixture(outside_path)

    with pytest.raises(ValueError, match="outside scope"):
        execute_cicd_security_assessment(
            [str(outside_path)],
            scope_allowlist={"pipeline_config_paths": [str(allowed_path)]},
        )


def test_cicd_security_missing_config_is_truthful(tmp_path) -> None:
    missing_path = tmp_path / "missing.yml"

    execution = execute_cicd_security_assessment(
        [str(missing_path)],
        scope_allowlist={"pipeline_config_paths": [str(missing_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_pipeline_config"
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["status"] == "skipped"
    assert payload["safety"]["pipeline_execution"] is False


def test_cicd_security_unsupported_pipeline_type_is_truthful(tmp_path) -> None:
    pipeline_path = tmp_path / "pipeline.txt"
    pipeline_path.write_text("not a supported pipeline format", encoding="utf-8")

    execution = execute_cicd_security_assessment(
        [str(pipeline_path)],
        scope_allowlist={"pipeline_config_paths": [str(pipeline_path)]},
        pipeline_type="teamcity",
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "unsupported_pipeline_type"


def test_cicd_security_missing_input_is_truthful() -> None:
    execution = execute_cicd_security_assessment([], scope_allowlist={})

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_cicd_security_input"
