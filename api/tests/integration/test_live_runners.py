from __future__ import annotations

from datetime import UTC, datetime

from scripts.run_live_fixture_matrix import build_live_fixture_matrix, render_markdown
from workers.orchestration.tasks import SUPPORTED_TOOLS


def test_live_fixture_matrix_covers_all_supported_tools_without_external_execution() -> None:
    report = build_live_fixture_matrix(
        image_checker=lambda image: (False, f"{image} missing locally"),
        generated_at=datetime(2026, 5, 10, tzinfo=UTC),
    )

    assert report["status"] == "blocked"
    assert report["summary"]["tools"] == len(SUPPORTED_TOOLS)
    assert {item["tool"] for item in report["runner_families"]} == set(SUPPORTED_TOOLS)
    assert report["summary"]["passed"] == 0
    assert report["summary"]["blocked"] > 0
    assert report["safety"] == {
        "local_fixtures_only": True,
        "external_live_infrastructure_touched": False,
        "docker_remote_pull_performed": False,
        "automatic_approval_performed": False,
        "scope_roe_bypass_performed": False,
        "credential_materialization_performed": False,
        "kill_switch_bypassed": False,
    }
    assert all(item["status"] != "passed" for item in report["runner_families"])


def test_collected_local_evidence_can_pass_one_runner_without_marking_others_green() -> None:
    report = build_live_fixture_matrix(
        collected_results={
            "httpx": {
                "artifacts": [{"name": "httpx-results.json", "sha256": "abc"}],
                "findings": [{"title": "HTTP service observed", "evidence_ref": "artifact:httpx-results.json"}],
            }
        },
        image_checker=lambda image: (True, "present locally"),
        generated_at=datetime(2026, 5, 10, tzinfo=UTC),
    )

    httpx = next(item for item in report["runner_families"] if item["tool"] == "httpx")
    assert httpx["status"] == "passed"
    assert httpx["artifact_count"] == 1
    assert httpx["finding_count"] == 1
    assert report["summary"]["passed"] == 1
    assert report["status"] == "blocked"
    assert any(item["status"] != "passed" for item in report["runner_families"] if item["tool"] != "httpx")


def test_collected_evidence_requires_artifacts_and_evidence_refs() -> None:
    report = build_live_fixture_matrix(
        collected_results={"httpx": {"artifacts": [], "findings": [{"title": "missing evidence"}]}},
        image_checker=lambda image: (True, "present locally"),
        generated_at=datetime(2026, 5, 10, tzinfo=UTC),
    )

    httpx = next(item for item in report["runner_families"] if item["tool"] == "httpx")
    assert httpx["status"] == "failed"
    assert "missing runner artifacts" in httpx["failures"]
    assert "finding 0 has no evidence reference" in httpx["failures"]
    assert report["status"] == "failed"


def test_markdown_records_blockers_instead_of_claiming_clean_pass() -> None:
    report = build_live_fixture_matrix(
        image_checker=lambda image: (False, f"{image} missing locally"),
        generated_at=datetime(2026, 5, 10, tzinfo=UTC),
    )

    markdown = render_markdown(report)

    assert "Status: `blocked`" in markdown
    assert "Missing Docker images or local lab evidence are recorded as blocked, not passed." in markdown
    assert "blocked_fixture_unavailable" in markdown
