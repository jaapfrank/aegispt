from __future__ import annotations

import json
from pathlib import Path

from scripts.run_enterprise_release_readiness import (
    build_release_readiness_report,
    render_markdown,
    write_report,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    _write(path, json.dumps(payload, indent=2))


def _seed_minimal_repo(root: Path, *, validation_status: str = "not_run") -> None:
    validation_scenario = {"scenario_id": "webgoat", "status": validation_status}
    if validation_status == "blocked":
        validation_scenario["reason"] = "Docker image is missing locally."
        validation_scenario["execution_blocker"] = {
            "type": "docker_image_missing",
            "reason": "Docker image is missing locally.",
            "safest_next_step": "Pre-pull the approved fixture image or update the catalog tag.",
        }
    _write_json(
        root / "codex/tasks/product_acceptance_matrix.json",
        {
            "matrix_id": "product_acceptance_matrix_v1",
            "scenarios": [
                {"id": "ui-wizard-profile-matrix", "lane": "ui_browser", "enabled": True},
                {"id": "ui-report-downloads", "lane": "ui_browser", "enabled": True},
            ],
        },
    )
    _write_json(
        root / "codex/tasks/target_lab_matrix.json",
        {
            "matrix_id": "safe_target_catalog_v2",
            "targets": [
                {"id": "local", "enabled": True, "authorized": True},
                {"id": "template", "enabled": False, "authorized": False},
            ],
            "real_run_scenarios": [{"id": "local-app-smoke", "enabled": True}],
        },
    )
    _write_json(
        root / "codex/results/validation-matrix-latest.json",
        {
            "matrix_id": "known_vulnerability_validation_v1",
            "status": validation_status,
            "scenarios": [validation_scenario],
        },
    )
    _write_json(
        root / "codex/results/runner-tool-certification-matrix.json",
        {
            "kind": "aegispt.runner_tool_certification_matrix",
            "tools": [
                {
                    "id": "nmap",
                    "certification_status": "certified",
                    "software_readiness": {"state": "ready"},
                },
                {
                    "id": "wifi-survey",
                    "certification_status": "blocked",
                    "software_readiness": {"state": "missing"},
                },
            ],
        },
    )
    _write(root / "codex/results/runner-tool-certification-matrix.md", "Runner and Tool Certification Matrix\n")
    _write_json(
        root / "codex/results/backlog-181-full-system-audit.json",
        {"defects": [{"severity": "medium"}]},
    )
    _write_json(root / "codex/results/backlog-181-ia-audit.json", {"pages": [], "failure_notes": []})
    _write(
        root / "docs/operator_product_operational_assurance.md",
        "Status Legend\nReal-Run Safe Target Coverage\nEvidence Replay\nExport and Report Paths\nintentionally-unsupported\n",
    )
    _write(root / "scripts/run_validation_matrix.py", "detection_rate false_positive_rate\n")
    _write(root / "api/tests/test_settings.py", "AI tool readiness\n")
    _write(root / "api/tests/test_diagnostics.py", "support_bundle redact raw_evidence_payloads\n")
    _write(root / "api/tests/test_backup_restore.py", "artifact_hash_verified\n")
    _write(root / "api/tests/test_auth.py", "identity logout\n")
    _write(root / "api/tests/test_input_validation_security.py", "tenant scope\n")
    _write(root / "docs/security_self_assessment.md", "Automated Validation\nDependency Audit\n")
    _write(root / "docs/accessibility_acceptance.md", "keyboard\n")
    _write(root / "ui/tests/test_accessibility_e2e.py", "focus keyboard\n")
    _write(
        root / "codex/results/backlog-151-wizard-input-prediction-matrix-20260430.json",
        "{}\n",
    )
    _write(
        root / "codex/results/backlog-164-wifi-readiness-20260501.md",
        "WiFi readiness\n",
    )
    _write(
        root / "codex/results/backlog-161-ai-signal-global-chatgpt-no-run-validation-20260501.md",
        "AI Signal\n",
    )
    _write(
        root / "codex/results/backlog-182-enterprise-identity-session-admin-20260502.md",
        "Enterprise Identity\nRemaining\n",
    )
    _write(
        root / "codex/results/backlog-183-backup-restore-upgrade-rollback-drill-20260502.md",
        "Artifact hash verified\nPlaintext secrets exposed: false\n",
    )
    _write(
        root / "codex/results/backlog-184-observability-support-diagnostics-bundle-20260502.md",
        "Support Diagnostics\nRedaction\n",
    )
    _write(
        root / "codex/results/backlog-185-accessibility-keyboard-enterprise-ux-gate-20260502.md",
        "Keyboard\nreduced-motion\n",
    )
    _write(
        root / "codex/results/backlog-186-enterprise-deployment-hardening-20260503.md",
        "Deployment Hardening\nRemaining Risk\n",
    )
    _write(root / "docs/host_service_install.md", "Production deployment hardening\n")
    _write(root / "scripts/verify_restore.py", "safe-local\n")
    _write(
        root / "DECISIONS.md",
        "No runtime self-modification\nNo uncontrolled plugin installation\nAI repair\nAI Signal\n",
    )


def test_release_readiness_fails_closed_when_accuracy_matrix_is_not_executed(tmp_path: Path) -> None:
    _seed_minimal_repo(tmp_path, validation_status="not_run")

    report = build_release_readiness_report(tmp_path)
    ledger = {claim["id"]: claim for claim in report["support_claim_ledger"]}

    assert report["release_decision"]["status"] == "blocked"
    assert report["release_decision"]["go_no_go"] == "no-go"
    assert report["release_decision"]["can_claim_enterprise_ready"] is False
    assert ledger["known_vulnerability_detection_accuracy"]["status"] == "blocked"
    assert ledger["known_vulnerability_detection_accuracy"]["next_task_refs"]
    assert ledger["false_positive_false_negative_posture"]["status"] == "blocked"


def test_release_readiness_surfaces_validation_scenario_blockers(tmp_path: Path) -> None:
    _seed_minimal_repo(tmp_path, validation_status="blocked")

    report = build_release_readiness_report(tmp_path)
    ledger = {claim["id"]: claim for claim in report["support_claim_ledger"]}
    accuracy = ledger["known_vulnerability_detection_accuracy"]
    markdown = render_markdown(report)

    assert accuracy["status"] == "blocked"
    assert accuracy["metrics"]["validation_matrix"]["scenario_blockers"] == [
        {
            "scenario_id": "webgoat",
            "scenario_name": None,
            "type": "docker_image_missing",
            "reason": "Docker image is missing locally.",
            "safest_next_step": "Pre-pull the approved fixture image or update the catalog tag.",
        }
    ]
    assert "docker_image_missing" in " ".join(accuracy["gaps"])
    assert "docker_image_missing" in markdown


def test_supported_claims_have_evidence_and_marketing_boundary_is_explicit(tmp_path: Path) -> None:
    _seed_minimal_repo(tmp_path, validation_status="passed")

    report = build_release_readiness_report(tmp_path)

    for claim in report["support_claim_ledger"]:
        assert claim["status"] in {"supported", "supported-with-gap", "blocked", "unsupported"}
        if claim["status"] == "supported":
            assert any(item["exists"] for item in claim["evidence"])

    unsupported = {claim["id"]: claim for claim in report["support_claim_ledger"]}["unsupported_claim_boundary"]
    assert unsupported["status"] == "unsupported"
    assert "Do not market" in unsupported["support_boundary"]


def test_release_readiness_writer_outputs_machine_and_human_reports(tmp_path: Path) -> None:
    _seed_minimal_repo(tmp_path, validation_status="not_run")
    report = build_release_readiness_report(tmp_path)
    output_json = tmp_path / "codex/results/enterprise-release-readiness.json"
    output_md = tmp_path / "codex/results/enterprise-release-readiness.md"

    write_report(report, output_json=output_json, output_md=output_md)

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    markdown = output_md.read_text(encoding="utf-8")
    assert payload["kind"] == "aegispt.enterprise_release_readiness"
    assert "Support-Claim Ledger" in markdown
    assert "`blocked`" in render_markdown(report)
