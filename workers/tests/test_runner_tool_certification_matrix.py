from __future__ import annotations

from scripts.build_runner_tool_certification_matrix import build_matrix, render_markdown
from workers.orchestration.tasks import SUPPORTED_TOOLS


def test_certification_matrix_covers_every_supported_runner() -> None:
    matrix = build_matrix()
    tools = {entry["id"]: entry for entry in matrix["tools"]}

    assert matrix["kind"] == "aegispt.runner_tool_certification_matrix"
    assert set(tools) == set(SUPPORTED_TOOLS)
    assert matrix["summary"]["tool_count"] == len(SUPPORTED_TOOLS)

    for tool_id, entry in tools.items():
        assert entry["certification_status"] in {"certified", "supported-with-gap", "blocked"}, tool_id
        assert entry["runner_module"].startswith("workers.runners."), tool_id
        assert entry["output_contract"]["artifact_names"], tool_id
        assert entry["diagnostics_reference"]["settings_capability_id"] == "runner_tool_certification"
        if entry["certification_status"] == "certified":
            assert entry["validation_evidence"]["deterministic_tests"], tool_id
            assert entry["report_mapping"]["verified"] is True, tool_id
        else:
            assert entry["gap_reason"], tool_id


def test_certification_matrix_separates_hardware_blockers_from_software_readiness() -> None:
    matrix = build_matrix()
    wifi = {entry["id"]: entry for entry in matrix["tools"]}["wifi-survey"]

    assert matrix["summary"]["overall_status"] == "ready_with_hardware_limitation"
    assert matrix["summary"]["hardware_blocker_tool_ids"] == ["wifi-survey"]
    assert matrix["summary"]["non_hardware_blocked_tool_ids"] == []
    assert wifi["certification_status"] == "blocked"
    assert wifi["software_readiness"]["settings_tool_group_id"] == "wifi"
    assert wifi["software_readiness"]["software_installable"] is True
    assert wifi["hardware_readiness"]["required"] is True
    assert wifi["hardware_readiness"]["kind"] == "wireless_adapter"
    assert "hardware lab" in wifi["hardware_readiness"]["blocker"]


def test_certification_matrix_records_crypto_audit_contract_and_report_mapping() -> None:
    matrix = build_matrix()
    crypto = {entry["id"]: entry for entry in matrix["tools"]}["crypto-audit"]

    assert crypto["certification_status"] == "certified"
    assert crypto["software_readiness"]["settings_tool_group_id"] == "crypto-audit"
    assert ["testssl.sh", "testssl"] in crypto["software_readiness"]["required_binary_groups"]
    assert ["ssh-audit"] in crypto["software_readiness"]["required_binary_groups"]
    assert "crypto-audit-results.json" in crypto["output_contract"]["artifact_names"]
    assert crypto["finding_mapping"]["verified"] is True
    assert crypto["report_mapping"]["verified"] is True


def test_certification_markdown_is_human_readable() -> None:
    markdown = render_markdown(build_matrix())

    assert "Runner and Tool Certification Matrix" in markdown
    assert "`crypto-audit`" in markdown
    assert "`wifi-survey`" in markdown
