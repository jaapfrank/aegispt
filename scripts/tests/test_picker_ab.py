from __future__ import annotations

import json

from scripts import picker_ab


def test_dry_run_report_has_two_matched_provider_results() -> None:
    report = picker_ab.build_dry_run_report(target="https://authorized.example")

    assert report.mode == "dry-run"
    assert report.target == "https://authorized.example"
    assert report.winner_claim is None
    assert report.matched_decision_count == 2
    assert [item.provider for item in report.provider_results] == ["claude", "chatgpt_oauth"]
    assert report.provider_results[0].provider_config["llm_provider"] == "claude-opus-4-7"
    assert report.provider_results[1].provider_config["llm_provider"] == "chatgpt_oauth"
    assert report.deltas["proof_delta"]["absolute_delta"] == 0


def test_markdown_report_states_no_winner_claim() -> None:
    markdown = picker_ab.report_to_markdown(picker_ab.build_dry_run_report())

    assert "# Picker A/B Comparison" in markdown
    assert "Winner claim: none" in markdown
    assert "## Limitations" in markdown
    assert "chatgpt_oauth" in markdown
    assert "claude" in markdown


def test_recorded_input_report_preserves_run_ids_and_failure_reasons(tmp_path) -> None:
    recorded = {
        "target": "lab://xbow/example",
        "evidence_fixture_id": "xbow-scenario-001",
        "runs": [
            {
                "provider": "claude",
                "provider_config": {"llm_provider": "claude-opus-4-7"},
                "run_id": "run-claude",
                "decisions": [{"action": "pick", "tool": "target-intel", "confidence": 0.8}],
                "finding_count": 2,
                "high_or_critical_count": 1,
                "canary_delta": 1,
                "proof_delta": 1,
                "failure_reasons": [],
            },
            {
                "provider": "chatgpt_oauth",
                "provider_config": {"llm_provider": "chatgpt_oauth", "model": "gpt-5.4"},
                "run_id": "run-chatgpt",
                "decisions": [{"action": "stop", "failure_reason": "picker_retry_exhausted"}],
                "finding_count": 1,
                "high_or_critical_count": 0,
                "canary_delta": 0,
                "proof_delta": 0,
                "failure_reasons": ["picker_retry_exhausted"],
            },
        ],
    }
    input_path = tmp_path / "recorded.json"
    input_path.write_text(json.dumps(recorded), encoding="utf-8")

    report = picker_ab.load_recorded_report(input_path)

    assert report.mode == "recorded"
    assert report.provider_results[0].run_id == "run-claude"
    assert report.provider_results[1].run_id == "run-chatgpt"
    assert report.deltas["finding_count"]["absolute_delta"] == -1
    assert report.deltas["failure_reasons_by_provider"]["chatgpt_oauth"] == ["picker_retry_exhausted"]


def test_cli_writes_json_report(tmp_path) -> None:
    output_path = tmp_path / "picker-ab.json"

    exit_code = picker_ab.main(["--target", "fixture://target", "--output", str(output_path)])

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "dry-run"
    assert payload["target"] == "fixture://target"
    assert payload["winner_claim"] is None
    assert len(payload["provider_results"]) == 2
