from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_validation_matrix import evaluate_scenario, main, normalize_findings


def _scenario(**overrides):
    data = {
        "id": "fixture-web",
        "name": "Fixture web target",
        "minimum_coverage_pct": 80,
        "expected_findings": [
            {
                "id": "sqli",
                "title_pattern": "(?i)sql.*injection",
                "severity": "high",
                "tool": "zap",
                "target_pattern": "fixture",
                "wstg": "WSTG-INPV-05",
            },
            {
                "id": "xss",
                "title_pattern": "(?i)xss|cross.?site scripting",
                "severity": "medium",
                "target_pattern": "fixture",
            },
        ],
        "forbidden_findings": [],
    }
    data.update(overrides)
    return data


def test_normalize_findings_accepts_common_api_shapes() -> None:
    normalized = normalize_findings(
        {
            "findings": [
                {
                    "name": "SQL Injection",
                    "severity": "HIGH",
                    "source_tool": "ZAP",
                    "url": "http://fixture.local/login",
                    "wstg_id": "WSTG-INPV-05",
                }
            ]
        }
    )

    assert normalized == [
        {
            "title": "SQL Injection",
            "severity": "high",
            "tool": "zap",
            "target": "http://fixture.local/login",
            "wstg": "WSTG-INPV-05",
            "raw": {
                "name": "SQL Injection",
                "severity": "HIGH",
                "source_tool": "ZAP",
                "url": "http://fixture.local/login",
                "wstg_id": "WSTG-INPV-05",
            },
        }
    ]


def test_evaluate_scenario_passes_when_expected_findings_match() -> None:
    result = evaluate_scenario(
        _scenario(),
        [
            {
                "title": "SQL Injection - login",
                "severity": "high",
                "tool": "zap",
                "target_id": "fixture.local/login",
                "wstg_id": "WSTG-INPV-05",
            },
            {
                "title": "Reflected XSS",
                "severity": "medium",
                "tool": "nuclei",
                "target_id": "fixture.local/search",
            },
        ],
    )

    assert result["status"] == "passed"
    assert result["detection_rate_pct"] == 100.0
    assert result["false_positive_rate_pct"] == 0.0
    assert result["missing_expected"] == []


def test_evaluate_scenario_fails_when_expected_findings_are_missing() -> None:
    result = evaluate_scenario(
        _scenario(),
        [
            {
                "title": "SQL Injection - login",
                "severity": "high",
                "tool": "zap",
                "target_id": "fixture.local/login",
                "wstg_id": "WSTG-INPV-05",
            }
        ],
    )

    assert result["status"] == "failed"
    assert result["detection_rate_pct"] == 50.0
    assert result["missing_expected"] == ["xss"]


def test_evaluate_scenario_fails_on_clean_target_false_positives() -> None:
    result = evaluate_scenario(
        _scenario(
            id="clean",
            minimum_coverage_pct=100,
            expected_findings=[],
            forbidden_findings=[
                {
                    "id": "clean-high",
                    "title_pattern": ".*",
                    "severity": "critical|high",
                }
            ],
        ),
        [
            {
                "title": "Remote code execution",
                "severity": "critical",
                "tool": "nuclei",
                "target_id": "clean.local",
            }
        ],
    )

    assert result["status"] == "failed"
    assert result["counts"]["forbidden_findings"] == 1
    assert result["forbidden_matches"][0]["rule_id"] == "clean-high"


def test_evaluate_scenario_fails_when_unexpected_findings_exceed_threshold() -> None:
    result = evaluate_scenario(
        _scenario(false_positive_threshold_pct=10),
        [
            {
                "title": "SQL Injection - login",
                "severity": "high",
                "tool": "zap",
                "target_id": "fixture.local/login",
                "wstg_id": "WSTG-INPV-05",
            },
            {
                "title": "Reflected XSS",
                "severity": "medium",
                "tool": "zap",
                "target_id": "fixture.local/search",
            },
            {
                "title": "Unexpected information disclosure",
                "severity": "low",
                "tool": "zap",
                "target_id": "fixture.local/debug",
            },
        ],
    )

    assert result["status"] == "failed"
    assert result["false_positive_rate_pct"] == 33.33
    assert result["counts"]["unexpected_findings"] == 1


def test_cli_writes_offline_fixture_results(tmp_path: Path) -> None:
    catalog = {
        "matrix_id": "fixture_matrix",
        "false_positive_threshold_pct": 10,
        "scenarios": [
            _scenario(id="fixture-web"),
            _scenario(id="disabled", enabled=False),
        ],
    }
    catalog_path = tmp_path / "catalog.json"
    fixtures_dir = tmp_path / "findings"
    results_path = tmp_path / "latest.json"
    fixtures_dir.mkdir()
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    (fixtures_dir / "fixture-web.json").write_text(
        json.dumps(
            [
                {
                    "title": "SQL Injection - login",
                    "severity": "high",
                    "tool": "zap",
                    "target_id": "fixture.local/login",
                    "wstg_id": "WSTG-INPV-05",
                },
                {
                    "title": "Reflected XSS",
                    "severity": "medium",
                    "tool": "zap",
                    "target_id": "fixture.local/search",
                },
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--catalog",
            str(catalog_path),
            "--actual-findings-dir",
            str(fixtures_dir),
            "--results-file",
            str(results_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    assert payload["status"] == "passed"
    assert payload["summary"] == {"failed": 0, "not_run": 0, "passed": 1, "scenarios": 1}


def test_validation_matrix_workflow_is_valid_yaml() -> None:
    workflow_path = REPO_ROOT / ".github" / "workflows" / "validation-matrix.yml"
    payload = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    assert payload["name"] == "validation-matrix"
    assert "validation-matrix" in payload["jobs"]
