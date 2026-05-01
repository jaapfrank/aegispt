from __future__ import annotations

import pytest

from api.app.services.benchmark_ai_eval import (
    BenchmarkEvalProviderResult,
    build_benchmark_eval_report,
    build_benchmark_eval_report_from_catalogs,
)


class ExplainingProvider:
    name = "fixture-provider"

    def explain(self, request):
        assert request["boundaries"]["dispatches_work"] is False
        assert request["boundaries"]["creates_findings"] is False
        return BenchmarkEvalProviderResult(
            explanations={
                "webgoat-sql-injection": "SQL injection was found through the stored ZAP finding.",
                "webgoat-cross-site-scripting": "No XSS-like evidence was present in the actual finding list.",
            },
            confidence_notes=[
                {"signal_id": "webgoat-cross-site-scripting", "confidence": "medium", "grounding": "missing matcher"}
            ],
            model="fixture-model",
            metadata={"review_only": True},
        )


class FailingProvider:
    name = "broken-provider"

    def explain(self, _request):
        raise RuntimeError("provider timed out while grading benchmark output")


def _benchmark_metadata() -> dict:
    return {
        "benchmark_family": "OWASP WebGoat",
        "vulnerable_families": ["SQL Injection", "Cross-Site Scripting", "Access Control"],
        "prerequisites": ["local WebGoat fixture"],
        "coverage_expectation": "Reference-guided web application benchmark coverage.",
    }


def _expected_findings() -> list[dict]:
    return [
        {
            "id": "webgoat-sql-injection",
            "title_pattern": "(?i)sql.*injection|injection.*sql",
            "severity": "high",
            "tool": "zap",
            "target_pattern": "(?i)webgoat",
            "wstg": "WSTG-INPV-05",
        },
        {
            "id": "webgoat-cross-site-scripting",
            "title_pattern": "(?i)(cross.?site scripting|\\bxss\\b)",
            "severity": "medium",
            "target_pattern": "(?i)webgoat",
            "wstg": "WSTG-INPV-01",
        },
    ]


def test_benchmark_eval_distinguishes_found_missed_uncertain_and_unexpected() -> None:
    report = build_benchmark_eval_report(
        benchmark_metadata=_benchmark_metadata(),
        expected_findings=_expected_findings(),
        actual_findings_payload={
            "findings": [
                {
                    "title": "SQL Injection - WebGoat lesson",
                    "severity": "high",
                    "tool": "zap",
                    "target_id": "http://127.0.0.1/WebGoat",
                    "wstg_id": "WSTG-INPV-05",
                },
                {
                    "title": "Informational Server Header",
                    "severity": "info",
                    "tool": "httpx",
                    "target_id": "http://127.0.0.1/WebGoat",
                },
            ]
        },
        scenario_id="webgoat-active-web-safe",
        target_id="owasp-webgoat-local",
        provider=ExplainingProvider(),
        provider_name="fixture-provider",
        artifacts=[{"artifact_ref": "inline://runs/webgoat/zap.json", "sha256": "abc123", "kind": "json"}],
    )

    assert report["status"] == "partial"
    assert report["coverage"]["counts"]["found"] == 1
    assert report["coverage"]["counts"]["missed"] == 1
    assert report["coverage"]["counts"]["uncertain"] == 1
    assert report["coverage"]["counts"]["unexpected"] == 1
    assert report["signals"]["found"][0]["id"] == "webgoat-sql-injection"
    assert report["signals"]["missed"][0]["id"] == "webgoat-cross-site-scripting"
    assert report["signals"]["uncertain"][0]["family"] == "Access Control"
    assert report["signals"]["unexpected"][0]["title"] == "Informational Server Header"
    assert report["grounding"]["sources"] == [
        "benchmark_metadata",
        "expected_finding_catalog",
        "actual_findings",
        "run_artifacts",
    ]
    assert report["ai_assistance"]["status"] == "succeeded"
    assert report["ai_assistance"]["authoritative"] is False
    assert report["ai_assistance"]["model"] == "fixture-model"
    assert report["boundaries"]["release_gate_authority"] is False
    assert report["boundaries"]["dispatches_work"] is False
    assert report["boundaries"]["creates_findings"] is False


def test_sparse_benchmark_metadata_degrades_to_uncertain_without_fabricating_coverage() -> None:
    report = build_benchmark_eval_report(
        benchmark_metadata={
            "benchmark_family": "PromptMe Reference",
            "vulnerable_families": ["Prompt Injection", "Data Leakage"],
            "prerequisites": ["documentation reference"],
        },
        expected_findings=[],
        actual_findings_payload=[],
        target_id="promptme-reference",
    )

    assert report["status"] == "limited_reference"
    assert report["coverage"]["expected_coverage_pct"] is None
    assert report["coverage"]["counts"]["expected"] == 0
    assert report["coverage"]["counts"]["uncertain"] == 2
    assert {signal["family"] for signal in report["signals"]["uncertain"]} == {
        "Prompt Injection",
        "Data Leakage",
    }
    assert report["ai_assistance"]["status"] == "disabled"
    assert report["ai_assistance"]["fallback"] == "reference_guided"
    assert report["grounding"]["expected_catalog_present"] is False


def test_provider_failure_keeps_reference_guided_report_and_never_changes_signal_statuses() -> None:
    report = build_benchmark_eval_report(
        benchmark_metadata=_benchmark_metadata(),
        expected_findings=_expected_findings(),
        actual_findings_payload=[
            {
                "title": "SQL Injection - WebGoat lesson",
                "severity": "high",
                "tool": "zap",
                "target": "WebGoat",
                "wstg": "WSTG-INPV-05",
            }
        ],
        provider=FailingProvider(),
        provider_name="broken-provider",
    )

    assert report["coverage"]["counts"]["found"] == 1
    assert report["coverage"]["counts"]["missed"] == 1
    assert report["signals"]["found"][0]["status"] == "found"
    assert report["signals"]["missed"][0]["status"] == "missed"
    assert report["ai_assistance"]["status"] == "failed"
    assert report["ai_assistance"]["fallback"] == "reference_guided"
    assert "provider timed out" in report["ai_assistance"]["failure_reason"]
    assert report["ai_assistance"]["authoritative"] is False
    assert report["boundaries"]["canonical_scoring_replacement"] is False


def test_catalog_entry_and_expected_catalog_are_joined_without_dispatch_or_findings() -> None:
    target_catalog = {
        "targets": [
            {
                "id": "owasp-webgoat-local",
                "label": "OWASP WebGoat",
                "runnability": "fixture_backed",
                "benchmark_metadata": _benchmark_metadata(),
            }
        ]
    }
    expected_catalog = {
        "scenarios": [
            {
                "id": "webgoat-active-web-safe",
                "name": "WebGoat active-safe",
                "expected_findings": _expected_findings(),
            }
        ]
    }

    report = build_benchmark_eval_report_from_catalogs(
        target_catalog=target_catalog,
        expected_catalog=expected_catalog,
        target_id="owasp-webgoat-local",
        validation_scenario_id="webgoat-active-web-safe",
        actual_findings_payload=[],
        provider_name="disabled",
    )

    assert report["benchmark"]["target_id"] == "owasp-webgoat-local"
    assert report["benchmark"]["scenario_id"] == "webgoat-active-web-safe"
    assert report["catalog_context"]["target_runnability"] == "fixture_backed"
    assert report["coverage"]["counts"]["missed"] == 2
    assert report["ai_assistance"]["status"] == "disabled"
    assert report["boundaries"] == {
        "advisory_only": True,
        "operator_review_required": True,
        "creates_findings": False,
        "mutates_findings": False,
        "dispatches_work": False,
        "expands_scope": False,
        "release_gate_authority": False,
        "canonical_scoring_replacement": False,
        "message": "Benchmark AI evaluation explains expected-vs-actual gaps only; deterministic validation remains authoritative.",
    }


def test_unknown_catalog_ids_are_rejected_before_any_report_is_built() -> None:
    with pytest.raises(ValueError, match="Unknown target"):
        build_benchmark_eval_report_from_catalogs(
            target_catalog={"targets": []},
            target_id="missing-target",
            actual_findings_payload=[],
        )
