from __future__ import annotations

from pathlib import Path

from scripts.run_ai_loop_gruyere_proof import (
    build_gruyere_ai_loop_proof_report,
    load_json,
    render_markdown,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG = load_json(REPO_ROOT / "scripts" / "validation" / "benchmark_coverage_expected.json")


def test_gruyere_ai_loop_proof_blocks_without_local_evidence() -> None:
    report = build_gruyere_ai_loop_proof_report(catalog=CATALOG)

    assert report["status"] == "blocked"
    assert report["summary"]["passes"] is False
    assert report["blockers"][0]["code"] == "local_gruyere_evidence_missing"
    assert report["target"]["external_live_infrastructure_touched"] is False
    assert report["safety"]["public_gruyere_touched"] is False
    assert report["execution_contract"]["dispatches_work"] is False
    assert report["execution_contract"]["creates_or_approves_proposals"] is False


def test_collected_three_iteration_evidence_passes() -> None:
    report = build_gruyere_ai_loop_proof_report(
        catalog=CATALOG,
        collected_evidence=_three_iteration_evidence(),
    )

    assert report["status"] == "passed"
    assert report["summary"]["iteration_count"] == 3
    assert report["summary"]["iteration_2_consumes_iteration_1"] is True
    assert report["summary"]["goal_closure_evidence_backed"] is True
    assert report["target"]["local_only"] is True
    assert report["execution_contract"]["live_target_actions_performed"] is False


def test_iteration_two_must_consume_iteration_one_artifacts() -> None:
    evidence = _three_iteration_evidence()
    evidence["iterations"][1]["consumes_evidence_refs"] = ["artifact://gruyere/unrelated"]

    report = build_gruyere_ai_loop_proof_report(catalog=CATALOG, collected_evidence=evidence)

    assert report["status"] == "failed"
    assert any(failure["code"] == "iteration_2_does_not_consume_iteration_1" for failure in report["failures"])
    assert report["summary"]["iteration_2_consumes_iteration_1"] is False


def test_public_gruyere_target_is_rejected_without_contacting_it() -> None:
    evidence = _three_iteration_evidence()
    evidence["target"]["url"] = "https://google-gruyere.appspot.com/123/"

    report = build_gruyere_ai_loop_proof_report(catalog=CATALOG, collected_evidence=evidence)

    assert report["status"] == "failed"
    assert any(failure["code"] == "public_gruyere_target_rejected" for failure in report["failures"])
    assert report["target"]["public_gruyere_rejected"] is True
    assert report["safety"]["public_gruyere_touched"] is False
    assert report["execution_contract"]["external_live_infrastructure_contacted"] is False


def test_markdown_records_blockers_or_goal_closure() -> None:
    blocked_markdown = render_markdown(build_gruyere_ai_loop_proof_report(catalog=CATALOG))
    passed_markdown = render_markdown(
        build_gruyere_ai_loop_proof_report(catalog=CATALOG, collected_evidence=_three_iteration_evidence())
    )

    assert "local_gruyere_evidence_missing" in blocked_markdown
    assert "Goal closure evidence-backed: `True`" in passed_markdown
    assert "Public/external infrastructure contacted: `False`" in passed_markdown


def _three_iteration_evidence() -> dict:
    return {
        "target": {"url": "http://127.0.0.1:8008/"},
        "iterations": [
            {
                "iteration": 1,
                "tool": "httpx",
                "target": "http://127.0.0.1:8008/",
                "status": "completed",
                "produced_evidence_refs": ["artifact://gruyere/httpx/surface"],
                "findings": [
                    {
                        "id": "finding-gruyere-surface",
                        "evidence_ref": "finding://gruyere/surface",
                    }
                ],
            },
            {
                "iteration": 2,
                "tool": "xss-extended",
                "target": "http://127.0.0.1:8008/",
                "status": "completed",
                "consumes_evidence_refs": ["artifact://gruyere/httpx/surface"],
                "produced_evidence_refs": ["artifact://gruyere/xss/stored-canary"],
                "findings": [
                    {
                        "id": "finding-gruyere-xss",
                        "evidence_ref": "finding://gruyere/xss-stored-canary",
                    }
                ],
            },
            {
                "iteration": 3,
                "tool": "client-state",
                "target": "http://127.0.0.1:8008/",
                "status": "completed",
                "consumes_evidence_refs": ["artifact://gruyere/xss/stored-canary"],
                "produced_evidence_refs": ["artifact://gruyere/client-state/admin-surface"],
                "goal_closure": {
                    "status": "reached",
                    "supporting_evidence_refs": [
                        "artifact://gruyere/httpx/surface",
                        "artifact://gruyere/xss/stored-canary",
                    ],
                },
            },
        ],
    }
