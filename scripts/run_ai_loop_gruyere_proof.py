#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_CATALOG = REPO_ROOT / "scripts" / "validation" / "benchmark_coverage_expected.json"
DEFAULT_RESULTS_FILE = REPO_ROOT / "codex" / "results" / "ai-loop-gruyere-proof-latest.json"
DEFAULT_MARKDOWN_FILE = REPO_ROOT / "codex" / "results" / "ai-loop-gruyere-proof-latest.md"
PROOF_VERSION = "ai-loop-gruyere-proof-v1"
PUBLIC_GRUYERE_HOST = "google-gruyere.appspot.com"
LOCAL_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def load_json(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def build_gruyere_ai_loop_proof_report(
    *,
    catalog: dict[str, Any],
    collected_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    benchmark = _gruyere_benchmark(catalog)
    evidence = collected_evidence if isinstance(collected_evidence, dict) else {}
    target_url = _target_url(evidence, benchmark)
    safety = _safety_contract(target_url)
    blockers: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []

    target_policy_gaps = _target_policy_gaps(target_url, benchmark)
    if target_policy_gaps:
        failures.extend(target_policy_gaps)

    iterations = _normalized_iterations(evidence)
    if not evidence:
        blockers.append(
            {
                "code": "local_gruyere_evidence_missing",
                "reason": "No collected local Gruyere ai_loop evidence was supplied.",
                "safest_next_step": (
                    "Run the approved local Gruyere fixture separately on loopback, collect "
                    "AegisPT run/task/artifact/finding evidence, then rerun with --collected-evidence."
                ),
            }
        )
    if evidence and len(iterations) < 3:
        failures.append(
            {
                "code": "minimum_iteration_count_not_met",
                "reason": "Collected evidence must include at least three deterministic ai_loop iterations.",
                "safest_next_step": "Collect at least surface, follow-up, and goal-closure iterations.",
            }
        )

    iteration_results = [_evaluate_iteration(iteration) for iteration in iterations]
    if evidence:
        failures.extend(_iteration_linkage_failures(iteration_results))
        failures.extend(_goal_closure_failures(iteration_results))

    has_failures = bool(failures)
    status = "failed" if has_failures else ("blocked" if blockers else "passed")
    return {
        "schema_version": 1,
        "proof_version": PROOF_VERSION,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "benchmark": {
            "id": benchmark.get("id"),
            "name": benchmark.get("name"),
            "target": benchmark.get("target"),
        },
        "status": status,
        "target": {
            "url": target_url,
            "local_only": _is_local_gruyere_url(target_url, benchmark),
            "public_gruyere_rejected": PUBLIC_GRUYERE_HOST in target_url.lower(),
            "external_live_infrastructure_touched": False,
        },
        "summary": {
            "iteration_count": len(iteration_results),
            "minimum_iteration_count": 3,
            "iteration_2_consumes_iteration_1": _iteration_two_consumes_iteration_one(iteration_results),
            "goal_closure_evidence_backed": _goal_closure_evidence_backed(iteration_results),
            "passes": status == "passed",
        },
        "iterations": iteration_results,
        "blockers": blockers,
        "failures": failures,
        "safety": safety,
        "execution_contract": {
            "live_target_actions_performed": False,
            "public_internet_targets_allowed": False,
            "external_live_infrastructure_contacted": False,
            "provider_mocked_or_deterministic": True,
            "dispatches_work": False,
            "creates_or_approves_proposals": False,
            "mutates_scope": False,
            "materializes_credentials": False,
            "runtime_self_modification": False,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# AI Loop Gruyere Proof",
        "",
        f"- Status: `{report.get('status')}`",
        f"- Iterations: {summary.get('iteration_count', 0)}",
        f"- Iteration 2 consumes iteration 1: `{summary.get('iteration_2_consumes_iteration_1')}`",
        f"- Goal closure evidence-backed: `{summary.get('goal_closure_evidence_backed')}`",
        f"- Public/external infrastructure contacted: `{report.get('target', {}).get('external_live_infrastructure_touched')}`",
        "",
        "## Safety",
        "",
    ]
    safety = report.get("safety") if isinstance(report.get("safety"), dict) else {}
    for key in sorted(safety):
        lines.append(f"- {key}: `{safety[key]}`")
    blockers = report.get("blockers") if isinstance(report.get("blockers"), list) else []
    failures = report.get("failures") if isinstance(report.get("failures"), list) else []
    if blockers:
        lines.extend(["", "## Blockers", ""])
        for blocker in blockers:
            if isinstance(blocker, dict):
                lines.append(f"- `{blocker.get('code')}`: {blocker.get('reason')}")
    if failures:
        lines.extend(["", "## Failures", ""])
        for failure in failures:
            if isinstance(failure, dict):
                lines.append(f"- `{failure.get('code')}`: {failure.get('reason')}")
    lines.extend(["", "## Iterations", ""])
    for iteration in report.get("iterations", []):
        if not isinstance(iteration, dict):
            continue
        lines.append(
            f"- Iteration {iteration.get('iteration')}: `{iteration.get('status')}` "
            f"tool=`{iteration.get('tool')}` refs={len(iteration.get('produced_evidence_refs') or [])}"
        )
    return "\n".join(lines).rstrip() + "\n"


def write_report(report: dict[str, Any], *, output: str | Path, markdown: str | Path | None = None) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if markdown is not None:
        markdown_path = Path(markdown)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_markdown(report), encoding="utf-8")


def _gruyere_benchmark(catalog: dict[str, Any]) -> dict[str, Any]:
    orchestrator = catalog.get("lab_orchestrator") if isinstance(catalog.get("lab_orchestrator"), dict) else {}
    for benchmark in orchestrator.get("benchmarks") or []:
        if isinstance(benchmark, dict) and benchmark.get("id") == "gruyere-local":
            return benchmark
    for benchmark in catalog.get("benchmarks") or []:
        if isinstance(benchmark, dict) and benchmark.get("id") == "gruyere-local":
            target = benchmark.get("target") if isinstance(benchmark.get("target"), dict) else {}
            return {
                "id": "gruyere-local",
                "name": benchmark.get("name") or "Google Gruyere Local",
                "target": {
                    "default_url": "http://127.0.0.1:8008/",
                    "allowed_hosts": ["127.0.0.1", "localhost"],
                    "image": target.get("image") or "karthequian/gruyere:latest",
                    "public_target_allowed": False,
                },
            }
    raise ValueError("benchmark catalog does not contain gruyere-local")


def _target_url(evidence: dict[str, Any], benchmark: dict[str, Any]) -> str:
    target = evidence.get("target") if isinstance(evidence.get("target"), dict) else {}
    value = (
        evidence.get("target_url")
        or evidence.get("url")
        or target.get("url")
        or target.get("root_url")
        or target.get("value")
        or _safe_dict(benchmark.get("target")).get("default_url")
        or ""
    )
    return str(value).strip()


def _target_policy_gaps(target_url: str, benchmark: dict[str, Any]) -> list[dict[str, str]]:
    if not target_url:
        return [
            {
                "code": "missing_target_url",
                "reason": "Collected evidence did not name a local Gruyere target URL.",
                "safest_next_step": "Record the loopback Gruyere root URL in collected evidence.",
            }
        ]
    if PUBLIC_GRUYERE_HOST in target_url.lower():
        return [
            {
                "code": "public_gruyere_target_rejected",
                "reason": "Public Google Gruyere targets are outside the build-lane proof boundary.",
                "safest_next_step": "Use only a local loopback Gruyere fixture.",
            }
        ]
    if not _is_local_gruyere_url(target_url, benchmark):
        return [
            {
                "code": "non_local_target_rejected",
                "reason": "The proof harness accepts only loopback Gruyere targets.",
                "safest_next_step": "Collect evidence from http://127.0.0.1 or localhost Gruyere.",
            }
        ]
    return []


def _is_local_gruyere_url(target_url: str, benchmark: dict[str, Any]) -> bool:
    parsed = urlparse(target_url if "://" in target_url else f"//{target_url}")
    allowed = set(str(host).lower() for host in _safe_dict(benchmark.get("target")).get("allowed_hosts") or [])
    allowed.update(LOCAL_ALLOWED_HOSTS)
    return (parsed.hostname or "").lower() in allowed


def _normalized_iterations(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    raw = evidence.get("iterations")
    if not isinstance(raw, list):
        raw = _safe_dict(evidence.get("ai_assessment_loop")).get("iterations")
    if not isinstance(raw, list):
        return []
    iterations = [item for item in raw if isinstance(item, dict)]
    return sorted(iterations, key=lambda item: int(item.get("iteration") or item.get("order") or 0))


def _evaluate_iteration(iteration: dict[str, Any]) -> dict[str, Any]:
    action = iteration.get("next_action") if isinstance(iteration.get("next_action"), dict) else iteration
    produced_refs = _evidence_refs(iteration, "produced_evidence_refs")
    produced_refs.extend(_evidence_refs(iteration, "evidence_refs"))
    produced_refs.extend(_evidence_refs(iteration, "artifact_refs"))
    produced_refs.extend(_finding_refs(iteration))
    produced_refs = sorted(set(ref for ref in produced_refs if ref))
    consumed_refs = sorted(set(_evidence_refs(iteration, "consumes_evidence_refs")))
    goal_closure = iteration.get("goal_closure") if isinstance(iteration.get("goal_closure"), dict) else {}
    return {
        "iteration": int(iteration.get("iteration") or iteration.get("order") or 0),
        "tool": str(action.get("tool") or iteration.get("tool") or ""),
        "target": str(action.get("target") or iteration.get("target") or ""),
        "status": str(iteration.get("status") or "recorded"),
        "produced_evidence_refs": produced_refs,
        "consumes_evidence_refs": consumed_refs,
        "finding_ids": sorted(set(_finding_refs(iteration))),
        "goal_closure": goal_closure,
        "has_artifact_or_finding_evidence": bool(produced_refs),
    }


def _evidence_refs(payload: dict[str, Any], key: str) -> list[str]:
    refs: list[str] = []
    value = payload.get(key)
    if isinstance(value, str):
        refs.append(value)
    elif isinstance(value, list):
        refs.extend(str(item) for item in value if str(item or "").strip())
    return refs


def _finding_refs(iteration: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for finding in iteration.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        ref = finding.get("evidence_ref") or finding.get("id") or finding.get("finding_id")
        if ref:
            refs.append(str(ref))
    return refs


def _iteration_linkage_failures(iterations: list[dict[str, Any]]) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    if not iterations:
        return failures
    for iteration in iterations:
        if not iteration["has_artifact_or_finding_evidence"]:
            failures.append(
                {
                    "code": f"iteration_{iteration['iteration']}_missing_artifact_or_finding",
                    "reason": "Every collected ai_loop iteration must produce artifact or finding evidence refs.",
                    "safest_next_step": "Attach runner artifact IDs or finding evidence refs for each iteration.",
                }
            )
    if len(iterations) >= 2 and not _iteration_two_consumes_iteration_one(iterations):
        failures.append(
            {
                "code": "iteration_2_does_not_consume_iteration_1",
                "reason": "Iteration 2 must explicitly consume an artifact or evidence ref produced by iteration 1.",
                "safest_next_step": "Record consumes_evidence_refs on iteration 2 with an iteration 1 artifact/finding ref.",
            }
        )
    return failures


def _goal_closure_failures(iterations: list[dict[str, Any]]) -> list[dict[str, str]]:
    if _goal_closure_evidence_backed(iterations):
        return []
    return [
        {
            "code": "goal_closure_not_evidence_backed",
            "reason": "The final collected iteration must record reached goal closure with supporting evidence refs.",
            "safest_next_step": "Record goal_closure.status='reached' plus supporting_evidence_refs from prior iterations.",
        }
    ]


def _iteration_two_consumes_iteration_one(iterations: list[dict[str, Any]]) -> bool:
    if len(iterations) < 2:
        return False
    produced = set(iterations[0].get("produced_evidence_refs") or [])
    consumed = set(iterations[1].get("consumes_evidence_refs") or [])
    return bool(produced & consumed)


def _goal_closure_evidence_backed(iterations: list[dict[str, Any]]) -> bool:
    if len(iterations) < 3:
        return False
    prior_refs = {
        ref
        for iteration in iterations[:-1]
        for ref in list(iteration.get("produced_evidence_refs") or [])
    }
    closure = iterations[-1].get("goal_closure") if isinstance(iterations[-1].get("goal_closure"), dict) else {}
    closure_refs = {
        str(ref)
        for ref in closure.get("supporting_evidence_refs") or closure.get("evidence_refs") or []
        if str(ref or "").strip()
    }
    return str(closure.get("status") or "").lower() in {"reached", "closed", "satisfied"} and bool(
        closure_refs & prior_refs
    )


def _safety_contract(target_url: str) -> dict[str, bool]:
    return {
        "local_loopback_only": PUBLIC_GRUYERE_HOST not in target_url.lower()
        and urlparse(target_url if "://" in target_url else f"//{target_url}").hostname in LOCAL_ALLOWED_HOSTS,
        "public_gruyere_touched": False,
        "external_live_infrastructure_touched": False,
        "provider_mocked_or_deterministic": True,
        "runtime_dispatch_performed": False,
        "proposal_approval_performed": False,
        "scope_roe_bypass_performed": False,
        "credential_materialization_performed": False,
        "kill_switch_bypassed": False,
    }


def _safe_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate local Gruyere multi-iteration ai_loop proof evidence.")
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    parser.add_argument("--collected-evidence")
    parser.add_argument("--output", default=str(DEFAULT_RESULTS_FILE))
    parser.add_argument("--markdown", default=str(DEFAULT_MARKDOWN_FILE))
    args = parser.parse_args(argv)

    catalog = load_json(args.catalog)
    evidence = load_json(args.collected_evidence) if args.collected_evidence else None
    report = build_gruyere_ai_loop_proof_report(catalog=catalog, collected_evidence=evidence)
    write_report(report, output=args.output, markdown=args.markdown)
    if report["status"] == "passed":
        return 0
    if report["status"] == "blocked":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
