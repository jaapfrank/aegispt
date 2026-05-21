from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

CLAUDE_PROVIDER = "claude-opus-4-7"
CHATGPT_OAUTH_PROVIDER = "chatgpt_oauth"


@dataclass(frozen=True)
class PickerDecisionLog:
    step: int
    action: str
    tool: str | None = None
    target: str | None = None
    confidence: float | None = None
    reasoning: str | None = None
    failure_reason: str | None = None


@dataclass(frozen=True)
class PickerProviderResult:
    provider: str
    provider_config: dict[str, Any]
    target: str
    evidence_fixture_id: str
    run_id: str | None
    decisions: list[PickerDecisionLog]
    finding_count: int
    high_or_critical_count: int
    canary_delta: int
    proof_delta: int
    failure_reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PickerComparisonReport:
    generated_at: str
    mode: str
    target: str
    evidence_fixture_id: str
    provider_results: list[PickerProviderResult]
    matched_decision_count: int
    deltas: dict[str, Any]
    limitations: list[str]
    winner_claim: None = None


def build_dry_run_report(*, target: str = "dry-run://picker-ab-fixture") -> PickerComparisonReport:
    evidence_fixture_id = "picker-ab-dry-run-v1"
    provider_results = [
        PickerProviderResult(
            provider="claude",
            provider_config={"llm_provider": CLAUDE_PROVIDER},
            target=target,
            evidence_fixture_id=evidence_fixture_id,
            run_id="dry-run-claude",
            decisions=[
                PickerDecisionLog(
                    step=1,
                    action="pick",
                    tool="target-intel",
                    target=target,
                    confidence=0.74,
                    reasoning="Establish baseline evidence before exploit planning.",
                ),
                PickerDecisionLog(
                    step=2,
                    action="exec_plan",
                    tool="exec-plan",
                    target=target,
                    confidence=0.68,
                    reasoning="Fixture contains a confirmed login form and captured prior response.",
                ),
            ],
            finding_count=1,
            high_or_critical_count=1,
            canary_delta=1,
            proof_delta=1,
            failure_reasons=[],
        ),
        PickerProviderResult(
            provider="chatgpt_oauth",
            provider_config={"llm_provider": CHATGPT_OAUTH_PROVIDER, "model": "gpt-5.4"},
            target=target,
            evidence_fixture_id=evidence_fixture_id,
            run_id="dry-run-chatgpt-oauth",
            decisions=[
                PickerDecisionLog(
                    step=1,
                    action="pick",
                    tool="target-intel",
                    target=target,
                    confidence=0.71,
                    reasoning="Use the same baseline evidence fixture before choosing a next step.",
                ),
                PickerDecisionLog(
                    step=2,
                    action="exec_plan",
                    tool="exec-plan",
                    target=target,
                    confidence=0.65,
                    reasoning="Fixture supports a bounded multi-step verification plan.",
                ),
            ],
            finding_count=1,
            high_or_critical_count=1,
            canary_delta=1,
            proof_delta=1,
            failure_reasons=[],
        ),
    ]
    return _build_report(
        mode="dry-run",
        target=target,
        evidence_fixture_id=evidence_fixture_id,
        provider_results=provider_results,
    )


def load_recorded_report(path: Path) -> PickerComparisonReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("recorded picker A/B input must be a JSON object")
    target = str(payload.get("target") or "").strip()
    evidence_fixture_id = str(payload.get("evidence_fixture_id") or payload.get("evidence_id") or "").strip()
    raw_results = payload.get("provider_results") or payload.get("runs")
    if not target:
        raise ValueError("recorded picker A/B input requires 'target'")
    if not evidence_fixture_id:
        raise ValueError("recorded picker A/B input requires 'evidence_fixture_id' or 'evidence_id'")
    if not isinstance(raw_results, list) or len(raw_results) != 2:
        raise ValueError("recorded picker A/B input requires exactly two provider results")
    provider_results = [_provider_result_from_payload(item, target, evidence_fixture_id) for item in raw_results]
    return _build_report(
        mode="recorded",
        target=target,
        evidence_fixture_id=evidence_fixture_id,
        provider_results=provider_results,
    )


def report_to_json(report: PickerComparisonReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True) + "\n"


def report_to_markdown(report: PickerComparisonReport) -> str:
    lines = [
        "# Picker A/B Comparison",
        "",
        f"- Mode: `{report.mode}`",
        f"- Target: `{report.target}`",
        f"- Evidence fixture: `{report.evidence_fixture_id}`",
        f"- Generated: `{report.generated_at}`",
        "- Winner claim: none; this report records measured deltas only.",
        "",
        "## Provider Results",
        "",
    ]
    for result in report.provider_results:
        lines.extend([
            f"### {result.provider}",
            "",
            f"- Run ID: `{result.run_id or 'not-recorded'}`",
            f"- Provider config: `{json.dumps(result.provider_config, sort_keys=True)}`",
            f"- Findings: `{result.finding_count}`",
            f"- High/Critical findings: `{result.high_or_critical_count}`",
            f"- Canary delta: `{result.canary_delta}`",
            f"- Proof delta: `{result.proof_delta}`",
            f"- Failure reasons: `{'; '.join(result.failure_reasons) if result.failure_reasons else 'none'}`",
            "",
            "| Step | Action | Tool | Target | Confidence | Failure reason |",
            "|---:|---|---|---|---:|---|",
        ])
        for decision in result.decisions:
            lines.append(
                "| {step} | {action} | {tool} | {target} | {confidence} | {failure} |".format(
                    step=decision.step,
                    action=decision.action,
                    tool=decision.tool or "",
                    target=decision.target or "",
                    confidence="" if decision.confidence is None else f"{decision.confidence:.2f}",
                    failure=decision.failure_reason or "",
                )
            )
        lines.append("")
    lines.extend([
        "## Deltas",
        "",
        "```json",
        json.dumps(report.deltas, indent=2, sort_keys=True),
        "```",
        "",
        "## Limitations",
        "",
    ])
    lines.extend(f"- {item}" for item in report.limitations)
    lines.append("")
    return "\n".join(lines)


def write_report(report: PickerComparisonReport, path: Path, *, output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "markdown":
        path.write_text(report_to_markdown(report), encoding="utf-8")
    else:
        path.write_text(report_to_json(report), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare Claude and ChatGPT-OAuth picker decisions.")
    parser.add_argument("--input", type=Path, help="Recorded run/result JSON to compare.")
    parser.add_argument("--target", default="dry-run://picker-ab-fixture", help="Target label for dry-run mode.")
    parser.add_argument("--output", type=Path, help="Write the comparison report to this path.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Report output format.")
    args = parser.parse_args(argv)

    report = load_recorded_report(args.input) if args.input else build_dry_run_report(target=args.target)
    rendered = report_to_markdown(report) if args.format == "markdown" else report_to_json(report)
    if args.output:
        write_report(report, args.output, output_format=args.format)
    else:
        print(rendered, end="")
    return 0


def _provider_result_from_payload(
    payload: Any,
    default_target: str,
    default_evidence_fixture_id: str,
) -> PickerProviderResult:
    if not isinstance(payload, dict):
        raise ValueError("provider result entries must be JSON objects")
    decisions = payload.get("decisions")
    if not isinstance(decisions, list):
        raise ValueError("provider result entry requires a decisions list")
    return PickerProviderResult(
        provider=str(payload.get("provider") or "").strip(),
        provider_config=_safe_dict(payload.get("provider_config")),
        target=str(payload.get("target") or default_target),
        evidence_fixture_id=str(payload.get("evidence_fixture_id") or default_evidence_fixture_id),
        run_id=str(payload.get("run_id") or "") or None,
        decisions=[_decision_from_payload(index + 1, item) for index, item in enumerate(decisions)],
        finding_count=int(payload.get("finding_count") or 0),
        high_or_critical_count=int(payload.get("high_or_critical_count") or 0),
        canary_delta=int(payload.get("canary_delta") or 0),
        proof_delta=int(payload.get("proof_delta") or 0),
        failure_reasons=[str(item) for item in (payload.get("failure_reasons") or [])],
    )


def _decision_from_payload(default_step: int, payload: Any) -> PickerDecisionLog:
    if not isinstance(payload, dict):
        raise ValueError("decision entries must be JSON objects")
    confidence = payload.get("confidence")
    return PickerDecisionLog(
        step=int(payload.get("step") or default_step),
        action=str(payload.get("action") or "").strip(),
        tool=str(payload.get("tool") or "") or None,
        target=str(payload.get("target") or "") or None,
        confidence=float(confidence) if confidence is not None else None,
        reasoning=str(payload.get("reasoning") or "") or None,
        failure_reason=str(payload.get("failure_reason") or "") or None,
    )


def _build_report(
    *,
    mode: str,
    target: str,
    evidence_fixture_id: str,
    provider_results: list[PickerProviderResult],
) -> PickerComparisonReport:
    if len(provider_results) != 2:
        raise ValueError("picker A/B report requires exactly two provider results")
    matched_decision_count = min(len(item.decisions) for item in provider_results)
    deltas = {
        "finding_count": _metric_delta(provider_results, "finding_count"),
        "high_or_critical_count": _metric_delta(provider_results, "high_or_critical_count"),
        "canary_delta": _metric_delta(provider_results, "canary_delta"),
        "proof_delta": _metric_delta(provider_results, "proof_delta"),
        "matched_decision_count": matched_decision_count,
        "failure_reasons_by_provider": {
            item.provider: item.failure_reasons for item in provider_results
        },
    }
    limitations = [
        "No winner is claimed by this harness; it records comparable evidence only.",
        "Dry-run mode proves report generation and provider configuration shape, not model capability.",
        "Live/lab claims require recorded run IDs, explicit target authorization, and comparable evidence inputs.",
    ]
    return PickerComparisonReport(
        generated_at=datetime.now(tz=UTC).isoformat(),
        mode=mode,
        target=target,
        evidence_fixture_id=evidence_fixture_id,
        provider_results=provider_results,
        matched_decision_count=matched_decision_count,
        deltas=deltas,
        limitations=limitations,
        winner_claim=None,
    )


def _metric_delta(provider_results: list[PickerProviderResult], field_name: str) -> dict[str, Any]:
    left, right = provider_results
    left_value = int(getattr(left, field_name))
    right_value = int(getattr(right, field_name))
    return {
        left.provider: left_value,
        right.provider: right_value,
        "absolute_delta": right_value - left_value,
    }


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


if __name__ == "__main__":
    raise SystemExit(main())
