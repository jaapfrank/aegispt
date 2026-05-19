from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    DISABLED_PROVIDER_NAMES,
    send_chatgpt_backend_streaming_json_request,
)

BENCHMARK_EVAL_MODE = "reference_guided_advisory"
BENCHMARK_EVAL_VERSION = "2026-04-29"


@dataclass(frozen=True, slots=True)
class BenchmarkEvalProviderResult:
    explanations: dict[str, str] = field(default_factory=dict)
    confidence_notes: list[dict[str, Any]] = field(default_factory=list)
    model: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BenchmarkEvalProvider(Protocol):
    name: str

    def explain(self, request: dict[str, Any]) -> BenchmarkEvalProviderResult:
        raise NotImplementedError


class ChatGPTOAuthBenchmarkEvalProvider:
    name = CHATGPT_OAUTH_PROVIDER

    def __init__(self, *, session: Session, engagement_id: Any, settings: Settings) -> None:
        self.session = session
        self.engagement_id = engagement_id
        self.settings = settings

    def explain(self, request: dict[str, Any]) -> BenchmarkEvalProviderResult:
        payload = send_chatgpt_backend_streaming_json_request(
            session=self.session,
            engagement_id=self.engagement_id,
            settings=self.settings,
            model=self.settings.chatgpt_oauth_model,
            instructions=(
                "You are grading an authorized AegisPT benchmark validation result. "
                "Return an object with explanations, confidence_notes, and metadata only. "
                "Do not create findings, dispatch scans, change scope, or make release-gate decisions."
            ),
            input_items=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "Explain benchmark expected-vs-actual coverage gaps from this grounded JSON. "
                                "Keep the deterministic status buckets unchanged.\n"
                                + _json_dumps_for_provider(request)
                            ),
                        }
                    ],
                }
            ],
        )
        result_payload = payload.get("benchmark_eval") if isinstance(payload.get("benchmark_eval"), dict) else payload
        return BenchmarkEvalProviderResult(
            explanations=_string_dict(result_payload.get("explanations")),
            confidence_notes=_json_object_list(result_payload.get("confidence_notes") or [], "confidence_notes"),
            model=str(result_payload.get("model") or self.settings.chatgpt_oauth_model),
            metadata={
                **_json_object(result_payload.get("metadata") or {}, "metadata"),
                "provider_mode": CHATGPT_OAUTH_PROVIDER,
                "token_exposed": False,
            },
        )


def build_benchmark_eval_report_from_catalogs(
    *,
    target_catalog: dict[str, Any],
    expected_catalog: dict[str, Any] | None = None,
    target_id: str,
    actual_findings_payload: Any,
    validation_scenario_id: str | None = None,
    provider: BenchmarkEvalProvider | None = None,
    provider_name: str | None = None,
    artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target = _find_by_id(target_catalog.get("targets"), target_id, "target")
    scenario = None
    if expected_catalog is not None and validation_scenario_id:
        scenario = _find_by_id(expected_catalog.get("scenarios"), validation_scenario_id, "validation scenario")

    expected_findings = list(scenario.get("expected_findings") or []) if scenario is not None else []
    benchmark_metadata = target.get("benchmark_metadata") if isinstance(target.get("benchmark_metadata"), dict) else {}
    return build_benchmark_eval_report(
        benchmark_metadata=benchmark_metadata,
        expected_findings=expected_findings,
        actual_findings_payload=actual_findings_payload,
        scenario_id=validation_scenario_id,
        target_id=target_id,
        provider=provider,
        provider_name=provider_name,
        artifacts=artifacts,
        catalog_context={
            "target_label": target.get("label"),
            "target_runnability": target.get("runnability"),
            "validation_scenario_name": scenario.get("name") if scenario is not None else None,
        },
    )


def build_benchmark_eval_report(
    *,
    benchmark_metadata: dict[str, Any],
    expected_findings: list[dict[str, Any]] | None,
    actual_findings_payload: Any,
    scenario_id: str | None = None,
    target_id: str | None = None,
    provider: BenchmarkEvalProvider | None = None,
    provider_name: str | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    catalog_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a review-only benchmark expected-vs-actual report.

    This service deliberately does not persist anything, create findings, dispatch
    work, or provide release-gate authority. Provider output can add explanations
    but cannot change the deterministic reference-guided status buckets.
    """

    metadata = _json_object(benchmark_metadata, "benchmark_metadata")
    expected = _json_object_list(expected_findings or [], "expected_findings")
    findings = _normalize_findings(actual_findings_payload)
    artifact_refs = _artifact_refs(artifacts or [])

    expected_signals, matched_indexes = _evaluate_expected_signals(expected, findings)
    uncertain_signals = _evaluate_uncertain_family_signals(
        metadata=metadata,
        expected=expected,
        findings=findings,
        matched_indexes=matched_indexes,
    )
    unexpected_signals = _unexpected_signals(findings, matched_indexes)
    counts = {
        "expected": len(expected_signals),
        "found": sum(1 for signal in expected_signals if signal["status"] == "found"),
        "missed": sum(1 for signal in expected_signals if signal["status"] == "missed"),
        "uncertain": len(uncertain_signals),
        "unexpected": len(unexpected_signals),
        "actual_findings": len(findings),
        "artifacts": len(artifact_refs),
    }

    deterministic_report = {
        "schema_version": 1,
        "mode": BENCHMARK_EVAL_MODE,
        "version": BENCHMARK_EVAL_VERSION,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "status": _overall_status(counts),
        "benchmark": {
            "family": str(metadata.get("benchmark_family") or "unknown-benchmark"),
            "scenario_id": scenario_id,
            "target_id": target_id,
            "vulnerable_families": _string_list(metadata.get("vulnerable_families")),
            "prerequisites": _string_list(metadata.get("prerequisites")),
            "coverage_expectation": str(metadata.get("coverage_expectation") or ""),
        },
        "catalog_context": _json_object(catalog_context or {}, "catalog_context"),
        "coverage": {
            "counts": counts,
            "expected_coverage_pct": _expected_coverage_pct(counts),
            "quality_note": _quality_note(counts),
        },
        "signals": {
            "found": [signal for signal in expected_signals if signal["status"] == "found"],
            "missed": [signal for signal in expected_signals if signal["status"] == "missed"],
            "uncertain": uncertain_signals,
            "unexpected": unexpected_signals,
        },
        "grounding": {
            "sources": _grounding_sources(expected, metadata, findings, artifact_refs),
            "artifact_refs": artifact_refs,
            "actual_finding_count": len(findings),
            "expected_catalog_present": bool(expected),
            "benchmark_metadata_present": bool(metadata),
        },
        "boundaries": _advisory_boundaries(),
    }

    provider_status = _provider_status(
        provider=provider,
        provider_name=provider_name,
        request=deterministic_report,
    )
    return {
        **deterministic_report,
        "ai_assistance": provider_status,
    }


def _evaluate_expected_signals(
    expected: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[int]]:
    signals: list[dict[str, Any]] = []
    matched_indexes: set[int] = set()
    for expectation in expected:
        indexes = [
            index
            for index, finding in enumerate(findings)
            if _finding_matches(expectation, finding)
        ]
        matched_indexes.update(indexes)
        expectation_id = str(expectation.get("id") or expectation.get("title_pattern") or "expected-signal")
        signals.append(
            {
                "id": expectation_id,
                "status": "found" if indexes else "missed",
                "title_pattern": expectation.get("title_pattern"),
                "severity": expectation.get("severity"),
                "tool": expectation.get("tool"),
                "target_pattern": expectation.get("target_pattern"),
                "wstg": expectation.get("wstg"),
                "matched_finding_indexes": indexes,
                "grounding": {
                    "expected_rule": expectation_id,
                    "actual_finding_indexes": indexes,
                },
            }
        )
    return signals, matched_indexes


def _evaluate_uncertain_family_signals(
    *,
    metadata: dict[str, Any],
    expected: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    matched_indexes: set[int],
) -> list[dict[str, Any]]:
    families = _string_list(metadata.get("vulnerable_families"))
    expected_text = " ".join(str(item.get("id") or "") + " " + str(item.get("title_pattern") or "") for item in expected)
    uncertain: list[dict[str, Any]] = []
    for family in families:
        if _contains_family_text(expected_text, family):
            continue
        family_matches = [
            index
            for index, finding in enumerate(findings)
            if index not in matched_indexes and _contains_family_text(_finding_search_text(finding), family)
        ]
        uncertain.append(
            {
                "id": _slug(f"family-{family}"),
                "status": "uncertain",
                "family": family,
                "matched_finding_indexes": family_matches,
                "reason": (
                    "Benchmark metadata names this vulnerable family, but the expected-finding catalog "
                    "does not contain a specific matcher for it. Treat this as a coverage question, not "
                    "a pass/fail signal."
                ),
                "grounding": {
                    "benchmark_metadata": "vulnerable_families",
                    "actual_finding_indexes": family_matches,
                },
            }
        )
    return uncertain


def _unexpected_signals(findings: list[dict[str, Any]], matched_indexes: set[int]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if index in matched_indexes:
            continue
        signals.append(
            {
                "id": f"unexpected-{index}",
                "status": "unexpected",
                "finding_index": index,
                "title": finding["title"],
                "severity": finding["severity"],
                "target": finding["target"],
                "tool": finding["tool"],
                "reason": "Actual finding did not match a reference expected-finding rule.",
                "grounding": {"actual_finding_index": index},
            }
        )
    return signals


def _provider_status(
    *,
    provider: BenchmarkEvalProvider | None,
    provider_name: str | None,
    request: dict[str, Any],
) -> dict[str, Any]:
    requested_name = str(provider_name or getattr(provider, "name", "") or "disabled").strip().lower()
    if provider is None or requested_name in DISABLED_PROVIDER_NAMES:
        return {
            "status": "disabled",
            "provider": requested_name or "disabled",
            "fallback": "reference_guided",
            "message": "No benchmark-eval provider is configured; deterministic reference-guided grading is active.",
            "authoritative": False,
        }

    try:
        result = provider.explain(request)
    except Exception as exc:
        return {
            "status": "failed",
            "provider": requested_name,
            "fallback": "reference_guided",
            "failure_reason": str(exc)[:1000],
            "authoritative": False,
        }

    return {
        "status": "succeeded",
        "provider": requested_name,
        "fallback": "reference_guided",
        "authoritative": False,
        "model": result.model,
        "explanations": _string_dict(result.explanations),
        "confidence_notes": _json_object_list(result.confidence_notes, "confidence_notes"),
        "metadata": _json_object(result.metadata, "provider_metadata"),
    }


def _normalize_findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("findings"), list):
            raw_findings = payload["findings"]
        elif isinstance(payload.get("items"), list):
            raw_findings = payload["items"]
        elif isinstance(payload.get("data"), list):
            raw_findings = payload["data"]
        else:
            raw_findings = [payload]
    elif isinstance(payload, list):
        raw_findings = payload
    else:
        raw_findings = []

    normalized: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "title": str(item.get("title") or item.get("name") or item.get("finding") or "").strip(),
                "severity": str(item.get("severity") or "").strip().lower(),
                "tool": str(item.get("tool") or item.get("tool_name") or item.get("source_tool") or item.get("scanner") or "").strip().lower(),
                "target": str(item.get("target_id") or item.get("target") or item.get("url") or item.get("asset") or item.get("host") or "").strip(),
                "wstg": str(item.get("wstg") or item.get("wstg_id") or "").strip(),
                "summary": str(item.get("summary") or item.get("description") or "").strip(),
                "raw": item,
            }
        )
    return normalized


def _finding_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    return (
        _regex_matches(expectation.get("title_pattern"), finding.get("title", ""))
        and _regex_matches(expectation.get("severity"), finding.get("severity", ""), flags=re.IGNORECASE)
        and _contains_expected_tool(expectation.get("tool"), finding.get("tool", ""))
        and _regex_matches(expectation.get("target_pattern"), finding.get("target", ""))
        and _regex_matches(expectation.get("wstg"), finding.get("wstg", ""))
    )


def _regex_matches(pattern: Any, value: str, *, flags: int = 0) -> bool:
    if pattern is None or pattern == "":
        return True
    return re.search(str(pattern), value or "", flags=flags) is not None


def _contains_expected_tool(expected: Any, actual: str) -> bool:
    if expected is None or expected == "":
        return True
    return str(expected).lower() in (actual or "").lower()


def _finding_search_text(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(key) or "")
        for key in ("title", "severity", "tool", "target", "wstg", "summary")
    )


def _contains_family_text(value: str, family: str) -> bool:
    family_tokens = [token for token in re.split(r"[^a-z0-9]+", family.lower()) if len(token) >= 3]
    value_lower = value.lower()
    return bool(family_tokens) and all(token in value_lower for token in family_tokens[:3])


def _overall_status(counts: dict[str, int]) -> str:
    if counts["expected"] == 0 and counts["uncertain"] > 0:
        return "limited_reference"
    if counts["missed"] and counts["found"]:
        return "partial"
    if counts["missed"]:
        return "gaps_detected"
    if counts["unexpected"] and counts["expected"] == 0:
        return "unexpected_only"
    if counts["expected"] == 0:
        return "no_reference_expectations"
    return "covered"


def _expected_coverage_pct(counts: dict[str, int]) -> float | None:
    if counts["expected"] == 0:
        return None
    return round((counts["found"] / counts["expected"]) * 100, 2)


def _quality_note(counts: dict[str, int]) -> str:
    if counts["expected"] == 0:
        return "No exact expected-finding rules were supplied, so this report cannot grade deterministic coverage."
    if counts["missed"]:
        return "One or more reference expected-finding signals were not observed in actual output."
    if counts["unexpected"]:
        return "Expected signals were observed, with additional unmatched findings that need review."
    return "All supplied expected-finding signals were observed."


def _grounding_sources(
    expected: list[dict[str, Any]],
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    artifact_refs: list[dict[str, Any]],
) -> list[str]:
    sources = []
    if metadata:
        sources.append("benchmark_metadata")
    if expected:
        sources.append("expected_finding_catalog")
    if findings:
        sources.append("actual_findings")
    if artifact_refs:
        sources.append("run_artifacts")
    return sources


def _artifact_refs(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            continue
        refs.append(
            {
                "index": index,
                "id": artifact.get("id"),
                "artifact_ref": artifact.get("artifact_ref") or artifact.get("uri"),
                "sha256": artifact.get("sha256"),
                "kind": artifact.get("kind") or artifact.get("artifact_kind"),
            }
        )
    return refs


def _advisory_boundaries() -> dict[str, Any]:
    return {
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


def _find_by_id(items: Any, item_id: str, label: str) -> dict[str, Any]:
    for item in items or []:
        if isinstance(item, dict) and item.get("id") == item_id:
            return item
    raise ValueError(f"Unknown {label}: {item_id}")


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _json_object_list(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return [dict(item) for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "signal"


def _json_dumps_for_provider(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True)
