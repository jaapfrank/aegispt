from __future__ import annotations

from typing import Any

from api.app.models import Finding, Task

EVIDENCE_GAP_REPORT_VERSION = "evidence-gap-report-v1"
CONFIRMED_STATUSES = {"confirmed", "validated", "verified", "true_positive"}
CONTRADICTED_STATUSES = {"false_positive", "not_reproducible", "resolved"}


def build_evidence_gap_report_from_context(context: dict[str, object]) -> dict[str, Any]:
    claims = _claims_from_context(context)
    sections = {
        "confirmed": [claim for claim in claims if claim["state"] == "confirmed"],
        "suspected": [claim for claim in claims if claim["state"] == "suspected"],
        "untested": [claim for claim in claims if claim["state"] == "untested"],
        "contradicted": [claim for claim in claims if claim["state"] == "contradicted"],
    }
    unsupported = [
        claim
        for claim in claims
        if not claim["evidence_refs"] and claim["state"] in {"suspected", "untested"}
    ]
    return {
        "report_version": EVIDENCE_GAP_REPORT_VERSION,
        "execution_contract": {
            "analysis_only": True,
            "runs_scans": False,
            "changes_findings": False,
            "creates_tasks": False,
            "dispatches_work_directly": False,
            "approves_proposals": False,
            "mutates_scope": False,
            "runtime_self_modification": False,
        },
        "summary": {
            "confirmed": len(sections["confirmed"]),
            "suspected": len(sections["suspected"]),
            "untested": len(sections["untested"]),
            "contradicted": len(sections["contradicted"]),
            "unsupported_excluded_count": len(unsupported),
        },
        "sections": sections,
        "unsupported_claims_excluded_from_customer_report": unsupported,
    }


def _claims_from_context(context: dict[str, object]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    findings = [finding for finding in context.get("findings", []) if isinstance(finding, Finding)]
    tasks = [task for task in context.get("tasks", []) if isinstance(task, Task)]
    for finding in findings:
        claims.append(_claim_from_finding(finding, tasks))
    claims.extend(_untested_claims(context))
    if not claims:
        claims.append(
            {
                "claim_id": "run:no-claims",
                "state": "untested",
                "text": "No findings or tested coverage claims are available for this run.",
                "evidence_refs": [],
                "customer_report_allowed": False,
                "exclusion_reason": "Unsupported because no evidence-backed claim exists.",
                "source": "report_context",
            }
        )
    return claims


def _claim_from_finding(finding: Finding, tasks: list[Task]) -> dict[str, Any]:
    evidence_refs = [str(finding.evidence_ref)] if finding.evidence_ref else []
    state = _finding_state(finding, evidence_refs)
    linked_tasks = [task for task in tasks if str(task.source_finding_id or "") == str(finding.id)]
    if not evidence_refs:
        for task in linked_tasks:
            for execution in task.executions or []:
                for artifact in execution.artifacts or []:
                    if artifact.uri:
                        evidence_refs.append(str(artifact.uri))
    allowed = bool(evidence_refs) and state in {"confirmed", "contradicted"}
    return {
        "claim_id": f"finding:{finding.id}",
        "state": state,
        "text": f"{finding.title} on {finding.target_id or 'unknown target'}",
        "evidence_refs": sorted(set(evidence_refs)),
        "customer_report_allowed": allowed,
        "exclusion_reason": None if allowed else _exclusion_reason(state, evidence_refs),
        "source": "finding",
        "source_id": str(finding.id),
        "validation_status": finding.validation_status,
        "finding_status": finding.status,
    }


def _untested_claims(context: dict[str, object]) -> list[dict[str, Any]]:
    coverage = context.get("coverage")
    if not isinstance(coverage, dict):
        return []
    untested_items: list[dict[str, Any]] = []
    for key in ("not_tested", "untested", "blocked", "skipped"):
        raw_items = coverage.get(key)
        if not isinstance(raw_items, list):
            continue
        for index, item in enumerate(raw_items, start=1):
            label = _coverage_label(item)
            untested_items.append(
                {
                    "claim_id": f"coverage:{key}:{index}:{_slug(label)}",
                    "state": "untested",
                    "text": f"{label} is not proven by stored evidence.",
                    "evidence_refs": _coverage_refs(item),
                    "customer_report_allowed": False,
                    "exclusion_reason": "Unsupported for customer-facing prose until evidence is collected.",
                    "source": "coverage",
                    "coverage_state": key,
                }
            )
    return untested_items


def _finding_state(finding: Finding, evidence_refs: list[str]) -> str:
    validation = str(finding.validation_status or "").lower()
    status = str(finding.status or "").lower()
    if validation in CONTRADICTED_STATUSES or status in {"false_positive"}:
        return "contradicted"
    if evidence_refs and validation in CONFIRMED_STATUSES:
        return "confirmed"
    if evidence_refs and status in {"open", "triaged", "in_progress", "reopened"}:
        return "confirmed"
    return "suspected"


def _exclusion_reason(state: str, evidence_refs: list[str]) -> str:
    if state == "contradicted":
        return "Contradicted claims may be discussed only as disproven or resolved evidence, not as active impact."
    if not evidence_refs:
        return "Unsupported because no evidence reference is attached."
    return "Requires operator review before customer-facing prose."


def _coverage_label(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("surface") or item.get("target") or item.get("name") or item.get("id") or "Untested surface")
    return str(item or "Untested surface")


def _coverage_refs(item: object) -> list[str]:
    if not isinstance(item, dict):
        return []
    refs = item.get("evidence_refs")
    if isinstance(refs, list):
        return [str(ref) for ref in refs if str(ref)]
    if refs:
        return [str(refs)]
    return []


def _slug(value: object) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value)).strip("-")[:72] or "item"
