from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import product
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Finding, FindingChain, Run

SEVERITY_SCORE = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.68,
    "low": 0.42,
    "info": 0.28,
}

CHAIN_BOUNDARY = {
    "message": (
        "Vulnerability chains are additive analysis records built from existing findings. "
        "They do not mutate component findings, auto-escalate severity, or execute chained exploitation."
    ),
    "mutates_component_findings": False,
    "auto_escalates_severity": False,
    "executes_exploits": False,
}

SIGNAL_TOKENS: dict[str, tuple[str, ...]] = {
    "exposed_management_surface": (
        "admin panel",
        "admin console",
        "management",
        "dashboard exposed",
        "public admin",
        "exposed",
        "unauthenticated",
    ),
    "credential_or_session_weakness": (
        "credential",
        "password",
        "default password",
        "weak password",
        "token",
        "session",
        "cookie",
        "auth bypass",
        "cwe-287",
        "cwe-798",
    ),
    "injection_execution": (
        "sql injection",
        "sqli",
        "command injection",
        "remote code execution",
        "rce",
        "injection",
        "cwe-89",
    ),
    "sensitive_data_exposure": (
        "sensitive data",
        "secret",
        "api key",
        "token leak",
        "information disclosure",
        "data exposure",
        "credentials exposed",
    ),
}


@dataclass(frozen=True, slots=True)
class ChainPattern:
    pattern_id: str
    title: str
    required_signals: tuple[str, ...]
    combined_impact: str
    operator_note: str


CHAIN_PATTERNS: tuple[ChainPattern, ...] = (
    ChainPattern(
        pattern_id="exposed-management-plus-credential-weakness",
        title="Exposed management surface plus credential/session weakness",
        required_signals=("exposed_management_surface", "credential_or_session_weakness"),
        combined_impact=(
            "An exposed management surface combined with credential or session weakness may increase "
            "the likelihood of unauthorized administrative access if both findings are reachable in the same scope."
        ),
        operator_note="Review reachability, authentication controls, and evidence refs together before making any risk claim.",
    ),
    ChainPattern(
        pattern_id="injection-plus-sensitive-data-exposure",
        title="Injection evidence plus sensitive data exposure",
        required_signals=("injection_execution", "sensitive_data_exposure"),
        combined_impact=(
            "Injection evidence combined with sensitive-data exposure may indicate a plausible data-access chain, "
            "but the record remains explanatory until an operator validates prerequisites."
        ),
        operator_note="Confirm shared target context and stored evidence before using this in a report narrative.",
    ),
)


def refresh_finding_chains_for_run(*, session: Session, run_id: UUID) -> list[FindingChain]:
    run = _load_run(session=session, run_id=run_id)
    if run is None:
        return []

    findings = [finding for finding in list(run.findings or []) if finding.run_id == run.id]
    detected: list[FindingChain] = []
    for pattern in CHAIN_PATTERNS:
        component_findings = _select_components_for_pattern(findings=findings, pattern=pattern)
        if len(component_findings) < 2:
            continue
        detected.append(_upsert_chain(session=session, run=run, pattern=pattern, findings=component_findings))

    session.flush()
    return _list_chains_for_run(session=session, run_id=run.id)


def build_finding_chain_context(
    *,
    session: Session,
    finding: Finding,
    refresh: bool = True,
) -> dict[str, Any]:
    if finding.run_id is None:
        return _empty_context(finding=finding, reason="Finding is not attached to a run, so no run-scoped chain can be derived.")

    if refresh:
        refresh_finding_chains_for_run(session=session, run_id=finding.run_id)

    chains = _list_chains_for_run(session=session, run_id=finding.run_id)
    matching = [
        chain
        for chain in chains
        if str(finding.id) in {str(item) for item in list(chain.component_finding_ids_json or [])}
    ]
    if not matching:
        return _empty_context(
            finding=finding,
            reason="No known chain pattern currently links this finding to another evidence-backed component finding.",
        )

    run_findings = _findings_by_id(session=session, ids={item for chain in matching for item in chain.component_finding_ids_json})
    return {
        "available": True,
        "finding_id": str(finding.id),
        "chains": [_chain_payload(chain=chain, findings_by_id=run_findings) for chain in matching],
        "no_chain_reason": None,
        "boundary": dict(CHAIN_BOUNDARY),
        "pattern_catalog": _pattern_catalog(),
    }


def _load_run(*, session: Session, run_id: UUID) -> Run | None:
    return session.scalar(
        select(Run)
        .where(Run.id == run_id, Run.deleted_at.is_(None))
        .options(
            selectinload(Run.findings),
            selectinload(Run.finding_chains),
        )
    )


def _list_chains_for_run(*, session: Session, run_id: UUID) -> list[FindingChain]:
    return list(
        session.scalars(
            select(FindingChain)
            .where(FindingChain.run_id == run_id)
            .order_by(FindingChain.confidence_score.desc(), FindingChain.created_at, FindingChain.id)
        )
    )


def _select_components_for_pattern(*, findings: list[Finding], pattern: ChainPattern) -> list[Finding]:
    by_signal: list[list[Finding]] = []
    for signal in pattern.required_signals:
        candidates = [finding for finding in findings if _finding_matches_signal(finding, signal)]
        if not candidates:
            return []
        by_signal.append(sorted(candidates, key=_finding_rank, reverse=True)[:4])

    best: tuple[float, list[Finding]] | None = None
    for candidate_group in product(*by_signal):
        unique: dict[str, Finding] = {str(finding.id): finding for finding in candidate_group}
        if len(unique) < 2:
            continue
        component_findings = list(unique.values())
        score = _confidence_score(component_findings)
        if best is None or score > best[0]:
            best = (score, component_findings)

    return best[1] if best is not None else []


def _finding_matches_signal(finding: Finding, signal: str) -> bool:
    haystack = " ".join(
        [
            finding.title or "",
            finding.summary or "",
            finding.control_family or "",
            finding.wstg_id or "",
            finding.asvs_reference or "",
            " ".join(finding.methodology_tags or []),
        ]
    ).lower()
    return any(token in haystack for token in SIGNAL_TOKENS[signal])


def _finding_rank(finding: Finding) -> tuple[float, int, str]:
    evidence_bonus = 1 if str(finding.evidence_ref or "").strip() else 0
    return (_severity_score(finding), evidence_bonus, str(finding.id))


def _confidence_score(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    base = sum(_severity_score(finding) for finding in findings) / len(findings)
    evidence_refs = [str(finding.evidence_ref or "").strip() for finding in findings]
    evidence_adjustment = 0.08 if all(evidence_refs) else -0.18
    target_adjustment = 0.04 if len({finding.target_id for finding in findings}) == 1 else 0.0
    component_adjustment = min(0.05, 0.02 * max(0, len(findings) - 2))
    return round(max(0.0, min(0.95, base + evidence_adjustment + target_adjustment + component_adjustment)), 2)


def _severity_score(finding: Finding) -> float:
    return SEVERITY_SCORE.get(str(finding.severity or "unknown").lower(), 0.35)


def _upsert_chain(*, session: Session, run: Run, pattern: ChainPattern, findings: list[Finding]) -> FindingChain:
    component_ids = sorted(str(finding.id) for finding in findings)
    component_hash = hashlib.sha256("|".join(component_ids).encode("utf-8")).hexdigest()
    confidence = _confidence_score(findings)
    status = "detected" if confidence >= 0.6 else "low_confidence"
    evidence_refs = sorted({str(finding.evidence_ref) for finding in findings if str(finding.evidence_ref or "").strip()})
    rationale = [
        {
            "finding_id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "target_id": finding.target_id,
            "evidence_ref": finding.evidence_ref,
        }
        for finding in findings
    ]
    metadata = {
        "mutates_component_findings": False,
        "auto_escalates_severity": False,
        "executes_exploits": False,
        "operator_note": pattern.operator_note,
    }
    chain = session.scalar(
        select(FindingChain).where(
            FindingChain.run_id == run.id,
            FindingChain.pattern_id == pattern.pattern_id,
            FindingChain.component_hash == component_hash,
        )
    )
    if chain is None:
        chain = FindingChain(
            run_id=run.id,
            pattern_id=pattern.pattern_id,
            component_hash=component_hash,
            title=pattern.title,
            status=status,
            component_finding_ids_json=component_ids,
            confidence_score=confidence,
            combined_impact_text=pattern.combined_impact,
            evidence_refs_json=evidence_refs,
            rationale_json=rationale,
            metadata_json=metadata,
        )
        session.add(chain)
    else:
        chain.status = status
        chain.component_finding_ids_json = component_ids
        chain.confidence_score = confidence
        chain.combined_impact_text = pattern.combined_impact
        chain.evidence_refs_json = evidence_refs
        chain.rationale_json = rationale
        chain.metadata_json = {**dict(chain.metadata_json or {}), **metadata}
    session.flush()
    return chain


def _findings_by_id(*, session: Session, ids: set[str]) -> dict[str, Finding]:
    if not ids:
        return {}
    parsed_ids: list[UUID] = []
    for value in ids:
        try:
            parsed_ids.append(UUID(str(value)))
        except ValueError:
            continue
    return {str(finding.id): finding for finding in session.scalars(select(Finding).where(Finding.id.in_(parsed_ids))).all()}


def _chain_payload(*, chain: FindingChain, findings_by_id: dict[str, Finding]) -> dict[str, Any]:
    components = []
    for finding_id in list(chain.component_finding_ids_json or []):
        finding = findings_by_id.get(str(finding_id))
        if finding is None:
            components.append({"finding_id": str(finding_id), "missing": True})
            continue
        components.append(
            {
                "finding_id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "target_id": finding.target_id,
                "evidence_ref": finding.evidence_ref,
            }
        )
    return {
        "id": str(chain.id),
        "pattern_id": chain.pattern_id,
        "title": chain.title,
        "status": chain.status,
        "component_finding_ids": [str(item) for item in list(chain.component_finding_ids_json or [])],
        "component_findings": components,
        "confidence_score": chain.confidence_score,
        "combined_impact": chain.combined_impact_text,
        "evidence_refs": list(chain.evidence_refs_json or []),
        "rationale": list(chain.rationale_json or []),
        "metadata": dict(chain.metadata_json or {}),
    }


def _empty_context(*, finding: Finding, reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "finding_id": str(finding.id),
        "chains": [],
        "no_chain_reason": reason,
        "boundary": dict(CHAIN_BOUNDARY),
        "pattern_catalog": _pattern_catalog(),
    }


def _pattern_catalog() -> list[dict[str, Any]]:
    return [
        {
            "pattern_id": pattern.pattern_id,
            "title": pattern.title,
            "required_signals": list(pattern.required_signals),
        }
        for pattern in CHAIN_PATTERNS
    ]
