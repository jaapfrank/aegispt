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

# Ranks for severity escalation comparison (higher = more severe)
SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
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
    "web_file_upload": (
        "file upload",
        "upload endpoint",
        "unrestricted file upload",
        "arbitrary file upload",
        "uploaded html",
        "filename traversal",
        "wstg-busl",
    ),
    "stored_xss": (
        "stored xss",
        "xss_stored",
        "persistent xss",
        "stored cross-site scripting",
        "cross-site scripting stored",
        "uploaded html executes",
        "admin panel visited",
        "admin visit",
        "wstg-clnt-02",
    ),
    "path_traversal": (
        "path traversal",
        "directory traversal",
        "file path traversal",
        "lfi",
        "../",
        "wstg-athz-01",
    ),
    "writable_filesystem_or_code_execution": (
        "writable filesystem",
        "writable file system",
        "file write",
        "arbitrary file write",
        "write primitive",
        "code execution",
        "remote code execution",
        "rce",
        "web shell",
    ),
    # Signals for proven exploitation chains (from xss-proof, idor-bac)
    "reflected_xss_confirmed": (
        "reflected xss",
        "xss confirmed",
        "xss via url",
        "reflected cross-site scripting",
        "xss_reflected",
        "cookie theft",
        "session cookie theft",
        "critical",  # xss-proof creates CRITICAL findings
    ),
    "cookie_no_httponly": (
        "httponly",
        "no httponly",
        "cookie without httponly",
        "cookie no httponly",
        "cookie set without httponly",
        "cwe-1004",
    ),
    "idor_confirmed": (
        "idor",
        "insecure direct object",
        "horizontal privilege",
        "object reference",
        "unauthorized access",
        "cwe-639",
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
        pattern_id="xss-plus-cookie-theft-confirmed",
        title="Reflected XSS with stealable session cookie — confirmed exploitation chain",
        required_signals=("reflected_xss_confirmed", "cookie_no_httponly"),
        combined_impact=(
            "Reflected XSS evidence combined with a session cookie missing the HttpOnly flag "
            "constitutes a confirmed cookie theft chain. An attacker who tricks a logged-in victim "
            "into clicking a crafted URL can steal their session token and impersonate them without credentials. "
            "This is the complete attack: XSS delivers the payload, missing HttpOnly makes the cookie accessible."
        ),
        operator_note=(
            "Evidence confirmed by xss-proof runner: session cookie captured, authenticated pages accessed. "
            "Severity: CRITICAL when both findings are present on the same target."
        ),
    ),
    ChainPattern(
        pattern_id="idor-plus-session-access",
        title="IDOR combined with authenticated session access",
        required_signals=("idor_confirmed", "reflected_xss_confirmed"),
        combined_impact=(
            "Insecure Direct Object Reference combined with confirmed session access demonstrates "
            "that an attacker with any valid session (obtained via XSS or other means) can access "
            "resources belonging to other users. The combination enables unauthorized data access at scale."
        ),
        operator_note="Validate that the IDOR target and XSS target share the same authentication domain.",
    ),
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
    ChainPattern(
        pattern_id="web-file-upload-plus-stored-xss",
        title="Unrestricted file upload plus stored XSS execution path",
        required_signals=("web_file_upload", "stored_xss"),
        combined_impact=(
            "File-upload evidence combined with stored XSS evidence can indicate a compound web path where "
            "uploaded HTML or script-bearing content may execute in a privileged review surface. This remains "
            "an operator-reviewed hypothesis until a safe validation task confirms the prerequisites."
        ),
        operator_note=(
            "Validate only with explicit authorization, benign proof markers, and existing approval gates; "
            "do not claim session theft or account takeover without separately stored evidence."
        ),
    ),
    ChainPattern(
        pattern_id="path-traversal-plus-writable-execution-signal",
        title="Path traversal plus writable execution prerequisite",
        required_signals=("path_traversal", "writable_filesystem_or_code_execution"),
        combined_impact=(
            "Path-traversal evidence combined with file-write or code-execution prerequisites can indicate a "
            "possible route toward executable content placement. The chain record is explanatory and must not "
            "perform file writes or execute payloads automatically."
        ),
        operator_note=(
            "Review traversal reachability and write/execution prerequisites with detection-only checks first; "
            "active exploitation remains outside automatic reasoning."
        ),
    ),
)


def refresh_finding_chains_for_run(*, session: Session, run_id: UUID) -> list[FindingChain]:
    run = _load_run(session=session, run_id=run_id)
    if run is None:
        return []

    findings = _engagement_findings_for_chain_refresh(session=session, run=run)
    detected: list[FindingChain] = []
    for pattern in CHAIN_PATTERNS:
        component_findings = _select_components_for_pattern(findings=findings, pattern=pattern)
        if len(component_findings) < 2:
            continue
        detected.append(_upsert_chain(session=session, run=run, pattern=pattern, findings=component_findings))

    session.flush()
    return _list_chains_for_run(session=session, run_id=run.id)


def _engagement_findings_for_chain_refresh(*, session: Session, run: Run) -> list[Finding]:
    return list(
        session.scalars(
            select(Finding)
            .join(Run, Finding.run_id == Run.id)
            .where(
                Run.engagement_id == run.engagement_id,
                Run.deleted_at.is_(None),
            )
            .order_by(Finding.created_at.desc(), Finding.id.desc())
        ).all()
    )


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
        "chain_record_type": "compound_attack_chain",
        "source_scope": "engagement_findings",
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


def link_pivot_chain_findings(
    *,
    session: Session,
    original_finding: Finding,
    follow_up_finding: Finding,
    pivot_type: str,
    run_id: UUID,
) -> FindingChain | None:
    """Create a FindingChain linking original → follow_up via a confirmed pivot.

    Requirements (both must hold, otherwise returns None):
    - follow_up_finding.status == 'open'
    - follow_up_finding.evidence_ref is non-empty

    If the follow-up severity outranks the original AND original is low/medium,
    escalates original_finding.severity in place.  Caller must flush/commit.

    Returns the upserted FindingChain, or None when prerequisites are not met.
    """
    if str(follow_up_finding.status or "").strip().lower() != "open":
        return None
    if not str(follow_up_finding.evidence_ref or "").strip():
        return None
    if str(follow_up_finding.id) == str(original_finding.id):
        return None

    orig_sev = str(original_finding.severity or "info").lower()
    followup_sev = str(follow_up_finding.severity or "info").lower()
    orig_rank = SEVERITY_RANK.get(orig_sev, 0)
    followup_rank = SEVERITY_RANK.get(followup_sev, 0)

    # Only escalate low/medium → higher
    severity_escalated = followup_rank > orig_rank and orig_rank <= SEVERITY_RANK["medium"]
    pre_escalation_severity = orig_sev
    if severity_escalated:
        original_finding.severity = followup_sev

    impact_summary = (
        f"{original_finding.title} → {pivot_type.replace('_', ' ')} → "
        f"{follow_up_finding.title} at {follow_up_finding.target_id or '(target)'} — "
        f"real access demonstrated"
    )
    impact_proof = {
        "original_finding_id": str(original_finding.id),
        "original_finding_title": original_finding.title,
        "pivot_type": pivot_type,
        "follow_up_finding_id": str(follow_up_finding.id),
        "follow_up_finding_title": follow_up_finding.title,
        "what_was_accessed": follow_up_finding.target_id,
        "summary": impact_summary,
        "severity_escalated": severity_escalated,
        "original_severity": pre_escalation_severity,
        "escalated_to": followup_sev if severity_escalated else None,
    }

    pattern_id = f"pivot-chain-{pivot_type or 'session'}"
    component_ids = sorted([str(original_finding.id), str(follow_up_finding.id)])
    component_hash = hashlib.sha256("|".join(component_ids).encode("utf-8")).hexdigest()
    confidence = _confidence_score([original_finding, follow_up_finding])
    status = "confirmed_pivot_chain" if confidence >= 0.55 else "low_confidence"
    evidence_refs = sorted(
        {str(original_finding.evidence_ref or "").strip(), str(follow_up_finding.evidence_ref or "").strip()} - {""}
    )
    rationale = [
        {
            "finding_id": str(original_finding.id),
            "title": original_finding.title,
            "severity": original_finding.severity,
            "target_id": original_finding.target_id,
            "evidence_ref": original_finding.evidence_ref,
            "role": "source",
        },
        {
            "finding_id": str(follow_up_finding.id),
            "title": follow_up_finding.title,
            "severity": follow_up_finding.severity,
            "target_id": follow_up_finding.target_id,
            "evidence_ref": follow_up_finding.evidence_ref,
            "role": "follow_up",
        },
    ]
    metadata = {
        "chain_record_type": "pivot_chain",
        "pivot_type": pivot_type,
        "impact_proof_json": impact_proof,
        "auto_escalates_severity": severity_escalated,
        "mutates_component_findings": severity_escalated,
        "executes_exploits": False,
    }

    existing = session.scalar(
        select(FindingChain).where(
            FindingChain.run_id == run_id,
            FindingChain.pattern_id == pattern_id,
            FindingChain.component_hash == component_hash,
        )
    )
    if existing is None:
        chain = FindingChain(
            run_id=run_id,
            pattern_id=pattern_id,
            component_hash=component_hash,
            title=f"Pivot chain: {original_finding.title} → {follow_up_finding.title}",
            status=status,
            component_finding_ids_json=component_ids,
            confidence_score=confidence,
            combined_impact_text=impact_summary,
            evidence_refs_json=evidence_refs,
            rationale_json=rationale,
            metadata_json=metadata,
        )
        session.add(chain)
        # Concurrent workers may both reach this point with the same
        # (run, pattern, component_hash) and both attempt INSERT. The unique
        # constraint catches it; we just need to recover gracefully so the
        # whole post-task pipeline doesn't get poisoned by a rollback.
        try:
            session.flush()
        except Exception as exc:
            msg = str(exc).lower()
            if "uniqueviolation" in msg or "unique constraint" in msg or "duplicate key" in msg:
                session.rollback()
                # Re-query — another worker won the race.
                chain = session.scalar(
                    select(FindingChain).where(
                        FindingChain.run_id == run_id,
                        FindingChain.pattern_id == pattern_id,
                        FindingChain.component_hash == component_hash,
                    )
                )
                if chain is not None:
                    return chain
            raise
    else:
        existing.status = status
        existing.confidence_score = confidence
        existing.rationale_json = rationale
        existing.metadata_json = {**dict(existing.metadata_json or {}), **metadata}
        chain = existing

    session.flush()
    return chain
