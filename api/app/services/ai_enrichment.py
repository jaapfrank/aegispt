from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Thread
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from api.app.config import Settings, get_settings
from api.app.methodology import (
    control_family_label,
    default_remediation_detail,
    default_remediation_summary,
    format_wstg_reference,
)
from api.app.models import (
    AgentProposal,
    AgentReasoning,
    Finding,
    FindingAiEnrichment,
    InventorySnapshot,
    RelevanceDecision,
    Run,
    Task,
)
from api.app.services.inventory import aggregate_inventory_snapshots
from api.app.services.settings import effective_runtime_settings_for_finding
from api.app.services.threat_intel import build_finding_threat_intel_badges
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    ChatGPTOAuthFindingEnrichmentProvider,
    effective_ai_provider_name,
)


class FindingEnrichmentError(RuntimeError):
    pass


AGENT_REASONING_STATUSES = {"recorded", "succeeded", "failed", "skipped"}
AGENT_PROPOSAL_STATUSES = {"pending_review", "approved", "rejected", "skipped", "superseded"}
AGENT_PROPOSAL_RISK_TIERS = {"passive", "active", "intrusive"}
CONTEXTUAL_INTELLIGENCE_METADATA_KEY = "contextual_intelligence"
ENRICHMENT_IN_PROGRESS_STATUSES = {"enriching", "queued"}
ENRICHMENT_TERMINAL_STATUSES = {"succeeded", "failed", "skipped", "unavailable"}
FORBIDDEN_GUIDANCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("automated exploit tool", re.compile(r"\b(?:sqlmap|msfconsole|metasploit|exploit-db)\b", re.IGNORECASE)),
    ("destructive command", re.compile(r"\b(?:rm\s+-rf|mkfs|drop\s+table|truncate\s+table)\b", re.IGNORECASE)),
    ("shell delivery", re.compile(r"\b(?:reverse\s+shell|bind\s+shell|/bin/sh|os-shell)\b", re.IGNORECASE)),
    ("credential abuse", re.compile(r"\b(?:password\s+spray|credential\s+stuffing|dump\s+credentials|mimikatz|hashcat|hydra)\b", re.IGNORECASE)),
)


@dataclass(slots=True, frozen=True)
class FindingEnrichmentResult:
    business_impact: str
    technical_context: str
    remediation_narrative: str
    metadata: dict[str, Any] = field(default_factory=dict)


class FindingEnrichmentProvider(Protocol):
    name: str

    def enrich(self, finding: Finding) -> FindingEnrichmentResult:
        raise NotImplementedError


class MissionGuidanceProvider(Protocol):
    name: str

    def refine(self, guidance: dict[str, Any], run: Run) -> dict[str, Any]:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ThreatContextRule:
    rule_id: str
    tokens: tuple[str, ...]
    technique_id: str
    technique_name: str
    tactic: str
    relevance: str
    confidence: str
    source_taxonomy: str


THREAT_CONTEXT_SOURCE = {
    "name": "AegisPT curated threat-context mapping",
    "version": "2026-04-22",
    "source_type": "static-curated",
    "boundary": (
        "Maps stored finding signals to technique-style context only; it does "
        "not attribute activity to a named actor or claim breach likelihood."
    ),
}

THREAT_CONTEXT_RULES: tuple[ThreatContextRule, ...] = (
    ThreatContextRule(
        rule_id="web-public-app-exploitation",
        tokens=("sql injection", "sqli", "cwe-89", "wstg-inpv", "injection"),
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="initial_access",
        relevance="Input-validation evidence can be relevant to public-facing application exploitation paths.",
        confidence="high",
        source_taxonomy="MITRE ATT&CK Enterprise technique reference, curated by AegisPT",
    ),
    ThreatContextRule(
        rule_id="command-execution-abuse",
        tokens=("command injection", "remote code execution", "rce", "unsafe_tool_use", "shell command"),
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="execution",
        relevance="Command-execution evidence can indicate technique relevance for script or shell execution abuse.",
        confidence="high",
        source_taxonomy="MITRE ATT&CK Enterprise technique reference, curated by AegisPT",
    ),
    ThreatContextRule(
        rule_id="credential-or-session-material-abuse",
        tokens=("credential", "password", "token", "session", "cookie", "cwe-287", "cwe-798"),
        technique_id="T1550/T1552",
        technique_name="Use Alternate Authentication Material / Unsecured Credentials",
        tactic="defense_evasion_or_credential_access",
        relevance="Credential, token, or session-material evidence can be relevant to authentication material abuse.",
        confidence="medium",
        source_taxonomy="MITRE ATT&CK Enterprise technique reference, curated by AegisPT",
    ),
    ThreatContextRule(
        rule_id="network-service-discovery",
        tokens=("network_service_discovery", "service enumeration", "port scan", "nmap", "open port"),
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="discovery",
        relevance="Service-enumeration evidence can be relevant to discovery activity context.",
        confidence="medium",
        source_taxonomy="MITRE ATT&CK Enterprise technique reference, curated by AegisPT",
    ),
    ThreatContextRule(
        rule_id="directory-account-discovery",
        tokens=("ldap", "active directory", "account discovery", "directory", "ad enumeration"),
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="discovery",
        relevance="Directory or account enumeration evidence can be relevant to identity discovery context.",
        confidence="medium",
        source_taxonomy="MITRE ATT&CK Enterprise technique reference, curated by AegisPT",
    ),
    ThreatContextRule(
        rule_id="llm-application-abuse",
        tokens=("llm_application_testing", "prompt_injection", "data_leakage", "unsafe_tool_use"),
        technique_id="AEGISPT-AI-APP-ABUSE",
        technique_name="AI application abuse pattern",
        tactic="application_abuse",
        relevance="LLM probe evidence can be relevant to AI application abuse review without actor attribution.",
        confidence="medium",
        source_taxonomy="AegisPT curated AI application safety mapping",
    ),
    ThreatContextRule(
        rule_id="configuration-hardening-weakness",
        tokens=("configuration", "security header", "missing header", "x-frame-options", "tls", "ssl"),
        technique_id="AEGISPT-HARDENING-CONTROL-WEAKNESS",
        technique_name="Security hardening control weakness",
        tactic="exposure_reduction",
        relevance="Configuration or header evidence gives defensive context but is not enough for strong actor technique relevance.",
        confidence="low",
        source_taxonomy="AegisPT curated hardening-control mapping",
    ),
)

DETECTION_ENGINEERING_SOURCE = {
    "name": "AegisPT curated detection-engineering mapping",
    "version": "2026-04-22",
    "source_type": "static-curated",
    "boundary": (
        "Maps stored finding signals to advisory detection ideas only; it does "
        "not deploy SIEM rules, modify EDR systems, or claim production readiness."
    ),
}


class DeterministicFindingEnrichmentProvider:
    name = "deterministic"

    def enrich(self, finding: Finding) -> FindingEnrichmentResult:
        severity = (finding.severity or "unknown").lower()
        title = finding.title or "finding"
        target = finding.target_id or "the assessed target"
        evidence_ref = finding.evidence_ref or "unlinked evidence"
        summary = finding.summary or "No analyst summary was recorded for this finding yet."

        impact_by_severity = {
            "critical": "could create immediate business disruption or customer-impacting compromise",
            "high": "could materially weaken confidentiality, integrity, or privileged workflows",
            "medium": "may enable follow-on abuse or reduce trust in a key control",
            "low": "has limited direct impact but still increases operational exposure",
            "info": "is primarily contextual and should be reviewed with the broader evidence trail",
        }
        impact = impact_by_severity.get(severity, "needs analyst review before business impact is claimed")

        return FindingEnrichmentResult(
            business_impact=(
                f"{title} on {target} {impact}. This enrichment is advisory and does not change "
                f"the canonical {severity} severity."
            ),
            technical_context=(
                f"The finding is linked to {evidence_ref}. {summary} Review the stored evidence before "
                "changing finding status or remediation ownership."
            ),
            remediation_narrative=(
                f"Address the affected control for {target}, keep remediation notes on the finding record, "
                "and use the existing single-finding retest flow to confirm closure."
            ),
            metadata={"provider_mode": "deterministic-test"},
        )


class HttpFindingEnrichmentProvider:
    name = "http"

    def __init__(
        self,
        *,
        endpoint: str,
        timeout_seconds: float,
        api_key_env: str | None = None,
        model: str | None = None,
    ) -> None:
        self.endpoint = endpoint.strip()
        self.timeout_seconds = timeout_seconds
        self.api_key_env = (api_key_env or "").strip() or None
        self.model = (model or "").strip() or None

    def enrich(self, finding: Finding) -> FindingEnrichmentResult:
        if not self.endpoint:
            raise FindingEnrichmentError("ai finding enrichment endpoint is not configured")

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key_env:
            token = os.environ.get(self.api_key_env)
            if token:
                headers["Authorization"] = f"Bearer {token}"

        response = httpx.post(
            self.endpoint,
            headers=headers,
            json={
                "model": self.model,
                "finding": {
                    "id": str(finding.id) if finding.id else None,
                    "title": finding.title,
                    "severity": finding.severity,
                    "target_id": finding.target_id,
                    "evidence_ref": finding.evidence_ref,
                    "status": finding.status,
                    "summary": finding.summary,
                    "methodology_tags": list(finding.methodology_tags or []),
                    "ptes_phase": finding.ptes_phase,
                    "nist_phase": finding.nist_phase,
                    "wstg_id": finding.wstg_id,
                    "wstg_version": finding.wstg_version,
                    "asvs_reference": finding.asvs_reference,
                    "control_family": finding.control_family,
                    "finding_origin": finding.finding_origin,
                },
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise FindingEnrichmentError("ai finding enrichment response was not a JSON object")

        result_payload = payload.get("enrichment") if isinstance(payload.get("enrichment"), dict) else payload
        return FindingEnrichmentResult(
            business_impact=_required_text(result_payload, "business_impact"),
            technical_context=_required_text(result_payload, "technical_context"),
            remediation_narrative=_required_text(result_payload, "remediation_narrative"),
            metadata={
                "http_status": response.status_code,
                "model": payload.get("model") or self.model,
            },
        )


def build_finding_enrichment_provider(
    settings: Settings,
    *,
    session: Session | None = None,
) -> FindingEnrichmentProvider | None:
    if not settings.ai_finding_enrichment_enabled:
        return None

    provider_name = effective_ai_provider_name(settings, settings.ai_finding_enrichment_provider)
    if provider_name in {"", "disabled", "none", "off"}:
        return None
    if provider_name in {"deterministic", "mock", "test"}:
        return DeterministicFindingEnrichmentProvider()
    if provider_name in {"http", "webhook"}:
        return HttpFindingEnrichmentProvider(
            endpoint=settings.ai_finding_enrichment_endpoint or "",
            timeout_seconds=settings.ai_finding_enrichment_timeout_seconds,
            api_key_env=settings.ai_finding_enrichment_api_key_env,
            model=settings.ai_finding_enrichment_model,
        )
    if provider_name == CHATGPT_OAUTH_PROVIDER:
        if session is None:
            raise FindingEnrichmentError("chatgpt_oauth finding enrichment requires a database session")
        return ChatGPTOAuthFindingEnrichmentProvider(session=session, settings=settings)

    raise FindingEnrichmentError(f"unsupported ai finding enrichment provider: {provider_name}")


def store_ai_enrichment_for_finding(
    *,
    session: Session,
    finding: Finding,
    settings: Settings | None = None,
    provider: FindingEnrichmentProvider | None = None,
) -> FindingAiEnrichment | None:
    settings = effective_runtime_settings_for_finding(
        session,
        finding=finding,
        settings=settings or get_settings(),
    )
    if provider is None and not settings.ai_finding_enrichment_enabled:
        return None

    if finding.id is None:
        session.flush()

    existing = _load_existing_enrichment(session=session, finding=finding)
    if existing is not None and existing.status == "succeeded":
        _ensure_contextual_intelligence_metadata(session=session, finding=finding, enrichment=existing)
        return existing

    provider_name = effective_ai_provider_name(settings, settings.ai_finding_enrichment_provider)
    try:
        active_provider = provider or build_finding_enrichment_provider(settings, session=session)
        if active_provider is None:
            return None
        provider_name = active_provider.name
        result = active_provider.enrich(finding)
        _validate_safe_finding_enrichment_result(result)
    except Exception as exc:
        return _upsert_enrichment(
            session=session,
            existing=existing,
            finding=finding,
            status="failed",
            provider=provider_name or "unknown",
            business_impact=None,
            technical_context=None,
            remediation_narrative=None,
            failure_reason=str(exc)[:1000],
            metadata_json={
                "error_type": type(exc).__name__,
                "failed_at": datetime.now(tz=UTC).isoformat(),
            },
        )

    return _upsert_enrichment(
        session=session,
        existing=existing,
        finding=finding,
        status="succeeded",
        provider=provider_name,
        business_impact=result.business_impact,
        technical_context=result.technical_context,
        remediation_narrative=result.remediation_narrative,
        failure_reason=None,
        metadata_json={
            **dict(result.metadata or {}),
            CONTEXTUAL_INTELLIGENCE_METADATA_KEY: build_contextual_finding_intelligence(
                session=session,
                finding=finding,
            ),
            "enriched_at": datetime.now(tz=UTC).isoformat(),
        },
    )


def enrich_finding_async(
    finding_id: UUID | str,
    session: Session,
    settings: Settings | None = None,
) -> FindingAiEnrichment | None:
    """Queue advisory finding enrichment without blocking finding creation."""

    finding_uuid = finding_id if isinstance(finding_id, UUID) else UUID(str(finding_id))
    effective_settings = effective_runtime_settings_for_finding(
        session,
        finding=finding_uuid,
        settings=settings or get_settings(),
    )
    if not effective_settings.ai_finding_enrichment_enabled:
        return None

    provider_name = effective_ai_provider_name(
        effective_settings,
        effective_settings.ai_finding_enrichment_provider,
    )
    finding = session.get(Finding, finding_uuid)
    if finding is None:
        return None

    existing = _load_existing_enrichment(session=session, finding=finding)
    if existing is not None and (
        existing.status == "succeeded" or existing.status in ENRICHMENT_IN_PROGRESS_STATUSES
    ):
        return existing

    if provider_name in {"", "disabled", "none", "off"}:
        return _upsert_enrichment(
            session=session,
            existing=existing,
            finding=finding,
            status="unavailable",
            provider="disabled",
            business_impact=None,
            technical_context=None,
            remediation_narrative=None,
            failure_reason="No AI provider is configured for finding enrichment.",
            metadata_json={"unavailable_at": datetime.now(tz=UTC).isoformat()},
        )

    queued = _upsert_enrichment(
        session=session,
        existing=existing,
        finding=finding,
        status="enriching",
        provider=provider_name or "unknown",
        business_impact=None,
        technical_context=None,
        remediation_narrative=None,
        failure_reason=None,
        metadata_json={
            "queued_at": datetime.now(tz=UTC).isoformat(),
            "background": True,
            "dispatches_work": False,
            "executes_tools": False,
        },
    )

    bind = session.get_bind()
    background_session_factory = sessionmaker(
        bind=bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    thread = Thread(
        target=_run_finding_enrichment_background,
        kwargs={
            "session_factory": background_session_factory,
            "finding_id": finding_uuid,
            "settings": effective_settings,
        },
        name=f"aegispt-finding-enrichment-{finding_uuid}",
        daemon=True,
    )
    thread.start()
    return queued


def _run_finding_enrichment_background(
    *,
    session_factory: sessionmaker[Session],
    finding_id: UUID,
    settings: Settings,
) -> None:
    deadline = time.monotonic() + 5.0
    while True:
        with session_factory() as background_session:
            finding = background_session.get(Finding, finding_id)
            if finding is not None:
                try:
                    store_ai_enrichment_for_finding(
                        session=background_session,
                        finding=finding,
                        settings=settings,
                    )
                except Exception as exc:  # defensive: finding storage must stay authoritative
                    existing = _load_existing_enrichment(
                        session=background_session,
                        finding=finding,
                    )
                    _upsert_enrichment(
                        session=background_session,
                        existing=existing,
                        finding=finding,
                        status="failed",
                        provider=effective_ai_provider_name(
                            settings,
                            settings.ai_finding_enrichment_provider,
                        )
                        or "unknown",
                        business_impact=None,
                        technical_context=None,
                        remediation_narrative=None,
                        failure_reason=str(exc)[:1000],
                        metadata_json={
                            "error_type": type(exc).__name__,
                            "failed_at": datetime.now(tz=UTC).isoformat(),
                            "background": True,
                        },
                    )
                background_session.commit()
                return

        if time.monotonic() >= deadline:
            return
        time.sleep(0.1)


def store_agent_reasoning_record(
    *,
    session: Session,
    run: Run,
    task: Task | None = None,
    reasoning_type: str = "analysis",
    status: str = "recorded",
    context_snapshot: dict[str, Any] | None = None,
    observations: list[dict[str, Any]] | None = None,
    hypotheses: list[dict[str, Any]] | None = None,
    proposals: list[dict[str, Any]] | None = None,
    provider: str = "not-configured",
    model: str | None = None,
    llm_tokens_used: int | None = None,
    confidence_score: float | None = None,
    failure_reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AgentReasoning:
    """Store an additive AI reasoning ledger entry without executing anything."""

    normalized_status = _validated_choice(status, AGENT_REASONING_STATUSES, "agent reasoning status")
    normalized_reasoning_type = _required_label(reasoning_type, "reasoning_type")
    normalized_provider = _required_label(provider, "provider")
    session.flush()

    if run.id is None:
        raise ValueError("run must be persisted before storing agent reasoning")
    task_id = None
    if task is not None:
        if task.id is None:
            raise ValueError("task must be persisted before storing task-scoped agent reasoning")
        if task.run_id != run.id:
            raise ValueError("task-scoped agent reasoning must reference a task from the same run")
        task_id = task.id

    reasoning = AgentReasoning(
        run_id=run.id,
        task_id=task_id,
        reasoning_type=normalized_reasoning_type,
        status=normalized_status,
        context_snapshot_json=_json_object(context_snapshot, "context_snapshot"),
        observations_json=_json_object_list(observations, "observations"),
        hypotheses_json=_json_object_list(hypotheses, "hypotheses"),
        proposals_json=_json_object_list(proposals, "proposals"),
        provider=normalized_provider,
        model=_optional_label(model),
        llm_tokens_used=llm_tokens_used,
        confidence_score=confidence_score,
        failure_reason=(failure_reason or None),
        metadata_json=_json_object(metadata, "metadata"),
    )
    session.add(reasoning)
    session.flush()
    return reasoning


def store_agent_proposal_record(
    *,
    session: Session,
    reasoning: AgentReasoning,
    proposed_tool: str,
    proposed_target: str,
    proposed_params: dict[str, Any] | None = None,
    reasoning_text: str | None = None,
    risk_tier: str = "passive",
    priority: int = 100,
    confidence_score: float | None = None,
    status: str = "pending_review",
    metadata: dict[str, Any] | None = None,
) -> AgentProposal:
    """Store a review-only proposal linked to an existing reasoning entry."""

    session.flush()
    if reasoning.id is None or reasoning.run_id is None:
        raise ValueError("agent reasoning must be persisted before storing proposals")

    proposal = AgentProposal(
        run_id=reasoning.run_id,
        agent_reasoning_id=reasoning.id,
        proposed_tool=_required_label(proposed_tool, "proposed_tool"),
        proposed_target=_required_label(proposed_target, "proposed_target"),
        proposed_params_json=_json_object(proposed_params, "proposed_params"),
        reasoning_text=(reasoning_text or None),
        risk_tier=_validated_choice(risk_tier, AGENT_PROPOSAL_RISK_TIERS, "agent proposal risk_tier"),
        priority=priority,
        confidence_score=confidence_score,
        status=_validated_choice(status, AGENT_PROPOSAL_STATUSES, "agent proposal status"),
        approved_by=None,
        approved_at=None,
        metadata_json=_json_object(metadata, "metadata"),
    )
    session.add(proposal)
    session.flush()
    return proposal


def list_agent_reasoning_for_run(
    *,
    session: Session,
    run_id: UUID,
) -> list[AgentReasoning]:
    return list(
        session.scalars(
            select(AgentReasoning)
            .where(AgentReasoning.run_id == run_id)
            .options(selectinload(AgentReasoning.proposals))
            .order_by(AgentReasoning.created_at, AgentReasoning.id)
        )
    )


def list_agent_proposals_for_run(
    *,
    session: Session,
    run_id: UUID,
) -> list[AgentProposal]:
    return list(
        session.scalars(
            select(AgentProposal)
            .where(AgentProposal.run_id == run_id)
            .order_by(AgentProposal.created_at, AgentProposal.priority, AgentProposal.id)
        )
    )


def build_mission_guidance_for_run(
    *,
    session: Session,
    run: Run,
    provider: MissionGuidanceProvider | None = None,
) -> dict[str, Any]:
    """Build read-only mission guidance from persisted run context.

    The provider seam is intentionally non-authoritative in this first slice:
    deterministic guidance is always returned and provider failures only annotate
    fallback status.
    """

    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    profile = run.profile
    profile_name = profile.name if profile is not None else str(configuration.get("execution_profile") or "unknown-profile")
    run_class = profile.run_class if profile is not None else "unknown"
    limits = profile.limits_json if profile is not None and isinstance(profile.limits_json, dict) else {}
    tools = [tool for tool in limits.get("tools", []) if isinstance(tool, str) and tool.strip()]
    targets = _target_values(configuration.get("targets"))
    safety = configuration.get("safety") if isinstance(configuration.get("safety"), dict) else {}
    inventory_basis = _effective_inventory_basis(session=session, run=run)
    relevance = _effective_relevance_decision(
        session=session,
        run=run,
        inventory_snapshot_id=inventory_basis.get("inventory_snapshot_id"),
    )

    findings = list(run.findings or [])
    task_counts = _status_counts([task.status for task in run.tasks or []])
    finding_counts = _status_counts([finding.severity for finding in findings])
    high_priority_count = sum(finding_counts.get(severity, 0) for severity in ("critical", "high"))
    inventory_summary = inventory_basis.get("summary") if isinstance(inventory_basis.get("summary"), dict) else {}
    relevance_recommendations = (
        relevance.recommendations_json
        if relevance is not None and isinstance(relevance.recommendations_json, dict)
        else {}
    )
    relevant_advisory_count = len(relevance_recommendations.get("relevant_advisories") or [])
    proposed_capability_count = len(relevance_recommendations.get("proposed_capabilities") or [])
    bound_pack = run.bound_pack
    pack_methodology_tags = list(bound_pack.methodology_tags or []) if bound_pack is not None else []
    grounding = [
        "run.profile",
        "run.configuration_json.targets",
        "run.configuration_json.safety",
        "run.tasks.status",
        "run.findings.summary",
    ]
    if inventory_basis.get("available"):
        grounding.append("inventory_snapshot.summary_json")
    if relevance is not None:
        grounding.append("relevance_decision.recommendations_json")
    if bound_pack is not None:
        grounding.append("run.pack_binding.provenance")

    guidance = {
        "available": True,
        "mode": "deterministic",
        "title": "Grounded Mission Guidance",
        "summary": (
            f"{profile_name} is being explained from the selected run record, safety posture, "
            "persisted output, and approved provenance. This guidance is advisory only."
        ),
        "profile_explanation": _profile_explanation(
            profile_name=profile_name,
            run_class=run_class,
            tools=tools,
            task_counts=task_counts,
        ),
        "safety_explanation": _safety_explanation(safety),
        "follow_up_recommendations": _mission_recommendations(
            run=run,
            inventory_summary=inventory_summary,
            finding_count=len(findings),
            high_priority_count=high_priority_count,
            task_counts=task_counts,
            has_pack=bound_pack is not None,
            relevant_advisory_count=relevant_advisory_count,
            proposed_capability_count=proposed_capability_count,
        ),
        "grounding": grounding,
        "deterministic_inputs": {
            "profile_name": profile_name,
            "run_class": run_class,
            "planned_tools": tools,
            "target_count": len(targets),
            "task_counts": task_counts,
            "finding_count": len(findings),
            "high_priority_finding_count": high_priority_count,
            "inventory": inventory_basis,
            "relevance": {
                "available": relevance is not None,
                "relevance_decision_id": str(relevance.id) if relevance is not None else None,
                "relevant_advisory_count": relevant_advisory_count,
                "proposed_capability_count": proposed_capability_count,
            },
            "pack": {
                "available": bound_pack is not None,
                "pack_id": str(bound_pack.id) if bound_pack is not None else None,
                "pack_version": run.bound_pack_version,
                "methodology_tags": pack_methodology_tags,
            },
        },
        "scope_boundary": {
            "expands_scope": False,
            "launches_work": False,
            "allowed_targets": targets,
            "message": (
                "Guidance may only reference targets already present in this run configuration "
                "or linked inventory. It cannot add targets, authorization, run class, or approvals."
            ),
        },
    }

    guidance["provider"] = _provider_status(provider=provider, guidance=guidance, run=run)
    return guidance


def finding_ai_enrichment_view(enrichment: FindingAiEnrichment | None) -> dict[str, Any]:
    if enrichment is None:
        return {
            "status": "disabled",
            "available": False,
            "label": "Enrichment unavailable",
        }

    metadata = dict(enrichment.metadata_json or {})
    contextual_intelligence = metadata.get(CONTEXTUAL_INTELLIGENCE_METADATA_KEY)
    payload: dict[str, Any] = {
        "status": enrichment.status,
        "available": enrichment.status == "succeeded",
        "provider": enrichment.provider,
        "updated_at": _format_datetime(enrichment.updated_at),
        "metadata": metadata,
        "label": _finding_ai_enrichment_label(enrichment),
    }
    if enrichment.status == "succeeded":
        payload.update(
            {
                "business_impact": enrichment.business_impact,
                "technical_context": enrichment.technical_context,
                "remediation_narrative": enrichment.remediation_narrative,
            }
        )
        if isinstance(contextual_intelligence, dict):
            payload["contextual_intelligence"] = dict(contextual_intelligence)
    else:
        payload["failure_reason"] = enrichment.failure_reason
    return payload


def _finding_ai_enrichment_label(enrichment: FindingAiEnrichment) -> str:
    status = str(enrichment.status or "").strip().lower()
    if status == "succeeded":
        return f"Enriched by {enrichment.provider}"
    if status in ENRICHMENT_IN_PROGRESS_STATUSES:
        return "Enriching"
    return "Enrichment unavailable"


def build_contextual_finding_intelligence(*, session: Session, finding: Finding) -> dict[str, Any]:
    signals = _threat_context_signals(finding)
    evidence_available = bool(str(finding.evidence_ref or "").strip())
    structured_signals_available = bool(
        signals["references"]
        or signals["methodology_tags"]
        or finding.wstg_id
        or finding.asvs_reference
        or finding.control_family
        or finding.summary
    )
    environment_context = _finding_environment_context(session=session, finding=finding)
    threat_intel_context = _finding_threat_intel_context(session=session, finding=finding)
    exploitability = _contextual_exploitability(
        finding=finding,
        evidence_available=evidence_available,
        structured_signals_available=structured_signals_available,
        environment_context=environment_context,
        threat_intel_context=threat_intel_context,
    )
    status = "grounded" if evidence_available and structured_signals_available else "unsupported_or_uncertain"

    return {
        "available": True,
        "status": status,
        "mode": "deterministic-advisory",
        "operator_review_required": True,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "evidence_basis": {
            "finding_id": str(finding.id) if finding.id else None,
            "evidence_ref": finding.evidence_ref or None,
            "evidence_available": evidence_available,
            "summary_available": bool(finding.summary),
            "detected_references": list(signals["references"]),
            "methodology_tags": list(finding.methodology_tags or []),
            "wstg_reference": format_wstg_reference(finding.wstg_id, finding.wstg_version),
            "asvs_reference": finding.asvs_reference,
            "control_family": control_family_label(finding.control_family),
            "grounding": _contextual_grounding_sources(
                evidence_available=evidence_available,
                structured_signals_available=structured_signals_available,
                environment_context=environment_context,
                threat_intel_context=threat_intel_context,
            ),
        },
        "environment_context": environment_context,
        "threat_intel_context": threat_intel_context,
        "prerequisites": _contextual_prerequisites(
            finding=finding,
            evidence_available=evidence_available,
            structured_signals_available=structured_signals_available,
            environment_context=environment_context,
            threat_intel_context=threat_intel_context,
        ),
        "exploitability": exploitability,
        "remediation": _contextual_remediation_guidance(
            finding=finding,
            environment_context=environment_context,
            threat_intel_context=threat_intel_context,
            exploitability=exploitability,
        ),
        "boundaries": {
            "guidance_only": True,
            "operator_review_required": True,
            "automatic_exploitation": False,
            "destructive_steps": False,
            "credential_abuse_guidance": False,
            "mutates_canonical_finding": False,
            "changes_finding_severity": False,
            "expands_scope": False,
            "message": (
                "Contextual remediation and exploitability intelligence is review-only guidance. "
                "It does not execute exploits, change findings, broaden scope, or bypass approval and runtime gates."
            ),
        },
    }


def _ensure_contextual_intelligence_metadata(
    *,
    session: Session,
    finding: Finding,
    enrichment: FindingAiEnrichment,
) -> None:
    metadata = dict(enrichment.metadata_json or {})
    if isinstance(metadata.get(CONTEXTUAL_INTELLIGENCE_METADATA_KEY), dict):
        return
    metadata[CONTEXTUAL_INTELLIGENCE_METADATA_KEY] = build_contextual_finding_intelligence(
        session=session,
        finding=finding,
    )
    enrichment.metadata_json = metadata
    session.flush()


def _validate_safe_finding_enrichment_result(result: FindingEnrichmentResult) -> None:
    payload = {
        "business_impact": result.business_impact,
        "technical_context": result.technical_context,
        "remediation_narrative": result.remediation_narrative,
        "metadata": dict(result.metadata or {}),
    }
    for text in _iter_strings(payload):
        for label, pattern in FORBIDDEN_GUIDANCE_PATTERNS:
            if pattern.search(text):
                raise FindingEnrichmentError(f"forbidden exploit guidance detected: {label}")


def _iter_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for nested in value.values():
            strings.extend(_iter_strings(nested))
        return strings
    if isinstance(value, list):
        strings = []
        for nested in value:
            strings.extend(_iter_strings(nested))
        return strings
    return []


def _contextual_grounding_sources(
    *,
    evidence_available: bool,
    structured_signals_available: bool,
    environment_context: dict[str, Any],
    threat_intel_context: dict[str, Any],
) -> list[str]:
    grounding = ["finding.title", "finding.severity", "finding.target_id"]
    if evidence_available:
        grounding.append("finding.evidence_ref")
    if structured_signals_available:
        grounding.append("finding.methodology_metadata")
    if environment_context.get("available"):
        grounding.append(str(environment_context.get("grounding") or "inventory_snapshot.summary_json"))
    if threat_intel_context.get("available"):
        grounding.append("local_threat_intel_cache.badges")
    return grounding


def _finding_environment_context(*, session: Session, finding: Finding) -> dict[str, Any]:
    snapshot = _source_inventory_snapshot_for_finding(session=session, finding=finding)
    if snapshot is not None:
        normalized = dict(snapshot.normalized_inventory_json or {})
        matches = _inventory_matches_for_target(normalized=normalized, target_id=finding.target_id)
        summary = dict(snapshot.summary_json or {})
        return {
            "available": bool(summary or any(matches.values())),
            "source": "source_inventory_snapshot",
            "grounding": "inventory_snapshot.normalized_inventory_json",
            "inventory_snapshot_id": str(snapshot.id),
            "confidence_score": snapshot.confidence_score,
            "summary": summary,
            "matched_target": matches,
            "environment_notes": list(snapshot.environment_notes_json or []),
            "assumptions": list(snapshot.assumptions_json or []),
        }

    run = finding.run or (session.get(Run, finding.run_id) if finding.run_id is not None else None)
    if run is None:
        return _empty_environment_context("no-linked-run-or-inventory")

    basis = _effective_inventory_basis(session=session, run=run)
    if not basis.get("available"):
        return _empty_environment_context(str(basis.get("source") or "inventory-unavailable"))
    return {
        "available": True,
        "source": str(basis.get("source") or "run-inventory"),
        "grounding": "inventory_snapshot.summary_json",
        "inventory_snapshot_id": basis.get("inventory_snapshot_id"),
        "confidence_score": None,
        "summary": dict(basis.get("summary") or {}),
        "matched_target": {
            "hosts": [],
            "services": [],
            "endpoints": [],
            "technologies": [],
            "direct_match": False,
            "detail": "Run-level inventory exists, but no target-specific inventory object was loaded for this finding.",
        },
        "environment_notes": [],
        "assumptions": [],
    }


def _source_inventory_snapshot_for_finding(*, session: Session, finding: Finding) -> InventorySnapshot | None:
    if finding.source_inventory_snapshot is not None:
        return finding.source_inventory_snapshot
    if finding.source_inventory_snapshot_id is not None:
        snapshot = session.get(InventorySnapshot, finding.source_inventory_snapshot_id)
        if snapshot is not None:
            return snapshot
    run = finding.run or (session.get(Run, finding.run_id) if finding.run_id is not None else None)
    if run is not None and run.source_inventory_snapshot_id is not None:
        return session.get(InventorySnapshot, run.source_inventory_snapshot_id)
    return None


def _empty_environment_context(reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "source": reason,
        "grounding": None,
        "inventory_snapshot_id": None,
        "confidence_score": None,
        "summary": {},
        "matched_target": {
            "hosts": [],
            "services": [],
            "endpoints": [],
            "technologies": [],
            "direct_match": False,
            "detail": "No inventory context was available for environment-aware remediation.",
        },
        "environment_notes": [],
        "assumptions": [],
    }


def _inventory_matches_for_target(*, normalized: dict[str, Any], target_id: str | None) -> dict[str, Any]:
    target = str(target_id or "").strip()
    target_host = _host_from_target(target)

    hosts = [
        _inventory_host_value(item)
        for item in list(normalized.get("hosts") or [])
        if _target_matches_inventory_value(target=target, target_host=target_host, value=_inventory_host_value(item))
    ]
    services = [
        _compact_inventory_item(item, ("host", "port", "protocol", "service", "product", "version"))
        for item in list(normalized.get("services") or [])
        if isinstance(item, dict)
        and _target_matches_inventory_value(
            target=target,
            target_host=target_host,
            value=" ".join(str(item.get(key) or "") for key in ("host", "service", "product", "version")),
        )
    ]
    endpoints = [
        _compact_inventory_item(item, ("url", "methods", "status_code", "title"))
        for item in [*list(normalized.get("http_endpoints") or []), *list(normalized.get("endpoints") or [])]
        if isinstance(item, dict)
        and _target_matches_inventory_value(target=target, target_host=target_host, value=str(item.get("url") or ""))
    ]
    technologies = [
        _compact_inventory_item(item, ("name", "vendor", "product", "version"))
        for item in [*list(normalized.get("technologies") or []), *list(normalized.get("vendor_product_fingerprints") or [])]
        if isinstance(item, dict)
        and (
            not target_host
            or _target_matches_inventory_value(
                target=target,
                target_host=target_host,
                value=" ".join(str(item.get(key) or "") for key in ("host", "url", "name", "vendor", "product", "version")),
            )
        )
    ]
    direct_match = bool(hosts or services or endpoints)
    return {
        "hosts": list(dict.fromkeys(hosts))[:5],
        "services": services[:5],
        "endpoints": endpoints[:5],
        "technologies": technologies[:5],
        "direct_match": direct_match,
        "detail": (
            "Inventory contains target-specific context for remediation planning."
            if direct_match
            else "Inventory is present, but no direct target match was found."
        ),
    }


def _inventory_host_value(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("host") or item.get("hostname") or item.get("address") or "")
    return ""


def _compact_inventory_item(item: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key in keys:
        value = item.get(key)
        if value is None or value == "" or value == []:
            continue
        compact[key] = value
    return compact


def _host_from_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.hostname:
        return parsed.hostname.lower()
    return target.split("/")[0].split(":")[0].strip().lower()


def _target_matches_inventory_value(*, target: str, target_host: str, value: str) -> bool:
    candidate = str(value or "").lower()
    if not candidate:
        return False
    target_value = target.lower()
    return bool(
        (target_host and (target_host in candidate or candidate in target_host))
        or (target_value and (target_value in candidate or candidate in target_value))
    )


def _finding_threat_intel_context(*, session: Session, finding: Finding) -> dict[str, Any]:
    context = build_finding_threat_intel_badges(session, finding)
    badges = list(context.get("badges") or []) if isinstance(context, dict) else []
    return {
        "available": bool(context.get("available")) if isinstance(context, dict) else False,
        "matched_badge_count": len(badges),
        "stale_record_count": int(context.get("stale_record_count") or 0) if isinstance(context, dict) else 0,
        "badges": [
            {
                "label": badge.get("label"),
                "source": badge.get("source"),
                "advisory_id": badge.get("advisory_id"),
                "cache_status": badge.get("cache_status"),
                "severity": badge.get("severity"),
            }
            for badge in badges[:5]
            if isinstance(badge, dict)
        ],
        "external_lookup_performed": False,
        "downloads_exploits": False,
        "changes_finding_severity": False,
        "no_badge_reason": context.get("no_badge_reason") if isinstance(context, dict) else None,
    }


def _contextual_prerequisites(
    *,
    finding: Finding,
    evidence_available: bool,
    structured_signals_available: bool,
    environment_context: dict[str, Any],
    threat_intel_context: dict[str, Any],
) -> list[dict[str, Any]]:
    matched_target = environment_context.get("matched_target") if isinstance(environment_context.get("matched_target"), dict) else {}
    return [
        {
            "id": "evidence-linked",
            "title": "Stored evidence reference",
            "status": "confirmed" if evidence_available else "missing",
            "basis": finding.evidence_ref or "No evidence reference is attached to this finding.",
            "grounding": ["finding.evidence_ref"],
        },
        {
            "id": "target-context",
            "title": "Target and environment context",
            "status": "confirmed" if matched_target.get("direct_match") else "unconfirmed",
            "basis": matched_target.get("detail") or "No target-specific inventory context was available.",
            "grounding": ["finding.target_id", "inventory_snapshot.normalized_inventory_json"],
        },
        {
            "id": "methodology-context",
            "title": "Methodology and control mapping",
            "status": "confirmed" if structured_signals_available else "review",
            "basis": (
                f"{format_wstg_reference(finding.wstg_id, finding.wstg_version) or 'No WSTG reference'}; "
                f"{control_family_label(finding.control_family) or 'no control family'}"
            ),
            "grounding": ["finding.methodology_tags", "finding.wstg_id", "finding.control_family"],
        },
        {
            "id": "local-threat-intel",
            "title": "Local threat-intel cache context",
            "status": "matched" if threat_intel_context.get("available") else "no-local-match",
            "basis": (
                f"{threat_intel_context.get('matched_badge_count')} local badge(s) matched."
                if threat_intel_context.get("available")
                else threat_intel_context.get("no_badge_reason")
            ),
            "grounding": ["local_threat_intel_cache.badges"],
        },
    ]


def _contextual_exploitability(
    *,
    finding: Finding,
    evidence_available: bool,
    structured_signals_available: bool,
    environment_context: dict[str, Any],
    threat_intel_context: dict[str, Any],
) -> dict[str, Any]:
    severity = str(finding.severity or "unknown").lower()
    matched_target = environment_context.get("matched_target") if isinstance(environment_context.get("matched_target"), dict) else {}
    score = 0.1
    if evidence_available:
        score += 0.25
    if structured_signals_available:
        score += 0.15
    if environment_context.get("available"):
        score += 0.1
    if matched_target.get("direct_match"):
        score += 0.1
    if severity in {"critical", "high"}:
        score += 0.15
    elif severity == "medium":
        score += 0.08
    if threat_intel_context.get("available"):
        score += 0.12
    if not evidence_available:
        score = min(score, 0.25)
    score = round(min(score, 0.9), 2)

    if not evidence_available:
        label = "unsupported-or-uncertain"
        confidence = "review"
        rationale = "Exploitability is not inflated because no stored evidence reference is attached."
    elif score >= 0.75:
        label = "evidence-supported-prerequisites"
        confidence = "high"
        rationale = "Stored evidence, methodology context, and environment or local threat-intel signals support reviewable exploitability prerequisites."
    elif score >= 0.55:
        label = "plausible-with-operator-review"
        confidence = "medium"
        rationale = "Stored evidence supports plausible exploitability, but at least one prerequisite still needs operator review."
    else:
        label = "limited-or-uncertain"
        confidence = "low"
        rationale = "The finding is evidence-linked but does not have enough contextual support for a stronger exploitability claim."

    return {
        "label": label,
        "confidence": confidence,
        "confidence_score": score,
        "unsupported_or_uncertain": label in {"unsupported-or-uncertain", "limited-or-uncertain"},
        "rationale": rationale,
        "requires_operator_validation": True,
        "changes_finding_severity": False,
        "automatic_exploitation": False,
        "destructive_steps": False,
    }


def _contextual_remediation_guidance(
    *,
    finding: Finding,
    environment_context: dict[str, Any],
    threat_intel_context: dict[str, Any],
    exploitability: dict[str, Any],
) -> dict[str, Any]:
    matched_target = environment_context.get("matched_target") if isinstance(environment_context.get("matched_target"), dict) else {}
    affected_surface = _affected_surface_label(finding=finding, matched_target=matched_target)
    immediate_actions = [
        f"Review the linked evidence for {finding.target_id or 'the affected target'} before assigning remediation ownership.",
        default_remediation_summary(finding.control_family),
        default_remediation_detail(finding.control_family),
    ]
    if affected_surface:
        immediate_actions.insert(1, f"Apply the fix to the observed environment surface: {affected_surface}.")
    if threat_intel_context.get("available"):
        immediate_actions.append(
            "Prioritize operator review of the local threat-intel match, but do not change canonical severity without analyst decision."
        )

    return {
        "immediate_actions": immediate_actions,
        "verification_steps": [
            "Use the existing single-finding retest flow or the same approved validation profile after remediation.",
            "Compare new evidence against the original evidence reference and keep both records available for review.",
            "Only mark the finding resolved after operator-reviewed retest evidence supports closure.",
        ],
        "rollback_cautions": [
            "Prepare an application or configuration rollback path before changing the affected service.",
            "Monitor the affected endpoint or service health after the fix, especially authentication, session, and routing behavior.",
        ],
        "prioritization_notes": [
            _prioritization_note(
                finding=finding,
                threat_intel_context=threat_intel_context,
                exploitability=exploitability,
            )
        ],
        "environment_aware": bool(environment_context.get("available")),
        "review_required": True,
    }


def _affected_surface_label(*, finding: Finding, matched_target: dict[str, Any]) -> str | None:
    endpoints = list(matched_target.get("endpoints") or [])
    services = list(matched_target.get("services") or [])
    hosts = list(matched_target.get("hosts") or [])
    if endpoints:
        return str(endpoints[0].get("url") or finding.target_id)
    if services:
        service = services[0]
        return " ".join(str(service.get(key) or "") for key in ("host", "port", "service")).strip()
    if hosts:
        return str(hosts[0])
    return None


def _prioritization_note(
    *,
    finding: Finding,
    threat_intel_context: dict[str, Any],
    exploitability: dict[str, Any],
) -> str:
    severity = str(finding.severity or "unknown").lower()
    if threat_intel_context.get("available"):
        return "Local threat-intel context is present, so review this item ahead of routine backlog work without auto-escalating severity."
    if severity in {"critical", "high"} and exploitability.get("confidence") in {"high", "medium"}:
        return "High-impact, evidence-linked findings should be triaged before lower-severity hygiene work."
    if exploitability.get("unsupported_or_uncertain"):
        return "Keep exploitability in review until missing prerequisites or evidence gaps are resolved."
    return "Prioritize according to the existing remediation priority and operator-owned risk context."


def build_detection_engineering_for_finding(finding: Finding) -> dict[str, Any]:
    signals = _threat_context_signals(finding)
    references = _extract_reference_tokens(signals["haystack"])
    evidence_available = bool(str(finding.evidence_ref or "").strip())
    structured_signals_available = any(
        signals[key] for key in ("methodology_tags", "wstg_id", "asvs_reference", "control_family", "references")
    )
    source_tools = _finding_source_tools(finding)

    if not evidence_available and not structured_signals_available:
        return _empty_detection_engineering(
            status="unsupported",
            reason="insufficient_evidence",
            detail=(
                "No evidence reference, methodology tag, CWE/CVE reference, control mapping, "
                "or task context is available to ground detection guidance."
            ),
            references=references,
            source_tools=source_tools,
            evidence_available=evidence_available,
            structured_signals_available=structured_signals_available,
        )

    threat_context = build_threat_context_for_finding(finding)
    suggestions = _detection_suggestions_for_signals(
        finding=finding,
        signals=signals,
        threat_context=threat_context,
        source_tools=source_tools,
    )
    if not suggestions:
        return _empty_detection_engineering(
            status="unsupported",
            reason="no_curated_detection_match",
            detail=(
                "Stored finding signals do not map to a curated detection-engineering suggestion yet. "
                "Treat this as a manual detection review item instead of fabricated SIEM logic."
            ),
            references=references,
            source_tools=source_tools,
            evidence_available=evidence_available,
            structured_signals_available=structured_signals_available,
        )

    low_confidence = all(item.get("confidence") == "low" for item in suggestions)
    return {
        "available": True,
        "status": "low_confidence" if low_confidence else "suggested",
        "mode": "deterministic-curated",
        "source": dict(DETECTION_ENGINEERING_SOURCE),
        "review_boundary": _detection_review_boundary(),
        "evidence_basis": {
            "evidence_ref": finding.evidence_ref or None,
            "methodology_tags": signals["methodology_tags"],
            "wstg_id": finding.wstg_id,
            "asvs_reference": finding.asvs_reference,
            "control_family": finding.control_family,
            "detected_references": references,
            "source_tools": source_tools,
            "attack_scenarios": _attack_scenarios_from_threat_context(threat_context),
        },
        "suggestions": suggestions[:3],
        "unsupported_telemetry": _unsupported_detection_telemetry(suggestions[:3]),
        "summary": (
            "Detection ideas are advisory starting points grounded in stored finding context. "
            "They require operator and detection-engineer review before use."
        ),
    }


def build_threat_context_for_finding(finding: Finding) -> dict[str, Any]:
    signals = _threat_context_signals(finding)
    references = _extract_reference_tokens(signals["haystack"])
    evidence_available = bool(str(finding.evidence_ref or "").strip())
    structured_signals_available = any(
        signals[key] for key in ("methodology_tags", "wstg_id", "asvs_reference", "control_family", "references")
    )

    if not evidence_available and not structured_signals_available:
        return _empty_threat_context(
            status="unmapped",
            reason="insufficient_evidence",
            detail="No evidence reference, methodology tag, CWE/CVE reference, or control mapping is available.",
        )

    mappings: list[dict[str, Any]] = []
    for rule in THREAT_CONTEXT_RULES:
        matched = [token for token in rule.tokens if token in signals["haystack"]]
        if not matched:
            continue
        confidence = _adjusted_threat_confidence(
            base_confidence=rule.confidence,
            evidence_available=evidence_available,
            structured_signals_available=structured_signals_available,
        )
        mappings.append(
            {
                "rule_id": rule.rule_id,
                "technique_id": rule.technique_id,
                "technique_name": rule.technique_name,
                "tactic": rule.tactic,
                "confidence": confidence,
                "relevance": rule.relevance,
                "matched_signals": matched,
                "source_taxonomy": rule.source_taxonomy,
                "actor_attribution": "not-assessed",
            }
        )

    if not mappings:
        return _empty_threat_context(
            status="unmapped",
            reason="no_curated_mapping_match",
            detail="Stored finding signals did not match the curated threat-context mapping table.",
            references=references,
            evidence_available=evidence_available,
            structured_signals_available=structured_signals_available,
        )

    status = "low_confidence" if all(mapping["confidence"] == "low" for mapping in mappings) else "mapped"
    return {
        "available": True,
        "status": status,
        "mode": "deterministic-curated",
        "source": dict(THREAT_CONTEXT_SOURCE),
        "attribution_boundary": _threat_attribution_boundary(),
        "evidence_basis": {
            "evidence_ref": finding.evidence_ref or None,
            "methodology_tags": signals["methodology_tags"],
            "wstg_id": finding.wstg_id,
            "asvs_reference": finding.asvs_reference,
            "control_family": finding.control_family,
            "detected_references": references,
        },
        "mappings": mappings[:3],
        "summary": (
            "Technique context is based on stored finding metadata and curated static mappings. "
            "It is contextual guidance only, not actor attribution."
        ),
    }


def _detection_suggestions_for_signals(
    *,
    finding: Finding,
    signals: dict[str, Any],
    threat_context: dict[str, Any],
    source_tools: list[str],
) -> list[dict[str, Any]]:
    haystack = signals["haystack"]
    suggestions: list[dict[str, Any]] = []

    if any(token in haystack for token in ("sql injection", "sqli", "cwe-89", "wstg-inpv", "injection")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="web-input-validation-detection",
                title="Detect suspicious input-validation probes against the affected route",
                description=(
                    "Review web request telemetry for repeated SQL metacharacters, error-prone parameters, "
                    "or scanner payloads targeting the same route as this finding."
                ),
                telemetry_sources=[
                    _telemetry("web_access_logs", "supported", "Correlate URI, status code, user agent, and source IP."),
                    _telemetry("waf_logs", "conditional", "Useful when a WAF is present; not required by AegisPT."),
                    _telemetry("database_error_logs", "conditional", "Can confirm syntax-error bursts but may be unavailable."),
                ],
                draft_logic=(
                    "Web requests to the affected target with SQL metacharacter patterns or repeated 4xx/5xx "
                    "responses in a short window should be reviewed against the evidence ref."
                ),
                confidence="high" if finding.evidence_ref else "medium",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    if any(token in haystack for token in ("command injection", "remote code execution", "rce", "unsafe_tool_use", "shell command")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="command-execution-follow-up-detection",
                title="Review application and endpoint telemetry for command execution indicators",
                description=(
                    "Use web/application logs to identify the triggering request and endpoint telemetry only "
                    "if the customer already collects it."
                ),
                telemetry_sources=[
                    _telemetry("application_logs", "supported", "Correlate request id, route, actor, and validation errors."),
                    _telemetry("endpoint_process_creation", "unsupported_without_edr", "Requires existing EDR/Sysmon-style telemetry; AegisPT does not deploy it."),
                    _telemetry("web_access_logs", "supported", "Identify command payload patterns and repeated probes."),
                ],
                draft_logic=(
                    "Flag requests containing shell metacharacters followed by unusual child-process or error output "
                    "only where those telemetry streams already exist."
                ),
                confidence="high" if finding.evidence_ref else "medium",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    if any(token in haystack for token in ("credential", "password", "token", "session", "cookie", "cwe-287", "cwe-798")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="credential-session-abuse-detection",
                title="Monitor authentication and session anomalies tied to the affected control",
                description=(
                    "Review login, token, session, and identity-provider events for reuse, replay, or failed control behavior."
                ),
                telemetry_sources=[
                    _telemetry("authentication_logs", "supported", "Review failed/successful login ratios and impossible session transitions."),
                    _telemetry("identity_provider_logs", "conditional", "Relevant when SSO or IdP telemetry exists."),
                    _telemetry("web_session_logs", "supported", "Correlate cookie/session id lifecycle with the finding target."),
                ],
                draft_logic=(
                    "Look for bursts of authentication failures followed by successful access, token reuse from new "
                    "network locations, or session lifecycle anomalies near the affected target."
                ),
                confidence="medium",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    if any(token in haystack for token in ("network_service_discovery", "service enumeration", "port scan", "nmap", "open port")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="network-service-discovery-detection",
                title="Detect service-enumeration bursts against in-scope assets",
                description="Review network flow or firewall telemetry for multi-port probing against the same host set.",
                telemetry_sources=[
                    _telemetry("firewall_logs", "supported", "Correlate blocked and allowed connection attempts by source."),
                    _telemetry("netflow", "conditional", "Useful for connection fan-out if collected."),
                    _telemetry("ids_events", "conditional", "Relevant where IDS signatures already exist."),
                ],
                draft_logic=(
                    "Flag a single source touching many ports or hosts in a short interval against the assessed asset set."
                ),
                confidence="medium",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    if any(token in haystack for token in ("ldap", "active directory", "account discovery", "directory", "ad enumeration")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="directory-enumeration-detection",
                title="Review directory-query volume and privileged group enumeration",
                description=(
                    "Use domain-controller or LDAP audit logs to identify unusual account, group, or SPN enumeration."
                ),
                telemetry_sources=[
                    _telemetry("domain_controller_security_logs", "conditional", "Requires Windows/AD audit collection."),
                    _telemetry("ldap_query_logs", "conditional", "Useful where directory query auditing is enabled."),
                    _telemetry("identity_inventory", "supported", "Use AegisPT identity inventory as review context, not as live detection."),
                ],
                draft_logic=(
                    "Review bursts of account/group/SPN lookups, especially from non-admin hosts or unusual service accounts."
                ),
                confidence="medium",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    if any(token in haystack for token in ("llm_application_testing", "prompt_injection", "data_leakage", "unsafe_tool_use")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="llm-application-abuse-detection",
                title="Monitor LLM gateway and prompt-audit events for unsafe interaction patterns",
                description=(
                    "Review prompt, response, policy decision, and tool-call audit logs where the LLM application already records them."
                ),
                telemetry_sources=[
                    _telemetry("llm_gateway_logs", "conditional", "Requires existing LLM gateway or application audit logs."),
                    _telemetry("tool_call_audit_logs", "conditional", "Relevant only when tool execution is already audited."),
                    _telemetry("application_logs", "supported", "Correlate request id, actor, and safety decision outcomes."),
                ],
                draft_logic=(
                    "Flag repeated policy bypass prompts, unsafe tool-use requests, or sensitive-data responses tied to one actor or session."
                ),
                confidence="medium",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    if any(token in haystack for token in ("configuration", "security header", "missing header", "x-frame-options", "tls", "ssl")):
        suggestions.append(
            _detection_suggestion(
                suggestion_id="configuration-drift-monitoring",
                title="Track configuration drift rather than runtime compromise",
                description=(
                    "This finding is better suited to configuration monitoring and regression checks than a production "
                    "intrusion-detection rule."
                ),
                telemetry_sources=[
                    _telemetry("configuration_scan_results", "supported", "Use recurring validation output and report deltas."),
                    _telemetry("web_response_headers", "supported", "Monitor header presence on the affected route."),
                    _telemetry("endpoint_or_edr_events", "unsupported", "Runtime endpoint telemetry is not a strong fit for this hardening signal."),
                ],
                draft_logic=(
                    "Alert when the affected security control disappears from the same endpoint after it has been remediated."
                ),
                confidence="low",
                finding=finding,
                source_tools=source_tools,
                threat_context=threat_context,
            )
        )

    return suggestions


def _detection_suggestion(
    *,
    suggestion_id: str,
    title: str,
    description: str,
    telemetry_sources: list[dict[str, str]],
    draft_logic: str,
    confidence: str,
    finding: Finding,
    source_tools: list[str],
    threat_context: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": suggestion_id,
        "title": title,
        "description": description,
        "confidence": confidence,
        "production_ready": False,
        "deploys_rules": False,
        "modifies_customer_systems": False,
        "operator_review_required": True,
        "telemetry_sources": telemetry_sources,
        "unsupported_telemetry": [
            source
            for source in telemetry_sources
            if source["support_status"].startswith("unsupported")
        ],
        "rule_starting_points": [
            {
                "type": "pseudologic",
                "title": f"Draft logic for {finding.title}",
                "draft": draft_logic,
                "production_ready": False,
                "deployment_status": "not_deployed",
                "operator_review_required": True,
            }
        ],
        "source_trace": _detection_source_trace(finding=finding, source_tools=source_tools, threat_context=threat_context),
    }


def _telemetry(source: str, status: str, rationale: str) -> dict[str, str]:
    return {"source": source, "status": status, "support_status": status, "rationale": rationale}


def _unsupported_detection_telemetry(suggestions: list[dict[str, Any]]) -> list[dict[str, str]]:
    unsupported: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for suggestion in suggestions:
        for source in suggestion.get("unsupported_telemetry") or []:
            if not isinstance(source, dict):
                continue
            key = (str(source.get("source") or ""), str(source.get("support_status") or source.get("status") or ""))
            if key in seen:
                continue
            seen.add(key)
            unsupported.append(
                {
                    "source": key[0],
                    "support_status": key[1],
                    "rationale": str(source.get("rationale") or "Telemetry is not available through AegisPT."),
                }
            )
    return unsupported


def _detection_source_trace(
    *,
    finding: Finding,
    source_tools: list[str],
    threat_context: dict[str, Any],
) -> list[str]:
    trace = ["finding.title", "finding.summary"]
    if finding.evidence_ref:
        trace.append("finding.evidence_ref")
    if finding.methodology_tags:
        trace.append("finding.methodology_tags")
    if finding.wstg_id:
        trace.append("finding.wstg_id")
    if finding.control_family:
        trace.append("finding.control_family")
    if source_tools:
        trace.append("run.tasks.tool")
    if threat_context.get("available") is True:
        trace.append("threat_context.mappings")
    return trace


def _attack_scenarios_from_threat_context(threat_context: dict[str, Any]) -> list[dict[str, str]]:
    mappings = threat_context.get("mappings") if isinstance(threat_context, dict) else []
    if not isinstance(mappings, list):
        return []
    scenarios: list[dict[str, str]] = []
    for mapping in mappings[:3]:
        if not isinstance(mapping, dict):
            continue
        scenarios.append(
            {
                "technique_id": str(mapping.get("technique_id") or ""),
                "technique_name": str(mapping.get("technique_name") or ""),
                "tactic": str(mapping.get("tactic") or ""),
                "confidence": str(mapping.get("confidence") or "review"),
            }
        )
    return scenarios


def _finding_source_tools(finding: Finding) -> list[str]:
    run = finding.run
    if run is None:
        return []
    tools = {
        str(task.tool).strip()
        for task in list(run.tasks or [])
        if str(getattr(task, "tool", "") or "").strip()
    }
    return sorted(tools)


def _empty_detection_engineering(
    *,
    status: str,
    reason: str,
    detail: str,
    references: list[str] | None = None,
    source_tools: list[str] | None = None,
    evidence_available: bool = False,
    structured_signals_available: bool = False,
) -> dict[str, Any]:
    return {
        "available": False,
        "status": status,
        "mode": "deterministic-curated",
        "source": dict(DETECTION_ENGINEERING_SOURCE),
        "review_boundary": _detection_review_boundary(),
        "reason": reason,
        "detail": detail,
        "evidence_basis": {
            "evidence_available": evidence_available,
            "structured_signals_available": structured_signals_available,
            "detected_references": list(references or []),
            "source_tools": list(source_tools or []),
        },
        "suggestions": [],
        "unsupported_telemetry": [],
    }


def _detection_review_boundary() -> dict[str, Any]:
    return {
        "advisory_only": True,
        "operator_review_required": True,
        "production_ready": False,
        "deploys_rules": False,
        "deploys_siem_rules": False,
        "deploys_edr_changes": False,
        "modifies_customer_systems": False,
        "claims_detection_effectiveness": False,
        "production_ready_claim": False,
        "changes_finding": False,
        "statement": (
            "Detection guidance is a non-production draft. It must be reviewed, adapted, "
            "tested, and deployed by the customer's detection team through their own change process."
        ),
    }


def _provider_status(
    *,
    provider: MissionGuidanceProvider | None,
    guidance: dict[str, Any],
    run: Run,
) -> dict[str, Any]:
    if provider is None:
        return {
            "status": "disabled",
            "fallback": "deterministic",
            "message": "No mission-guidance provider is configured; deterministic guidance is active.",
        }

    try:
        provider.refine(dict(guidance), run)
    except Exception as exc:
        return {
            "status": "failed",
            "provider": getattr(provider, "name", "unknown"),
            "fallback": "deterministic",
            "failure_reason": str(exc)[:500],
        }

    return {
        "status": "ignored",
        "provider": getattr(provider, "name", "unknown"),
        "fallback": "deterministic",
        "message": "Provider output is not authoritative in this slice; deterministic guidance remains the rendered contract.",
    }


def _empty_threat_context(
    *,
    status: str,
    reason: str,
    detail: str,
    references: list[str] | None = None,
    evidence_available: bool = False,
    structured_signals_available: bool = False,
) -> dict[str, Any]:
    return {
        "available": False,
        "status": status,
        "mode": "deterministic-curated",
        "source": dict(THREAT_CONTEXT_SOURCE),
        "attribution_boundary": _threat_attribution_boundary(),
        "reason": reason,
        "detail": detail,
        "evidence_basis": {
            "evidence_available": evidence_available,
            "structured_signals_available": structured_signals_available,
            "detected_references": list(references or []),
        },
        "mappings": [],
    }


def _threat_attribution_boundary() -> dict[str, Any]:
    return {
        "claims_actor_attribution": False,
        "claims_breach_likelihood": False,
        "changes_severity": False,
        "statement": (
            "This context links evidence to technique-style relevance only. "
            "It must not be read as named actor attribution or probability of compromise."
        ),
    }


def _threat_context_signals(finding: Finding) -> dict[str, Any]:
    methodology_tags = [
        str(tag).strip().lower()
        for tag in list(finding.methodology_tags or [])
        if str(tag).strip()
    ]
    text_parts = [
        finding.title,
        finding.summary,
        finding.evidence_ref,
        finding.wstg_id,
        finding.asvs_reference,
        finding.control_family,
        " ".join(methodology_tags),
    ]
    haystack = " ".join(str(part or "").lower() for part in text_parts)
    references = _extract_reference_tokens(haystack)
    return {
        "haystack": haystack,
        "methodology_tags": methodology_tags,
        "wstg_id": str(finding.wstg_id or "").strip().lower(),
        "asvs_reference": str(finding.asvs_reference or "").strip().lower(),
        "control_family": str(finding.control_family or "").strip().lower(),
        "references": references,
    }


def _extract_reference_tokens(text: str) -> list[str]:
    references = {
        match.group(0).upper()
        for match in re.finditer(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d{1,5})\b", text, flags=re.IGNORECASE)
    }
    return sorted(references)


def _adjusted_threat_confidence(
    *,
    base_confidence: str,
    evidence_available: bool,
    structured_signals_available: bool,
) -> str:
    if base_confidence == "low":
        return "low"
    if evidence_available and structured_signals_available:
        return base_confidence
    if evidence_available or structured_signals_available:
        return "medium" if base_confidence == "high" else base_confidence
    return "low"


def _target_values(targets_payload: Any) -> list[str]:
    if not isinstance(targets_payload, dict):
        return []
    values: list[str] = []
    seen: set[str] = set()
    for raw_items in targets_payload.values():
        if not isinstance(raw_items, list):
            continue
        for raw_item in raw_items:
            if not isinstance(raw_item, str):
                continue
            item = raw_item.strip()
            if item and item not in seen:
                seen.add(item)
                values.append(item)
    return values


def _status_counts(values: list[str | None]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        normalized = str(value or "unknown").strip().lower() or "unknown"
        counts[normalized] = counts.get(normalized, 0) + 1
    return counts


def _effective_inventory_basis(*, session: Session, run: Run) -> dict[str, Any]:
    snapshots = session.scalars(
        select(InventorySnapshot)
        .where(InventorySnapshot.engagement_id == run.engagement_id)
        .order_by(InventorySnapshot.created_at.desc(), InventorySnapshot.id.desc())
    ).all()
    derived_snapshots = [
        snapshot
        for snapshot in snapshots
        if str((snapshot.raw_inputs_json or {}).get("run_id") or "") == str(run.id)
    ]
    if len(derived_snapshots) > 1:
        aggregated = aggregate_inventory_snapshots(derived_snapshots) or {}
        return {
            "available": True,
            "source": "derived-run-inventory-aggregate",
            "inventory_snapshot_id": None,
            "snapshot_count": len(derived_snapshots),
            "source_tools": sorted(
                {
                    tool
                    for snapshot in derived_snapshots
                    for tool in list(snapshot.source_tools_json or [])
                    if isinstance(tool, str)
                }
            ),
            "summary": dict(aggregated.get("summary_json") or {}),
        }
    if len(derived_snapshots) == 1:
        return _inventory_basis_from_snapshot(derived_snapshots[0], source="derived-run-inventory")

    source_inventory_id = run.source_inventory_snapshot_id
    if source_inventory_id is None and run.bound_pack is not None:
        source_inventory_id = run.bound_pack.source_inventory_snapshot_id
    if source_inventory_id is None:
        return {
            "available": False,
            "source": "none",
            "inventory_snapshot_id": None,
            "snapshot_count": 0,
            "source_tools": [],
            "summary": {},
        }

    for snapshot in snapshots:
        if snapshot.id == source_inventory_id:
            return _inventory_basis_from_snapshot(snapshot, source="linked-inventory")

    return {
        "available": False,
        "source": "missing-linked-inventory",
        "inventory_snapshot_id": str(source_inventory_id),
        "snapshot_count": 0,
        "source_tools": [],
        "summary": {},
    }


def _inventory_basis_from_snapshot(snapshot: InventorySnapshot, *, source: str) -> dict[str, Any]:
    return {
        "available": True,
        "source": source,
        "inventory_snapshot_id": str(snapshot.id),
        "snapshot_count": 1,
        "source_tools": list(snapshot.source_tools_json or []),
        "summary": dict(snapshot.summary_json or {}),
    }


def _effective_relevance_decision(
    *,
    session: Session,
    run: Run,
    inventory_snapshot_id: str | None,
) -> RelevanceDecision | None:
    if run.bound_pack is not None and run.bound_pack.relevance_decision_id is not None:
        decision = session.scalar(
            select(RelevanceDecision).where(RelevanceDecision.id == run.bound_pack.relevance_decision_id)
        )
        if decision is not None:
            return decision

    if inventory_snapshot_id:
        try:
            parsed_inventory_snapshot_id = UUID(inventory_snapshot_id)
        except ValueError:
            return None
        return session.scalar(
            select(RelevanceDecision)
            .where(
                RelevanceDecision.engagement_id == run.engagement_id,
                RelevanceDecision.inventory_snapshot_id == parsed_inventory_snapshot_id,
            )
            .order_by(RelevanceDecision.created_at.desc(), RelevanceDecision.id.desc())
        )
    return None


def _profile_explanation(
    *,
    profile_name: str,
    run_class: str,
    tools: list[str],
    task_counts: dict[str, int],
) -> str:
    tool_label = ", ".join(tools) if tools else "the queued tasks already attached to this run"
    queued = task_counts.get("queued", 0)
    running = task_counts.get("running", 0)
    completed = task_counts.get("completed", 0)
    failed = task_counts.get("failed", 0)
    return (
        f"{profile_name} is a {run_class} run profile using {tool_label}. "
        f"Persisted task state shows {queued} queued, {running} running, "
        f"{completed} completed, and {failed} failed checks."
    )


def _safety_explanation(safety: dict[str, Any]) -> str:
    active_checks = safety.get("active_checks") or "not recorded"
    depth = safety.get("max_validation_depth") or "not recorded"
    concurrency = safety.get("concurrency") or "not recorded"
    rate_limit = safety.get("rate_limit_rps") or "not recorded"
    budget = safety.get("time_budget_minutes") or "not recorded"
    return (
        f"Safety posture is {active_checks}, depth {depth}, concurrency {concurrency}, "
        f"rate limit {rate_limit} rps, and time budget {budget} minutes. Guidance cannot raise these limits."
    )


def _mission_recommendations(
    *,
    run: Run,
    inventory_summary: dict[str, Any],
    finding_count: int,
    high_priority_count: int,
    task_counts: dict[str, int],
    has_pack: bool,
    relevant_advisory_count: int,
    proposed_capability_count: int,
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    queued = task_counts.get("queued", 0)
    running = task_counts.get("running", 0)
    host_count = int(inventory_summary.get("host_count") or 0)
    service_count = int(inventory_summary.get("service_count") or 0)
    endpoint_count = int(inventory_summary.get("endpoint_count") or 0)

    if queued:
        recommendations.append(
            _recommendation(
                title="Start only the queued validation when ready",
                rationale=(
                    f"{queued} queued checks already exist for this run. Starting them uses the existing "
                    "run/approval/dispatch path rather than creating new work."
                ),
                operator_action="Use the existing Start Queued Checks control only if the approved scope is still valid.",
                grounding=["run.tasks.status", "run.profile"],
            )
        )
    elif running:
        recommendations.append(
            _recommendation(
                title="Monitor persisted run progress",
                rationale=f"{running} checks are already running, so the safest next step is review, not more launch activity.",
                operator_action="Watch Mission Control telemetry and wait for persisted task, inventory, or finding output.",
                grounding=["run.tasks.status"],
            )
        )
    elif high_priority_count:
        recommendations.append(
            _recommendation(
                title="Review high-priority findings before any follow-up",
                rationale=(
                    f"{high_priority_count} critical or high finding records are already attached to this run."
                ),
                operator_action="Open Findings Theater and Evidence Replay before requesting a retest or follow-up run.",
                grounding=["run.findings.summary", "run.findings.severity"],
            )
        )
    elif host_count or service_count or endpoint_count:
        recommendations.append(
            _recommendation(
                title="Review mapped inventory before deeper validation",
                rationale=(
                    f"Inventory shows {host_count} hosts, {service_count} services, and {endpoint_count} endpoints. "
                    "Follow-up should reuse these observed assets and the existing approved targets."
                ),
                operator_action="Open Surface Map or Explorer, then choose only existing in-scope follow-up controls if needed.",
                grounding=["inventory_snapshot.summary_json", "run.configuration_json.targets"],
            )
        )
    else:
        recommendations.append(
            _recommendation(
                title="Wait for evidence before changing course",
                rationale="No persisted findings or discovery-confirmed inventory are available yet for this run.",
                operator_action="Review task output and reports first; do not broaden targets based on absent data.",
                grounding=["run.tasks.status", "run.findings.summary"],
            )
        )

    if has_pack:
        recommendations.append(
            _recommendation(
                title="Keep adaptive pack provenance visible",
                rationale="This run has a bound pack, so generated coverage must stay tied to reviewed validation and deployment records.",
                operator_action="Review Pack Forge provenance if the next step depends on adaptive coverage.",
                grounding=["run.pack_binding.provenance"],
            )
        )
    elif relevant_advisory_count or proposed_capability_count:
        recommendations.append(
            _recommendation(
                title="Treat relevance as planning context only",
                rationale=(
                    f"Relevance data includes {relevant_advisory_count} relevant advisories and "
                    f"{proposed_capability_count} proposed capabilities, but no bound pack is active on this run."
                ),
                operator_action="Generate, validate, approve, and deploy a pack before expecting adaptive runtime coverage.",
                grounding=["relevance_decision.recommendations_json"],
            )
        )

    return recommendations[:3]


def _recommendation(
    *,
    title: str,
    rationale: str,
    operator_action: str,
    grounding: list[str],
) -> dict[str, Any]:
    return {
        "title": title,
        "rationale": rationale,
        "operator_action": operator_action,
        "grounding": grounding,
        "changes_execution": False,
        "launches_work": False,
        "scope_effect": "no-scope-expansion",
    }


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FindingEnrichmentError(f"ai finding enrichment response missing {key}")
    return value.strip()


def _required_label(value: str, field_name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field_name} is required")
    return normalized


def _optional_label(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def _validated_choice(value: str, allowed: set[str], field_name: str) -> str:
    normalized = _required_label(value, field_name)
    if normalized not in allowed:
        raise ValueError(f"{field_name} must be one of {sorted(allowed)}")
    return normalized


def _json_object(value: dict[str, Any] | None, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return dict(value)


def _json_object_list(value: list[dict[str, Any]] | None, field_name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{field_name} must be a list of JSON objects")
    return [dict(item) for item in value]


def _load_existing_enrichment(
    *,
    session: Session,
    finding: Finding,
) -> FindingAiEnrichment | None:
    if finding.ai_enrichment is not None:
        return finding.ai_enrichment
    if finding.id is None:
        return None
    return session.scalar(select(FindingAiEnrichment).where(FindingAiEnrichment.finding_id == finding.id))


def _upsert_enrichment(
    *,
    session: Session,
    existing: FindingAiEnrichment | None,
    finding: Finding,
    status: str,
    provider: str,
    business_impact: str | None,
    technical_context: str | None,
    remediation_narrative: str | None,
    failure_reason: str | None,
    metadata_json: dict[str, Any],
) -> FindingAiEnrichment:
    enrichment = existing or FindingAiEnrichment(finding_id=finding.id, provider=provider)
    enrichment.status = status
    enrichment.provider = provider
    enrichment.business_impact = business_impact
    enrichment.technical_context = technical_context
    enrichment.remediation_narrative = remediation_narrative
    enrichment.failure_reason = failure_reason
    enrichment.metadata_json = metadata_json
    if existing is None:
        session.add(enrichment)
        finding.ai_enrichment = enrichment
    session.flush()
    return enrichment


def _format_datetime(value: Any) -> str | None:
    return value.isoformat() if value is not None and hasattr(value, "isoformat") else None
