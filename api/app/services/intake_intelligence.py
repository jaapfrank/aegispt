from __future__ import annotations

import copy
import re
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    ChatGPTOAuthIntakeInterpretationProvider,
    effective_ai_provider_name,
)
from api.app.services.settings import (
    effective_runtime_settings,
    effective_runtime_settings_for_engagement,
)

INTAKE_INTELLIGENCE_BOUNDARY = {
    "mode": "operator_review_advisory",
    "operator_confirmation_required": True,
    "deterministic_intake_preserved": True,
    "can_broaden_scope": False,
    "can_assume_access": False,
    "can_approve_or_deploy_packs": False,
    "can_create_or_dispatch_runs": False,
    "message": (
        "LLM intake intelligence may clarify ambiguity, surface warnings, and suggest follow-up "
        "questions, but it cannot add scope, assume access, approve packs, deploy packs, or dispatch work."
    ),
}

SAFE_INFERENCE_FIELDS = {
    "assessment_type",
    "primary_goal",
    "output_style",
    "safety_posture",
    "boundary_handling",
    "lateral_discovery",
    "methodology_context",
    "pack_context",
}
SCOPE_FIELDS = {"scope", "target", "targets", "allowlist", "denylist", "approved_scope"}
ACCESS_FIELDS = {"access", "auth", "auth_strategy", "credentials", "session", "token"}
PACK_DEPLOYMENT_WORDS = {"approved", "deployed", "bound", "auto_bind", "deploy", "runtime_binding"}
BROAD_SCOPE_PHRASES = (
    "anything reachable",
    "anything public",
    "whatever you can find",
    "look around everywhere",
    "scan the internet",
    "all public websites",
    "scan random public targets",
)
ACCESS_SIGNAL_PHRASES = (
    "credential",
    "credentials",
    "account",
    "accounts",
    "login",
    "logged in",
    "api key",
    "api token",
    "bearer",
    "session",
    "cookie",
    "manual auth",
)
FULL_PENTEST_PHRASES = (
    "full pentest",
    "full penetration test",
    "complete pentest",
    "complete penetration test",
    "all phases",
    "volle pentest",
    "volledige pentest",
    "volledige penetratietest",
    "complete pentest",
    "alle fases",
)
ACTIVE_SCAN_PHRASES = (
    "active scan",
    "active scanning",
    "actieve scan",
    "actief scannen",
    "validation scan",
)
PASSIVE_SCAN_PHRASES = ("passive", "passief", "recon", "reconnaissance", "inventory only")


class IntakeInterpretationError(RuntimeError):
    pass


class IntakeInterpretationProvider(Protocol):
    name: str

    def interpret(
        self,
        *,
        question_id: str,
        answer: str,
        configuration: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError


class DeterministicIntakeInterpretationProvider:
    name = "deterministic"

    def interpret(
        self,
        *,
        question_id: str,
        answer: str,
        configuration: dict[str, Any],
    ) -> dict[str, Any]:
        normalized_answer = answer.lower()
        warnings: list[str] = []
        safe_inferences: list[dict[str, Any]] = []
        follow_up_questions: list[dict[str, Any]] = []
        methodology_suggestions: list[dict[str, Any]] = []
        pack_suggestions: list[dict[str, Any]] = []
        blocked_suggestions: list[dict[str, Any]] = []

        if any(phrase in normalized_answer for phrase in BROAD_SCOPE_PHRASES):
            warnings.append(
                "The answer contains broad scope language; exact authorized targets must remain explicit."
            )
            follow_up_questions.append(
                {
                    "question_id": "scope",
                    "question": "Which exact URLs, domains, IPs, CIDRs, or API roots are explicitly authorized?",
                    "reason": "Vague scope language cannot become authorization.",
                }
            )
            blocked_suggestions.append(
                {
                    "type": "scope_expansion",
                    "value": answer,
                    "reason": "Broad or vague target language cannot add scope.",
                }
            )

        if "api" in normalized_answer:
            safe_inferences.append(
                {
                    "field": "assessment_type",
                    "value": "API",
                    "basis": "The operator mentioned API context.",
                    "requires_operator_confirmation": True,
                }
            )
            methodology_suggestions.append(
                {
                    "label": "OWASP WSTG API-adjacent review",
                    "reason": "API wording may affect methodology emphasis after confirmation.",
                    "advisory_only": True,
                    "requires_operator_confirmation": True,
                }
            )

        if "authenticated" in normalized_answer or "portal account" in normalized_answer:
            safe_inferences.append(
                {
                    "field": "auth_strategy",
                    "value": "credentialed",
                    "basis": "The operator explicitly mentioned authenticated access.",
                    "requires_operator_confirmation": True,
                }
            )
            follow_up_questions.append(
                {
                    "question_id": "auth",
                    "question": "Should this run use protected account, token, or session references?",
                    "reason": "Access context must be operator-confirmed before use.",
                }
            )

        if "adaptive" in normalized_answer or "custom pack" in normalized_answer:
            pack_suggestions.append(
                {
                    "label": "Adaptive pack context",
                    "reason": "The operator asked for customer-specific follow-up context.",
                    "advisory_only": True,
                    "requires_operator_confirmation": True,
                    "deployment_performed": False,
                }
            )

        return {
            "warnings": warnings,
            "safe_inferences": safe_inferences,
            "follow_up_questions": follow_up_questions,
            "methodology_suggestions": methodology_suggestions,
            "pack_suggestions": pack_suggestions,
            "blocked_suggestions": blocked_suggestions,
            "provider_metadata": {"provider_mode": "deterministic-test"},
        }


class UnsafeFixtureIntakeInterpretationProvider:
    name = "unsafe-fixture"

    def interpret(
        self,
        *,
        question_id: str,
        answer: str,
        configuration: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "warnings": ["Fixture intentionally returns unsafe suggestions for validation."],
            "safe_inferences": [
                {
                    "field": "targets",
                    "value": ["https://admin.example.com"],
                    "basis": "Unsafe fixture target expansion.",
                },
                {
                    "field": "auth_strategy",
                    "value": "credentialed",
                    "basis": "Unsafe fixture access assumption.",
                },
                {
                    "field": "safety_posture",
                    "value": "conservative",
                    "basis": "Allowed advisory inference.",
                },
            ],
            "follow_up_questions": [
                {"question_id": "scope", "question": "Confirm exact scope before continuing."}
            ],
            "methodology_suggestions": [
                {"label": "OWASP WSTG", "reason": "Advisory only."}
            ],
            "pack_suggestions": [
                {
                    "label": "Unapproved external pack",
                    "status": "approved",
                    "deployment_performed": True,
                }
            ],
        }


def build_intake_interpretation(
    *,
    question_id: str | None,
    answer: str | None,
    configuration_json: dict[str, Any] | None,
    settings: Settings,
    tenant_id: str | None = None,
    provider_override: IntakeInterpretationProvider | None = None,
    session: Session | None = None,
    engagement_id: UUID | str | None = None,
) -> dict[str, Any]:
    if session is not None:
        if engagement_id is not None:
            settings = effective_runtime_settings_for_engagement(
                session,
                engagement_id=engagement_id,
                settings=settings,
            )
        else:
            settings = effective_runtime_settings(session, tenant_id=tenant_id, settings=settings)
    provider_name = effective_ai_provider_name(settings, settings.ai_intake_interpretation_provider)
    generated_at = datetime.now(tz=UTC)
    configuration = _safe_dict(configuration_json)
    normalized_question_id = str(question_id or "intake").strip() or "intake"
    normalized_answer = str(answer or "").strip()

    base = {
        "status": "disabled",
        "available": False,
        "provider": provider_name or "disabled",
        "generated_at": generated_at.isoformat(),
        "question_id": normalized_question_id,
        "warnings": [],
        "safe_inferences": [],
        "follow_up_questions": [],
        "methodology_suggestions": [],
        "pack_suggestions": [],
        "blocked_suggestions": [],
        "boundary": dict(INTAKE_INTELLIGENCE_BOUNDARY),
        "operator_confirmation_required": True,
        "deterministic_intake_preserved": True,
        "scope_expansion_blocked": True,
        "failure_reason": None,
        "provider_metadata": {},
        "intent_mission_plan": _build_intent_mission_plan(
            answer=normalized_answer,
            configuration=configuration,
            generated_at=generated_at,
        ),
    }

    if not settings.ai_intake_interpretation_enabled or provider_name in {"", "disabled", "none", "off"}:
        return {
            **base,
            "failure_reason": "LLM intake interpretation is disabled; deterministic intake remains unchanged.",
        }

    if settings.execution_kill_switch and provider_name == CHATGPT_OAUTH_PROVIDER:
        return {
            **base,
            "status": "failed",
            "provider": provider_name,
            "failure_reason": "Execution kill switch blocks ChatGPT OAuth intake provider calls.",
        }

    if provider_name in {"fail", "failed", "failing", "failure", "error"}:
        return {
            **base,
            "status": "failed",
            "provider": provider_name,
            "failure_reason": "Configured LLM intake provider failed deterministically; deterministic intake remains unchanged.",
        }

    try:
        provider = provider_override or _provider_for_settings(
            settings,
            session=session,
            engagement_id=engagement_id,
        )
        provider_output = provider.interpret(
            question_id=normalized_question_id,
            answer=normalized_answer,
            configuration=configuration,
        )
        validated = _validate_provider_output(
            provider_output,
            answer=normalized_answer,
            configuration=configuration,
        )
    except Exception as exc:  # pragma: no cover - defensive provider boundary
        return {
            **base,
            "status": "failed",
            "provider": provider_name,
            "failure_reason": f"LLM intake provider failed: {exc}",
        }

    return {
        **base,
        **validated,
        "status": "ready",
        "available": True,
        "provider": provider.name,
        "failure_reason": None,
    }


def attach_intake_interpretation_to_configuration(
    configuration_json: dict[str, Any] | None,
    *,
    settings: Settings,
    tenant_id: str | None = None,
    session: Session | None = None,
    engagement_id: UUID | str | None = None,
) -> dict[str, Any]:
    if session is not None:
        if engagement_id is not None:
            settings = effective_runtime_settings_for_engagement(
                session,
                engagement_id=engagement_id,
                settings=settings,
            )
        else:
            settings = effective_runtime_settings(session, tenant_id=tenant_id, settings=settings)
    configuration = copy.deepcopy(configuration_json or {})
    intake = configuration.get("intake")
    if not isinstance(intake, dict):
        return configuration
    if not settings.ai_intake_interpretation_enabled:
        return configuration

    answer = str(
        intake.get("confirmation_summary")
        or _safe_dict(intake.get("preferences")).get("mission_intent")
        or ""
    )
    interpretation = build_intake_interpretation(
        question_id="run_submission",
        answer=answer,
        configuration_json=configuration,
        settings=settings,
        tenant_id=tenant_id,
        session=session,
        engagement_id=engagement_id,
    )
    intake["llm_interpretation"] = interpretation
    configuration["intake"] = intake
    return configuration


def _provider_for_settings(
    settings: Settings,
    *,
    session: Session | None = None,
    engagement_id: UUID | str | None = None,
) -> IntakeInterpretationProvider:
    provider_name = effective_ai_provider_name(settings, settings.ai_intake_interpretation_provider)
    if provider_name in {"deterministic", "mock", "test"}:
        return DeterministicIntakeInterpretationProvider()
    if provider_name in {"unsafe-fixture", "unsafe_test", "unsafe-test"}:
        return UnsafeFixtureIntakeInterpretationProvider()
    if provider_name == CHATGPT_OAUTH_PROVIDER:
        normalized_engagement_id = _uuid_or_none(engagement_id)
        if session is None or normalized_engagement_id is None:
            raise IntakeInterpretationError("chatgpt_oauth intake interpretation requires engagement context")
        return ChatGPTOAuthIntakeInterpretationProvider(
            session=session,
            settings=settings,
            engagement_id=normalized_engagement_id,
        )
    raise IntakeInterpretationError(f"unsupported LLM intake provider: {provider_name}")


def _validate_provider_output(
    provider_output: dict[str, Any] | None,
    *,
    answer: str,
    configuration: dict[str, Any],
) -> dict[str, Any]:
    output = provider_output if isinstance(provider_output, dict) else {}
    explicit_targets = set(_explicit_targets(configuration))
    access_explicit = _has_explicit_access_signal(answer, configuration)
    warnings = _string_list(output.get("warnings"))
    blocked = _dict_list(output.get("blocked_suggestions"))
    safe_inferences: list[dict[str, Any]] = []

    for inference in _dict_list(output.get("safe_inferences")):
        field = str(inference.get("field") or "").strip().lower()
        if not field:
            blocked.append(
                {
                    "type": "invalid_inference",
                    "value": inference,
                    "reason": "Inference did not declare a field.",
                }
            )
            continue
        if field in SCOPE_FIELDS or any(part in field for part in SCOPE_FIELDS):
            blocked.append(
                {
                    "type": "scope_expansion",
                    "field": field,
                    "value": inference.get("value"),
                    "reason": "LLM intake cannot add or alter authorized targets.",
                }
            )
            continue
        if field in ACCESS_FIELDS or any(part in field for part in ACCESS_FIELDS):
            if not access_explicit:
                blocked.append(
                    {
                        "type": "access_assumption",
                        "field": field,
                        "value": inference.get("value"),
                        "reason": "Access mode cannot be inferred without explicit operator access language.",
                    }
                )
                continue
        if field not in SAFE_INFERENCE_FIELDS and field not in ACCESS_FIELDS:
            blocked.append(
                {
                    "type": "unsupported_inference",
                    "field": field,
                    "value": inference.get("value"),
                    "reason": "Inference field is not part of the allowed advisory intake schema.",
                }
            )
            continue
        normalized = dict(inference)
        normalized["advisory_only"] = True
        normalized["requires_operator_confirmation"] = True
        safe_inferences.append(normalized)

    follow_up_questions = []
    for question in _dict_list(output.get("follow_up_questions")):
        normalized = dict(question)
        normalized["requires_operator_confirmation"] = True
        follow_up_questions.append(normalized)

    pack_suggestions: list[dict[str, Any]] = []
    for suggestion in _dict_list(output.get("pack_suggestions")):
        if _suggests_pack_approval_or_deployment(suggestion):
            blocked.append(
                {
                    "type": "unapproved_pack_action",
                    "value": suggestion,
                    "reason": "Intake intelligence cannot approve, deploy, or bind packs.",
                }
            )
            continue
        normalized = dict(suggestion)
        normalized["advisory_only"] = True
        normalized["requires_operator_confirmation"] = True
        normalized["deployment_performed"] = False
        pack_suggestions.append(normalized)

    methodology_suggestions = []
    for suggestion in _dict_list(output.get("methodology_suggestions")):
        normalized = dict(suggestion)
        normalized["advisory_only"] = True
        normalized["requires_operator_confirmation"] = True
        methodology_suggestions.append(normalized)

    if any(phrase in answer.lower() for phrase in BROAD_SCOPE_PHRASES):
        warnings.append("Broad scope language was detected and treated as non-authorizing.")

    return {
        "warnings": _dedupe_strings(warnings),
        "safe_inferences": safe_inferences,
        "follow_up_questions": follow_up_questions,
        "methodology_suggestions": methodology_suggestions,
        "pack_suggestions": pack_suggestions,
        "blocked_suggestions": blocked,
        "provider_metadata": _safe_dict(output.get("provider_metadata")),
        "explicit_target_count": len(explicit_targets),
    }


def _build_intent_mission_plan(
    *,
    answer: str,
    configuration: dict[str, Any],
    generated_at: datetime,
) -> dict[str, Any]:
    normalized = answer.lower()
    target = _extract_primary_target(answer) or _first_explicit_target(configuration)
    target_map = _target_map_for_target(target)
    assessment_type = _assessment_type_from_intent(normalized, target)
    depth = _depth_from_intent(normalized, configuration)
    assessment_mode = _assessment_mode_for_intent(assessment_type, depth)
    run_mode = "assessment_chain" if assessment_mode else "standard_run"
    authorization = _intent_authorization_summary(configuration, depth)
    missing_fields = []
    if not assessment_type:
        missing_fields.append("assessment_type")
    if not target:
        missing_fields.append("target")
    if not depth:
        missing_fields.append("depth")
    required_actions = []
    if depth == "Full Pentest" and not authorization["written_authorization_confirmed"]:
        required_actions.append(
            {
                "id": "written_authorization_required",
                "label": "Confirm written authorization from the system owner.",
                "blocks_launch": True,
            }
        )
    unsafe_scope = any(phrase in normalized for phrase in BROAD_SCOPE_PHRASES)
    blocked_items = []
    if unsafe_scope:
        blocked_items.append(
            {
                "id": "broad_scope_language",
                "label": "Broad scope language cannot become authorized target scope.",
            }
        )
    preview_ready = bool(target and assessment_type and depth and not unsafe_scope)
    launch_ready = bool(preview_ready and not any(item["blocks_launch"] for item in required_actions))
    next_missing_field = (
        "unsafe_scope"
        if unsafe_scope
        else missing_fields[0]
        if missing_fields
        else "authorization"
        if required_actions
        else "complete"
    )
    automatic_work = _automatic_work_for_intent(assessment_type, depth, assessment_mode)
    approval_work = _approval_work_for_intent(depth, authorization)
    return {
        "planner_version": "intent-to-mission-planner-v1",
        "generated_at": generated_at.isoformat(),
        "preview_ready": preview_ready,
        "launch_ready": launch_ready,
        "next_missing_field": next_missing_field,
        "extracted": {
            "target": target,
            "target_map": target_map,
            "assessment_type": assessment_type,
            "depth": depth,
            "run_mode": run_mode,
            "assessment_mode": assessment_mode,
            "authorization_summary": authorization,
        },
        "configuration_preview": {
            "assessment_type": assessment_type,
            "test_profile": depth,
            "targets": target_map,
            "run_mode": run_mode,
            "assessment_mode": assessment_mode,
            "dispatch_after_create": bool(assessment_mode),
        },
        "evidence_plan": {
            "inventory_seed": bool(target),
            "expected_evidence": [
                "operator_intent",
                "scope_allowlist",
                "authorization_confirmation",
                "runner_task_ledger",
                "coverage_truth",
                "roe_policy_decision",
            ],
            "report_sections": ["execution_ledger", "coverage_truth", "evidence_appendix"],
        },
        "launch_summary": {
            "automatic": automatic_work,
            "requires_approval": approval_work,
            "out_of_scope": blocked_items,
            "required_actions": required_actions,
            "operator_text": _intent_operator_summary(
                assessment_type=assessment_type,
                target=target,
                depth=depth,
                assessment_mode=assessment_mode,
                required_actions=required_actions,
                blocked_items=blocked_items,
            ),
        },
        "follow_up_questions": _intent_follow_ups(
            missing_fields=missing_fields,
            unsafe_scope=unsafe_scope,
        ),
        "safety": {
            "scope_expansion_allowed": False,
            "authorization_bypass_allowed": False,
            "credential_consent_bypass_allowed": False,
            "kill_switch_bypass_allowed": False,
            "manual_wizard_preserved": True,
        },
    }


def _extract_primary_target(answer: str) -> str | None:
    url_match = re.search(r"https?://[^\s,;]+", answer)
    if url_match:
        return url_match.group(0).rstrip(".,)")
    cidr_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", answer)
    if cidr_match:
        return cidr_match.group(0)
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", answer)
    if ip_match:
        return ip_match.group(0)
    domain_match = re.search(r"\b[a-z0-9][a-z0-9.-]+\.[a-z]{2,}\b", answer, flags=re.I)
    if domain_match:
        return domain_match.group(0).rstrip(".,)")
    return None


def _first_explicit_target(configuration: dict[str, Any]) -> str | None:
    explicit = _explicit_targets(configuration)
    return explicit[0] if explicit else None


def _target_map_for_target(target: str | None) -> dict[str, list[str]]:
    if not target:
        return {}
    if target.startswith(("http://", "https://")):
        return {"urls": [target]}
    if "/" in target and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", target):
        return {"cidr_ranges": [target]}
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", target):
        return {"ip_addresses": [target]}
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]+\.[a-z]{2,}", target, flags=re.I):
        return {"domains": [target]}
    return {"hosts": [target]}


def _assessment_type_from_intent(normalized: str, target: str | None) -> str:
    if any(token in normalized for token in ("api", "graphql", "rest")):
        return "API Security"
    if any(token in normalized for token in ("active directory", "ad assessment", "domain controller")):
        return "Active Directory"
    if any(token in normalized for token in ("internal", "lan", "network", "subnet")):
        return "Internal Range / LAN"
    if any(token in normalized for token in ("cloud", "aws", "azure", "gcp")):
        return "Cloud Infrastructure"
    if target and str(target).startswith(("http://", "https://")):
        return "External Web App"
    if target and "/" in target:
        return "Internal Range / LAN"
    return "External Web App"


def _depth_from_intent(normalized: str, configuration: dict[str, Any]) -> str:
    configured = str(configuration.get("test_profile") or "").strip()
    if any(phrase in normalized for phrase in FULL_PENTEST_PHRASES):
        return "Full Pentest"
    if any(phrase in normalized for phrase in ACTIVE_SCAN_PHRASES):
        return "Active Scan"
    if any(phrase in normalized for phrase in PASSIVE_SCAN_PHRASES):
        return "Passive"
    if configured:
        if "full" in configured.lower():
            return "Full Pentest"
        if "active" in configured.lower() or "standard" in configured.lower():
            return "Active Scan"
    return "Passive"


def _assessment_mode_for_intent(assessment_type: str, depth: str) -> str | None:
    if depth != "Full Pentest":
        return None
    normalized = assessment_type.lower()
    if "active directory" in normalized:
        return "FULL-AD-ASSESSMENT"
    if "internal" in normalized or "lan" in normalized:
        return "FULL-INTERNAL-LAN"
    if "web" in normalized or "api" in normalized:
        return "FULL-EXTERNAL-WEB"
    return None


def _intent_authorization_summary(configuration: dict[str, Any], depth: str) -> dict[str, Any]:
    assessment_mode = _safe_dict(configuration.get("assessment_mode"))
    access = _safe_dict(configuration.get("access"))
    prerequisites = _safe_dict(access.get("prerequisites"))
    authorization_level = str(assessment_mode.get("authorization_level") or "").strip().lower()
    written_confirmed = bool(
        configuration.get("authorization_confirmed")
        or assessment_mode.get("written_authorization_confirmed")
        or authorization_level == "full"
    )
    return {
        "written_authorization_required": depth == "Full Pentest",
        "written_authorization_confirmed": written_confirmed,
        "authorization_level": authorization_level or ("full_required" if depth == "Full Pentest" else "standard"),
        "intrusive_lan_authorized": bool(
            prerequisites.get("intrusive_lan_authorized")
            or assessment_mode.get("intrusive_lan_authorized")
        ),
        "credential_consent_required": bool(access.get("accounts") or access.get("manual_auth_steps")),
        "credential_consent_confirmed": bool(access.get("accounts") or access.get("manual_auth_steps")),
    }


def _automatic_work_for_intent(
    assessment_type: str,
    depth: str,
    assessment_mode: str | None,
) -> list[dict[str, Any]]:
    if assessment_mode:
        return [
            {
                "id": "assessment_chain",
                "label": f"{assessment_mode} phase chain starts automatically after launch.",
            },
            {
                "id": "seed_inventory",
                "label": "Seed inventory and passive baseline evidence are recorded first.",
            },
        ]
    if depth == "Active Scan":
        return [{"id": "active_recon", "label": f"Approval-aware active checks for {assessment_type}."}]
    return [{"id": "passive_baseline", "label": f"Passive-safe baseline for {assessment_type}."}]


def _approval_work_for_intent(depth: str, authorization: dict[str, Any]) -> list[dict[str, Any]]:
    if depth != "Full Pentest":
        return []
    if authorization.get("written_authorization_confirmed"):
        return []
    return [
        {
            "id": "written_authorization",
            "label": "Launch remains blocked until written authorization is confirmed.",
        }
    ]


def _intent_follow_ups(*, missing_fields: list[str], unsafe_scope: bool) -> list[dict[str, Any]]:
    if unsafe_scope:
        return [
            {
                "question_id": "scope",
                "question": "Which exact URLs, domains, IPs, or CIDRs are explicitly authorized?",
                "reason": "Broad scope language cannot become authorization.",
            }
        ]
    if "target" in missing_fields:
        return [
            {
                "question_id": "scope",
                "question": "Which exact URL, domain, IP, or CIDR is explicitly authorized?",
                "reason": "A target is required before a mission can be previewed.",
            }
        ]
    if "assessment_type" in missing_fields:
        return [
            {
                "question_id": "targetType",
                "question": "What kind of surface is this: web app, API, internal LAN, AD, or cloud?",
                "reason": "Assessment type controls the safe runner profile.",
            }
        ]
    if "depth" in missing_fields:
        return [
            {
                "question_id": "depth",
                "question": "Should this be Passive, Active Scan, or Full Pentest?",
                "reason": "Execution depth controls approval and ROE policy.",
            }
        ]
    return []


def _intent_operator_summary(
    *,
    assessment_type: str,
    target: str | None,
    depth: str,
    assessment_mode: str | None,
    required_actions: list[dict[str, Any]],
    blocked_items: list[dict[str, Any]],
) -> str:
    if blocked_items:
        return "Scope is not launch-ready because broad or unsafe target language must be replaced with exact authorized targets."
    if not target:
        return "Mission preview needs an exact authorized target before launch."
    if required_actions:
        return (
            f"{depth} preview for {assessment_type} on {target} is complete; written authorization "
            "must be confirmed before launch."
        )
    if assessment_mode:
        return f"{depth} on {target} will launch {assessment_mode} with automatic phase progression."
    return f"{depth} on {target} is ready for operator-reviewed launch."


def _explicit_targets(configuration: dict[str, Any]) -> list[str]:
    targets = configuration.get("targets")
    if not isinstance(targets, dict):
        return []
    values: list[str] = []
    for value in targets.values():
        if isinstance(value, list):
            values.extend(str(item).strip() for item in value if str(item).strip())
    return sorted(set(values))


def _has_explicit_access_signal(answer: str, configuration: dict[str, Any]) -> bool:
    normalized = answer.lower()
    if any(phrase in normalized for phrase in ACCESS_SIGNAL_PHRASES):
        return True
    access = configuration.get("access")
    if not isinstance(access, dict):
        return False
    accounts = access.get("accounts")
    if isinstance(accounts, list) and accounts:
        return True
    return any(str(access.get(field) or "").strip() for field in ("manual_auth_steps", "cookie_notes"))


def _suggests_pack_approval_or_deployment(suggestion: dict[str, Any]) -> bool:
    haystack = " ".join(
        str(value).lower()
        for value in suggestion.values()
        if isinstance(value, (str, bool, int, float))
    )
    if suggestion.get("deployment_performed") is True or suggestion.get("auto_bind") is True:
        return True
    return any(word in haystack for word in PACK_DEPLOYMENT_WORDS)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _uuid_or_none(value: UUID | str | None) -> UUID | None:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result
