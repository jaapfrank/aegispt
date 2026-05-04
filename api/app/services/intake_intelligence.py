from __future__ import annotations

import copy
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
