from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse, urlunparse

from api.app.config import Settings
from api.app.models import Run, Scope
from api.app.policy.engine import (
    RunClass,
    execution_kill_switch_enabled,
    normalize_profile_limits,
    parse_run_class,
)
from api.app.services.runner_contracts import RunnerContractError, runner_contract_for
from api.app.services.runs import (
    approval_step_id,
    derive_targets_for_run,
    granted_approvals,
    pending_approvals,
    required_approvals,
    target_value_is_allowed,
)

ROE_POLICY_VERSION = "roe-policy-compiler-v1"
POLICY_DECISIONS = {
    "allow",
    "deny",
    "approval_required",
    "wait_for_prerequisite",
    "kill_switch_blocked",
}
TIER_RANK = {
    RunClass.PASSIVE.value: 0,
    RunClass.ACTIVE.value: 1,
    RunClass.INTRUSIVE.value: 2,
}


def compile_roe_policy_decision(
    *,
    run: Run,
    scope: Scope | None,
    target: str | None = None,
    runner: str | None = None,
    action_type: str = "runner_action",
    requested_risk_tier: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Compile current ROE/scope/runtime state into an advisory policy decision."""

    generated_at = datetime.now(UTC).isoformat()
    source_policy_ids = [f"run:{run.id}", f"engagement:{run.engagement_id}"]
    profile = run.profile
    if profile is not None:
        source_policy_ids.append(f"run_profile:{profile.id}:{profile.name}")

    runner_contract = _runner_contract(runner)
    if runner_contract is not None:
        source_policy_ids.append(f"runner_contract:{runner_contract['contract_id']}")
    elif runner:
        source_policy_ids.append(f"runner_contract:{runner}:missing")

    profile_tier = parse_run_class(profile.run_class if profile is not None else None)
    requested_tier = _requested_tier(
        requested_risk_tier=requested_risk_tier,
        runner_contract=runner_contract,
        fallback=profile_tier,
    )
    target_value = _select_target(run=run, scope=scope, target=target)
    target_normalization = _target_normalization(target_value)
    affected_action = {
        "runner": str(runner or "").strip() or None,
        "action_type": action_type,
        "requested_risk_tier": requested_tier.value,
        "profile_risk_tier": profile_tier.value,
        "runner_contract_id": runner_contract.get("contract_id") if runner_contract else None,
    }
    rate_limits = _rate_limits(profile)
    credential_policy = _credential_policy(run)
    authorization = _authorization_context(run)
    execution_contract = _execution_contract()

    if execution_kill_switch_enabled(settings):
        return _decision_payload(
            decision="kill_switch_blocked",
            run=run,
            generated_at=generated_at,
            source_policy_ids=[*source_policy_ids, "kill_switch:execution"],
            target_normalization=target_normalization,
            affected_action=affected_action,
            rate_limits=rate_limits,
            credential_policy=credential_policy,
            authorization=authorization,
            approval_state=_approval_state(run, profile, runner_contract),
            execution_contract=execution_contract,
            explanation=(
                "Planning and dispatch are blocked because the execution kill switch is enabled. "
                "No runner action may proceed until an operator clears the kill switch."
            ),
            blocker_reason_ids=["kill_switch:execution"],
        )

    if scope is None:
        return _decision_payload(
            decision="wait_for_prerequisite",
            run=run,
            generated_at=generated_at,
            source_policy_ids=[*source_policy_ids, "scope:missing"],
            target_normalization=target_normalization,
            affected_action=affected_action,
            rate_limits=rate_limits,
            credential_policy=credential_policy,
            authorization=authorization,
            approval_state=_approval_state(run, profile, runner_contract),
            execution_contract=execution_contract,
            explanation=(
                "Policy cannot allow this action yet because the engagement has no active scope record."
            ),
            blocker_reason_ids=["missing_scope"],
        )

    source_policy_ids.extend([f"scope:{scope.id}:allowlist", f"scope:{scope.id}:denylist"])
    if not target_value:
        return _decision_payload(
            decision="wait_for_prerequisite",
            run=run,
            generated_at=generated_at,
            source_policy_ids=source_policy_ids,
            target_normalization=target_normalization,
            affected_action=affected_action,
            rate_limits=rate_limits,
            credential_policy=credential_policy,
            authorization=authorization,
            approval_state=_approval_state(run, profile, runner_contract),
            execution_contract=execution_contract,
            explanation="Policy cannot allow this action yet because no target was provided or derivable.",
            blocker_reason_ids=["missing_target"],
        )

    denylisted = target_value_is_allowed(scope.denylist_json, target_value)
    allowlisted = target_value_is_allowed(scope.allowlist_json, target_value)
    target_normalization.update(
        {
            "allowed_by_allowlist": allowlisted,
            "blocked_by_denylist": denylisted,
        }
    )
    if denylisted:
        return _decision_payload(
            decision="deny",
            run=run,
            generated_at=generated_at,
            source_policy_ids=source_policy_ids,
            target_normalization=target_normalization,
            affected_action=affected_action,
            rate_limits=rate_limits,
            credential_policy=credential_policy,
            authorization=authorization,
            approval_state=_approval_state(run, profile, runner_contract),
            execution_contract=execution_contract,
            explanation=(
                f"{target_normalization['display']} is denied because it matches the engagement denylist."
            ),
            blocker_reason_ids=["target_denylisted"],
        )
    if not allowlisted:
        return _decision_payload(
            decision="deny",
            run=run,
            generated_at=generated_at,
            source_policy_ids=source_policy_ids,
            target_normalization=target_normalization,
            affected_action=affected_action,
            rate_limits=rate_limits,
            credential_policy=credential_policy,
            authorization=authorization,
            approval_state=_approval_state(run, profile, runner_contract),
            execution_contract=execution_contract,
            explanation=(
                f"{target_normalization['display']} is denied because it is outside the current scope allowlist."
            ),
            blocker_reason_ids=["target_out_of_scope"],
        )

    approval_state = _approval_state(run, profile, runner_contract)
    requested_rank = TIER_RANK[requested_tier.value]
    profile_rank = TIER_RANK[profile_tier.value]
    roe_confirms_requested_tier = _roe_confirms_tier(authorization, requested_tier)
    approval_reason_ids: list[str] = []
    if approval_state["pending_approvals"] > 0:
        approval_reason_ids.append(f"approval_step:{approval_state['approval_step_id']}")
    if approval_state["runner_contract_pending_approvals"] > 0:
        approval_reason_ids.extend(approval_state["runner_contract_approval_reason_ids"])
    if requested_rank > profile_rank and not roe_confirms_requested_tier:
        approval_reason_ids.append(f"risk_tier_upgrade:{profile_tier.value}->{requested_tier.value}")

    if approval_reason_ids:
        return _decision_payload(
            decision="approval_required",
            run=run,
            generated_at=generated_at,
            source_policy_ids=source_policy_ids,
            target_normalization=target_normalization,
            affected_action=affected_action,
            rate_limits=rate_limits,
            credential_policy=credential_policy,
            authorization=authorization,
            approval_state=approval_state,
            execution_contract=execution_contract,
            explanation=(
                "The target is in scope, but this action requires operator approval before it can be "
                "planned as executable work."
            ),
            approval_reason_ids=sorted(set(approval_reason_ids)),
        )

    return _decision_payload(
        decision="allow",
        run=run,
        generated_at=generated_at,
        source_policy_ids=source_policy_ids,
        target_normalization=target_normalization,
        affected_action=affected_action,
        rate_limits=rate_limits,
        credential_policy=credential_policy,
        authorization=authorization,
        approval_state=approval_state,
        execution_contract=execution_contract,
        explanation=(
            "The target is in scope, no denylist rule matched, the kill switch is clear, and the "
            "current ROE/approval state permits this policy decision."
        ),
    )


def _runner_contract(runner: str | None) -> dict[str, Any] | None:
    normalized = str(runner or "").strip()
    if not normalized:
        return None
    try:
        return runner_contract_for(normalized)
    except RunnerContractError:
        return None


def _select_target(*, run: Run, scope: Scope | None, target: str | None) -> str | None:
    provided = str(target or "").strip()
    if provided:
        return provided
    if scope is None:
        return None
    derived = derive_targets_for_run(scope, run)
    return derived[0]["value"] if derived else None


def _requested_tier(
    *,
    requested_risk_tier: str | None,
    runner_contract: dict[str, Any] | None,
    fallback: RunClass,
) -> RunClass:
    if requested_risk_tier:
        return parse_run_class(requested_risk_tier)
    if runner_contract is not None:
        return parse_run_class(runner_contract.get("risk_tier"))
    return fallback


def _target_normalization(target: str | None) -> dict[str, Any]:
    raw = str(target or "").strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}") if raw else None
    host = parsed.hostname.lower() if parsed and parsed.hostname else ""
    scheme = parsed.scheme.lower() if parsed and parsed.scheme else ""
    normalized = raw
    kind = "missing"
    if raw:
        try:
            ip_address(host or raw)
            kind = "ip"
        except ValueError:
            kind = "url" if scheme else "host"
        if parsed and scheme and host:
            netloc = host
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            path = parsed.path or ""
            normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
        elif host:
            normalized = host
    return {
        "raw": raw or None,
        "normalized": normalized or None,
        "display": normalized or raw or "<missing target>",
        "kind": kind,
        "host": host or None,
        "allowed_by_allowlist": False,
        "blocked_by_denylist": False,
    }


def _rate_limits(profile) -> dict[str, Any]:
    if profile is None:
        limits = normalize_profile_limits(None, None)
        return {"source": "default_profile_limits", "run_class": RunClass.PASSIVE.value, **limits}
    limits = normalize_profile_limits(profile.run_class, profile.limits_json)
    return {
        "source": f"run_profile:{profile.name}",
        "profile_id": str(profile.id),
        "run_class": parse_run_class(profile.run_class).value,
        **limits,
    }


def _credential_policy(run: Run) -> dict[str, Any]:
    configuration = _as_dict(run.configuration_json)
    secret_bindings = _as_list(configuration.get("secret_bindings"))
    vault_refs = _as_list(_as_dict(configuration.get("credential_vault")).get("secret_refs"))
    return {
        "plaintext_credentials_allowed": False,
        "secret_refs_allowed": True,
        "materialization": "existing_runtime_only",
        "secret_ref_count": len(secret_bindings) + len(vault_refs),
        "credential_storage_changed": False,
        "source_policy_id": "credential_policy:secret_refs_only",
    }


def _authorization_context(run: Run) -> dict[str, Any]:
    configuration = _as_dict(run.configuration_json)
    assessment_mode = _as_dict(configuration.get("assessment_mode"))
    access = _as_dict(configuration.get("access"))
    prerequisites = _as_dict(access.get("prerequisites"))
    authorization_level = str(assessment_mode.get("authorization_level") or "").strip().lower()
    intrusive_authorized = bool(
        prerequisites.get("intrusive_lan_authorized")
        or access.get("intrusive_lan_authorized")
        or configuration.get("intrusive_lan_authorized")
    )
    exploit_authorized = bool(
        prerequisites.get("exploit_confirmation_authorized")
        or access.get("exploit_confirmation_authorized")
        or configuration.get("exploit_confirmation_authorized")
    )
    full_authorization = authorization_level in {"full", "full_pentest", "full-pentest"}
    return {
        "authorization_level": authorization_level or None,
        "full_authorization_confirmed": full_authorization,
        "intrusive_lan_authorized": intrusive_authorized,
        "exploit_confirmation_authorized": exploit_authorized,
        "typed_scope_confirmation_present": bool(assessment_mode.get("typed_scope_confirmation")),
        "controlled_proof_requires_later_approval": bool(
            assessment_mode.get("controlled_proof_requires_later_approval", True)
        ),
        "source_policy_id": "roe:authorization_context",
    }


def _roe_confirms_tier(authorization: dict[str, Any], requested_tier: RunClass) -> bool:
    if requested_tier == RunClass.PASSIVE:
        return True
    if requested_tier == RunClass.ACTIVE:
        return bool(authorization.get("full_authorization_confirmed"))
    return bool(
        authorization.get("full_authorization_confirmed")
        or authorization.get("intrusive_lan_authorized")
        or authorization.get("exploit_confirmation_authorized")
    )


def _approval_state(
    run: Run,
    profile,
    runner_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    if profile is None:
        profile_required = 0
        profile_granted = 0
        profile_pending = 0
        step_id = "run-profile:missing"
    else:
        step_id = approval_step_id(profile)
        profile_required = required_approvals(profile)
        profile_granted = granted_approvals(run, profile=profile)
        profile_pending = pending_approvals(run, profile)
    contract_required = _safe_int(_as_dict(runner_contract.get("approval") if runner_contract else {}).get("required_approvals"))
    contract_pending = max(contract_required - (profile_granted if profile is not None else 0), 0)
    return {
        "approval_step_id": step_id,
        "required_approvals": profile_required,
        "granted_approvals": profile_granted,
        "pending_approvals": profile_pending,
        "runner_contract_required_approvals": contract_required,
        "runner_contract_pending_approvals": contract_pending,
        "runner_contract_approval_reason_ids": _string_list(
            _as_dict(runner_contract.get("approval") if runner_contract else {}).get("approval_reason_ids")
        ),
    }


def _decision_payload(
    *,
    decision: str,
    run: Run,
    generated_at: str,
    source_policy_ids: list[str],
    target_normalization: dict[str, Any],
    affected_action: dict[str, Any],
    rate_limits: dict[str, Any],
    credential_policy: dict[str, Any],
    authorization: dict[str, Any],
    approval_state: dict[str, Any],
    execution_contract: dict[str, Any],
    explanation: str,
    blocker_reason_ids: list[str] | None = None,
    approval_reason_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "policy_version": ROE_POLICY_VERSION,
        "decision": decision,
        "run_id": str(run.id),
        "engagement_id": str(run.engagement_id),
        "generated_at": generated_at,
        "source_policy_ids": sorted(set(source_policy_ids)),
        "target_normalization": target_normalization,
        "affected_action": affected_action,
        "rate_limits": rate_limits,
        "credential_policy": credential_policy,
        "authorization": authorization,
        "approval_state": approval_state,
        "explanation": explanation,
        "blocker_reason_ids": blocker_reason_ids or [],
        "approval_reason_ids": approval_reason_ids or [],
        "execution_contract": execution_contract,
        "provenance": {
            "compiler": ROE_POLICY_VERSION,
            "analysis_only": True,
            "dispatches_work": False,
            "mutates_scope": False,
            "mutates_approvals": False,
            "mutates_credentials": False,
            "runtime_self_modification": False,
            "approval_gates_bypassed": False,
            "scope_roe_bypassed": False,
        },
    }


def _execution_contract() -> dict[str, bool]:
    return {
        "analysis_only": True,
        "dispatches_work": False,
        "mutates_scope": False,
        "mutates_approvals": False,
        "mutates_credentials": False,
        "runtime_self_modification": False,
        "runner_registry_bypassed": False,
        "approval_gates_bypassed": False,
    }


def _safe_int(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    normalized: list[str] = []
    for item in _as_list(value):
        candidate = str(item or "").strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized
