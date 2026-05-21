"""Layer 0 Governance Control Plane — single authorization API for AegisPT.

Per backlog-409 (sprint mythos-exploitation-foundation, task 3/15): every
agent decision and runner dispatch validates through ONE class instead of
the verspreide scope / approval / credential / budget checks that previously
lived in `api/app/services/assessment_loop.py`, `api/app/services/runs.py`
(scope helpers), and `workers/orchestration/tasks.py` (post-task scope guard).

The class is intentionally thin: it composes the existing primitives
(`target_value_is_allowed`, `pending_approvals`, `RunProfile.run_class`) and
returns a structured ``DispatchAuthorization`` dataclass so callers don't
recompute the verdict.

Concretely the migration target is:

1. ``authorize_dispatch(run, runner, target, tier)`` — replaces ad-hoc
   `_scope_target_allowed` + `pending_approvals` + `intrusive_authorized`
   chains. Returns allow/deny/needs_approval + a human-readable reason.

2. ``authorize_credential_use(run, cred_id)`` — for runners that consume
   credentials from the run's vault (responder, impacket, ssh-brute, etc.).

3. ``authorize_external_network(run, target)`` — for the future sandbox
   runner egress allowlist. Default-deny on external IPs unless the
   engagement scope explicitly permits.

4. ``authorize_exec_plan_step(run, step)`` — each step inside an exec_plan
   re-validates target + method + headers before the sandbox actually
   issues the request.

5. ``check_budget(run)`` — tracks per-run rps / concurrency / duration
   consumption against the profile's limits. Returns a ``BudgetState`` so
   callers can short-circuit further dispatch when exhausted.

No business logic moves into Layer 0 in the first pass; only consolidation.
Future refactors can deepen the semantics without changing the call shape.

Per ANTI_DRIFT.md Rule 4 (no mocked-live): every method has a unit test
exercising the deny + allow + needs-approval paths; integration test
asserts that post-task dispatch in `workers/orchestration/tasks.py` routes
through `authorize_dispatch` and not the legacy inline call.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from api.app.models import Run, RunProfile, Scope
from api.app.services.runs import (
    latest_scope_query,
    pending_approvals,
    target_value_is_allowed,
)

logger = logging.getLogger(__name__)


_INTRUSIVE_TIERS = frozenset({"intrusive", "active"})
_ALWAYS_ALLOWED_TIERS = frozenset({"passive", "informational", "info"})


@dataclass
class DispatchAuthorization:
    """Verdict of :meth:`GovernanceControlPlane.authorize_dispatch`.

    ``allow=True`` means the runner may dispatch without further checks.
    ``allow=False`` plus ``needs_approval=True`` means the operator can
    unblock with an approval (the caller typically returns a 4xx that the
    operator UI converts to an approval prompt).
    ``allow=False`` plus ``needs_approval=False`` is a hard deny — usually
    out-of-scope, missing-roe, or intrusive-not-authorized.
    """

    allow: bool
    deny_reason: str | None = None
    needs_approval: bool = False
    pending_count: int = 0
    notes: list[str] = field(default_factory=list)

    @classmethod
    def allowed(cls, *, notes: list[str] | None = None) -> "DispatchAuthorization":
        return cls(allow=True, notes=notes or [])

    @classmethod
    def denied(cls, reason: str) -> "DispatchAuthorization":
        return cls(allow=False, deny_reason=reason)

    @classmethod
    def needs_approval_for(cls, pending: int, reason: str) -> "DispatchAuthorization":
        return cls(
            allow=False,
            deny_reason=reason,
            needs_approval=True,
            pending_count=pending,
        )


@dataclass
class BudgetState:
    """Per-run resource budget snapshot returned by :meth:`check_budget`.

    The values are advisory in this first slice; later passes can add hard
    cutoffs once metrics flow into the same plane. The point of having the
    state object now is that every caller asks Layer 0 — not its own counter.
    """

    rps_cap: int
    concurrency_cap: int
    exhausted: bool = False
    notes: list[str] = field(default_factory=list)


class GovernanceControlPlane:
    """Central authorization API. Stateless beyond the SQLAlchemy session.

    Construct one per request handler; do NOT cache across requests because
    the session-scoped objects (Scope, Run) must be live in the calling
    session.
    """

    def __init__(self, session: Session, *, default_actor: str | None = None) -> None:
        self._session = session
        self._default_actor = default_actor

    # ------------------------------------------------------------------
    # 1. Dispatch authorization — the hot path.
    # ------------------------------------------------------------------

    def authorize_dispatch(
        self,
        *,
        run: Run,
        runner: str,
        target: str,
        tier: str | None = None,
    ) -> DispatchAuthorization:
        """Single source of truth for "may this runner dispatch this target?"

        Combines: engagement authorization (ROE / written authorization),
        live scope check (allowlist + denylist), profile approvals, and
        intrusive-authorization flag. Returns a structured verdict.
        """
        # 1. Engagement authorization gate (ROE or explicit confirm).
        engagement = getattr(run, "engagement", None)
        if engagement is not None:
            roe_ref = str(getattr(engagement, "roe_ref", "") or "").strip()
            confirmed_at = getattr(engagement, "authorization_confirmed_at", None)
            if not roe_ref and confirmed_at is None:
                return DispatchAuthorization.denied(
                    "engagement lacks roe_ref AND authorization_confirmed_at — "
                    "operator must confirm written authorization before any dispatch"
                )

        # 2. Scope check (allowlist + denylist).
        scope = self._latest_scope(run)
        if scope is None:
            return DispatchAuthorization.denied(
                f"engagement {getattr(run, 'engagement_id', '?')} has no Scope record"
            )
        if not self._target_in_scope(scope, target):
            return DispatchAuthorization.denied(
                f"target {target!r} is outside the approved engagement scope"
            )

        # 3. Profile-driven approval gate.
        profile = getattr(run, "profile", None)
        if profile is not None:
            pending = pending_approvals(run, profile)
            if pending > 0:
                return DispatchAuthorization.needs_approval_for(
                    pending,
                    f"runner {runner!r} needs {pending} approval(s) under profile "
                    f"{profile.name!r} (run_class={profile.run_class})",
                )

        # 4. Intrusive-tier gate — must match either the run's flag or the
        #    profile's run_class.
        effective_tier = (tier or "").strip().lower() or self._tier_for_profile(profile)
        if effective_tier in _INTRUSIVE_TIERS:
            if not getattr(run, "autonomous_intrusive_allowed", False):
                return DispatchAuthorization.denied(
                    f"runner {runner!r} dispatch is intrusive (tier={effective_tier}) "
                    "but run.autonomous_intrusive_allowed is False"
                )

        return DispatchAuthorization.allowed(
            notes=[f"runner={runner}", f"tier={effective_tier or 'unset'}"],
        )

    # ------------------------------------------------------------------
    # 2. Credential use.
    # ------------------------------------------------------------------

    def authorize_credential_use(self, *, run: Run, cred_id: str) -> DispatchAuthorization:
        """Authorize use of a specific credential id against this run."""
        cred_id_stripped = str(cred_id or "").strip()
        if not cred_id_stripped:
            return DispatchAuthorization.denied("empty credential id")
        run_status = str(getattr(run, "status", "") or "").lower()
        if run_status in {"completed", "failed", "rejected", "cancelled"}:
            return DispatchAuthorization.denied(
                f"run {run.id} is terminal ({run_status}); credentials cannot be used"
            )
        return DispatchAuthorization.allowed(notes=[f"cred_id={cred_id_stripped}"])

    # ------------------------------------------------------------------
    # 3. External network (sandbox egress).
    # ------------------------------------------------------------------

    def authorize_external_network(self, *, run: Run, target: str) -> DispatchAuthorization:
        """Default-deny external egress; only scope-allowed targets pass."""
        scope = self._latest_scope(run)
        if scope is None:
            return DispatchAuthorization.denied("no scope to authorize egress against")
        if not self._target_in_scope(scope, target):
            return DispatchAuthorization.denied(
                f"egress to {target!r} is denied by default — target not in scope allowlist"
            )
        return DispatchAuthorization.allowed(notes=[f"egress={target}"])

    # ------------------------------------------------------------------
    # 4. Per-step exec_plan validation.
    # ------------------------------------------------------------------

    def authorize_exec_plan_step(
        self,
        *,
        run: Run,
        step: dict[str, Any],
    ) -> DispatchAuthorization:
        """Validate one exec_plan step (target + method + headers)."""
        method = str(step.get("method") or "").strip().upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return DispatchAuthorization.denied(
                f"exec_plan step uses non-allowed method {method!r}"
            )
        url = str(step.get("url") or "").strip()
        if not url:
            return DispatchAuthorization.denied("exec_plan step missing url")
        scope = self._latest_scope(run)
        if scope is None:
            return DispatchAuthorization.denied("no scope to authorize step against")
        if not self._target_in_scope(scope, url):
            return DispatchAuthorization.denied(
                f"exec_plan step target {url!r} is outside engagement scope"
            )
        headers = step.get("headers") or {}
        if isinstance(headers, dict):
            for h in headers.keys():
                if str(h or "").strip().lower() == "host":
                    return DispatchAuthorization.denied(
                        "exec_plan step attempts to override Host header — denied"
                    )
        return DispatchAuthorization.allowed(notes=[f"step={method} {url}"])

    # ------------------------------------------------------------------
    # 5. Budget snapshot.
    # ------------------------------------------------------------------

    def check_budget(self, *, run: Run) -> BudgetState:
        """Return advisory budget snapshot (values come from profile limits)."""
        profile = getattr(run, "profile", None)
        if profile is None:
            return BudgetState(rps_cap=10, concurrency_cap=5, notes=["no profile"])
        limits = profile.limits_json if isinstance(profile.limits_json, dict) else {}
        rps = int(limits.get("max_rps", 10) or 10)
        concurrency = int(limits.get("max_concurrency", 5) or 5)
        return BudgetState(rps_cap=rps, concurrency_cap=concurrency)

    # ------------------------------------------------------------------
    # Internal helpers.
    # ------------------------------------------------------------------

    def _latest_scope(self, run: Run) -> Scope | None:
        engagement_id = getattr(run, "engagement_id", None)
        if engagement_id is None:
            return None
        try:
            return self._session.scalar(latest_scope_query(engagement_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning("control_plane: scope lookup failed for run %s: %s", run.id, exc)
            return None

    def _target_in_scope(self, scope: Scope, target: str) -> bool:
        if target_value_is_allowed(scope.denylist_json, target):
            return False
        return target_value_is_allowed(scope.allowlist_json, target)

    def _tier_for_profile(self, profile: RunProfile | None) -> str:
        if profile is None:
            return ""
        return str(getattr(profile, "run_class", "") or "").strip().lower()


__all__ = [
    "BudgetState",
    "DispatchAuthorization",
    "GovernanceControlPlane",
]
