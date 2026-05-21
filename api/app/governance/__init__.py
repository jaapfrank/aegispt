"""Layer 0 — Governance Control Plane.

Per Codex 6-layer architectuur (sprint mythos-exploitation-foundation, task 3/15):
every agent decision and runner dispatch routes through one central authorization
API instead of consulting verspreide scope/ROE/approval/credential checks across
api/app/services/* and workers/orchestration/*.

Public surface:

    from api.app.governance import GovernanceControlPlane, DispatchAuthorization

    plane = GovernanceControlPlane(session, settings)
    auth = plane.authorize_dispatch(run=run, runner="exec-plan", target=url, tier="intrusive")
    if not auth.allow:
        # auth.deny_reason explains; auth.needs_approval tells whether the
        # operator can flip it with an approval.
        ...

Per ANTI_DRIFT.md Rule 3: callers MUST be migrated to this API and the legacy
verspreide checks REMOVED in the same commit. Parallel coexistence is forbidden.
"""
from __future__ import annotations

from api.app.governance.control_plane import (
    BudgetState,
    DispatchAuthorization,
    GovernanceControlPlane,
)

__all__ = [
    "BudgetState",
    "DispatchAuthorization",
    "GovernanceControlPlane",
]
