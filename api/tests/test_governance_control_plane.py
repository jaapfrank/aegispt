"""Unit tests for backlog-409 GovernanceControlPlane (Layer 0).

Covers the deny / allow / needs_approval paths for each authorize-* method
plus the budget snapshot. No DB fixtures — uses lightweight stand-ins for
Run / Scope / Profile because Layer 0 only reads attributes it documents.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import pytest

from api.app.governance import (
    BudgetState,
    DispatchAuthorization,
    GovernanceControlPlane,
)

# --- lightweight stand-ins -------------------------------------------------


@dataclass
class _FakeEngagement:
    id: str = "eng-1"
    roe_ref: str = "ROE-XBOW-2026"
    authorization_confirmed_at: Any = None


@dataclass
class _FakeProfile:
    name: str = "autonomous-web"
    run_class: str = "passive"
    limits_json: dict = field(default_factory=lambda: {"max_rps": 5, "max_concurrency": 3})


@dataclass
class _FakeRun:
    id: UUID = UUID("00000000-0000-0000-0000-000000000001")
    engagement_id: str = "eng-1"
    engagement: Any = None
    profile: Any = None
    status: str = "running"
    autonomous_intrusive_allowed: bool = False
    approvals: list = field(default_factory=list)  # consumed by pending_approvals()


@dataclass
class _FakeScope:
    allowlist_json: dict = field(default_factory=dict)
    denylist_json: dict = field(default_factory=dict)


class _SessionStub:
    """Patches in a fixed Scope without hitting a database."""

    def __init__(self, scope: _FakeScope | None) -> None:
        self._scope = scope

    def scalar(self, _query: Any) -> Any:
        return self._scope


# --- fixtures -------------------------------------------------------------


@pytest.fixture()
def run_with_url_scope() -> tuple[_FakeRun, _FakeScope]:
    eng = _FakeEngagement()
    scope = _FakeScope(allowlist_json={"urls": ["http://127.0.0.1:8080"]})
    run = _FakeRun(
        engagement=eng,
        profile=_FakeProfile(),
        autonomous_intrusive_allowed=True,
    )
    return run, scope


@pytest.fixture()
def plane(run_with_url_scope) -> GovernanceControlPlane:
    _run, scope = run_with_url_scope
    return GovernanceControlPlane(session=_SessionStub(scope))  # type: ignore[arg-type]


# --- authorize_dispatch ---------------------------------------------------


def test_authorize_dispatch_allows_in_scope_target(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    auth = plane.authorize_dispatch(run=run, runner="httpx", target="http://127.0.0.1:8080/login")
    assert auth.allow, auth.deny_reason


def test_authorize_dispatch_denies_out_of_scope_target(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    auth = plane.authorize_dispatch(run=run, runner="httpx", target="http://10.0.0.5/admin")
    assert not auth.allow
    assert "outside the approved engagement scope" in (auth.deny_reason or "")


def test_authorize_dispatch_denies_when_engagement_lacks_roe() -> None:
    eng = _FakeEngagement(roe_ref="", authorization_confirmed_at=None)
    scope = _FakeScope(allowlist_json={"urls": ["http://x"]})
    run = _FakeRun(engagement=eng, profile=_FakeProfile())
    plane = GovernanceControlPlane(session=_SessionStub(scope))  # type: ignore[arg-type]
    auth = plane.authorize_dispatch(run=run, runner="httpx", target="http://x")
    assert not auth.allow
    assert "roe_ref" in (auth.deny_reason or "")


def test_authorize_dispatch_denies_intrusive_when_flag_off() -> None:
    eng = _FakeEngagement()
    scope = _FakeScope(allowlist_json={"urls": ["http://x"]})
    profile = _FakeProfile(run_class="intrusive")
    run = _FakeRun(engagement=eng, profile=profile, autonomous_intrusive_allowed=False)
    plane = GovernanceControlPlane(session=_SessionStub(scope))  # type: ignore[arg-type]
    auth = plane.authorize_dispatch(run=run, runner="metasploit", target="http://x")
    assert not auth.allow
    assert "intrusive" in (auth.deny_reason or "").lower()


def test_authorize_dispatch_denies_when_no_scope() -> None:
    eng = _FakeEngagement()
    run = _FakeRun(engagement=eng, profile=_FakeProfile())
    plane = GovernanceControlPlane(session=_SessionStub(None))  # type: ignore[arg-type]
    auth = plane.authorize_dispatch(run=run, runner="httpx", target="http://x")
    assert not auth.allow
    assert "no Scope record" in (auth.deny_reason or "")


# --- authorize_credential_use --------------------------------------------


def test_authorize_credential_use_denies_empty_id(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    assert not plane.authorize_credential_use(run=run, cred_id="").allow
    assert not plane.authorize_credential_use(run=run, cred_id="   ").allow


def test_authorize_credential_use_denies_terminal_run(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    run.status = "completed"
    auth = plane.authorize_credential_use(run=run, cred_id="cred-123")
    assert not auth.allow
    assert "terminal" in (auth.deny_reason or "")


def test_authorize_credential_use_allows_live_run(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    auth = plane.authorize_credential_use(run=run, cred_id="cred-abc")
    assert auth.allow


# --- authorize_external_network ------------------------------------------


def test_authorize_external_network_default_deny_off_scope(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    auth = plane.authorize_external_network(run=run, target="http://attacker.com/exfil")
    assert not auth.allow
    assert "denied by default" in (auth.deny_reason or "")


def test_authorize_external_network_allows_in_scope(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    auth = plane.authorize_external_network(run=run, target="http://127.0.0.1:8080/api/x")
    assert auth.allow


# --- authorize_exec_plan_step --------------------------------------------


def test_exec_plan_step_denies_disallowed_method(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    step = {"method": "TRACE", "url": "http://127.0.0.1:8080/x"}
    assert not plane.authorize_exec_plan_step(run=run, step=step).allow


def test_exec_plan_step_denies_host_header_override(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    step = {
        "method": "POST",
        "url": "http://127.0.0.1:8080/login",
        "headers": {"Host": "attacker.com"},
    }
    auth = plane.authorize_exec_plan_step(run=run, step=step)
    assert not auth.allow
    assert "Host header" in (auth.deny_reason or "")


def test_exec_plan_step_allows_well_formed_step(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    step = {
        "method": "POST",
        "url": "http://127.0.0.1:8080/login",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "username=test&password=test",
    }
    auth = plane.authorize_exec_plan_step(run=run, step=step)
    assert auth.allow, auth.deny_reason


# --- check_budget --------------------------------------------------------


def test_check_budget_reads_profile_limits(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    state = plane.check_budget(run=run)
    assert isinstance(state, BudgetState)
    assert state.rps_cap == 5
    assert state.concurrency_cap == 3


def test_check_budget_falls_back_when_no_profile(plane, run_with_url_scope) -> None:
    run, _ = run_with_url_scope
    run.profile = None
    state = plane.check_budget(run=run)
    assert state.rps_cap > 0
    assert "no profile" in state.notes


# --- DispatchAuthorization factory helpers -------------------------------


def test_authorization_factories() -> None:
    assert DispatchAuthorization.allowed().allow is True
    assert DispatchAuthorization.denied("nope").deny_reason == "nope"
    a = DispatchAuthorization.needs_approval_for(3, "two operators required")
    assert a.needs_approval is True
    assert a.pending_count == 3
