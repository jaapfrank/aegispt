"""Unit tests for backlog-415 multi-agent coordinator."""
from __future__ import annotations

from pathlib import Path

import pytest

from api.app.agents.coordinator import (
    CONFIDENCE_DELEGATION_THRESHOLD,
    DEFAULT_ACL,
    INTENT_ROUTING,
    DelegationDecision,
    MetaCoordinator,
    SpecialistACL,
    SpecialistRole,
    approve_prompt_change,
    load_active_specialist_prompt,
)

# --- Role enum + ACL defaults ----------------------------------------


def test_six_specialist_roles_exist() -> None:
    expected = {"recon", "hypothesis", "exploit_dev", "validator", "memorist", "reporter", "reflector"}
    assert {r.value for r in SpecialistRole} == expected


def test_default_acl_has_one_entry_per_role() -> None:
    assert set(DEFAULT_ACL) == set(SpecialistRole)
    for role, entry in DEFAULT_ACL.items():
        assert "allow" in entry
        assert "deny" in entry


def test_recon_acl_allows_target_intel_and_denies_metasploit() -> None:
    acl = SpecialistACL.for_role(SpecialistRole.RECON)
    assert acl.allows("target-intel")
    assert not acl.allows("metasploit")
    assert "deny list" in acl.deny_reason("metasploit")


def test_exploit_dev_acl_allows_composer_and_exec_plan() -> None:
    acl = SpecialistACL.for_role(SpecialistRole.EXPLOIT_DEV)
    assert acl.allows("exploit-developer-agent")
    assert acl.allows("exec-plan")
    assert not acl.allows("target-intel")  # specialist boundary


def test_memorist_acl_is_dispatch_free() -> None:
    acl = SpecialistACL.for_role(SpecialistRole.MEMORIST)
    assert not acl.allows("target-intel")
    assert "does not dispatch runners" in acl.deny_reason("target-intel")


def test_validator_can_only_replay_via_exec_plan() -> None:
    acl = SpecialistACL.for_role(SpecialistRole.VALIDATOR)
    assert acl.allows("exec-plan")
    assert not acl.allows("exploit-developer-agent")  # validator never generates new chains


# --- Delegation routing ----------------------------------------------


def test_delegate_to_recon_when_confidence_low_and_intent_recon() -> None:
    coord = MetaCoordinator(run_id="r1")
    decision = coord.decide(intent="need_recon", coordinator_confidence=0.3)
    assert isinstance(decision, DelegationDecision)
    assert decision.delegate_to == SpecialistRole.RECON
    assert decision.confidence == 0.3
    assert "delegating" in decision.reasoning


def test_coordinator_handles_directly_above_threshold() -> None:
    coord = MetaCoordinator()
    decision = coord.decide(intent="need_recon", coordinator_confidence=0.9)
    assert decision.delegate_to is None
    assert "handles directly" in decision.reasoning


def test_unknown_intent_falls_back_to_coordinator() -> None:
    coord = MetaCoordinator()
    decision = coord.decide(intent="hallucinated_intent", coordinator_confidence=0.4)
    assert decision.delegate_to is None
    assert "not in routing table" in decision.reasoning


def test_intent_routing_covers_every_role() -> None:
    routed = set(INTENT_ROUTING.values())
    assert routed == set(SpecialistRole)


def test_specialist_can_dispatch_helper() -> None:
    assert MetaCoordinator.specialist_can_dispatch(SpecialistRole.HYPOTHESIS, "nuclei")
    assert not MetaCoordinator.specialist_can_dispatch(SpecialistRole.HYPOTHESIS, "metasploit")
    reason = MetaCoordinator.specialist_deny_reason(SpecialistRole.HYPOTHESIS, "metasploit")
    assert "deny list" in reason


def test_confidence_threshold_is_exposed() -> None:
    assert 0 < CONFIDENCE_DELEGATION_THRESHOLD < 1


# --- Versioned prompt proposals --------------------------------------


def test_proposal_without_approve_header_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    proposal = tmp_path / "proposals" / "2026-05-21-recon-rev1.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    proposal.write_text("title: recon prompt revision\n\nBody without approve flag.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="approve: true"):
        approve_prompt_change(proposal, approver="alice")


def test_proposal_with_approve_header_promotes_to_active(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    proposal = tmp_path / "proposals" / "2026-05-21-recon-rev1.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    proposal.write_text(
        "approve: true\ntitle: recon prompt revision\n\nNew recon prompt body.\n",
        encoding="utf-8",
    )
    dest = approve_prompt_change(proposal, approver="alice")
    assert dest.exists()
    assert dest.name == "recon.md"
    assert load_active_specialist_prompt(SpecialistRole.RECON).startswith("approve: true")


def test_promotion_writes_audit_log(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    proposal = tmp_path / "proposals" / "2026-05-21-exploit_dev-rev1.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    proposal.write_text("approve: true\n\nbody\n", encoding="utf-8")
    approve_prompt_change(proposal, approver="bob")
    audit = tmp_path / "active" / "exploit_dev.audit.log"
    assert audit.exists()
    assert "approver=bob" in audit.read_text(encoding="utf-8")


def test_promotion_requires_non_empty_approver(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    proposal = tmp_path / "proposals" / "2026-05-21-recon-rev1.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    proposal.write_text("approve: true\n\nbody\n", encoding="utf-8")
    with pytest.raises(ValueError, match="approver"):
        approve_prompt_change(proposal, approver="   ")


def test_promotion_role_inferred_from_filename(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    proposal = tmp_path / "proposals" / "2026-05-21-validator-rev2.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    proposal.write_text("approve: true\n\nbody\n", encoding="utf-8")
    dest = approve_prompt_change(proposal, approver="ops")
    assert dest.name == "validator.md"


def test_promotion_role_required_when_not_in_filename(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    proposal = tmp_path / "proposals" / "ambiguous-rev1.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    proposal.write_text("approve: true\n\nbody\n", encoding="utf-8")
    with pytest.raises(ValueError, match="could not infer specialist role"):
        approve_prompt_change(proposal, approver="ops")


def test_load_active_returns_empty_when_no_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    assert load_active_specialist_prompt(SpecialistRole.REPORTER) == ""


# --- Defense-in-depth: agent self-write forbidden -------------------


def test_writing_active_prompt_directly_is_not_what_the_module_does(tmp_path: Path, monkeypatch) -> None:
    """Sentinel: the public API for promoting a prompt change is
    ``approve_prompt_change`` and it requires an ``approve: true`` header.
    A test that asserts this contract is the discipline tripwire — if
    someone adds a back-door later, this test fails.
    """
    monkeypatch.setenv("AEGISPT_PROMPTS_ROOT", str(tmp_path))
    # Module's public surface lists approve_prompt_change but NOT a
    # write-active helper. Sentinel against future drift.
    from api.app.agents import coordinator as mod
    assert "approve_prompt_change" in mod.__all__
    assert not hasattr(mod, "write_active_prompt")
