"""Layer 4 agents package — multi-agent coordinator + specialists.

Per backlog-415 (sprint mythos-exploitation-foundation, task 9/15):
the picker becomes a meta-coordinator that delegates to specialists
(Recon/Hypothesis/ExploitDev/Validator/Memorist/Reporter/Reflector)
under per-agent tool ACLs. Prompt changes go through versioned
proposals (``prompts/proposals/``) gated by an explicit
``approve_prompt_change()`` API — no agent overwrites its own prompt
at runtime.
"""
from api.app.agents.coordinator import (
    DelegationDecision,
    MetaCoordinator,
    SpecialistACL,
    SpecialistRole,
    approve_prompt_change,
    load_active_specialist_prompt,
)

__all__ = [
    "DelegationDecision",
    "MetaCoordinator",
    "SpecialistACL",
    "SpecialistRole",
    "approve_prompt_change",
    "load_active_specialist_prompt",
]
