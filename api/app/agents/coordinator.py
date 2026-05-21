"""Multi-Agent Coordinator + per-specialist ACL + versioned prompt proposals.

Per backlog-415 (sprint mythos-exploitation-foundation, task 9/15) and the
Codex 6-layer architectuur Layer 4: ONE meta-coordinator owns the picker's
KNOW→THINK→TEST→VALIDATE loop and delegates to specialists when its own
confidence drops under a threshold. Specialists are narrow, single-purpose
agents with their own tool ACLs (OpenClaw pattern) so a Recon specialist
can't, e.g., dispatch metasploit.

The coordinator is intentionally **structural** in this slice:

- It exposes the delegation API (``MetaCoordinator.delegate``) + ACL
  enforcement (``SpecialistACL.allows`` / ``deny_reason``) + confidence-
  gated routing (``decide(...)``) + the versioned-prompt-proposal flow
  (``approve_prompt_change``).
- It does NOT yet replace the picker — the picker stays in place and
  consumes the coordinator's delegation hints. Later slices wire the
  coordinator inline; this commit gives the coordinator real state +
  tests so the wiring slice can stay focused on the routing logic.

Per ``no_runtime_self_modification`` constraint: agents NEVER rewrite
their own prompts. ``approve_prompt_change(proposal_file, approver)`` is
the only path that promotes a ``prompts/proposals/{date}-{specialist}-revN.md``
file into ``prompts/active/{specialist}.md`` for live use. The proposal
file format intentionally requires an explicit ``approve:`` field set by
the operator — copying a proposal in by hand without that field is a
no-op.
"""
from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


PROMPTS_ROOT_ENV = "AEGISPT_PROMPTS_ROOT"


def _prompts_root() -> Path:
    """Where ``prompts/proposals/`` and ``prompts/active/`` live."""
    env = os.environ.get(PROMPTS_ROOT_ENV, "").strip()
    if env:
        return Path(env).expanduser().resolve()
    here = Path(__file__).resolve()
    # api/app/agents/coordinator.py → up 3 → repo root → prompts/
    return (here.parents[3] / "prompts").resolve()


class SpecialistRole(str, Enum):
    """The six specialists the meta-coordinator can delegate to."""

    RECON = "recon"
    HYPOTHESIS = "hypothesis"
    EXPLOIT_DEV = "exploit_dev"
    VALIDATOR = "validator"
    MEMORIST = "memorist"
    REPORTER = "reporter"
    REFLECTOR = "reflector"


# Default tool ACLs per specialist (OpenClaw allow/deny pattern). Operators
# can override by writing a versioned ACL proposal (out of scope for slice 1;
# the override hook lives in `SpecialistACL.from_override`).
DEFAULT_ACL: dict[SpecialistRole, dict[str, list[str]]] = {
    SpecialistRole.RECON: {
        "allow": ["target-intel", "httpx", "content-discovery", "headers-security", "smart-web-probe"],
        "deny": ["metasploit", "exec-plan", "exploit-developer-agent"],
    },
    SpecialistRole.HYPOTHESIS: {
        "allow": ["nuclei", "xss-extended", "session-security", "sqlmap", "ssti-probe", "ssrf-probe", "graphql-probe", "jwt-probe", "idor-bac"],
        "deny": ["metasploit"],
    },
    SpecialistRole.EXPLOIT_DEV: {
        "allow": ["exploit-developer-agent", "exec-plan"],
        "deny": [],
    },
    SpecialistRole.VALIDATOR: {
        # The validator re-executes captured chains via exec_plan and never
        # generates new ones.
        "allow": ["exec-plan"],
        "deny": ["exploit-developer-agent", "metasploit"],
    },
    SpecialistRole.MEMORIST: {
        # The memorist queries episodic memory; it does not dispatch runners.
        "allow": [],
        "deny": [],
    },
    SpecialistRole.REPORTER: {
        "allow": [],
        "deny": [],
    },
    SpecialistRole.REFLECTOR: {
        "allow": [],
        "deny": [],
    },
}


@dataclass
class SpecialistACL:
    """Per-specialist tool allow/deny list. Stateless lookup wrapper."""

    role: SpecialistRole
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    @classmethod
    def for_role(cls, role: SpecialistRole) -> "SpecialistACL":
        entry = DEFAULT_ACL.get(role, {"allow": [], "deny": []})
        return cls(role=role, allow=list(entry.get("allow", [])), deny=list(entry.get("deny", [])))

    def allows(self, tool: str) -> bool:
        tool_name = (tool or "").strip()
        if not tool_name:
            return False
        if tool_name in self.deny:
            return False
        # Empty allow list = the specialist doesn't dispatch runners (Memorist /
        # Reporter / Reflector).
        if not self.allow:
            return False
        return tool_name in self.allow

    def deny_reason(self, tool: str) -> str:
        tool_name = (tool or "").strip()
        if not tool_name:
            return "empty tool name"
        if tool_name in self.deny:
            return f"tool {tool_name!r} is on the deny list for specialist {self.role.value}"
        if not self.allow:
            return f"specialist {self.role.value} does not dispatch runners"
        return f"tool {tool_name!r} is not on the allow list for specialist {self.role.value}"


@dataclass
class DelegationDecision:
    """Verdict of :meth:`MetaCoordinator.decide`."""

    delegate_to: SpecialistRole | None
    confidence: float
    reasoning: str = ""
    notes: list[str] = field(default_factory=list)


# Confidence routing table — picks the specialist by intent signal in the
# coordinator's current "situation" snapshot. Keys are intent labels the
# coordinator emits; values are the role to delegate to. Routing logic is
# narrow + deterministic in this slice; later slices can layer Claude
# reasoning on top once the routing tests pin the contract.
INTENT_ROUTING: dict[str, SpecialistRole] = {
    "need_recon": SpecialistRole.RECON,
    "need_hypothesis_test": SpecialistRole.HYPOTHESIS,
    "need_multi_step_exploit": SpecialistRole.EXPLOIT_DEV,
    "need_validation": SpecialistRole.VALIDATOR,
    "need_memory_lookup": SpecialistRole.MEMORIST,
    "need_report": SpecialistRole.REPORTER,
    "need_reflection": SpecialistRole.REFLECTOR,
}

CONFIDENCE_DELEGATION_THRESHOLD = 0.70


class MetaCoordinator:
    """The meta-agent. Owns the per-run delegation + ACL enforcement.

    Stateless except for the optional ``run_id`` it carries for OTEL
    traceability. Construct one per advance.
    """

    def __init__(self, *, run_id: str | None = None) -> None:
        self.run_id = run_id

    # ------------------------------------------------------------------
    # Delegation routing
    # ------------------------------------------------------------------

    def decide(
        self,
        *,
        intent: str,
        coordinator_confidence: float,
    ) -> DelegationDecision:
        """Return the specialist (if any) the coordinator wants to delegate to.

        Coordinator delegates when its own confidence drops below
        ``CONFIDENCE_DELEGATION_THRESHOLD`` AND the intent maps to a known
        specialist. Above the threshold the coordinator handles the step
        directly (returns ``delegate_to=None``).
        """
        intent_key = (intent or "").strip().lower()
        role = INTENT_ROUTING.get(intent_key)
        if coordinator_confidence >= CONFIDENCE_DELEGATION_THRESHOLD:
            return DelegationDecision(
                delegate_to=None,
                confidence=coordinator_confidence,
                reasoning=f"confidence {coordinator_confidence:.2f} >= threshold; coordinator handles directly",
            )
        if role is None:
            return DelegationDecision(
                delegate_to=None,
                confidence=coordinator_confidence,
                reasoning=f"intent {intent_key!r} not in routing table; coordinator handles directly",
                notes=[f"known intents: {sorted(INTENT_ROUTING)}"],
            )
        return DelegationDecision(
            delegate_to=role,
            confidence=coordinator_confidence,
            reasoning=(
                f"confidence {coordinator_confidence:.2f} < {CONFIDENCE_DELEGATION_THRESHOLD}; "
                f"delegating intent {intent_key!r} to specialist {role.value}"
            ),
        )

    # ------------------------------------------------------------------
    # ACL enforcement
    # ------------------------------------------------------------------

    @staticmethod
    def specialist_can_dispatch(role: SpecialistRole, tool: str) -> bool:
        return SpecialistACL.for_role(role).allows(tool)

    @staticmethod
    def specialist_deny_reason(role: SpecialistRole, tool: str) -> str:
        return SpecialistACL.for_role(role).deny_reason(tool)


# --------------------------------------------------------------------------
# Versioned prompt proposals — the only path that updates a specialist's prompt.
# --------------------------------------------------------------------------


def load_active_specialist_prompt(role: SpecialistRole) -> str:
    """Return the currently-active prompt body for ``role``. Empty string
    when no active prompt is published yet (specialist falls back to a
    coordinator-supplied default).
    """
    active = _prompts_root() / "active" / f"{role.value}.md"
    if not active.is_file():
        return ""
    try:
        return active.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("active prompt for %s unreadable (%s)", role.value, exc)
        return ""


def _parse_proposal_header(body: str) -> dict[str, str]:
    """Parse the minimal proposal header — ``key: value`` lines until the
    first blank line. The required field is ``approve:`` which MUST equal
    ``true`` (case-insensitive) for the promotion to succeed.
    """
    header: dict[str, str] = {}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            break
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        header[key.strip().lower()] = value.strip()
    return header


def approve_prompt_change(
    proposal_file: Path | str,
    *,
    approver: str,
    role: SpecialistRole | None = None,
) -> Path:
    """Promote a proposal file into the live ``prompts/active/<role>.md``.

    The proposal MUST contain an ``approve: true`` header line — copying
    a file into ``prompts/active/`` outside this function is a violation
    of the ``no_runtime_self_modification`` constraint.

    Returns the path of the activated prompt file.
    """
    src = Path(proposal_file).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f"proposal not found: {src}")
    body = src.read_text(encoding="utf-8")
    header = _parse_proposal_header(body)
    if header.get("approve", "").lower() != "true":
        raise ValueError(
            "proposal lacks 'approve: true' header — runtime self-modification by "
            "agents is forbidden; operator approval required"
        )
    if not (approver or "").strip():
        raise ValueError("approver must be a non-empty operator identity")
    # Infer the role from filename when not explicitly passed:
    # ``YYYY-MM-DD-<role>-revN.md`` — middle stem is the role.
    resolved_role = role
    if resolved_role is None:
        for candidate in SpecialistRole:
            if f"-{candidate.value}-" in src.name:
                resolved_role = candidate
                break
    if resolved_role is None:
        raise ValueError(
            f"could not infer specialist role from filename {src.name!r}; "
            "pass role= explicitly"
        )
    active_dir = _prompts_root() / "active"
    active_dir.mkdir(parents=True, exist_ok=True)
    dest = active_dir / f"{resolved_role.value}.md"
    shutil.copy2(src, dest)
    audit_path = _prompts_root() / "active" / f"{resolved_role.value}.audit.log"
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(
            f"{datetime.now(UTC).isoformat()} approver={approver} from={src.name}\n"
        )
    logger.info("approved prompt change: %s -> %s (approver=%s)", src.name, dest.name, approver)
    return dest


__all__ = [
    "CONFIDENCE_DELEGATION_THRESHOLD",
    "DEFAULT_ACL",
    "DelegationDecision",
    "INTENT_ROUTING",
    "MetaCoordinator",
    "PROMPTS_ROOT_ENV",
    "SpecialistACL",
    "SpecialistRole",
    "approve_prompt_change",
    "load_active_specialist_prompt",
]


# Silence the "unused" import lint when callers only need re-exports.
_ = Any
