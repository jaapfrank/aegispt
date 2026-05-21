"""Score-climb iteration step 1 — cluster XBOW failure modes.

Per backlog-423 (sprint mythos-exploitation-foundation, task 15/15): the
motor that drives AegisPT from 0% → 80% XBOW score works by iteration:

    benchmark run → cluster failures → propose change → operator approves
    → re-run → measure delta.

This module owns the *failure clustering* step. Given a baseline JSON
emitted by ``scripts/xbow_benchmark.py``, it bucketizes per-challenge
outcomes into structured ``FailurePattern`` records and (optionally)
asks Claude to label each cluster's *root-cause hypothesis* + propose a
*change-kind* (prompt / state_machine / tool / infrastructure).

Determinism + skepticism per Codex evidence-first:

- The clustering itself is **deterministic** — string-matching against
  a fixed taxonomy of crash reasons (API timeout, Docker build failure,
  out-of-scope rejection, capability ceiling, etc.). No LLM needed.
- The hypothesis labelling step is OPTIONAL and DISABLED when no
  ``ANTHROPIC_API_KEY`` (or the configured provider key) is set —
  empty-hypothesis clusters still drop into the proposal generator,
  letting an operator hand-author the change.
- Per ``no_runtime_self_modification`` (backlog-415): this module
  generates *suggestions*, not commits. Promotion still requires the
  ``approve_prompt_change`` gate.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Fixed taxonomy of failure modes. Strings deliberately overlap with the
# raw error fields produced by scripts/xbow_benchmark.py so the matcher
# stays simple.
FAILURE_TAXONOMY: dict[str, tuple[str, str]] = {
    "api_timeout": ("infra", "Anthropic API call timed out or connection dropped"),
    "api_disconnected": ("infra", "Anthropic API server disconnected without response"),
    "docker_build_failed": ("infra", "Upstream docker compose build failed"),
    "docker_up_failed": ("infra", "Upstream docker compose up failed (network conflict, etc.)"),
    "port_resolution_failed": ("infra", "Could not resolve published host port after docker compose up"),
    "scope_collision_refused": ("infra", "Challenge port collides with AegisPT API; harness refused (backlog-409 safety)"),
    "agent_attempted_no_flag": ("capability", "Agent attempted the challenge but did not capture the flag"),
    "subprocess_timeout": ("infra", "Subprocess timeout (build / up / down hit the wall-time budget)"),
    "out_of_scope_rejection": ("scope", "Post-task scope guard rejected the target (rare after backlog-409 fix)"),
    "unknown": ("unknown", "Failure not matched by the taxonomy"),
}

# Per-mode mapping: which change-kind a proposal for this cluster should suggest.
SUGGESTED_CHANGE_KIND: dict[str, str] = {
    "api_timeout": "infra",            # picker retry/backoff
    "api_disconnected": "infra",
    "docker_build_failed": "infra",
    "docker_up_failed": "infra",
    "port_resolution_failed": "infra",
    "scope_collision_refused": "infra",
    "subprocess_timeout": "infra",
    "agent_attempted_no_flag": "prompt",   # capability ceiling: prompt or specialist
    "out_of_scope_rejection": "tool",
    "unknown": "prompt",
}


@dataclass
class FailurePattern:
    """One cluster of related failures with a proposed change shape."""

    cluster_name: str
    failure_mode: str
    change_kind: str                     # "prompt" | "state_machine" | "tool" | "infra"
    affected_challenges: list[str] = field(default_factory=list)
    representative_error: str = ""
    root_cause_hypothesis: str = ""
    proposed_change_summary: str = ""
    proposed_target_component: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_name": self.cluster_name,
            "failure_mode": self.failure_mode,
            "change_kind": self.change_kind,
            "affected_challenges": list(self.affected_challenges),
            "representative_error": self.representative_error,
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "proposed_change_summary": self.proposed_change_summary,
            "proposed_target_component": self.proposed_target_component,
        }


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


_TIMEOUT_RE = re.compile(r"timed out|timeout", re.IGNORECASE)
_DISCONNECT_RE = re.compile(r"server disconnected", re.IGNORECASE)
_DOCKER_BUILD_RE = re.compile(r"docker compose build failed", re.IGNORECASE)
_DOCKER_UP_RE = re.compile(r"docker compose up failed", re.IGNORECASE)
_PORT_RESOLVE_RE = re.compile(r"could not resolve published host port", re.IGNORECASE)
_PORT_COLLISION_RE = re.compile(r"collides with the AegisPT API|refusing to drive the agent against the harness", re.IGNORECASE)
_OOS_RE = re.compile(r"out_of_scope|outside the approved engagement scope", re.IGNORECASE)
_SUBPROCESS_RE = re.compile(r"subprocess timeout", re.IGNORECASE)


def classify_result(result: dict[str, Any]) -> str:
    """Return the taxonomy key (``api_timeout`` / ``docker_build_failed`` /
    etc.) for one challenge result. ``agent_attempted_no_flag`` is the
    capability bucket: the run reached the agent loop but didn't capture.
    """
    if result.get("solved"):
        return "solved"
    error = str(result.get("error") or "").strip()
    run_status = str(result.get("run_status") or "").strip().lower()
    tools = int(result.get("tool_chain_length") or 0)
    if not error and run_status in {"running", "completed"} and tools > 0:
        return "agent_attempted_no_flag"
    if not error:
        return "unknown"
    if _PORT_COLLISION_RE.search(error):
        return "scope_collision_refused"
    if _PORT_RESOLVE_RE.search(error):
        return "port_resolution_failed"
    if _DOCKER_BUILD_RE.search(error):
        return "docker_build_failed"
    if _DOCKER_UP_RE.search(error):
        return "docker_up_failed"
    if _SUBPROCESS_RE.search(error):
        return "subprocess_timeout"
    if _DISCONNECT_RE.search(error):
        return "api_disconnected"
    if _TIMEOUT_RE.search(error):
        return "api_timeout"
    if _OOS_RE.search(error):
        return "out_of_scope_rejection"
    return "unknown"


# --------------------------------------------------------------------------
# Clustering
# --------------------------------------------------------------------------


def _target_component_for_mode(mode: str) -> str:
    if mode == "agent_attempted_no_flag":
        return "_AI_PICKER_SYSTEM_PROMPT (or exploit-developer-agent prompt)"
    if mode in {"api_timeout", "api_disconnected"}:
        return "scripts/xbow_benchmark.py + api/app/services/assessment_loop._call_picker_with_retries"
    if mode in {"docker_build_failed", "docker_up_failed", "port_resolution_failed", "scope_collision_refused"}:
        return "scripts/xbow_benchmark.py (compose pre-flight / normalizer)"
    if mode == "out_of_scope_rejection":
        return "api/app/services/runs.target_value_is_allowed (or scope-validator extension)"
    if mode == "subprocess_timeout":
        return "scripts/xbow_benchmark.py --build-timeout / --up-timeout defaults"
    return "(operator decision)"


def cluster_failures(baseline_json_path: str | Path) -> list[FailurePattern]:
    """Read a baseline JSON and return one ``FailurePattern`` per
    detected failure mode (sorted by affected-challenge count, descending).
    """
    path = Path(baseline_json_path)
    if not path.is_file():
        raise FileNotFoundError(f"baseline JSON not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    results = data.get("results") or []

    bucket: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        mode = classify_result(result)
        if mode == "solved":
            continue
        bucket[mode].append(result)

    patterns: list[FailurePattern] = []
    for mode, entries in bucket.items():
        category, blurb = FAILURE_TAXONOMY.get(mode, FAILURE_TAXONOMY["unknown"])
        representative_error = str(entries[0].get("error") or "").strip()[:300]
        change_kind = SUGGESTED_CHANGE_KIND.get(mode, "prompt")
        pattern = FailurePattern(
            cluster_name=f"{category}:{mode}",
            failure_mode=mode,
            change_kind=change_kind,
            affected_challenges=[str(e.get("challenge_id")) for e in entries],
            representative_error=representative_error,
            root_cause_hypothesis=blurb,
            proposed_change_summary=_default_proposed_change(mode, len(entries)),
            proposed_target_component=_target_component_for_mode(mode),
        )
        patterns.append(pattern)

    patterns.sort(key=lambda p: len(p.affected_challenges), reverse=True)
    return patterns


def _default_proposed_change(mode: str, count: int) -> str:
    if mode == "api_timeout":
        return (
            f"Found {count} challenges where the picker's Anthropic call timed out. "
            "Raise PICKER_MAX_TIMEOUT_SECONDS and broaden `_call_picker_with_retries` "
            "window from 1+2 to 1+4, and add a per-run circuit breaker that switches to "
            "claude-sonnet-4-6 (cheaper, faster) after 2 consecutive timeouts."
        )
    if mode == "api_disconnected":
        return (
            f"Found {count} challenges with Anthropic server disconnects. "
            "Pair with the api_timeout proposal — same retry/backoff logic covers both."
        )
    if mode in {"docker_build_failed", "docker_up_failed"}:
        return (
            f"Found {count} upstream Docker errors. Extend the compose normalizer "
            "(scripts/xbow_benchmark._normalize_compose) to dedupe duplicate keys at "
            "ANY nesting level and to `docker compose down -v` the challenge directory tree "
            "before `up` so leftover networks/state from prior aborts don't leak in."
        )
    if mode == "port_resolution_failed":
        return (
            f"{count} challenges had short-form `ports: - <container>` but the runtime "
            "port query returned no published mapping. Add a fallback that calls "
            "`docker compose port <service> <container>` directly when "
            "`docker compose ps --format json` returns no Publishers."
        )
    if mode == "scope_collision_refused":
        return (
            f"{count} challenges hardcoded a host port that collides with the AegisPT API. "
            "Harness already refuses safely; either remap the challenge port via a "
            "`docker-compose.override.yml` (auto-generated) or document the collision in "
            "the per-challenge skip list."
        )
    if mode == "agent_attempted_no_flag":
        return (
            f"{count} challenges ran the agent loop but produced no verified-exploited "
            "finding. Capability ceiling — most likely root cause is empty specialist "
            "prompts (backlog-415 slice 2) + picker not dispatching exploit-developer-agent "
            "for multi-step chains (backlog-414 wire-in)."
        )
    if mode == "subprocess_timeout":
        return (
            f"{count} challenges hit the harness subprocess timeout. Bump "
            "--build-timeout / --up-timeout for the affected challenges' image sizes."
        )
    return (
        f"{count} challenges failed with mode `{mode}`. No automated suggestion — "
        "operator review required."
    )


# --------------------------------------------------------------------------
# Summary helpers
# --------------------------------------------------------------------------


def summarize_patterns(patterns: list[FailurePattern]) -> dict[str, Any]:
    """Return a compact JSON-shaped summary used by the orchestrator report."""
    total_failed = sum(len(p.affected_challenges) for p in patterns)
    by_kind: dict[str, int] = defaultdict(int)
    for p in patterns:
        by_kind[p.change_kind] += len(p.affected_challenges)
    return {
        "total_failed": total_failed,
        "cluster_count": len(patterns),
        "by_change_kind": dict(by_kind),
        "patterns": [p.to_dict() for p in patterns],
    }


__all__ = [
    "FAILURE_TAXONOMY",
    "FailurePattern",
    "SUGGESTED_CHANGE_KIND",
    "classify_result",
    "cluster_failures",
    "summarize_patterns",
]
