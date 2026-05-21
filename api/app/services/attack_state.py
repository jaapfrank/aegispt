"""Layer 3 Attack State Machine — foothold model + TAP-style attack tree.

Per backlog-412 (sprint mythos-exploitation-foundation, task 6/15) and the
user's vision: *find 1 high, exploit to layer 3, back to layer 1 for next
exploit*. Currently AegisPT is stateless per advance — there is no concept
of "have we landed a foothold yet?" or "is this hypothesis exhausted?". This
module owns that state.

Foothold semantics (`FootholdState` enum, ordered low → high):
- ``anonymous``         — no credentials, no session, baseline web access only.
- ``authenticated_user``— a user-level credential confirmed against the app.
- ``admin``             — admin/operator-level credential confirmed.
- ``file_read``         — arbitrary-file-read primitive proven (LFI, path
                          traversal, exposed mount). Includes admin-level.
- ``code_execution``    — server-side code or command execution proven.
- ``shell_like``        — interactive shell access proven (SSH, reverse,
                          interactive RCE).

Transitions are ONE-WAY (foothold only goes up). Downgrades on lost session
are not tracked here — the higher state remains a fact about what the
attacker has *demonstrated*, not what they currently hold in memory.

TAP-style attack tree (TAP = Tree-of-Attacks with Pruning, Mehrotra et al.):
- The root is the initial hypothesis at run-start. Children are derived
  attack angles; each is one node.
- ``next_hypothesis_breadth_first`` and ``next_hypothesis_depth_first``
  return the next *pending* node by walk order; ``back_off`` returns the
  parent when the current branch is exhausted; ``exhausted`` is the whole-
  tree terminal state.
- ``prune(node_id)`` marks the node + descendants as ``pruned`` so they
  don't appear in future walks.

Replay-first integration: at run-start, the wiring layer (assessment_loop)
consults ``api.app.services.episodic_memory.skeptical_recall_with_verify_hint``
for similar prior episodes and seeds the tree with their suggested actions
as the first batch of children. Per the skeptical-memory rule, every replay
hint is just that — a HINT, not proof; the picker still validates before
trusting.

State transitions are gated: per the backlog-412 constraint
``no_unverified_transitions`` the foothold ONLY advances when a
validator-verified exploit (finding.severity ∈ {critical, high}) lands.
The validator-verifier layer is backlog-413 territory; this module accepts
a verification predicate as input so it can be swapped without touching the
state machine.
"""
from __future__ import annotations

import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class FootholdState(str, Enum):
    """Ordered ladder of demonstrated attacker capabilities."""

    ANONYMOUS = "anonymous"
    AUTHENTICATED_USER = "authenticated_user"
    ADMIN = "admin"
    FILE_READ = "file_read"
    CODE_EXECUTION = "code_execution"
    SHELL_LIKE = "shell_like"


_FOOTHOLD_RANK: dict[FootholdState, int] = {
    FootholdState.ANONYMOUS: 0,
    FootholdState.AUTHENTICATED_USER: 1,
    FootholdState.ADMIN: 2,
    FootholdState.FILE_READ: 3,
    FootholdState.CODE_EXECUTION: 4,
    FootholdState.SHELL_LIKE: 5,
}


def is_higher_foothold(candidate: FootholdState, current: FootholdState) -> bool:
    """Return True iff `candidate` represents strictly more capability."""
    return _FOOTHOLD_RANK[candidate] > _FOOTHOLD_RANK[current]


class NodeStatus(str, Enum):
    PENDING = "pending"
    ATTEMPTED = "attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PRUNED = "pruned"
    EXHAUSTED = "exhausted"


@dataclass
class AttackNode:
    """One vertex of the attack tree.

    A node represents a *hypothesis* the agent might try (e.g. "exploit SQLi
    on the login form to escalate to authenticated_user"). The node's
    ``tool_chain`` is an ordered list of (tool, params) tuples the agent
    plans to invoke; ``parent_id`` links it to its causal parent so we can
    walk back when the branch exhausts.
    """

    id: str
    hypothesis: str
    tool_chain: list[dict[str, Any]] = field(default_factory=list)
    parent_id: str | None = None
    status: NodeStatus = NodeStatus.PENDING
    target_foothold: FootholdState | None = None
    notes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def is_terminal(self) -> bool:
        return self.status in {NodeStatus.SUCCEEDED, NodeStatus.FAILED, NodeStatus.PRUNED, NodeStatus.EXHAUSTED}


@dataclass
class TreeStepResult:
    """Verdict of :meth:`AttackTree.step` per advance."""

    next_node: AttackNode | None
    action: str  # one of "next", "back_off", "exhausted"
    foothold: FootholdState
    tree_depth: int = 0
    notes: list[str] = field(default_factory=list)


class AttackTree:
    """In-memory TAP-style attack tree per run.

    Not persisted by default — caller can serialize to ``run.configuration_json``
    if they need it across advances. The picker hooks call ``step()`` once
    per advance to get the next hypothesis to try.
    """

    def __init__(self, *, root_hypothesis: str, foothold: FootholdState = FootholdState.ANONYMOUS) -> None:
        self._nodes: dict[str, AttackNode] = {}
        self._children: dict[str, list[str]] = {}
        self.foothold: FootholdState = foothold
        root = self._make_node(root_hypothesis, parent_id=None)
        self.root_id: str = root.id

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------

    def _make_node(
        self,
        hypothesis: str,
        *,
        parent_id: str | None,
        tool_chain: list[dict[str, Any]] | None = None,
        target_foothold: FootholdState | None = None,
        notes: list[str] | None = None,
    ) -> AttackNode:
        node = AttackNode(
            id=uuid.uuid4().hex[:12],
            hypothesis=hypothesis,
            tool_chain=list(tool_chain or []),
            parent_id=parent_id,
            target_foothold=target_foothold,
            notes=list(notes or []),
        )
        self._nodes[node.id] = node
        self._children.setdefault(node.id, [])
        if parent_id is not None:
            self._children.setdefault(parent_id, []).append(node.id)
        return node

    def add_child(
        self,
        parent_id: str,
        hypothesis: str,
        *,
        tool_chain: list[dict[str, Any]] | None = None,
        target_foothold: FootholdState | None = None,
        notes: list[str] | None = None,
    ) -> AttackNode:
        """Append a child hypothesis to ``parent_id``."""
        if parent_id not in self._nodes:
            raise KeyError(f"unknown parent node {parent_id!r}")
        return self._make_node(
            hypothesis,
            parent_id=parent_id,
            tool_chain=tool_chain,
            target_foothold=target_foothold,
            notes=notes,
        )

    def mark(self, node_id: str, status: NodeStatus, *, note: str | None = None) -> AttackNode:
        node = self._nodes[node_id]
        node.status = status
        if note:
            node.notes.append(note)
        return node

    def prune(self, node_id: str, *, note: str | None = None) -> int:
        """Mark ``node_id`` and all descendants as PRUNED. Returns count pruned."""
        if node_id not in self._nodes:
            return 0
        pruned = 0
        queue: deque[str] = deque([node_id])
        while queue:
            current_id = queue.popleft()
            current = self._nodes[current_id]
            if current.status != NodeStatus.PRUNED:
                current.status = NodeStatus.PRUNED
                if note:
                    current.notes.append(note)
                pruned += 1
            queue.extend(self._children.get(current_id, []))
        return pruned

    def maybe_advance_foothold(
        self,
        candidate: FootholdState,
        *,
        verified: bool,
    ) -> bool:
        """Advance the foothold IFF ``verified`` is True and ``candidate``
        is strictly higher than the current state. Returns True when the
        state moved. Per `no_unverified_transitions`: the caller is
        responsible for providing the verification signal — the state
        machine itself never decides verification."""
        if not verified:
            return False
        if not is_higher_foothold(candidate, self.foothold):
            return False
        logger.info(
            "attack_state: foothold %s -> %s (verified)",
            self.foothold.value, candidate.value,
        )
        self.foothold = candidate
        return True

    # ------------------------------------------------------------------
    # Walks
    # ------------------------------------------------------------------

    def next_hypothesis_breadth_first(self) -> AttackNode | None:
        queue: deque[str] = deque([self.root_id])
        while queue:
            node_id = queue.popleft()
            node = self._nodes[node_id]
            if node.status == NodeStatus.PENDING:
                return node
            queue.extend(self._children.get(node_id, []))
        return None

    def next_hypothesis_depth_first(self) -> AttackNode | None:
        stack: list[str] = [self.root_id]
        while stack:
            node_id = stack.pop()
            node = self._nodes[node_id]
            if node.status == NodeStatus.PENDING:
                return node
            stack.extend(reversed(self._children.get(node_id, [])))
        return None

    def back_off(self, exhausted_node_id: str) -> AttackNode | None:
        """When the current branch is exhausted, return the nearest
        ancestor that still has PENDING siblings, else None.
        """
        if exhausted_node_id not in self._nodes:
            return None
        # Mark the exhausted node + walk up.
        self.mark(exhausted_node_id, NodeStatus.EXHAUSTED, note="branch exhausted")
        current = self._nodes[exhausted_node_id]
        while current.parent_id is not None:
            parent = self._nodes[current.parent_id]
            for sibling_id in self._children.get(parent.id, []):
                sibling = self._nodes[sibling_id]
                if sibling.status == NodeStatus.PENDING:
                    return sibling
            # No pending siblings; the parent itself becomes exhausted.
            self.mark(parent.id, NodeStatus.EXHAUSTED, note="all children exhausted")
            current = parent
        return None

    def depth(self) -> int:
        """Return the depth of the deepest node (root = 0)."""
        depth_by_node: dict[str, int] = {self.root_id: 0}
        max_depth = 0
        queue: deque[str] = deque([self.root_id])
        while queue:
            node_id = queue.popleft()
            d = depth_by_node[node_id]
            for child_id in self._children.get(node_id, []):
                depth_by_node[child_id] = d + 1
                max_depth = max(max_depth, d + 1)
                queue.append(child_id)
        return max_depth

    # ------------------------------------------------------------------
    # The hook called from advance_assessment_loop.
    # ------------------------------------------------------------------

    def step(self, *, prefer: str = "breadth") -> TreeStepResult:
        """Return the next attack node to try.

        ``prefer="breadth"`` does BFS (explores adjacent hypotheses before
        going deeper). ``prefer="depth"`` does DFS (pursues a single chain).
        """
        if prefer == "depth":
            candidate = self.next_hypothesis_depth_first()
        else:
            candidate = self.next_hypothesis_breadth_first()
        if candidate is not None:
            return TreeStepResult(
                next_node=candidate,
                action="next",
                foothold=self.foothold,
                tree_depth=self.depth(),
            )
        # Nothing pending — exhausted.
        return TreeStepResult(
            next_node=None,
            action="exhausted",
            foothold=self.foothold,
            tree_depth=self.depth(),
            notes=["all nodes terminal"],
        )

    # ------------------------------------------------------------------
    # Picker prompt envelope
    # ------------------------------------------------------------------

    def to_picker_envelope(self) -> dict[str, Any]:
        """Return the dict the picker prompt section consumes."""
        available: list[dict[str, Any]] = []
        # Top 3 pending nodes by BFS order.
        queue: deque[str] = deque([self.root_id])
        while queue and len(available) < 3:
            node_id = queue.popleft()
            node = self._nodes[node_id]
            if node.status == NodeStatus.PENDING and node.id != self.root_id:
                available.append({
                    "id": node.id,
                    "hypothesis": node.hypothesis,
                    "target_foothold": node.target_foothold.value if node.target_foothold else None,
                })
            queue.extend(self._children.get(node_id, []))
        return {
            "current_foothold": self.foothold.value,
            "tree_depth": self.depth(),
            "available_hypotheses": available,
            "exhausted": len(available) == 0,
        }


# --------------------------------------------------------------------------
# Replay-first integration (uses backlog-410 episodic memory).
# --------------------------------------------------------------------------


def seed_tree_with_replay_hints(
    tree: AttackTree,
    *,
    session,
    query: str,
    max_hints: int = 3,
) -> int:
    """Pull top hint episodes from backlog-410 and append them as children
    of the tree root. Returns the count added. Per `feedback_anti_drift_contract`
    Rule 1 — memory-driven seeding never breaks the tree if the recall layer
    is unavailable.
    """
    try:
        from api.app.services.episodic_memory import (  # noqa: E402
            skeptical_recall_with_verify_hint,
        )
    except Exception:  # noqa: BLE001
        return 0
    try:
        hints = skeptical_recall_with_verify_hint(session, query=query, k=max_hints)
    except Exception as exc:  # noqa: BLE001
        logger.debug("attack_state: replay hint recall skipped (%s)", exc)
        return 0
    count = 0
    for hint in hints[:max_hints]:
        action = str(hint.get("action_type") or "")
        if not action.startswith("pick:"):
            continue  # skip non-actionable episodes
        tool = action.split(":", 1)[1]
        tree.add_child(
            tree.root_id,
            hypothesis=f"replay {tool} (similar past episode)",
            tool_chain=[{"tool": tool, "params": {}}],
            notes=[
                f"replay-source episode_id={hint.get('episode_id')} similarity={hint.get('similarity')}",
                hint.get("marker", "[HINT, VERIFY BEFORE USE]"),
            ],
        )
        count += 1
    return count


__all__ = [
    "AttackNode",
    "AttackTree",
    "FootholdState",
    "NodeStatus",
    "TreeStepResult",
    "is_higher_foothold",
    "seed_tree_with_replay_hints",
]
