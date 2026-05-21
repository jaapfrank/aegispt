"""Unit tests for backlog-412 attack state machine."""
from __future__ import annotations

from api.app.services.attack_state import (
    AttackTree,
    FootholdState,
    NodeStatus,
    is_higher_foothold,
)

# --- FootholdState ordering ----------------------------------------------


def test_foothold_ordering_is_one_way() -> None:
    assert is_higher_foothold(FootholdState.AUTHENTICATED_USER, FootholdState.ANONYMOUS)
    assert is_higher_foothold(FootholdState.ADMIN, FootholdState.AUTHENTICATED_USER)
    assert is_higher_foothold(FootholdState.SHELL_LIKE, FootholdState.CODE_EXECUTION)
    assert not is_higher_foothold(FootholdState.ANONYMOUS, FootholdState.ADMIN)
    assert not is_higher_foothold(FootholdState.ANONYMOUS, FootholdState.ANONYMOUS)


# --- Tree construction + walks -------------------------------------------


def test_tree_root_created_and_initial_foothold_anonymous() -> None:
    tree = AttackTree(root_hypothesis="probe surface")
    assert tree.foothold is FootholdState.ANONYMOUS
    assert tree.depth() == 0
    env = tree.to_picker_envelope()
    assert env["current_foothold"] == "anonymous"
    assert env["tree_depth"] == 0


def test_add_child_increases_depth() -> None:
    tree = AttackTree(root_hypothesis="probe")
    a = tree.add_child(tree.root_id, "try sqli on login")
    tree.add_child(tree.root_id, "try idor on user list")
    grandchild = tree.add_child(a.id, "escalate via union select")
    assert tree.depth() == 2
    assert grandchild.parent_id == a.id


def test_bfs_returns_root_first_then_children_left_to_right() -> None:
    tree = AttackTree(root_hypothesis="probe")
    c1 = tree.add_child(tree.root_id, "child A")
    c2 = tree.add_child(tree.root_id, "child B")
    # Mark root attempted so BFS walks to children.
    tree.mark(tree.root_id, NodeStatus.ATTEMPTED)
    bfs_first = tree.next_hypothesis_breadth_first()
    assert bfs_first.id == c1.id
    tree.mark(c1.id, NodeStatus.ATTEMPTED)
    bfs_next = tree.next_hypothesis_breadth_first()
    assert bfs_next.id == c2.id


def test_dfs_walks_deepest_first() -> None:
    tree = AttackTree(root_hypothesis="probe")
    c1 = tree.add_child(tree.root_id, "branch A")
    tree.add_child(c1.id, "branch A1")
    tree.add_child(tree.root_id, "branch B")
    tree.mark(tree.root_id, NodeStatus.ATTEMPTED)
    tree.mark(c1.id, NodeStatus.ATTEMPTED)
    dfs_pick = tree.next_hypothesis_depth_first()
    assert dfs_pick.hypothesis == "branch A1"


# --- Pruning -------------------------------------------------------------


def test_prune_marks_subtree() -> None:
    tree = AttackTree(root_hypothesis="root")
    a = tree.add_child(tree.root_id, "branch a")
    b = tree.add_child(a.id, "leaf b")
    c = tree.add_child(tree.root_id, "branch c")
    pruned = tree.prune(a.id)
    assert pruned == 2  # a + b
    bfs = tree.next_hypothesis_breadth_first()
    # only the still-pending root (we haven't marked it) OR branch c.
    # The root is the first pending node BFS sees.
    assert bfs.id in {tree.root_id, c.id}
    # b is now PRUNED, not PENDING.
    assert tree._nodes[b.id].status == NodeStatus.PRUNED  # type: ignore[attr-defined]


# --- back_off ------------------------------------------------------------


def test_back_off_returns_pending_sibling_when_branch_exhausted() -> None:
    tree = AttackTree(root_hypothesis="root")
    a = tree.add_child(tree.root_id, "child a")
    b = tree.add_child(tree.root_id, "child b")
    # Mark child a's branch as exhausted; back_off should surface child b.
    fallback = tree.back_off(a.id)
    assert fallback is not None
    assert fallback.id == b.id
    assert tree._nodes[a.id].status == NodeStatus.EXHAUSTED  # type: ignore[attr-defined]


def test_back_off_returns_none_when_root_chain_exhausted() -> None:
    tree = AttackTree(root_hypothesis="solo")
    fallback = tree.back_off(tree.root_id)
    assert fallback is None


# --- Foothold advancement gate ------------------------------------------


def test_foothold_advances_only_when_verified_and_higher() -> None:
    tree = AttackTree(root_hypothesis="root")
    moved = tree.maybe_advance_foothold(FootholdState.AUTHENTICATED_USER, verified=False)
    assert moved is False
    assert tree.foothold is FootholdState.ANONYMOUS

    moved = tree.maybe_advance_foothold(FootholdState.AUTHENTICATED_USER, verified=True)
    assert moved is True
    assert tree.foothold is FootholdState.AUTHENTICATED_USER

    # A lower or equal verified candidate must NOT downgrade.
    moved = tree.maybe_advance_foothold(FootholdState.ANONYMOUS, verified=True)
    assert moved is False
    assert tree.foothold is FootholdState.AUTHENTICATED_USER


# --- step() verdicts -----------------------------------------------------


def test_step_returns_next_when_pending_present() -> None:
    tree = AttackTree(root_hypothesis="root")
    tree.add_child(tree.root_id, "candidate")
    result = tree.step()
    assert result.action == "next"
    assert result.next_node is not None


def test_step_returns_exhausted_when_all_terminal() -> None:
    tree = AttackTree(root_hypothesis="root")
    tree.mark(tree.root_id, NodeStatus.SUCCEEDED)
    result = tree.step()
    assert result.action == "exhausted"
    assert result.next_node is None


# --- Picker envelope -----------------------------------------------------


def test_picker_envelope_lists_top_3_pending_hypotheses() -> None:
    tree = AttackTree(root_hypothesis="root")
    for i in range(5):
        tree.add_child(tree.root_id, f"hypothesis-{i}", target_foothold=FootholdState.AUTHENTICATED_USER)
    env = tree.to_picker_envelope()
    assert len(env["available_hypotheses"]) == 3
    assert env["current_foothold"] == "anonymous"
    assert env["exhausted"] is False
