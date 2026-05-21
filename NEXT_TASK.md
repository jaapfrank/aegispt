# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Attack State Machine — foothold model + TAP-style attack tree per hypothesis — **Sprint mythos-exploitation-foundation, task 6 of 15**

## Goal

Layer 3 van de nieuwe architectuur: `foothold_state` per run ∈ {anonymous, authenticated_user, admin, file_read, code_execution, shell_like}. Attack tree per finding. TAP-style breadth-first + depth-first + pruning. Recursion + back-to-root per exhausted branch. Replay-first on previously-proven paths (uses backlog-410 episodic memory).

## Sprint context

Task 6 van 15 in sprint `mythos-exploitation-foundation`. backlog-411 (context curation) DONE — picker context-budget governed. Tijd voor stateful attack-tree zodat de picker niet stateless per advance maar via een foothold-graph werkt. Replay-first leverage'd `skeptical_recall_with_verify_hint` uit backlog-410 voor proven-path bias.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/services/attack_state.py` met `FootholdState` dataclass + `AttackTree` (LangGraph-style stateful graph) + `attack_tree_step(run, current_foothold) -> next_hypothesis | back_off | exhausted`. Picker prompt krijgt huidige foothold + tree_state geïnjecteerd. Delta-metric: ≥1 run toont foothold transition van `anonymous` → `authenticated_user` na verified exploit OF tree_depth ≥3 op één XBOW challenge.

## Scope

(1) New `api/app/services/attack_state.py`:
- `FootholdState` Enum: anonymous / authenticated_user / admin / file_read / code_execution / shell_like.
- `AttackNode` dataclass: `id`, `hypothesis`, `tool_chain`, `parent_id`, `status` ∈ {pending, attempted, succeeded, failed, exhausted}.
- `AttackTree`: in-memory tree per run with `add_node`, `expand`, `prune`, `next_hypothesis_breadth_first`, `next_hypothesis_depth_first`, `back_to_root_when_exhausted`.
- `attack_tree_step(run, current_foothold)` returns the next hypothesis to try OR `back_off` (exhausted branch, go back to parent) OR `exhausted` (whole tree exhausted).

(2) State transitions: foothold ONLY changes when a validator-verified exploit lands. For this slice, treat `task.status==completed AND finding.severity in {critical, high}` as the verification signal (until backlog-413 lands the deterministic validator).

(3) Picker prompt injection: extend `_AI_PICKER_SYSTEM_PROMPT` with a `=== ATTACK STATE ===` section that lists `current_foothold`, `tree_depth`, `available_hypotheses` (top 3 from tree).

(4) Replay-first: at run-start, `skeptical_recall_with_verify_hint(query="similar target type")` from backlog-410. Convert top hint into an initial AttackNode that the picker can try BEFORE blind recon.

(5) Tests: `api/tests/test_attack_state.py` — tree expand/prune, foothold transitions on verified exploit, BFS+DFS ordering, back-to-root on exhausted, replay-first injection from episodic recall.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "≥1 foothold transition observed live OR tree_depth ≥3 in one XBOW challenge run".
- Per Rule 2: `attack_tree_step` MOET aangeroepen worden vanuit `advance_assessment_loop` in dezelfde commit; geen dead code.
- Per Rule 3: oude stateless picker-helpers die door tree worden vervangen MOET removed/wrapped — cite line count.
- Per Rule 4: live verification via XBOW run — foothold-transition trace OR tree-depth ≥3 logged.
- Per Rule 5: `no_unverified_transitions` — foothold transitions ONLY on validator-verified evidence; no claim-based transitions. Until backlog-413 lands, finding-severity ≥ high is the proxy verifier.

## Source Package

`codex/tasks/backlog-412-attack-state-machine-foothold-tree.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED: `attack_tree_step` called from `advance_assessment_loop` every advance
- [ ] Delta-metric: foothold transition OR tree_depth ≥3 logged in one XBOW run
- [ ] Removed code: cite N lines of stateless picker code superseded by tree
- [ ] Geen scope creep: attack_state.py + 1 hook + prompt section + tests only
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: link/trace evidence

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_attack_state.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/attack_state.py`
- `git diff --check`
- Live: XBOW run produces ≥1 foothold transition OR tree_depth ≥3.
