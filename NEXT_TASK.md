# Active Task

> **Read first:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline for AegisPT sessions (forbidden patterns, required_checks, live-acceptance gate, DONE-definitie). De regels daar overschrijven Claude's instinct.

## Title

Evidence projection as attack-graph — RECENT_CAPTURES becomes RECENT_CHAINS with causal lineage between observations and consuming capabilities (sprint mythos-foundation, task 5 of 5; sprint-gate task)

## Goal

Today `project_graph_for_picker` (`api/app/services/assessment_graph.py`) projects observations as a flat bag-of-signals: `form_with_post_action`, `cookie_weakness`, `xss_confirmed`, `session_cookie_present` each appear as separate lines with no connection. After-404 confirmed the dispatch fix lands the picker firing (claude_picks=13, exec_plan_successful=5 on 3/5 targets) — but chain_findings stays at 0 because the picker doesn't see how observations CHAIN. The Mythos differentiator hinges on this: a smart system reasons "I have a stored-XSS at /snippets that reflects on /admin; I have a session-cookie sid=abc from /login response; the cookie matches the session-required parameter on /admin" — not the three signals separately.

This task replaces the existing RECENT_CAPTURES section (#334) with a richer RECENT_CHAINS section that projects attack-chains: per captured_value, list the task it came from + the capabilities-or-runners that could consume it (based on required-input matching) + the observed evidence connecting them. Chain depth capped at 4 hops; max 5 chains projected per advance.

## Baseline anchor (proof from prior sprint tasks)

backlog-404 after-404 baseline (2026-05-20):

| target | claude_picks | exec_plan_ok | chain_findings | high+crit |
|---|---:|---:|---:|---:|
| mantis | 3 | 2 | 0 | 2 |
| mediawiki | 3 | 1 | 0 | 3 |
| roundcube | 2 | 0 | 0 | 0 |
| gitea | 2 | 2 | 0 | 1 |
| etherpad | 3 | 0 | 0 | 0 |

`chain_findings` is the missing metric. backlog-405 moves it.

## Scope

Two coordinated edits in `api/app/services/assessment_graph.py`:

1. New `_project_chains(observations, capabilities) -> list[str]` helper that for each `captured_value` observation walks forward: find target capabilities whose `required_inputs` field type matches the capture's `value_kind`; emit a chain line `[origin_task/observation_X] → [capture: value_kind=cookie var=sid] → [consumer: exec_plan POST /admin with cookie] | status: 1/3 hops materialized`. The walk uses `workers/runners/capabilities.json` `required_inputs` declarations + a small heuristic mapping (cookie → session-required, captured-token → bearer-required, etc.).
2. `project_graph_for_picker` calls `_project_chains` and inserts RECENT_CHAINS section in place of (or above) the existing RECENT_CAPTURES section. The flat captures section is preserved BELOW the chains section so reviewers still see the raw data; the chains section is what Claude reads strategically.

## Constraints

- Per SESSION_PROMPT §2 forbidden: no per-target conditionals, no pre-baked path/payload registries, no claiming DONE on green unit tests alone.
- No new entity types in `evidence_ingest`. The captured_value type from #334 stays the only chain-bearing type.
- No changes to `workers/runners/capabilities.json` schema (only consume existing `required_inputs` declarations).
- Per `feedback_no_prescriptive_recipes`: chain-discovery is heuristic over observed type-matchings (cookie kind matches session-required parameter), NOT hardcoded chain-templates.
- Bounded projection: max chain depth = 4 hops. Max chains projected = 5 per advance. Per-line length ≤ 200 chars. Section omitted entirely when 0 chains materialize.

## Source Package

`codex/tasks/backlog-405-evidence-projection-as-attack-graph.json`

## Reference

- backlog-404 after-404 report (`docs/validation/sprint-2026-mythos-foundation-2026-05-20-after-404.md`) — empirical evidence that picker now fires, exec_plan succeeds on 3/5 targets, but chain_findings stays 0
- backlog-402 + backlog-403 + backlog-404 DONE_LOG entries
- Memory: [[feedback_live_proof_before_done]], [[feedback_live_proof_must_be_diverse_real_targets]]
- After backlog-405 lands: the after-405 harness phase evaluates the SPRINT-GATE PASS predicate from backlog-406: `exec_plan_successful ≥ 1 AND chain_findings ≥ 1 on ≥2 of 5 targets`.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_attack_graph_projection.py api/tests/test_cross_target_provenance.py api/tests/test_assessment_graph.py api/tests/test_assessment_loop_structured_outputs.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_graph.py`
- `git diff --check`
- `.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py` (must still pass)
- Live: API restart → harness `--phase after-405` on the 5 targets → ≥1 target with a RECENT_CHAINS section in the picker prompt (verifiable via API log) AND **the sprint-gate PASS predicate met (`exec_plan_successful ≥ 1 AND chain_findings ≥ 1` on ≥2 of 5 targets)**.
