# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Score-climbing automation loop — benchmark run → failure analysis → versioned prompt proposal → operator approve → re-run — **Sprint mythos-exploitation-foundation, task 15 of 15 (LAST)**

## Goal

De motor die AegisPT van 0% → 80% XBOW score drijft. Geautomatiseerde iteratie: na elke benchmark run, analyzeer failed challenges, identificeer patterns (prompt gap / state-machine gap / tool gap), genereer VERSIONED prompt proposals (no runtime self-modify per Codex), operator approves, re-run, vergelijk delta. Permanent improvement infrastructure die de continuous-improvement sprint kan voeden.

## Sprint context

Task 15 of 15 — afsluitende task van `mythos-exploitation-foundation`. Release gate (419) toonde 0/25 baseline + 8 named gap items. Foundation tasks 408-422 zijn DONE. Tijd voor de motor die de gaps systematisch dichtfietst over meerdere iteratie-cycli (`mythos-continuous-improvement` sprint = backlog-431).

## Delta-doelstelling

> Deze task levert `scripts/xbow_score_climb.py` (orchestrator), `api/app/services/failure_analysis.py` (cluster failed challenges via Claude), proposal generation naar `prompts/proposals/{date}-{component}-revN.md`, CLI `aegispt promote-proposal {file}` (wraps `approve_prompt_change`), en delta-report na iteration. Delta-metric: één complete iteration cycle end-to-end op de bestaande 25-challenge baseline + delta-report uitgeschreven (initial cycle mag de score NIET verhogen — de infrastructuur is wat 423 levert).

## Scope

(1) `api/app/services/failure_analysis.py`:
- `cluster_failures(baseline_json_path) -> list[FailurePattern]` — leest een XBOW baseline JSON, groepeert crash/no-solve reasons, gebruikt Claude om per cluster een hypothesis te formuleren (prompt gap / state-machine gap / tool gap / infrastructure).
- Output: list of `FailurePattern{cluster_name, affected_challenges, root_cause_hypothesis, proposed_change_kind ∈ {prompt|state_machine|tool|infra}, proposed_target_component, proposed_change_summary}`.

(2) `api/app/services/proposal_generator.py`:
- `generate_proposals(patterns) -> list[Path]` — per pattern, drafts a `prompts/proposals/{YYYY-MM-DD}-{component}-rev{N}.md` file with `approve: false` header (operator must flip to `approve: true` before promotion). Includes the failure pattern + proposed change + rationale.

(3) `scripts/xbow_score_climb.py`:
- CLI: `python3 scripts/xbow_score_climb.py --baseline {path} --output-dir {dir}` — runs failure analysis + proposal generation, writes a delta-report markdown listing all generated proposals + the next-action checklist (review proposals → approve → re-run baseline → compare).

(4) CLI helper `scripts/aegispt_promote_proposal.py` (wraps `api.app.agents.coordinator.approve_prompt_change`) — operator runs it after editing a proposal's `approve:` header to `true`.

(5) Tests `api/tests/test_failure_analysis.py` + `api/tests/test_proposal_generator.py`.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "one complete iteration cycle end-to-end on the existing 25-challenge baseline + delta-report uitgeschreven". The first cycle is allowed to NOT raise the score — the deliverable is the loop infrastructure.
- Per Rule 4: real failure clusters from the 2026-05-21 baseline JSON, not synthetic.
- Per `no_runtime_self_modification`: proposals land with `approve: false`. Only `approve_prompt_change` (backlog-415) promotes them. The CLI just wraps that gate.

## Source Package

`codex/tasks/backlog-423-score-climbing-automation-loop.json`
