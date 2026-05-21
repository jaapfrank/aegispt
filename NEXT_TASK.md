# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Deterministic validator + reproducible PoC artifact engine — **Sprint mythos-exploitation-foundation, task 7 of 15**

## Goal

Per Codex 6-layer architectuur Layer 1: deterministic validator engine that re-executes any claimed exploit in isolated context and produces a reproducible PoC artifact (executable script + expected output). Every finding categorized as: `verified-exploited` | `observed-vulnerable` | `hypothesis`. Per XBOW pattern: findings only accepted when exploitability confirmed through controlled validation. Backlog-412 attack state machine consumes this verdict to gate foothold transitions deterministically.

## Sprint context

Task 7 van 15 in sprint `mythos-exploitation-foundation`. backlog-412 (Attack State Machine) DONE — foothold ladder + advancement gate live but using finding.severity ≥ high as the proxy verifier. backlog-413 replaces the proxy with a real deterministic validator: re-run the captured exec_plan chain in a fresh container, assert response markers, emit ValidationResult. Then `_infer_foothold_from_findings` in `advance_assessment_loop` switches to consult validator verdicts instead of severity heuristics.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/services/exploit_validator.py` met `validate_exploit(finding, replay_artifact) -> ValidationResult{verified|failed|inconclusive, evidence_hash, replay_script}` PLUS `api/app/services/poc_artifact.py` met `build_executable_poc(finding, captured_evidence)` die een standalone Python script genereert. Foothold transitions in `attack_state` switchen naar consult van validator-verdicts. Delta-metric: ≥1 reproducible PoC artifact gegenereerd EN ≥1 finding heeft `verified-exploited` classificatie na live XBOW run.

## Scope

(1) `api/app/services/exploit_validator.py`:
- `ValidationResult` dataclass: `verdict` ∈ {verified, failed, inconclusive}, `evidence_hash`, `replay_script`, `expected_markers`, `observed_markers`, `notes`.
- `validate_exploit(finding, replay_artifact)`: re-runs the captured request chain (via `workers/orchestration/sandbox_runner.py` from backlog-409 if Docker available, else inline httpx with strict timeout) and asserts the same response markers that the original exec_plan claimed. Pure deterministic — NO LLM call.
- Constraint `deterministic_only`: no model calls inside the validator path.

(2) `api/app/services/poc_artifact.py`:
- `build_executable_poc(finding, captured_evidence)` generates a standalone Python script with:
  - `#!/usr/bin/env python3` shebang + docstring describing the vulnerability
  - `--target URL` CLI arg + the captured request chain as `httpx.Client` calls
  - response-marker assertions that match the original validator
  - exit code 0 = reproduced, 2 = expected response markers absent
- Artifact is stored alongside the finding's `evidence_ref` and surfaced in the run report.

(3) Wire-in:
- `_infer_foothold_from_findings` in `assessment_loop.py`: replace severity heuristic with `validator_verdict == "verified"` check.
- New finding-classification column / field: `validation_status` ∈ {verified-exploited, observed-vulnerable, hypothesis} (the AegisPT finding model already has `validation_status` per backlog-385; reuse + extend).

(4) Tests `api/tests/test_exploit_validator.py` + `test_poc_artifact.py`:
- Verifier deterministically replays a stored request chain and matches markers.
- PoC artifact script is runnable (subprocess smoke).
- Foothold transitions ONLY when validator verdict = "verified" (regression against 412's proxy heuristic).

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "≥1 verified-exploited finding emitted by validator OR ≥1 PoC artifact reproducible by human via `python poc.py --target X`".
- Per Rule 2: validator called from finding-creation path AND from `_infer_foothold_from_findings`; no dead code.
- Per Rule 3 (geen backward-compat creep): the proxy heuristic in `_infer_foothold_from_findings` is REPLACED, not parallel-kept.
- Per Rule 4: validator is DETERMINISTIC (no LLM). Re-runs captured request chain, asserts markers.
- Per `poc_replayable_by_human`: PoC script runnable standalone via `python poc.py --target X`.

## Source Package

`codex/tasks/backlog-413-deterministic-validator-reproducible-poc.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED: validate_exploit called from finding-creation path; build_executable_poc called per verified finding
- [ ] Delta-metric: ≥1 verified-exploited finding + ≥1 runnable PoC artifact (cite path)
- [ ] Removed code: cite N lines of severity-heuristic foothold inference superseded by validator verdict
- [ ] Geen scope creep: validator + PoC + finding-class wire-in only
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: XBOW run produces ≥1 verified-exploited finding OR PoC reproduces an exploit standalone

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_exploit_validator.py api/tests/test_poc_artifact.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/exploit_validator.py api/app/services/poc_artifact.py`
- `git diff --check`
- Live: ≥1 PoC script reproducible standalone.
