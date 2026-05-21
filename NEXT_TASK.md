# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Governance Control Plane (Layer 0) — central scope/ROE/approvals/credentials/sandbox/budget API + Docker isolation per tool — **Sprint mythos-exploitation-foundation, task 3 of 15**

## Goal

Consolidate verspreide scope/ROE/approval/credential/sandbox/budget checks into one central Layer 0 Governance Control Plane (per Codex 6-layer architectuur). Every agent decision and runner dispatch validates through this single API. ADDITIONALLY: Docker isolation per exec_plan execution (heavy isolation per PentAGI pattern) so escape risk cannot reach host. No agent bypasses Layer 0.

## Sprint context

Task 3 van 15 in sprint `mythos-exploitation-foundation`. backlog-408 (XBOW baseline harness) DONE — harness empirisch geverifieerd: 16 tools / 20 findings / 3/3 exec-plan per challenge, geen API self-attack, scope+AI-loop+terminal-UI werken. Een 25-challenge background batch draait voor de finale ≥20-challenge meting; backlog-408 DONE entry wordt aangevuld als die landt. Per Codex 6-layer architectuur: Layer 0 Governance Control Plane wraps EVERYTHING — daarna pas kan Layer 1+ veilig uitbreiden.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/governance/control_plane.py` met `GovernanceControlPlane` klasse en methodes `authorize_dispatch(...)`, `authorize_credential_use(...)`, `authorize_external_network(...)`, `authorize_exec_plan_step(...)`, `check_budget(...)`. Verspreide approval-check code in `assessment_loop.py` + `ai_action_selector.py` + `workers/orchestration/tasks.py` wordt VERVANGEN door calls naar Layer 0. PLUS `workers/orchestration/sandbox_runner.py` — exec_plan steps draaien in vers Docker container per step. Greppable test verifieert 100% van dispatch sites routes through control_plane.

## Scope

(1) New `api/app/governance/` module met `control_plane.py`: single class `GovernanceControlPlane` met methodes:
- `authorize_dispatch(run, runner, target, tier) -> DispatchAuthorization` (allow/deny/needs_approval)
- `authorize_credential_use(run, cred_id) -> bool`
- `authorize_external_network(run, target) -> bool`
- `authorize_exec_plan_step(run, step) -> bool`
- `check_budget(run) -> BudgetState` (rps/concurrency/duration consumed vs limits)

(2) Refactor: vervang verspreide approval-checks in `assessment_loop.py` + `ai_action_selector.py` + `workers/orchestration/tasks.py` door calls naar `GovernanceControlPlane`. Oude code REMOVE in dezelfde commit (per ANTI_DRIFT Rule 3 — geen parallel coexistence).

(3) Docker isolation: nieuwe `workers/orchestration/sandbox_runner.py` — exec_plan steps draaien in vers Docker container per step (gVisor-isolated als gVisor beschikbaar, plain Docker anders). Container teardown verplicht. Netwerk default-deny + expliciete allowlist per engagement scope.

(4) Tests: `api/tests/test_governance_control_plane.py` — unit tests voor elke authorize-methode + integration test dat assessment_loop een dispatch correct routeert via Layer 0.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "100% dispatch decisions route via GovernanceControlPlane" (greppable + tested).
- Per Rule 2: control_plane MOET aangeroepen worden vanuit de drie call sites in dezelfde commit; geen dead code.
- Per Rule 3 (geen backward-compat creep): verspreide approval checks REMOVE in dezelfde commit; cite git diff line-count voor deletions.
- Per Rule 4 (geen mocked-live): live verificatie via XBOW harness run met sandboxed exec_plan ≥1 challenge.
- Per Rule 5: geen sluipweg om Layer 0 te bypassen.
- `no_bypass`: greppable test verifies every dispatch site routes through control_plane.
- `isolation_default_deny`: sandbox_runner default-deny op container network egress; allowlist explicit per scope.

## Source Package

`codex/tasks/backlog-409-governance-control-plane-docker-isolation.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

```
- [ ] Mijn code is INVOKED in production path (control_plane called from assessment_loop + ai_action_selector + workers/orchestration/tasks)
- [ ] Delta-metric bewoog: 100% dispatch decisions route via control_plane (grep + test verified)
- [ ] Removed code I replaced: cite N lines deleted from assessment_loop.py + ai_action_selector.py + tasks.py
- [ ] Geen scope creep: governance module + 3 refactored call sites + sandbox_runner only
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: <link to live trace OR XBOW challenge run via sandboxed exec_plan>
```

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_governance_control_plane.py`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check api/app/governance/control_plane.py workers/orchestration/sandbox_runner.py`
- `git diff --check`
- `git grep -nE 'authorize_dispatch' -- api/app/services/ workers/orchestration/` → ≥3 distinct call sites
- Live: an XBOW challenge run produces ≥1 exec_plan step that ran inside a sandboxed Docker container (visible in trace logs).
