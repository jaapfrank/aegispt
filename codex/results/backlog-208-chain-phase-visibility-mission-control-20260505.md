# Backlog 208 Evidence - Chain Phase Visibility In Mission Control

## Scope

- Active package: `codex/tasks/backlog-208-chain-phase-visibility-mission-control.json`
- UI-only change: render existing `assessment_chain` phase data in Mission Control.
- Backend chain logic, approval gating, dispatch, scope, ROE, credentials, runtime binding, pack registry, validation, deployment, and kill-switch behavior were not changed.

## Implementation Proof

- Mission Control now renders chain phase cards with explicit visual states:
  - `complete` for completed phases, including duration when `started_at` and `completed_at` exist.
  - `active` for the current active phase.
  - `waiting` for `pending_phase_approval` / `pending_approval` phases.
  - `pending` for future phases.
- Pending approval now shows one primary approval action: `Approve Phase N`.
- The approval action uses the existing endpoint:
  - `POST /api/v1/assessment-chains/{chain_id}/phases/{phase_key}/decision`
  - body: `{"decision": "approved"}`
- Pending approval summary shows:
  - previous phase completion summary,
  - next phase name,
  - approval requirement,
  - planned runner names from existing phase steps,
  - host/finding signals when the selected run already has inventory/finding evidence,
  - mission ETA-derived window when present.
- Non-chain runs do not render the assessment-chain panel or phase strip.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation: 250 queued task packages mapped one-to-one, exactly one active task.
- `node --input-type=module --check < ui/assets/modules/mission-control.js` passed.
- Focused Mission Control smoke E2E passed:
  - `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_chain_phase_progress_shows_pending_approval_and_posts_decision ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_hides_chain_phase_progress_for_non_chain_runs -q`
- Required checks passed:
  - `python3 scripts/validate_backlog_tasks.py`
  - `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - `git diff --check`
- Full smoke E2E passed:
  - `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q`

## Browser Acceptance

`http://127.0.0.1:8000` was relevant for validation, but the already-running service may serve stale code. Current-code browser acceptance was therefore performed on an isolated temporary Uvicorn server on `http://127.0.0.1:8022` with a temporary SQLite database.

Observed browser acceptance output:

```json
{
  "port": 8022,
  "phase_cards": 4,
  "pending_state": "waiting",
  "approve_button": "Approve Phase 2",
  "decision_payloads": [
    {
      "decision": "approved"
    }
  ],
  "non_chain_strip_count": 0
}
```

The temporary server was stopped after acceptance.

## Remaining Risks

- This task does not change wizard runner selection, full-pentest tool coverage, approval bundling, or auto-start semantics; the operator-reported Gruyere full-pentest/all-tools issue remains outside this active task.
- Phase-specific time estimates are only shown when existing run ETA data is available; no new backend ETA model was added.
- No live third-party target, Gruyere instance, or customer target was scanned.
