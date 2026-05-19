# Backlog 257 - Adaptive Recon-First Wizard Flow

Date: 2026-05-07

## Scope

Implemented the active backlog package `codex/tasks/backlog-257-adaptive-recon-first-wizard-flow.json`.

The slice adds a recon-first wizard path for Website/Web App style targets while preserving the existing manual/depth flow. The new path creates an approval-gated single recon run using existing registered runners only.

## Product Truth

- Wizard Step 2 now shows `Start with quick recon (recommended)`.
- The operator-facing copy states: `Sends network traffic to target (nmap port scan + HTTP fingerprinting). No exploitation. ~5 minutes.`
- Existing `I already know what to test (pick depth now)` passive/active/full tiles remain visible and functional.
- Recon-first creates a single `active-low-impact-web-recon` run and leaves `assessment_mode` disabled, so it does not globally replace `FULL-EXTERNAL-WEB`.
- `active-low-impact-web-recon` is an active, approval-gated profile using existing `nmap` and `httpx` runners.
- URL-only recon derives the URL hostname for nmap only when the profile explicitly opts into `derive_url_hosts_for_nmap`; httpx remains targeted at the approved URL.
- Deeper assessment remains driven by SignalProfile and the backlog-255 AssessmentPlan after real recon evidence exists.

## Validation

Passed:

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_low_impact_web_recon_requires_approval_and_queues_nmap_plus_httpx_for_url_scope ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_external_web_wizard_offers_recon_first_without_removing_depth_selection -q`
- `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_low_impact_web_recon_requires_approval_and_queues_nmap_plus_httpx_for_url_scope -q`
- `source .venv/bin/activate && python -m pytest ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_wizard_launch_flow_matches_matrix_for_each_assessment_family ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_external_web_wizard_offers_recon_first_without_removing_depth_selection -q`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- Playwright current-code acceptance on `http://127.0.0.1:8765/app/` for 1440px, 1024px, 768px, and 375px.

Executed but not green:

- `source .venv/bin/activate && python -m pytest ui/tests/ -q`

The full UI suite failed in legacy/full-system audit and older conversational-flow tests. Task-relevant wizard matrix tests pass. Notable unrelated failure roots include `scripts/run_full_system_acceptance_audit.py` referencing `field.get` instead of the loop variable and older audit tests expecting the previous stepper-style wizard flow.

## Browser Evidence

- `codex/results/backlog-257-adaptive-recon-first-wizard-flow-playwright-20260507.json`
- `codex/results/backlog-257-adaptive-recon-first-wizard-flow-1440-20260507.png`
- `codex/results/backlog-257-adaptive-recon-first-wizard-flow-1024-20260507.png`
- `codex/results/backlog-257-adaptive-recon-first-wizard-flow-768-20260507.png`
- `codex/results/backlog-257-adaptive-recon-first-wizard-flow-375-20260507.png`

## Boundaries

- No new runner implementation was added.
- No approval, scope, ROE, credential, runtime binding, provenance, report, or kill-switch gate was bypassed.
- No live customer/public target was scanned.
- No exploitation, fuzzing, payload delivery, or form submission was enabled by the recon-first path.

## Follow-Up

- Live worker dispatch from recon artifacts into SignalProfile and AssessmentPlan remains extra validation: `extra_tests.md` XT-017.
- Full UI suite reconciliation remains a product/release risk: `risico.md` R-014.
