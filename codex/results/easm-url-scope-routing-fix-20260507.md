# EASM URL-Scope Routing Fix

Date: 2026-05-07

## Issue

Website/Web App missions with URL-only scope could enter `FULL-EXTERNAL-WEB` phase 1 at `passive-easm-discovery`. That made a normal website test depend on EASM behavior and could leave the chain stale without execution evidence.

## Fix

`FULL-EXTERNAL-WEB` chain phase construction is now target-aware:

- URL-only Website/Web App scope removes `passive-easm-discovery` from phase 1 and starts with `passive-web-baseline`.
- Domain/root-domain scope keeps `passive-easm-discovery` first.
- Existing chain approval, queue, scope, ROE, credentials, runtime binding, reports, provenance, and kill-switch behavior are unchanged.

## Validation

- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py::test_full_external_web_url_only_website_starts_with_web_baseline_not_easm api/tests/test_assessment_chain.py::test_full_external_web_domain_scope_keeps_easm_first api/tests/test_assessment_chain.py::test_full_external_web_chain_keeps_active_phase_on_configured_scope_when_httpx_has_no_inventory -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py api/tests/test_easm_dispatch.py api/tests/test_runs.py::test_list_run_profiles -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with exit code 0.
- `python3 scripts/validate_backlog_tasks.py` passed.

## Boundary

No runner implementations were changed, no live target was contacted, and no EASM/customer/public scan was run.
