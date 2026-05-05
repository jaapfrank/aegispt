# Backlog 230 OAuth/OIDC Probe Runner Evidence

## Scope

- Active task: `OAuth2/OIDC misconfiguration runner: redirect_uri bypass, missing state parameter, absent PKCE for SPAs, token in URL, implicit flow still supported`.
- Implemented tool: `oauth-probe`.
- Validation target policy: deterministic local fixtures plus read-only local API/UI acceptance only.
- No Google, Microsoft, Gruyere, WebGoat, public internet target, or third-party IdP endpoint was actively exercised in this build-lane slice.

## Implemented Behavior

- Adds `workers/runners/oauth_probe/runner.py`.
- Enforces approved web/API scope before runtime probing.
- Discovers OAuth/OIDC signals from:
  - target HTML and login links
  - same-origin JavaScript files
  - `/.well-known/openid-configuration`
  - configured same-scope authorization URLs, paths, scripts, and token-evidence records
- Emits standard JSON findings through `oauth-probe-results.json` for:
  - `OAuth2 Redirect URI Bypass - Account Takeover Possible`
  - `OAuth2 State Parameter Missing`
  - `OAuth2 Authorization Code Flow Without PKCE`
  - `OAuth2/OIDC Token Leaked in URL`
  - `OAuth2 Implicit Flow Still Supported`
  - `OAuth2 Token Scope Over-Provisioning`
- Records safety evidence:
  - `follow_redirects=false`
  - `third_party_idp_requests_attempted=false`
  - `direct_third_party_idp_interaction=false`
  - `token_exchange_performed=false`
  - `browser_automation_performed=false`
  - `raw_tokens_stored=false`
  - `runtime_self_modification=false`

## Registrations

- `workers/orchestration/tasks.py`: `oauth-probe` in supported tools, dispatch, and command preview.
- `workers/orchestration/findings.py`: standard JSON finding extraction for `oauth-probe-results.json`.
- `api/app/services/runs.py`: planning, configuration extraction, scope validation, timeout validation, and queued task params.
- `api/app/services/run_profiles.py`: `active-web-oauth-probe` with `approval_step_id=active-web-oauth-probe`.
- `api/app/services/assessment_chain.py`: `active-web-oauth-probe` in `FULL-EXTERNAL-WEB` Phase 2 and web follow-up target inheritance.
- `api/app/routers/runs.py`: eligible post-approval launch auto-dispatch set for this safe web non-exploitation tool.
- `api/app/services/ai_agent.py`: AI/manual proposal allowlists.
- `api/app/methodology.py`: WSTG/control-family/tool-tag mapping.
- `ui/assets/modules/packs.js`: Tool Library entry.
- `ui/assets/modules/wizard.js`: Full External Web preview/chain profile and Web/API tile assessment-mode route.
- `scripts/acceptance_harness.py`: `active-web-oauth-probe` tool hint.

## Package Exception

The package suggested browser automation, but it also forbids third-party IdP interaction and live target actions outside safe/local/authorized validation. This implementation uses the existing AegisPT static/httpx runner pattern and same-origin discovery/probing only. Browser automation is explicitly recorded as not performed.

## Operator Complaint Boundary

This slice wires the new OAuth/OIDC runner into the Full External Web/API chain path. It does not claim to fix the broader Gruyere full-pentest complaint that all newly added runners must be selected, approved, and launched as one cohesive wizard flow; that broader cross-runner wiring remains mapped to queued backlog-250.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 250 queued task packages and exactly one active task.
- `source .venv/bin/activate && python -m pytest workers/tests/test_oauth_probe_runner.py workers/tests/test_web_depth_runner.py::test_web_depth_tools_are_supported -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_pentest_depth_registration.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_oauth_probe_profile_requires_named_approval_and_queues_oauth_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py::test_full_external_web_chain_includes_oauth_probe_in_active_phase -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_wizard_prediction_matrix_covers_visible_tiles_and_toggle_contract ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_ssl_tls_and_authenticated_app_tiles_reach_specialized_preview ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_wizard_preview_copy_defects_are_cleaned_up -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed; existing Alembic warnings appeared and the `AEGISPT_DB_KEY or --key is required.` line came from an existing negative startup test.
- `source .venv/bin/activate && python -m pytest ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_wizard_launch_flow_matches_matrix_for_each_assessment_family -q` was attempted for extra coverage but is not claimed green: it hit the existing `run_create` API rate limit at 10 requests while the matrix creates 11 runs.
- Read-only live acceptance on `http://127.0.0.1:8000` passed after `AEGISPT_LOCAL_ENSURE_ZAP=0 scripts/restart_local_inline_host.sh`:
  - `/health/live` returned healthy.
  - `/api/v1/run-profiles` contained `active-web-oauth-probe` with `tools=["oauth-probe"]`.
  - `/app/assets/modules/wizard.js` contained `active-web-oauth-probe` in `FULL-EXTERNAL-WEB` and routes Web/API active/full selections to `FULL-EXTERNAL-WEB`.

## Residual Risk

- No third-party IdP, Gruyere, WebGoat, or public internet target was actively scanned during this build-lane slice.
- Redirect-URI acceptance findings are safe no-follow redirect evidence and should be reviewed by a human before report wording implies completed account takeover.
- Scope over-provisioning is derived from configured token-evidence records only; the runner does not exchange tokens.
- The broader all-runner full-wizard coverage issue remains pending until the queued runner/profile/wizard wiring task becomes active.
