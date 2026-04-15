# Done Log

## 2026-04-15

- Added the initial Prompt 3 Codex build lane with read-only pack review endpoints, repo workspace export, validation wrapper scripts, and companion runbooks/docs.
- Added repository governance files (`AGENTS.md`, `CURRENT_STATE.md`, `NEXT_TASK.md`, `TASK_QUEUE.md`, `DONE_LOG.md`, `DECISIONS.md`) so future Codex runs can follow repo-defined instructions instead of large prompts.
- Added repo-backed Codex task management with minimal API endpoints, file-backed task/result storage, and safe run planning that does not mutate active runtime behavior.
- Added future-ready placeholder hooks for attack paths, identity-aware modeling, and risk scoring, plus forward-looking documentation for continuous mode, customer memory, integrations, and UI requirements.
- Added a FastAPI-served operator console under `/app` with a mandatory engagement wizard, mission control summaries, drilldowns for runs/packs/findings/tasks, report previews, evidence links, and Codex build-lane visibility.
- Added additive UI-support list endpoints for engagements, latest scope, engagement inventory, engagement relevance decisions, engagement packs, and Codex tasks so the console can reuse the existing backend models instead of creating parallel UI-only data shapes.
- Refined the operator console so engagement changes keep run/pack selection state coherent and scope/ROE context remains visible in the left-rail summary.
- Verified the operator-console slice with `api/tests/test_ui_support.py`, plus a full `api/tests` pass and bytecode compilation over `api/app`, `ui`, and `api/tests`.
- Expanded the operator console into the primary product UI with a multi-step mandatory assessment wizard, mission control, surface / attack map, findings theater, evidence replay, pack forge, report center, explorer, and history / comparison views.
- Added additive run configuration persistence on the existing run model so wizard output becomes the run-backed source of truth used by mission control and reports.
- Added report catalog metadata, report variants, and finding theater / evidence replay API views without replacing the existing evidence-first reporting and findings architecture.
- Added concise UI docs covering the wizard, mission flow, visual system, ETA model, report center, explorer hierarchy, and history/comparison model.
- Polished the operator UI into a more coherent product flow with a persistent lifecycle strip, clearer next actions, improved Mission Control hierarchy, consistent severity/status presentation, cleaner report previews, and more intuitive history/explorer drilldowns.
- Hardened the report pipeline with direct `format=pdf` support, a Playwright-backed PDF renderer, and updated export tooling/runbooks for markdown, HTML, and PDF outputs.
- Added a safer credential-handling baseline by materializing wizard-entered secrets into protected `SecretRef` bindings, sanitizing run configuration responses, and documenting the baseline storage model.
- Split the operator-console frontend into focused native modules so `ui/assets/app.js` now acts as a thinner orchestration layer instead of a monolithic controller.
- Added browser-level Playwright validation for `/app/`, the mandatory wizard flow, Mission Control, drilldowns, empty states, and report preview/export wiring, with traces and screenshots on failure.
- Added `TESTING_POLICY.md` plus hardening docs for browser validation, PDF rendering, secret handling, and frontend modularization.
- Verified the hardening pass with `python -m compileall api/app api/tests ui/tests` and `python -m pytest -q -s api/tests ui/tests`.
