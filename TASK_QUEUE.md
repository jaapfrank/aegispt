# Task Queue

The current active implementation task remains the one in `NEXT_TASK.md`.

The ordered backlog below now absorbs `PRODUCT_RECOMMENDATIONS.md` through `docs/product_recommendations_scope_alignment.md`.

Each queue item must map one-to-one to a repo-backed task package in `codex/tasks/`.

Run `python3 scripts/validate_backlog_tasks.py` before promoting a queued package into `NEXT_TASK.md` or changing this order.

1. Commercial-viability UI slice 1: font-stack hardening, first-run onboarding, explicit empty states, and Surface Map host-card fallback. `codex/tasks/backlog-01-commercial-ui-foundation.json`
2. Remediation slice 1: additive remediation tracking, single-finding retest linkage, and proof-of-resolution reporting. `codex/tasks/backlog-02-remediation-status-and-single-finding-retest.json`
3. Live-operations slice 1: run-status SSE streaming and Mission Control live activity truth. `codex/tasks/backlog-03-live-ops-run-stream.json`
4. Integration slice 1: Jira-only configuration and finding-link synchronization foundation. `codex/tasks/backlog-04-jira-integration-foundation.json`
5. Attack-path slice 1: attack-graph service foundation and choke-point summary without a heavy graph UI. `codex/tasks/backlog-05-attack-path-summary-foundation.json`
6. Continuous-mode slice 1: scheduled-run model, cadence API, and dispatcher reuse for recurring validation. `codex/tasks/backlog-06-scheduled-validation-foundation.json`
7. Compliance slice 1: SOC 2 report package built on the existing methodology and report layers. `codex/tasks/backlog-07-soc2-report-package.json`
8. Coverage-expansion slice 1: read-only LDAP / AD enumeration for identity-aware internal validation. `codex/tasks/backlog-08-ldap-ad-enumeration-foundation.json`
9. AI-leverage slice 1: opt-in finding enrichment foundation with additive stored AI output. `codex/tasks/backlog-09-ai-finding-enrichment-foundation.json`
10. Frontend-state watch slice 1: runtime-store seam around shared UI state without a framework rewrite. `codex/tasks/backlog-10-runtime-store-foundation.json`
