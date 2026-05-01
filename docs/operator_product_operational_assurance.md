# Operator Product Operational Assurance Matrix

## Purpose

This document is the first repo-owned operational assurance matrix for the supported AegisPT operator product.

It exists to prevent overclaiming. AegisPT can only claim a path is supported when the path is listed here with a status, evidence source, and known gap or next task.

## Status Legend

| Status | Meaning |
| --- | --- |
| `supported-and-tested` | The path has current repo evidence through at least one applicable validation lane. |
| `supported-with-gap` | The path is intended to be supported, but one or more signoff lanes are missing, environment-dependent, or not exhaustive. |
| `blocked` | The product has a known blocking prerequisite or explicit blocked state for this combination. |
| `intentionally-unsupported` | The path is outside the current supported product boundary and must not be implied by UI/docs. |

## Evidence Sources

| Evidence source | Current role |
| --- | --- |
| `codex/tasks/product_acceptance_matrix.json` | Machine-readable product acceptance catalog across UI, API, and real-run lanes. |
| `codex/tasks/ui_acceptance_matrix.json` | Browser-level operator-flow matrix for supported assessment types, profiles, access modes, safety clusters, state/output surfaces, and downloads. |
| `codex/tasks/target_lab_matrix.json` | Safe target catalog for local, authorized, and deliberately vulnerable training-lab real runs. |
| `docs/product_test_matrix.md` | Human-readable product matrix and required scenario groups. |
| `docs/ui_browser_validation.md` | Browser validation coverage and live-host proof references. |
| `docs/acceptance_runbook.md` | Safe real-run acceptance procedure and reference result files. |
| `docs/operator_console_phase7_checklist.md` | Phase 7 supported-path signoff summary and non-blocking follow-up notes. |
| `docs/operational_truth_signoff.md` | Release-truth rules, completion language, and combination coverage requirements. |

## Route Signoff Rule

A route is not `supported-and-tested` on repo unit tests, API tests, or mocked browser tests alone.

Support claims should use three layers where applicable:

- deterministic code validation
- browser/operator validation for UI-driven flows
- at least one safe real-run, benchmark-lab run, or explicitly authorized target proof for the route being claimed

If the third layer does not yet exist for a route, the route should stay `supported-with-gap` or `blocked` instead of being described as fully supported.

For reproducibility and safety, preferred proof targets are:

- local fixtures
- official intentionally vulnerable labs
- explicitly authorized customer-owned targets

Arbitrary public internet targets are not the default validation method.

## Supported Assessment Types

| Assessment type | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Website / Web App | `supported-and-tested` | UI matrix covers conversational completion; real-run catalog covers `local-app-smoke` and `juice-shop-baseline`; runbook references `acceptance-local-app-smoke-*` and `acceptance-juice-shop-baseline-20260417-112346.json`. | Real-run evidence is limited to local/dev and training-lab targets, not arbitrary public sites. | Keep under normal task validation; no new backlog item needed for the baseline. |
| Domain / Domains | `supported-with-gap` | UI matrix covers domain intake and browser run-dossier parity. | No enabled safe real-run domain scenario exists in `target_lab_matrix.json`; external domain scanning remains authorization-dependent. | Add a future safe domain fixture only when an authorized target exists. |
| External IP / WAN | `supported-with-gap` | UI/browser validation covers public-edge wording, staged passive discovery, and authenticated-review normalization. | No enabled real WAN target exists; public or customer WAN execution requires explicit authorization. | Use `backlog-12-kali-reproducibility-signoff-foundation` for host-path smoke only; add a later authorized WAN lab if needed. |
| Internal Range / LAN | `supported-with-gap` | UI matrix covers LAN intake, safety, boundary, discovery-first normalization, and follow-up continuity; product matrix covers inline `nmap` regression. | The safe real-run catalog has `metasploitable3-template` disabled and unauthorized, so repeatable internal lab execution is not currently green by default. | Future enabled internal lab scenario after local lab authorization and addressing are prepared. |
| API | `supported-and-tested` | UI matrix covers API/adaptive intake and access; real-run catalog covers `crapi-authenticated-safe`; runbook references `acceptance-crapi-authenticated-safe-20260419-215821.json`. | Current crAPI reference passed acceptance while the run status recorded `completed_with_errors` for one subtarget reset; that nuance must stay visible. | Revalidate under `backlog-12` if host/lab prerequisites are available. |
| SSL/TLS Only | `supported-and-tested` | UI/browser validation covers TLS-only goal guardrails, safety/boundary stops, and passive-lane dossier parity. | Current evidence is browser/API-oriented; no dedicated TLS-only real-run target is separated from web smoke/Juice Shop. | Optional future safe TLS fixture if TLS-only claims need separate real-run signoff. |
| Authenticated App | `supported-and-tested` | UI matrix covers authenticated-app intake, credential/manual/session routes, and dossier parity; real-run catalog covers `webgoat-auth-safe`; runbook references `acceptance-webgoat-auth-safe-20260419-215958.json`. | Requires WebGoat fixture and local ZAP prerequisite for active-safe validation. | `backlog-12` should make host prerequisite checks reproducible. |
| Mixed Assessment | `supported-with-gap` | UI matrix covers mixed web/API intake and explicit boundary stops. | `authorized-customer-template` is disabled and unauthorized; no repeatable mixed real-run scenario is enabled. | Future authorized mixed lab/customer fixture before broader mixed real-run claims. |

## Profiles, Lanes, and Module Clusters

| Profile or cluster | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Light / passive baseline | `supported-and-tested` | Product matrix and target catalog cover `local-app-smoke` with `passive-web-baseline`. | Local smoke validates the harness path, not broad vulnerability depth. | `backlog-12` for repeatable host smoke signoff. |
| Standard / guarded standard | `supported-and-tested` | UI profile matrix and safety-cluster matrix cover standard profile alignment; Juice Shop covers a standard safe web run. | Real-run breadth remains limited to safe lab fixtures. | Continue using acceptance harness. |
| Deep | `supported-with-gap` | UI matrix covers deep-goal normalization and guardrail copy. | Deep execution is often staged into passive discovery for internal/WAN routes; no broad deep real-run lab is enabled. | Future deep-safe fixture only after explicit authorization and safety review. |
| External Surface Only | `supported-with-gap` | UI matrix covers domain/WAN external-surface routes and passive discovery staging. | No enabled external WAN/domain real target exists. | Future authorized public-edge fixture. |
| Authenticated Only | `supported-and-tested` | UI matrix and WebGoat safe real-run cover authenticated app behavior and protected access context. | Depends on local WebGoat/ZAP availability. | `backlog-12` for reproducibility procedure. |
| SSL/TLS Only | `supported-and-tested` | Browser validation covers TLS-only guardrails and dossier persistence. | Dedicated TLS-only real-run evidence is not separated from broader web evidence. | Optional future TLS fixture. |
| Internal Validation | `supported-with-gap` | UI/API coverage proves discovery-first internal validation and fake-`nmap` browser regression. | Enabled real internal lab is absent; `metasploitable3-template` is disabled. | Future internal lab enablement task. |
| Adaptive Customer-Specific Mode | `supported-with-gap` | API product matrix covers inventory-to-relevance, pack validation/deploy, runtime binding, and adaptive report context; crAPI exercises adaptive UI/lab path. | Deeper adaptive permutations are future expansion opportunities, not exhaustive current signoff. | Existing queued AI/pack tasks 18, 19, 21, 35. |
| Passive baseline module cluster | `supported-and-tested` | Local smoke, browser matrix, and API regressions cover baseline behavior. | None for first slice. | None. |
| Authenticated surface cluster | `supported-and-tested` | WebGoat and access-mode/multi-role UI matrix cover supported authenticated paths. | Lab prerequisite dependent. | `backlog-12`. |
| TLS-only cluster | `supported-with-gap` | Browser proof exists for TLS-only mission shaping. | Separate real-run TLS target missing. | Future optional TLS fixture. |
| Adaptive customer-specific cluster | `supported-with-gap` | API product matrix and Pack Forge/browser visibility cover pack lifecycle. | Artifact reimport and deeper adaptive permutations are not complete. | `backlog-21-controlled-artifact-reimport-foundation`. |
| Internal validation cluster | `supported-with-gap` | Browser/API/fake-`nmap` coverage exists. | Disabled internal lab template blocks repeatable real-run signoff. | Future internal lab enablement. |

## Access Modes

| Access mode | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Unauthenticated | `supported-and-tested` | UI access matrix and common phrasing coverage include unauthenticated routes and downgrade revisions. | None for browser/API signoff. | None. |
| Credential reference | `supported-and-tested` | UI access matrix and multi-role tests cover credential references and protected binding metadata. | External vault-backed materialization is not complete. | `backlog-22-vault-backed-secret-materialization-foundation`. |
| API key reference | `supported-and-tested` | UI access matrix and API-token routes cover API key references. | External vault-backed materialization is not complete. | `backlog-22`. |
| Bearer token reference | `supported-and-tested` | UI access matrix covers bearer/API-token behavior. | External vault-backed materialization is not complete. | `backlog-22`. |
| Session reference | `supported-and-tested` | UI and live-host proofs cover session/cookie access from advanced drawer through Mission Control and Explorer. | External vault-backed materialization is not complete. | `backlog-22`. |
| Manual auth only | `supported-and-tested` | UI matrix covers shared manual-auth guidance without account rows and note-only per-role MFA context. | Manual human steps are not automated execution. | None; keep explicit as manual operator handoff. |
| Raw secret exposure in UI/report/log/MCP | `intentionally-unsupported` | Guardrails in current state and secret-handling docs forbid raw secret display. | N/A. | `backlog-22` strengthens materialization without exposing secrets. |

## Safety Modes and Blocked States

| Safety or state | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Passive/light | `supported-and-tested` | UI safety-cluster matrix and local smoke cover passive behavior. | None for first slice. | None. |
| Guarded/standard | `supported-and-tested` | UI safety-cluster matrix and standard web lab cover guardrail alignment. | Safe lab breadth remains limited. | None. |
| Deep/guarded | `supported-with-gap` | UI safety-cluster matrix covers guardrail visibility and lane alignment. | Deep execution breadth is not exhaustively real-run validated. | Future safe deep-lab task if needed. |
| Active-approved | `supported-with-gap` | WebGoat/crAPI active-safe scenarios and approval-gated UI states are covered. | Requires local ZAP and live lab prerequisites. | `backlog-12` for reproducible host prerequisite signoff. |
| Pending approval | `blocked` | UI execution-outcome matrix covers `pending_approval` as an explicit blocked state. | Block is expected until approvals are granted. | None; this is intended safety behavior. |
| Manual dispatch without worker | `blocked` | Acceptance runbook notes fail-fast behavior for manual dispatch/no-worker hosts. | Requires inline mode or worker availability. | `backlog-12` host signoff should verify supported dispatch mode. |
| Unauthorized public target expansion | `intentionally-unsupported` | Product matrix and acceptance runbook guardrails require catalog-backed safe/authorized targets. | N/A. | None; keep forbidden. |
| Runtime self-modification or uncontrolled plugin installation | `intentionally-unsupported` | `DECISIONS.md` and `docs/operational_truth_signoff.md` forbid it. | N/A. | None; keep forbidden. |

## Analysis Surfaces

| Surface | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Intake / wizard | `supported-and-tested` | UI matrix and browser validation cover completion, revision, calmness, access, safety, and boundary flows. | Human stakeholder review on day-to-day calmness remains useful but non-blocking. | Future UI polish tasks 23-25. |
| Mission Control | `supported-and-tested` | Phase 2/7 docs cover queued, running, completed, blocked, failed, and thin-output truth. | Deeper live telemetry and stdout streaming are future work. | `backlog-14`, `backlog-26`, `backlog-27`. |
| Surface / Attack Map | `supported-with-gap` | Browser coverage proves host-card fallback, inventory search/filter, and attack-path summary display. | Heavy graph rendering and richer attack-path visualization are future work. | `backlog-15`. |
| Findings Theater | `supported-and-tested` | Browser/API coverage covers finding, remediation, retest, Jira link, AI enrichment display, and remediation portfolio planning when present. | Automatic batch retest dispatch, ticketing workers, and contractual SLA enforcement remain out of scope. | Keep under normal regression validation. |
| Remediation portfolio / SLA planning | `supported-and-tested` | `api/tests/test_findings.py` covers owner/SLA filters, overdue/due-soon/blocked/verified states, tenant boundary behavior, and planning-only batch retest groups; browser coverage renders the portfolio and approval-aware plan in Finding Theater. | The plan does not create retest runs or dispatch work; operators still use explicit single-finding retest requests and existing approval gates. | Future package only if automatic orchestration is explicitly approved. |
| Evidence Replay | `supported-with-gap` | Browser validation covers zero-finding run-level evidence posture. | Product recommendation calls for consolidation into Findings Theater. | `backlog-23`. |
| Pack Forge | `supported-and-tested` | Phase 7 and Codex lifecycle docs cover pack visibility, Codex suggestions, prepare output, and validation handoff. | Controlled artifact reimport is not implemented. | `backlog-21`. |
| Report Center | `supported-and-tested` | Product matrix covers report previews and browser downloads; API tests cover report catalog/export. | Assurance package, ISO/PCI, and AI drafting are future work. | `backlog-20`, `backlog-29`, `backlog-33`. |
| Explorer | `supported-with-gap` | Browser validation covers run dossier, access context, and follow-up lineage. | Product recommendation calls for moving run dossier value into Report Center. | `backlog-23`. |
| History / Comparison | `supported-and-tested` | Browser validation covers history search and inventory-delta comparison. | Trend/drift over scheduled validation is future work. | `backlog-28`. |

## Export and Report Paths

| Export path | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Markdown export | `supported-and-tested` | `docs/product_test_matrix.md` and report download matrix cover format-specific browser downloads. | None for current report variants. | None. |
| HTML export | `supported-and-tested` | Browser matrix and API report tests cover HTML output. | None for current report variants. | None. |
| PDF export | `supported-and-tested` | Browser matrix validates downloaded PDF signatures; runbook records acceptance report links. | Depends on Playwright Chromium availability on host. | `backlog-12` host signoff should verify browser runtime availability. |
| Executive, technical, evidence, retest, SOC 2 reports | `supported-and-tested` | Current state and report tests record these variants as implemented. | SOC 2 is not a CPA attestation; ISO/PCI are not implemented. | `backlog-20`, `backlog-29`. |
| ISO 27001 / PCI DSS packages | `intentionally-unsupported` | Current state lists them as future work. | Not implemented yet. | `backlog-29`. |
| Evidence-backed assurance package | `supported-with-gap` | Assurance boundary is documented, but package output is future work. | Not implemented yet. | `backlog-20`. |

## Real-Run Safe Target Coverage

| Safe scenario or target | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| `local-app-smoke` | `supported-and-tested` | Runbook references `acceptance-local-app-smoke-*` result files; target catalog has enabled local fixture. | Host reproducibility needs a fresh signoff packet. | `backlog-12`. |
| `juice-shop-baseline` | `supported-and-tested` | Runbook references `acceptance-juice-shop-baseline-20260417-112346.json`; target catalog enables Juice Shop. | Requires local Juice Shop container. | `backlog-12` may document prerequisites but should not enable arbitrary targets. |
| `webgoat-auth-safe` | `supported-with-gap` | Runbook references `acceptance-webgoat-auth-safe-20260419-215958.json`; harness uses Docker fixture. | Requires local ZAP plus fixture startup. | `backlog-12`. |
| `crapi-authenticated-safe` | `supported-with-gap` | Runbook references `acceptance-crapi-authenticated-safe-20260419-215821.json`. | Passed with `completed_with_errors` nuance due one subtarget reset. | `backlog-12` if crAPI stack is present. |
| `owasp-benchmark-reference` | `blocked` | Target catalog records vulnerable-family metadata and disabled `owasp-benchmark-reference-stub`. | No local fixture URL/startup recipe is recorded yet, so it must not dispatch. | Future local benchmark fixture or backlog-108 scoring work. |
| `owasp-wrongsecrets-local-template` | `blocked` | Target catalog records WrongSecrets secret-family coverage and disabled `wrongsecrets-reference-stub`. | No local WrongSecrets endpoint/exported fixture files are scoped yet. | Future secrets benchmark fixture work. |
| `promptme-reference` | `blocked` | Target catalog records PromptMe/LLM security metadata and disabled `promptme-reference-stub`. | Documentation-only; no approved LLM endpoint is enabled by default. | Future LLM benchmark/eval work. |
| `goad-ad-lab-template` | `blocked` | Target catalog records GOAD-style AD lab prerequisites and disabled `goad-ad-lab-reference-stub`. | No isolated AD lab CIDR/hosts/domain are filled in, and intrusive phases still require explicit approval gates. | Future internal-lab enablement task. |
| `gruyere-reference` | `blocked` | Target catalog records Gruyere vulnerable-family metadata. | Documentation-only; public hosted instances must not be targeted by the harness. | Future local/authorized Gruyere fixture if needed. |
| `portswigger-academy-reference` | `blocked` | Target catalog records PortSwigger Academy vulnerable-family metadata. | Hosted per-user labs are documentation-only here and not automatically runnable. | Human-guided mapping or future authorized fixture work. |
| `metasploitable3-template` | `blocked` | Target catalog marks it disabled and unauthorized. | Cannot be run until local lab and authorization are added. | Future internal-lab enablement task. |
| `authorized-customer-template` | `blocked` | Target catalog marks it disabled and unauthorized. | Must be copied, filled, authorized, and reviewed before use. | Customer-specific authorized validation task, not generic backlog work. |
| Arbitrary public websites | `intentionally-unsupported` | Acceptance runbook forbids arbitrary public targets. | N/A. | None. |

## Cross-Browser and Host Coverage

| Environment | Status | Current evidence | Known gap or limit | Next task candidate |
| --- | --- | --- | --- | --- |
| Chromium browser validation | `supported-and-tested` | `docs/ui_browser_validation.md` defines Chromium as the required browser and Playwright lane. | None for current browser lane. | None. |
| Firefox / WebKit browser validation | `intentionally-unsupported` | Current state lists Firefox and WebKit expansion as future work. | No claims should imply cross-browser parity. | Future cross-browser expansion task if needed. |
| Local direct-host path on `127.0.0.1:8000` | `supported-with-gap` | Current state references live-host proofs and repaired inline host path. | Needs a reproducible install/update/restart/signoff packet instead of ad hoc proof. | `backlog-12`. |
| Kali host path | `supported-with-gap` | Host scripts and prior live-host notes exist. | Needs repeatable documented signoff and current evidence. | `backlog-12`. |
| Hosted SaaS / MSSP multi-tenant path | `supported-with-gap` | `docs/mssp_multitenant_readiness.md` maps tenant boundaries, and the API has a narrow optional `X-Tenant-ID` isolation foundation for engagement/run/report/finding/inventory/task/artifact paths. | Not hosted-SaaS ready: no tenant membership model, SSO, RBAC suite, billing, tenant switcher, cross-tenant reporting, or full router/storage partitioning yet. | Future hosted/MSSP hardening package. |

## Future Task Candidates From Open Gaps

These are not permission to work ahead. They are explicit gap mappings that future promotions can use.

| Gap | Classification | Candidate package |
| --- | --- | --- |
| Reproducible Kali/local-host install, restart, static asset, PDF, and safe smoke signoff | `supported-with-gap` | `codex/tasks/backlog-12-kali-reproducibility-signoff-foundation.json` |
| Finding Theater intelligence-brief and terminal-style evidence presentation | `supported-with-gap` | `codex/tasks/backlog-13-finding-evidence-brief-ux-foundation.json` |
| Task-level telemetry, swimlanes, and live counters | `supported-with-gap` | `codex/tasks/backlog-14-live-operations-telemetry-ux-foundation.json` |
| Attack-path graph visualization | `supported-with-gap` | `codex/tasks/backlog-15-attack-path-graph-visualization-foundation.json` |
| Additional workflow handoff beyond Jira | `supported-with-gap` | `codex/tasks/backlog-16-workflow-handoff-expansion-foundation.json` |
| Read-only cloud inventory | `supported-with-gap` | `codex/tasks/backlog-17-cloud-inventory-discovery-foundation.json` |
| Grounded AI mission guidance | `supported-with-gap` | `codex/tasks/backlog-18-ai-mission-guidance-foundation.json` |
| Read-only MCP operator context | `supported-with-gap` | `codex/tasks/backlog-19-read-only-mcp-operator-interface-foundation.json` |
| Evidence-backed assurance package | `supported-with-gap` | `codex/tasks/backlog-20-evidence-backed-assurance-package-foundation.json` |
| Controlled Codex artifact reimport | `supported-with-gap` | `codex/tasks/backlog-21-controlled-artifact-reimport-foundation.json` |
| Vault/deployment-key-backed secret materialization | `supported-with-gap` | `codex/tasks/backlog-22-vault-backed-secret-materialization-foundation.json` |
| UI consolidation, visual polish, and fetch performance | `supported-with-gap` | `codex/tasks/backlog-23-*.json` through `codex/tasks/backlog-25-*.json` |
| Per-task stdout streaming and active scan map | `supported-with-gap` | `codex/tasks/backlog-26-*.json` and `codex/tasks/backlog-27-*.json` |
| Scheduled validation trend/delta | `supported-with-gap` | `codex/tasks/backlog-28-continuous-trend-delta-foundation.json` |
| ISO 27001 / PCI DSS report packages | `supported-with-gap` | `codex/tasks/backlog-29-compliance-framework-expansion-foundation.json` |
| Read-only cloud IAM/Kubernetes analysis from stored inventory | `supported-with-gap` | `codex/tasks/backlog-30-cloud-iam-kubernetes-analysis-foundation.json` |
| Bounded LLM application endpoint probing | `supported-with-gap` | `codex/tasks/backlog-31-llm-application-testing-foundation.json` |
| Shadow AI discovery, uncontrolled LLM tool use, and autonomous AI exploit chaining | `intentionally-unsupported` | Explicit non-goals of `codex/tasks/backlog-31-llm-application-testing-foundation.json` |
| AI reporting, detection engineering, MCP actions, and integration portfolio expansion | `supported-with-gap` | `codex/tasks/backlog-32-*.json` through `codex/tasks/backlog-35-*.json`, plus `codex/tasks/backlog-38-*.json` |
| Automatic remediation orchestration, contractual SLA enforcement, and ticketing background workers | `intentionally-unsupported` | The remediation portfolio foundation is planning-only and explicitly does not create retest runs, dispatch scans, enforce contracts, or run ticketing workers. |
| Hosted SaaS / complete MSSP operating model | `intentionally-unsupported` | `docs/mssp_multitenant_readiness.md` records that backlog-36 only added a narrow tenant-isolation foundation, not hosted SaaS, billing, full RBAC, or tenant-portal operation. |

## Signoff Boundary

This matrix does not declare AegisPT complete.

It declares the current supported-combination truth for the first operational-assurance slice:

- many browser/API operator paths are supported and tested
- several real-run paths are supported only when their safe local lab prerequisites exist
- customer or public target execution remains blocked until explicit authorization exists
- several product recommendations are intentionally unsupported until their queued task packages are promoted
- future work must update this matrix when support status changes
