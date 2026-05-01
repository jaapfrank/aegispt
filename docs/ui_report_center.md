# UI Report Center

## Purpose

The Report Center turns exported outputs into a first-class operator workflow rather than a raw download endpoint.

## Supported report variants

- Executive Report
- Technical Report
- Evidence Appendix
- Retest / Verification Report
- SOC 2 Report Package
- Evidence-Backed Assurance Package
- Run Attack Narrative

## UI workflow

- switch between a `Reports` tab and a `Dossier` tab inside Report Center without leaving the selected run
- list report variants for the selected run
- show metadata, selected run context, source scope/profile, methodology references, and hash
- show a compact run dossier context directly in Report Center, including scope, access summary, protected binding count, inventory totals, finding count, task/evidence totals, report readiness, and stored mission handoff
- show discovery-aware inventory totals alongside findings totals so inventory-first runs do not look empty when they mapped assets but produced no vulnerability findings yet
- show the enforced execution lane and planned runtime tools for the selected run alongside the report metadata
- when the selected run is a controlled discovery follow-up, show lineage metadata for:
  - follow-up strategy
  - source run
  - source inventory snapshot
  - rationale
- generate preview on demand
- request an optional AI-assisted narrative draft for selected sections when report drafting is enabled
- review an optional run attack narrative that summarizes stored reconnaissance, attack paths, chain detections, critical findings, remediation priority, and evidence references
- export Markdown, HTML, or PDF directly against the selected run dossier
- surface assurance-package boundary metadata when the selected variant is the evidence-backed assurance package
- make it clear that export links always apply to the currently selected run so stale URLs from another environment are easier to spot
- compare report posture against a baseline run

## Navigation consolidation behavior

- Finding Theater is now the primary finding decision surface and includes the selected finding's Evidence Replay context inline
- Report Center is now the primary export-ready run dossier surface and includes a dedicated `Dossier` tab for the practical run dossier context that operators previously had to fetch from Explorer first
- Evidence Replay and Explorer remain available for compatibility and deeper inspection, but their copy points operators back to the consolidated decision surfaces
- the active shell labels the primary analysis paths as `Findings + Evidence` and `Reports + Dossier` so normal review flows start from fewer high-friction choices
- the topbar engagement context now carries customer / engagement / ROE orientation so the Explorer customer index is no longer the normal way to understand where the operator is
- this is a presentation and navigation consolidation only; it does not add backend evidence models, remove audit trails, change report exports, or alter runtime behavior

## Backend integration

The UI reuses the existing run report endpoint and adds:

- report variant selection
- report catalog metadata for the run
- SOC 2 compliance-package metadata for the SOC 2 variant only
- evidence-backed assurance metadata for the assurance variant only
- AI-assisted draft metadata that points operators to the review-only draft action without changing export facts
- run attack narrative metadata for the `attack_narrative` variant only

## Constraint

This layer does not replace the reporting model from Prompt 1. It only packages it into a stronger product workflow.

## AI-assisted draft behavior

- the draft path is separate from Markdown, HTML, and PDF exports; generating a draft does not mutate findings, evidence, methodology mappings, or canonical report content
- drafts are visibly marked as AI-assisted and require operator review before any wording is used in a final report
- drafts are grounded in stored run context: client/engagement metadata, run configuration, report variant, findings, task state, methodology mapping, inventory summary when present, and linked finding evidence references
- provider-disabled and provider-failure states are deterministic and leave normal report previews/downloads unchanged
- the first supported sections are `executive_summary`, `risk_highlights`, and `remediation_overview`; additional sections must remain explicit and review-only
- the draft response lists source data categories and evidence references so operators can trace what informed the wording

## Run attack narrative behavior

- the run attack narrative is exposed as a normal report catalog variant and uses the same Markdown, HTML, and PDF export path as the other reports
- the narrative is AI-assisted/advisory operator-review material only; it does not replace canonical report facts, mutate findings, prove exploitation, or make unreviewed customer claims
- the narrative is grounded in stored run records only: run status, profile, sanitized configuration, findings, task evidence, inventory summary, deterministic attack-path summary, stored chain detections, and linked evidence references
- completed runs with stored findings, attack paths, or chain detections receive a `ready` narrative status; completed sparse runs receive a `limited` narrative that states what is missing
- queued, running, failed-before-completion, cancelled, or otherwise incomplete runs receive an `unavailable` narrative state instead of fabricated attack story text
- chain detections remain explanatory records only and do not execute chained exploitation or auto-escalate severity
- the variant must keep normal executive, technical, evidence, retest, compliance, and assurance exports available without an AI provider

## SOC 2 package behavior

- the SOC 2 package is exposed as a normal report catalog variant and uses the same Markdown, HTML, and PDF export path as the other reports
- the SOC 2 package is limited to SOC 2 Trust Services Criteria Security mapping in this slice
- findings are grouped through a separate report-time control mapping table layered on existing methodology metadata such as `control_family`, `methodology_tags`, `wstg_id`, and `asvs_reference`
- findings that do not match the current SOC 2 mapping table stay visible in a Manual SOC 2 Review Queue instead of being silently forced into a control
- zero-finding runs state that no evidence-backed findings were recorded for mapping, without asserting that SOC 2 controls are effective

## Evidence-backed assurance package behavior

- the assurance package is exposed as a normal report catalog variant and uses the same Markdown, HTML, and PDF export path as the other reports
- the package is scoped to the selected run, recorded engagement/scope, methodology metadata, task/evidence artifacts, finding status, remediation state, retest state, and report provenance
- the package must state that it is not a certification, attestation, or guarantee of security
- unresolved, in-progress, triaged, reopened, and accepted-risk findings remain visible as residual-risk items
- zero-finding runs may say that no evidence-backed finding records were created by the executed checks, but must not imply exhaustive testing or risk absence
- out-of-scope items stay visible, including denied scope, untested assets or controls, post-run changes, and external audit/certification conclusions
- forbidden overclaim language includes `hack-proof`, `guaranteed secure`, `fully secure`, `certified compliant`, `SOC 2 attested`, `ISO 27001 certified`, `all risk removed`, `all vulnerabilities found`, and unsupported `all findings fixed` claims

## Discovery-first behavior

- if a run has zero findings but linked inventory, the Report Center must say that clearly instead of implying the run had no value
- technical/executive/evidence/retest variants should still surface the mapped inventory counts and discovery summary
- direct export links remain valid for the currently selected run only, so operators should prefer launching downloads from the active dossier instead of reusing stale URLs
- follow-up reports should also make it clear when the current run came from a prior discovery run so the operator can trace that lineage without leaving the report workflow first
- the evidence appendix should stay useful even when the run has zero findings, because task evidence and discovery/follow-up inventory context can still be reviewable outputs

## Finding Theater evidence brief

Finding Theater now presents the selected finding as an operator evidence brief before the operator moves to Report Center:

- risk posture is rendered from existing severity, status, confidence, exploitability, and target fields
- evidence readiness is derived from the existing evidence reference plus matched replay executions
- replay context is attached inline from the existing finding evidence payload, including execution count, artifact count, validation history count, artifact summaries, and pack/inventory/relevance lineage
- methodology lineage shows the existing PTES, NIST, WSTG, ASVS, control-family, and methodology-tag data
- provenance keeps the existing origin, pack version, inventory snapshot, and relevance decision visible
- related execution excerpts render in a terminal-style evidence block only when stored stdout or stderr excerpts exist
- sparse findings degrade truthfully with explicit "not assigned" and "no matched execution excerpt" copy instead of fabricated evidence

This is a presentation-layer improvement only. It does not change canonical finding fields, severity semantics, methodology mapping, report variants, or report generation.
