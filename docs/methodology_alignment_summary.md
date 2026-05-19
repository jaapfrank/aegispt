# Methodology Alignment Summary

## What Changed

- Added a lightweight methodology constants and mapping layer for PTES, OWASP WSTG, and NIST SP 800-115.
- Extended persisted findings with methodology metadata:
  - `methodology_tags`
  - `ptes_phase`
  - `nist_phase`
  - `wstg_id`
  - `wstg_version`
  - `asvs_reference`
  - `control_family`
- Added first-pass normalization logic so common finding types map to practical methodology references without a complex taxonomy engine.
- Upgraded report rendering so exported reports now include:
  - scope
  - rules of engagement summary
  - methodology
  - coverage summary
  - confirmed findings
  - evidence and reproduction
  - remediation priorities
  - retest / verification status
- Added enterprise-facing methodology documentation:
  - `docs/methodology_mapping.md`
  - `docs/testing_coverage_matrix.md`

## What Did Not Change

- The core evidence-first architecture.
- The current tool integrations and orchestration model.
- The approval-gated execution model.
- The controlled internal validation model.
- The existing API shape for requesting runs, listing findings, or exporting reports.
- The no-worming / no autonomous self-propagation posture.

## Prompt 2 Additive Extension

The adaptive testing patch builds on this methodology alignment without replacing it.

It adds:

- inventory snapshots
- threat intelligence normalization
- relevance decisions
- customer-specific capability packs
- validation and promotion records
- runtime pack binding and finding provenance

It does not replace the Prompt 1 methodology constants, metadata fields, or report structure. It reuses them.

## Why This Is an Alignment Patch

This patch professionalizes the existing implementation without introducing a new subsystem.

The platform still works the same way:

- AI proposes or assists
- the engine executes approved tools
- findings are backed by stored evidence
- reports are generated from the same execution and artifact chain

The difference is that findings, reports, and workflow language now map to recognizable assessment frameworks used by enterprise security teams.

## Follow-Up Recommendations

1. Add analyst-editable report metadata for confidence, exploitability, business impact, and remediation ownership.
2. Expand the dedicated API-first lane with live-safe benchmark fixtures and richer operator-authored business-flow checks while keeping fuzzing, load testing, and account creation out of scope unless explicitly approved in a future task.
3. Expand the bounded Playwright-backed validation lane with richer, operator-authored browser journeys while keeping the existing evidence and approval boundaries.
4. Support precise ASVS requirement identifiers when analysts intentionally attach control references.
