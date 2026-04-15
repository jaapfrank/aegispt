# Relevance Engine

## Purpose

The relevance engine turns inventory plus threat intelligence into explicit customer-specific testing recommendations.

It is intentionally rule-assisted and practical. It is not a large ML subsystem.

## Inputs

- normalized inventory snapshot
- current engagement scope
- selected threat intelligence records
- prior findings for the same engagement
- existing methodology metadata from Prompt 1

## Output

Each `relevance_decision` stores:

- `threat_intel_refs_json`
- `prior_finding_refs_json`
- `methodology_tags`
- `recommendations_json`
- `justification_text`
- `evidence_basis_json`
- `confidence_score`

`recommendations_json` contains:

- `relevant_advisories`
- `informational_advisories`
- `suppressed_advisories`
- `proposed_capabilities`
- `proposed_templates`
- `proposed_playwright_flows`
- `proposed_semgrep_rules`
- `proposed_scanner_profiles`
- `proposed_methodology_tags`
- `justification`
- `evidence_basis`
- `confidence`

## Matching strategy

The current first-pass engine scores advisories using:

- product and technology term matches
- vendor or architecture hint matches
- attack-surface matches such as web, API, auth, TLS, or code
- advisory severity
- advisory confidence

The result is grouped into:

- relevant
- informational
- suppressed

## Methodology reuse

The engine does not introduce a second methodology taxonomy.

Instead it reuses the existing Prompt 1 methodology helper so proposed capabilities inherit:

- `methodology_tags`
- `ptes_phase`
- `nist_phase`
- `wstg_id`
- `wstg_version`
- `asvs_reference`
- `control_family`

## Operational intent

The relevance decision is a planning artifact.

It answers:

- which advisories matter here
- which extra checks should be generated
- why those checks are justified
- which methodology labels should travel with them

