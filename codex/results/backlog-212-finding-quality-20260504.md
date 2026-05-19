# backlog-212 Finding Quality Evidence

Date: 2026-05-04

## Scope

Completed the active backlog-212 slice for enterprise finding quality. Findings now receive additive CVSS, OWASP, and proof-reference metadata through existing finding/evidence structures, and the Finding drawer renders those fields without changing the severity model, finding types, evidence storage, report generation, pack registry, approval flow, runtime binding, scope, ROE, credentials, or kill switch.

## Implementation Evidence

- Added deterministic finding quality service with NVD-cache CVSS lookup for CVE findings and deterministic fallback CVSS for non-CVE findings.
- Added deterministic OWASP mapping by finding type/surface and additive proof-reference extraction from existing evidence references and replay recipes.
- Stored quality metadata in the existing `Finding.replay_recipe_json["finding_quality"]` container when a real finding has enough context; sparse placeholder findings remain compatible with existing insufficient-evidence behavior.
- Extended `FindingRead` response shape with additive `cvss_source`, `owasp_*`, `owasp_mapping`, and `proof_reference` fields.
- Extended AI enrichment prompts and deterministic remediation fallback so connected ChatGPT enrichment is asked for business impact and numbered, stack-aware remediation steps.
- Added Finding drawer quality cards for CVSS, OWASP, and Reproduce/proof reference.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_finding_enrichment.py::test_finding_quality_adds_cvss_owasp_and_proof_reference workers/tests/test_findings_contract.py -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_findings_drawer_shows_quality_cvss_owasp_and_reproduce -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed after preserving sparse-placeholder insufficient-evidence behavior.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q` passed.
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/health/live` passed with a healthy runtime state.
- Safe read-only browser acceptance against `http://127.0.0.1:8000/app/` passed with injected finding state: CVSS gauge showed `9.8`, source `nvd-cache`; OWASP badge showed `API8`; Reproduce control was visible.
- `python3 scripts/validate_backlog_tasks.py` passed during final verification.
- `git diff --check` passed during final verification.

## Limitations and Risks

- Live acceptance used injected browser state and read-only health only; no live target action was run.
- NVD CVSS values are used only when a CVE is already present in the local threat-intel cache; this task did not add scan-time external CVE lookups.
- This task does not change report generation, so report export quality must be handled by a future report-specific task if the new fields need special report rendering.
- AI business impact/remediation quality depends on a connected ChatGPT provider; deterministic fallback remediation remains available without provider calls.
