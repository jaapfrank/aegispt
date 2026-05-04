# backlog-217 Vulnerable Components Runner

## Result

Implemented the `vuln-components` active runner for approved web/API targets.

## Product Behavior

- Fingerprints component versions from response headers, HTML comments/body, linked script URLs/content, and explicitly exposed dependency files.
- Probes dependency files only below the approved web root: `package.json`, `package-lock.json`, `yarn.lock`, `pom.xml`, and Gradle-style files.
- Parses JavaScript and Java dependency declarations when exposed by the running application.
- Matches detected product/version pairs against local CVE threat-intel records passed from the existing `ThreatIntelRecord` cache, or explicitly supplied local fixture records.
- Emits structured `Outdated Library` findings with CVE IDs, local-cache provenance, methodology tags, references, and explicit no-exploitation/no-external-lookup metadata.
- Registers the capability in supported tools, dispatch, command preview, finding extraction, run profiles, methodology mapping, AI proposal allowlists, run planning/validation, and Tool Library.

## Safety Boundary

- Read-only fingerprinting and dependency-file retrieval only.
- No exploitation of identified vulnerable components.
- No broad source-code review.
- No external CVE lookup during runner execution.
- No uncontrolled RetireJS or OWASP Dependency Check installation; the task-package tooling reference was handled through deterministic Python fingerprinting to satisfy the active acceptance slice safely.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `source .venv/bin/activate && python -m pytest workers/tests/test_web_depth_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py::test_list_run_profiles -q` passed.
- `python3 -m py_compile workers/runners/web_depth/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings.
- `python3 scripts/validate_backlog_tasks.py` passed during validation.
- `git diff --check` passed before administrative updates.
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/health/live` returned a healthy development runtime.
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "vuln-components|Vulnerable Components"` confirmed the live-served Tool Library asset contains the new capability.

## Safe Fixture Evidence

`workers/tests/test_web_depth_runner.py::test_vulnerable_components_scan_matches_local_cve_fixture` starts a loopback HTTP fixture that exposes:

- `X-Powered-By: Express/4.16.0`
- an HTML comment with `Spring 4.3.18.RELEASE`
- a linked `jquery.min.js?v=1.6.4`
- an in-scope `package.json`
- an in-scope `pom.xml`

The test supplies local CVE records for `CVE-2019-11358` and `CVE-2022-22965` and asserts both CVE IDs appear in structured findings with read-only safety metadata.

## Remaining Risk

- No external target or public WebGoat/Gruyere instance was actively tested during this build-lane task.
- Real CVE matching quality depends on local threat-intel cache freshness and product/version normalization.
- RetireJS and OWASP Dependency Check integration remains a possible future enhancement if added through governed installation and readiness controls.
