# backlog-221 SSRF Probe Runner Evidence

## Outcome

backlog-221 is complete. AegisPT now has a dedicated approval-gated `ssrf-probe` active runner for approved web/API roots.

## Implemented

- Added `workers/runners/ssrf_probe/runner.py`.
- Detects parameter-based SSRF by injecting governed callback, approved internal-service, cloud-metadata, and protocol payloads into common URL-consuming parameters.
- Detects header-based SSRF candidates through `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, and `Referer` probes.
- Supports blind/OOB SSRF only through supplied governed callback context and recorded OOB confirmation references.
- Restricts internal service payloads to URLs already allowed by the web root or covered by approved CIDRs; unapproved internal URLs are skipped.
- Requires explicit `cloud_hosted=true` context before cloud metadata payloads can be queued, and supports AWS, GCP, and Azure metadata payload families.
- Emits `ssrf-results.json` with structured findings, checks, replay metadata, summary counts, and safety metadata.
- Registered `ssrf-probe` in supported worker tools, dispatch, command previews, standard finding extraction, target planning, configuration validation, AI/manual proposal allowlists, methodology mapping, an `active-web-ssrf-probe` run profile, and the Tool Library.

## Safety Notes

- The runner does not perform SSRF-to-RCE escalation.
- The runner does not pivot through internal networks.
- Real internal service payloads are ignored unless they are explicitly approved by URL scope or approved CIDR.
- Cloud metadata payloads are disabled unless explicit cloud-hosted context is present.
- Build-lane proof used deterministic local/mock fixtures, not public target scanning.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile workers/runners/ssrf_probe/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_ssrf_probe_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_ssrf_probe_profile_requires_approval_and_queues_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings.
- `python3 scripts/validate_backlog_tasks.py` passed after promotion.
- `git diff --check` passed.
- `curl -sS --max-time 5 http://127.0.0.1:8000/health/live` returned healthy development runtime.
- `curl -sS --max-time 5 http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "ssrf-probe|SSRF Probe"` confirmed the live-served Tool Library module contains the SSRF Probe entry.

## Remaining Risk

- No public WebGoat target was actively exercised during this build-lane slice; proof is from deterministic safe fixtures.
- OOB confirmation depends on a governed callback context or supplied interaction evidence.
- Cloud metadata checks are intentionally gated by explicit cloud-hosted context and do not prove every provider-specific metadata hardening path.
