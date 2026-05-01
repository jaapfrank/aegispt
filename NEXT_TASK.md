# Active Task

## Title

Add NVD API key hint when NVD feed fails with HTTP 429 rate limit in Settings Threat Intel

## Promoted From

`codex/tasks/backlog-162-nvd-rate-limit-api-key-hint-settings.json`

## Goal

In the Settings Threat Intel section, when the NVD CVE feed status shows HTTP 429 or `reason=rate_limited`, display an actionable hint below the error text: `NVD rate-limits unauthenticated requests. Configure an NVD API key in Settings to increase your quota.` The hint must point to the existing `nvd_api_key` setting field. This task is UI-only and must not add backend endpoints.

## Scope

Implement the active backlog package `codex/tasks/backlog-162-nvd-rate-limit-api-key-hint-settings.json`.

Expected slice:

- detect NVD provider status/error metadata containing HTTP 429 or `rate_limited`
- render the NVD API key hint directly below the NVD error/status text in Settings Threat Intel
- link or scroll/focus to the existing `nvd_api_key` setting field
- avoid backend changes, new endpoints, or broad Settings redesign
- preserve existing Threat Intel refresh/sync behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Fix only the specific bug described.
- Do not use this task for broad redesign.
- Do not install new tools.
- Do not run live customer or intrusive targets.
- Do not change unrelated schemas or prompts.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- When NVD feed status shows HTTP 429 or `rate_limited`, an actionable hint appears below the error.
- The hint explains NVD rate limiting and points to the NVD API key setting field.
- No new API endpoints or backend changes are added.
- No regression in Threat Intel Settings tests.
