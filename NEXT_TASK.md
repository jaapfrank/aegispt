# Active Task

## Title

Move finding_verifier hook from post-advance (assessment_loop) to pre-persistence (workers/orchestration/findings.py) — closes the #335 un-verified critical visibility window (backfill 3 of 6)

## Goal

Task \#335 wired the verifier as a POST-advance hook in `assessment_loop.py`. Findings are first persisted with their original (un-verified) severity, then the verifier runs in the next advance and downgrades. There is a brief window — possibly several seconds, longer if the next picker call stalls — where downstream consumers (UI Mission Control polling, report exporters, webhooks) see a critical severity that the verifier would have downgraded. The fix is to call the verifier from the orchestration finding-persistence path BEFORE the finding row is committed, so the severity that lands in the DB is already verifier-adjusted.

## Scope

- Confirm via Grep which module is the canonical finding-persistence point (likely `workers/orchestration/findings.py`).
- For critical/high findings (VERIFIABLE_SEVERITIES from \#335), call `finding_verifier.verify_finding(finding, run, scope)` synchronously BEFORE the Finding row is flushed; apply the verdict to the in-memory Finding object via `apply_verifier_verdict`; THEN persist.
- Remove or downgrade the `assessment_loop.py` post-advance hook — prefer removal, fall back to a defensive backstop that no-ops when the verdict is already present.
- Tests prove: (a) DB row carries the verifier verdict + adjusted severity at first flush, (b) verifier exception → finding still persists with verdict=inconclusive, (c) no regression in the 28 existing test_finding_verifier tests.

## Constraints

- Hook relocation + small orchestration change ONLY. Do NOT modify the verifier strategies (\#335 contract), do NOT add new severities, do NOT change `FindingAiEnrichment.metadata_json` layout, do NOT extend the verifier to medium/low/info severity.
- Structural independence preserved: verifier still imports zero runner modules. Orchestration imports verifier, not the other way.
- Non-blocking for low severity: VERIFIABLE_SEVERITIES = {critical, high} unchanged. Medium/low/info persist unchanged.
- Graceful degradation: if verifier raises, log warning + persist with verdict=inconclusive + severity unchanged — do NOT block finding persistence.
- Must NOT touch: `finding_verifier.py` strategy functions, `VerifierVerdict` dataclass shape, `VERIFIABLE_SEVERITIES` / `_SEVERITY_DOWNGRADE` constants, `FindingAiEnrichment.metadata_json` key layout, finding schema in `models/control.py`, `workers/runners/`, `_AI_PICKER_SYSTEM_PROMPT`.

## Source Package

`codex/tasks/backlog-394-verifier-pre-persistence-hook.json`

## Reference

- `workers/orchestration/findings.py` (the relocation target — canonical finding-persistence path)
- `api/app/services/finding_verifier.py` (\#335 — strategies are must_not_touch; consume via `verify_finding` + `apply_verifier_verdict`)
- `api/app/services/assessment_loop.py` (current post-advance hook to remove or backstop)
- `api/tests/test_finding_verifier.py` (where new pre-persistence tests should sit; 28 existing tests must continue to pass)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_finding_verifier.py api/tests/test_finding_chains.py workers/tests/`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check workers/orchestration/findings.py api/app/services/finding_verifier.py api/app/services/assessment_loop.py`
- `git diff --check`
