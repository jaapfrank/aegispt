# Codex UI/Reporting W6B - Management Report Rewrite

Date: 2026-06-02
Owner: Codex

## Scope

W6B rewrites management-facing report output so it reads as a customer-ready
management document instead of an internal proof export.

Touched files:

- `api/app/services/reports.py`
- `api/tests/test_reports.py`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `DONE_LOG.md`

## Before / After

Before:

- Executive/summary Markdown used the generic professional report header and
  included run identifiers in the management title layer.
- Management output could include raw finding titles, benchmark/runner markers,
  tool labels, flag-like proof markers, and Codex task identifiers.
- Executive HTML summary still rendered technical panels such as scope JSON,
  run configuration, adaptive pack details, and raw risk highlights.
- Dutch management output explained some known findings ad hoc and fell back to
  generic text for many categories.

After:

- Summary Markdown uses a dedicated management header with customer, assessed
  system, assessment window, and evidence-basis copy. Run ID is no longer in
  the management-facing title/header layer.
- Management titles are rewritten through safe business clusters when they
  contain internal markers or technical jargon.
- Summary Markdown and HTML use business impact and cluster-specific
  remediation actions instead of raw tool output or generic filler.
- Summary HTML hides technical-only scope/configuration/adaptive panels and
  keeps those details in technical/evidence report variants.
- Dutch management Markdown and ChatGPT prompt input use the same safe scope,
  cluster title, business impact, and remediation action rules.

## Readability / Truthfulness Checklist

- [x] Customer/scope header is clean and does not include run IDs.
- [x] Internal run labels, benchmark IDs, loop labels, raw flags, raw exploit
  markers, and tool names stay out of management-facing summary output.
- [x] Business impact is phrased as customer/business risk.
- [x] Remediation recommendations are cluster-specific.
- [x] Technical identifiers remain available in technical/evidence reports.
- [x] Management summary states an evidence boundary instead of presenting raw
  source ledgers as customer copy.

## Validation

Commands run:

```bash
python3 -m compileall -q api/app/services/reports.py api/tests/test_reports.py
. .venv/bin/activate && ruff check api/app/services/reports.py api/tests/test_reports.py
. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k "management_reports_rewrite_internal_runner_language or web_assessment_report_endpoint"
. .venv/bin/activate && python -m pytest api/tests/test_reports.py
```

Observed results:

- compileall: passed
- ruff touched files: passed
- focused management-report regression: 1 passed, 22 deselected
- full report suite: 23 passed

## Non-Collision

No Claude score-lane files were changed. `NEXT_TASK.md`, `TASK_QUEUE.md`,
runtime runner files, scoring code, and active XBEN validation artifacts were
left untouched.
