# Codex UI/Reporting M6 - Management Attack Map and Technique Story

Date: 2026-06-02
Owner: Codex
Lane: UI/reporting, non-overlap with Claude score-lane

## Scope

Continued M6 by making management-facing reports explain what was tested, how
the assessment path moved from scope to evidence, and which techniques were
used in plain language.

Touched files:

- `api/app/services/reports.py`
- `api/app/schemas/report_center.py`
- `api/tests/test_reports.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

No score-lane runtime, solver, worker, `NEXT_TASK.md`, `TASK_QUEUE.md`, or
active XBEN validation files were touched.

## Behavior Proven

- English management Markdown/HTML/PDF now include an `Attack Map`, `What Was
  Tested`, and `Techniques Used in Plain Language` layer.
- Dutch management Markdown/PDF now include `Aanvalskaart`, `Wat is er precies
  getest?`, and `Gebruikte technieken in gewone taal`.
- The new technique layer maps raw task tools to management-safe technique
  categories such as network/service discovery, known-risk checklist, database
  input validation, controlled proof attempt, and web behavior checks.
- Management outputs continue to suppress raw runner/tool/lab labels such as
  `interactive-exploit`, `sqlmap`, `nmap`, `nuclei`, `httpx`, `XBOW`, `XBEN`,
  raw flags, and HTTP baseline titles.
- Management report-draft payloads now expose `management_story` in the same
  inspectable structured boundary as `management_decision`; technical variants
  receive neither management-only object.
- ChatGPT OAuth draft instructions now treat `management_story` as the
  canonical attack-map/technique source for management variants.

## Validation

- `python3 -m compileall -q api/app/services/reports.py api/app/schemas/report_center.py api/app/services/report_pdf.py api/tests/test_reports.py`
- `. .venv/bin/activate && ruff check api/app/services/reports.py api/app/schemas/report_center.py api/app/services/report_pdf.py api/tests/test_reports.py`
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k "management_reports_rewrite_internal_runner_language or ai_report_draft" -vv` (6 passed, 18 deselected)
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py` (24 passed)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`
