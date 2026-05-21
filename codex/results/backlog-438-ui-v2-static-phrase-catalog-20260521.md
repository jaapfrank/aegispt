# backlog-438 — ui-v2 static phrase catalog validation

## Scope

Extended the backlog-435 keyed i18n layer with a deterministic static phrase catalog for high-visibility screen chrome that still lived as English literals in `ui-v2`.

The running product still does **not** call Google Translate, DeepL, browser translation, LLMs, or any other external translation service. All translations are stored in repo source.

## Implemented Coverage

The phrase catalog covers high-visibility static UI chrome for:

- Dashboard
- Problems Center
- History
- Evidence Replay
- Surface Map
- Packs
- Research
- CVE Library
- Findings
- Reports
- Intake
- Autopilot Workbench
- Mission Control labels already touched by the prior i18n slice

## Explicit Boundary

The catalog intentionally does not translate:

- API-provided customer data
- target names
- finding titles/details produced by backend data
- report body content
- runner stdout/stderr
- evidence artifact content
- CVE identifiers
- tool names, protocol names, and security acronyms where translation would reduce operator precision

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed.
- `cd ui-v2 && npm run lint` passed.
- `cd ui-v2 && npm run build` passed.
- `cd ui-v2 && npm run test -- --run i18n` passed:
  - locale key parity: 80 keys across `en`, `nl`, `de`, `fr`
  - 3 Playwright tests covering shell persistence plus deeper screen chrome on Dashboard, Problems, History, Research, Evidence Replay, and Packs
- `git diff --check` passed on scoped files.

## Notes

The existing non-blocking Vite/PostCSS warning about `@import` ordering in `src/index.css` still appears during build and Playwright web-server startup.
