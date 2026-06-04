# Codex UI/reporting W2 — Findings Theater truth pass

Date: 2026-06-01
Owner: Codex
Scope: React v2 Findings Theater, critical-path UI fixtures/tests

## Behavior Proven

W2 makes Findings Theater present finding truth without relying on raw runner
labels or unsupported filler text:

- finding rows now show a canonical truth badge, evidence badge, workflow status,
  validation state, and source label
- raw exploit-runner titles such as `Flag captured (interactive-exploit): ...`
  are normalized as primary operator copy while the stored title remains visible
  as metadata in the drawer
- the drawer separates Finding Truth, Evidence Summary, Technical Evidence,
  Business Impact, AI Enrichment, and Remediation
- remediation and next-step copy appears only when the theater detail payload
  provides supported remediation/next-step data
- blocked findings with no evidence reference show missing evidence and no
  supported remediation/next-step guidance instead of generic advice

## Fixture Proof

`ui-v2/tests/react-v2-critical-paths.spec.ts` now covers three explicit theater
truth cases:

- verified raw-runner finding: primary copy becomes
  `Verified flag capture on app.example.test`; raw runner/flag title is not row
  primary copy, and evidence/business/remediation sections remain distinct
- observed finding: evidence reference exists, validation is queued, row remains
  `Observed finding`
- blocked finding: evidence reference is missing, validation is skipped, and the
  drawer shows no supported remediation or next-step language

## Validation

Commands run from `ui-v2/` unless noted:

- `npm run build`
- `npx eslint src/viewModels/findingTruth.ts src/components/screens/FindingsTheater.tsx src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Findings Theater"`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Cinema Mode"`
- `npm test`
- `python3 scripts/validate_backlog_tasks.py` from repo root

Notes:

- The first full `npm test` pass after the Mission Control heading repair showed
  one Cinema Mode timing miss on `CAMERA // FOCUSED`. The isolated Cinema test
  passed, and the next full `npm test` run passed all 17 tests.
- The Mission Control heading repair was required because W1 had removed the
  stable `Mission Control` screen heading expected by the all-screen smoke test.
