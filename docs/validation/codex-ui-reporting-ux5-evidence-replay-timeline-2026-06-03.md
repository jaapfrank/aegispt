# Codex UX5 Evidence Replay Timeline

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Completed UX5 from the Codex UI/reporting worklist without editing
`NEXT_TASK.md`, `TASK_QUEUE.md`, Claude-owned score-lane files, assessment-loop
runtime files, worker runner files, scoring code, or active XBEN validation
artifacts.

This slice turns Evidence Replay into a timeline-first evidence surface while
preserving the existing task transcript, artifact, hash, timestamp, redaction,
and provenance drilldowns.

## Behavior

- Evidence Replay now builds a chronological timeline from loaded task details
  and saved findings.
- The first viewport shows the selected evidence step and timeline before the
  run selector and long task drilldown list.
- The selected step explicitly separates:
  - what this evidence proves
  - what this evidence does not prove
- Task events prove execution/output/provenance only. They do not imply a
  reportable vulnerability unless a saved finding links back to them.
- Finding events try to trace back to task/artifact evidence through evidence
  refs, proof references, task ids, artifact ids, artifact hashes, target host,
  and replay recipe/tool metadata.
- Finding-linked evidence exposes linked task, linked artifact, validation
  state, and Findings/Reports navigation without inventing business impact,
  remediation, or report wording.
- Clicking a route phase now also selects the first timeline event for that
  phase, so the path cards, selected step, and drilldown list move together.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-ux5-evidence-replay-timeline-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/EvidenceReplay.tsx src/viewModels/evidenceReplay.ts tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Evidence Replay"` (`3` passed)
- `cd ui-v2 && AEGISPT_CAPTURE_UX5_EVIDENCE_TIMELINE=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Evidence Replay timeline traces finding evidence"` (`1` passed, screenshot captured)
- `cd ui-v2 && npm test` (`35` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)

## Notes

The first screenshot pass showed that the new timeline was still below the
first viewport because the run selector and route cards came first. The screen
order was adjusted so the timeline and selected evidence step now lead the
page, with run selection and detailed task drilldowns available below.
