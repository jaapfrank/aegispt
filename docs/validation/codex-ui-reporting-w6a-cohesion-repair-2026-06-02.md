# Codex UI/Reporting W6A - Mission Story Cohesion Repair

Date: 2026-06-02
Owner: Codex UI/reporting lane

## Scope

This repair follows operator feedback that Mission Control, Run Picture, and
Evidence Replay were still visually and conceptually separate. The UI now uses
one shared mission-story vocabulary so the operator can move from current path,
to run outcome, to evidence provenance without mentally rebuilding the story on
each page.

Touched files:

- `ui-v2/src/viewModels/missionStory.ts`
- `ui-v2/src/viewModels/evidenceReplay.ts`
- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/src/components/screens/EvidenceReplay.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `DONE_LOG.md`

## Change

- Added a shared `missionStory` view model for route phases, safe finding
  titles, target summaries, task journey titles, and plain-language task
  explanations.
- Mission Control, the global mission spine, and Evidence Replay now share the
  same phase language: map surface, inspect behavior, test routes, prove impact,
  and tell outcome.
- Evidence Replay now opens with a clickable `Mission evidence path` instead of
  only metric cards and execution rows. Phase cards filter the evidence list,
  while transcript, artifact, hash, timestamp, and raw task metadata remain as
  drilldowns.
- Mission Control's run picture and proof nodes use safe mission themes for
  the lead outcome instead of raw runner, flag, benchmark, or exploit labels.
- Primary UI copy now favors plain-language route context; raw tool names and
  targets remain visible as secondary technical facts.

## Visual Proof

Screenshots captured with the real React v2 app:

- `docs/validation/codex-ui-reporting-w6a-cohesion-repair-mission-control-1536x864.png`
- `docs/validation/codex-ui-reporting-w6a-cohesion-repair-evidence-replay-1536x864.png`
- `docs/validation/codex-ui-reporting-w6a-cohesion-repair-evidence-list-row-1536x864.png`

Visual review notes:

- Mission Control now starts with the global cockpit spine, compact current
  path, run picture, and test story before technical feeds.
- Evidence Replay uses the same route phases and proof route headline as
  Mission Control, then lets the operator click into task provenance.
- Evidence rows use journey titles such as inspected behavior or tested route,
  with the raw tool and target retained as secondary metadata.

## Validation

Commands run:

```bash
cd ui-v2 && npx eslint src/viewModels/missionStory.ts src/viewModels/evidenceReplay.ts src/components/screens/EvidenceReplay.tsx src/components/MissionExperienceSpine.tsx src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts
cd ui-v2 && npm run build
cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts
cd ui-v2 && npm test
```

Observed results:

- touched-file ESLint: passed
- Vite production build: passed with the existing large chunk warning only
- React v2 critical-path Playwright suite: 20 passed
- UI test command: 23 passed, including i18n key parity

## Non-Collision

No Claude score-lane files were edited for this repair. `NEXT_TASK.md`,
`TASK_QUEUE.md`, scoring/orchestration code, runner files, and active XBEN
validation artifacts were left untouched.
