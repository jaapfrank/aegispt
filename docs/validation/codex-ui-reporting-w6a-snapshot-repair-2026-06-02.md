# Codex UI/Reporting W6A - Mission Control Snapshot Repair

Date: 2026-06-02
Owner: Codex UI/reporting lane

## Scope

This repair follows operator feedback that Mission Control still felt messy and
did not answer the mission state at a glance. The previous cohesion repair
aligned terminology, but the first viewport still duplicated the global spine,
mission path, run story, run picture, queue, and detail feeds.

Touched files:

- `ui-v2/src/App.tsx`
- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
- `CURRENT_STATE.md`
- `DONE_LOG.md`

## Change

- Hid the global `MissionExperienceSpine` on `/mission-control` so the page no
  longer repeats the same route/story layer twice.
- Added a dominant `Mission snapshot` cockpit at the top of Mission Control's
  Live view.
- The snapshot answers the state in one glance:
  - current outcome headline
  - target and checked count
  - next meaningful action
  - five-step mission route
  - lead proof
  - impact gauge with severity distribution
- Moved story cards, run picture, plain explanation, and technical facts behind
  one expandable details section.
- Kept attack map, queue, Live CLI, and live events as drilldowns below the
  snapshot instead of competing with the first answer.

## Visual Proof

Screenshots captured with the real React v2 app:

- `docs/validation/codex-ui-reporting-w6a-snapshot-repair-mission-control-1536x864.png`
- `docs/validation/codex-ui-reporting-w6a-snapshot-repair-mission-control-1280x720.png`

Visual review notes:

- 1536x864: first viewport shows one large mission answer instead of a global
  spine plus duplicated local panels.
- 1280x720: the same snapshot remains readable with target, checked count,
  next action, route, lead proof, and impact gauge visible without overlapping
  text.
- Detailed story/run-picture/technical facts are still accessible, but no
  longer dominate the first screen.

## Validation

Commands run:

```bash
cd ui-v2 && npx eslint src/App.tsx src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts
cd ui-v2 && npm run build
cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control renders interactive"
cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts
cd ui-v2 && npm test
```

Observed results:

- touched-file ESLint: passed
- focused Mission Control Playwright test: passed
- Vite production build: passed with the existing large chunk warning only
- React v2 critical-path Playwright suite: 20 passed
- UI test command: 23 passed, including i18n key parity

## Non-Collision

No Claude score-lane files were edited for this repair. `NEXT_TASK.md`,
`TASK_QUEUE.md`, scoring/orchestration code, runner files, and active XBEN
validation artifacts were left untouched.
