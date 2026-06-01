# Codex Universal Execution Contract

Purpose: give Codex one durable in-repo execution contract to follow until the
Codex-owned lane is explicitly closed by the operator.

This contract is designed for the current parallel-working reality:

- Claude owns the active score-lane in `NEXT_TASK.md`
- Codex owns the separate UI/reporting lane described in
  `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

Codex must keep making progress without breaking queue truth, git hygiene, or
Claude's active worktree.

## Short launcher prompt

Use this as the short prompt for future Codex sessions:

```text
Use /docs/strategy/codex-universal-execution-contract.md as your execution contract for this session.

Read CURRENT_STATE.md, NEXT_TASK.md, DECISIONS.md, DONE_LOG.md, and /docs/strategy/codex-ui-reporting-worklist-2026-06-01.md first.

If the previous Codex-owned work item is not truly complete in behavior, proof, docs, and repo state, finish or repair it first.
If it is complete, continue with the next Codex-owned work item from the Codex UI/reporting worklist.

Do not collide with Claude's score-lane files. Keep working until the active Codex-owned task is actually proven, validations are clean, lint is clean in touched files, docs/state are updated, and the repo is left tidy.
```

## Contract

### 1. Core rule

Code changes do not count as progress on their own. Only proven behavior,
truthful UI/reporting outcomes, clean validation, and tidy repo state count.

### 2. Mandatory read order

At the start of every Codex session, read:

1. `CURRENT_STATE.md`
2. `NEXT_TASK.md`
3. `DECISIONS.md`
4. `DONE_LOG.md`
5. `TASK_QUEUE.md` if queue context matters
6. `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
7. any files directly touched by the active Codex-owned work item

### 3. Task-selection rule

Codex must distinguish between:

- the repository-wide active task in `NEXT_TASK.md`
- the Codex-owned parallel lane in
  `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

Default behavior:

- respect `NEXT_TASK.md` as the repo's canonical active task record
- do not overwrite or promote over it while Claude owns the score-lane
- do Codex work only inside the Codex-owned worklist unless the operator
  explicitly reassigns ownership

### 4. Previous-task-first rule

Before starting new work, verify whether the previous Codex-owned work item is
actually complete.

Check:

- does the real behavior now work on the relevant path?
- do UI state, findings state, evidence state, and report state agree?
- do `CURRENT_STATE.md`, `DONE_LOG.md`, and the Codex worklist agree?
- did the previous task leave lint/test/doc/git residue behind?

If the answer is no, repair that first.

If yes, continue the next Codex-owned work item.

### 5. Non-overlap rule

Do not silently edit files in Claude's active lane without explicit operator
approval.

Claude-owned active lane includes at least:

- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `api/app/services/assessment_loop.py`
- `api/app/services/assessment_loop_internals/guards.py`
- `api/app/services/m2_verdict_gate.py`
- `workers/orchestration/tasks.py`
- `workers/runners/interactive_exploit/**`
- active score-lane validation artifacts tied to solver throughput

If an active Codex task truly requires overlap:

1. stop before changing the overlapping file
2. record the blocker clearly
3. ask for approval or leave a narrow handoff note

### 6. Codex-owned lane rule

Codex's default lane currently includes:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `ui/index.html` only if needed for legacy truth fixes
- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- `api/app/schemas/report_center.py`
- `api/app/routers/runs.py` for report/export/read-model wiring
- docs and validation artifacts for UI/reporting/evidence truth

### 7. Definition of done

Not done:

- code written
- file split
- one passing unit test
- one screenshot
- one local observation
- “looks better”
- “should work now”

Done:

- the relevant UI/report/reporting behavior works on the real relevant path
- truth is canonical across the affected surfaces
- evidence supports the visible claims
- docs/state files are updated
- touched lint/test/validation are clean
- git state is tidy and understandable

### 8. Keep-going rule

Do not stop at:

- analysis only
- a partial refactor
- a plausible fix
- a passing fixture if the real behavior is still unproven
- one failed validation cycle

Keep iterating until:

1. the active Codex-owned task is really proven, or
2. there is a hard blocker with exact evidence

### 9. Hard-blocker rule

Only conclude “blocked” when all are true:

- relevant validations were actually run
- exact failure evidence exists
- the blocking dependency or ownership conflict is precisely named
- further local iteration is unlikely to make progress without new input or
  explicit overlap approval

### 10. Canonical truth rule

Never allow two competing truths to survive in the UI/reporting lane.

If any of these disagree:

- run summary
- findings list
- findings theater
- evidence replay
- report preview
- exported reports
- stored docs / validation artifacts

then resolving that mismatch is higher priority than polishing presentation.

### 11. Evidence-backed reporting rule

LLM assistance in reporting is allowed only for phrasing structured facts.

The LLM must not invent:

- tested scope
- untested components
- findings
- business impact facts not grounded in the structured payload
- remediation facts unsupported by the evidence-backed mapping

Management reports, technical reports, and proof exports must be clearly
separated.

### 12. Modularization rule

Modularization is allowed only when it improves the Codex-owned lane without
crossing into Claude's active lane.

Safe modularization targets include:

- `ui-v2/src/App.tsx`
- `ui-v2/src/store/index.ts`
- `ui-v2/src/api/client.ts`
- UI view-model / adapter layers
- `api/app/services/reports.py`

Modularization does not count as done unless behavior and truth remain proven.

### 13. Validation rule

For each Codex-owned task, run the relevant checks for the touched area.

Minimum expected:

- relevant frontend tests if UI behavior changed
- relevant backend tests if reporting/export logic changed
- `ruff` on touched files
- any available build/type/lint checks for touched UI code
- `git diff --check`

If a task changes visible product truth, produce a durable validation artifact
under `docs/validation/`.

### 14. Repo-state rule

Always update:

- `DONE_LOG.md`
- `CURRENT_STATE.md`

Update `DECISIONS.md` whenever a durable UI/reporting/evidence rule changes.

Do not advance `NEXT_TASK.md` unless the operator explicitly gives Codex control
of the repo-wide active task.

### 15. Git-hygiene rule

Before stopping:

- ensure touched files are cleanly formatted and lint-clean
- remove temporary debug leftovers
- keep diffs narrow and understandable
- leave unrelated dirty files alone
- confirm `git diff --check` is clean

### 16. Final report rule

Always report:

- what active Codex-owned work item was handled
- whether an earlier Codex work item had to be repaired first
- what changed
- what is now actually proven
- exactly which validations were run
- what files were updated
- what the remaining blockers or risks are
- what the next Codex-owned work item should be

### 17. Stop criterion

Codex may stop only when:

- the previous Codex-owned work item is genuinely complete or explicitly
  superseded
- the current Codex-owned work item is genuinely complete or genuinely blocked
  with evidence
- proof, docs, and UI/report truth are consistent
- touched validations are clean
- git is tidy
- the Codex worklist still clearly indicates the next step
