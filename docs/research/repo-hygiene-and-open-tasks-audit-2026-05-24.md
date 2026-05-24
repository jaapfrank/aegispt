# Repo hygiene and open tasks audit

Date: 2026-05-24

Goal: inspect the current AegisPT system, open task state, dirty worktree, and likely stale/old files. This is an audit only. No cleanup or runtime behavior changes were performed.

## Executive finding

The repo is currently not in a healthy build-lane state. The biggest issue is not "old code" in the normal sense; it is task/source-of-truth drift plus half-landed work.

Top risks:

1. `scripts/validate_backlog_tasks.py` fails hard.
2. `codex/tasks/` has 390 modified tracked JSON files.
3. `TASK_QUEUE.md` has open items 389 and 390 without task-package file references.
4. `api/app/services/codex_tasks.py` now persists normalized legacy task payloads back to disk while reading, which appears to have stripped required task-package fields from hundreds of files.
5. Several tracked runtime files import untracked modules, so a partial commit would break clean checkout/runtime.
6. Legacy UI (`ui/`) is still mounted at `/app` alongside React v2 at `/app-v2`; old test/docs references remain.
7. The working directory contains many generated/local artifacts that should be ignored, cleaned, or promoted intentionally.

## Current open task truth

`NEXT_TASK.md` says:

- no queued task remains after queue item #388
- wait for operator selection

`TASK_QUEUE.md` says something different:

- items 389 and 390 exist, both open
- neither references a backlog task JSON file in backticks
- validator errors:
  - `TASK_QUEUE.md item 389 must reference exactly one backlog task file in backticks`
  - `TASK_QUEUE.md item 390 must reference exactly one backlog task file in backticks`

My queue parse found:

- total queue items: 390
- done: 311
- open: 55
- deferred: 16
- closed: 5
- blocked: 3

Important nuance: many historical items 321-338 are marked open in queue text even though `CURRENT_STATE.md`/`DONE_LOG.md` describe them as completed. So the queue is not currently a reliable status ledger without manual interpretation.

## Validator failure

Command:

```bash
python3 scripts/validate_backlog_tasks.py
```

Result: failed.

Root causes observed:

- queue items 389/390 lack task-package references
- hundreds of `codex/tasks/backlog-*.json` now miss required fields such as:
  - `title`
  - `goal`
  - `success_criteria`
  - `likely_touched_files`
  - `must_not_touch`
  - `validation`
  - `promotion_requirements`
  - `out_of_scope`

Likely cause:

- `api/app/services/codex_tasks.py` changed `_load_task_from_path()` so legacy task normalization is written back to the task JSON file
- this mutates repo source files during read/list operations
- the normalized `CodexTaskRead` shape is not the same as the stricter backlog package schema required by `validate_backlog_tasks.py`

This should be treated as priority-zero repository repair.

## Dirty worktree snapshot

Task files:

- 390 modified tracked files under `codex/tasks`
- 1 untracked task JSON
- 541 tracked `codex/tasks/*.json` files total

Runtime/code files with modifications:

- `api/app/config.py`
- `api/app/routers/runs.py`
- `api/app/services/assessment_loop.py`
- `api/app/services/chatgpt_oauth.py`
- `api/app/services/codex_tasks.py`
- `api/app/services/llm_provider.py`
- `api/app/services/narrator.py`
- `api/app/services/scheduled_runs.py`
- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `workers/orchestration/tasks.py`
- `workers/runners/exec_plan/runner.py`

Untracked but runtime-relevant code:

- `api/app/services/m2_verdict_gate.py`
- `api/app/services/picker_specialists/`
- `workers/runners/code_exec_attack/`
- `workers/runners/pre_recon_cpg/`
- `workers/runners/pre_recon_source/`
- `workers/runners/recon_deliverable/`

Problem:

- tracked files import some of these untracked modules
- a commit/push that omits the untracked modules would break clean checkout
- these should either be promoted with task packages/tests or the tracked imports should be removed before committing

## Old / duplicated surfaces

### Legacy UI

The app still mounts:

- `ui/` at `/app`
- `ui-v2/dist` at `/app-v2`

`ui/` is not dead:

- 33 tracked files under `ui`
- legacy UI tests still exist and are referenced
- API tests still read `ui/assets/modules/wizard.js` and `ui/assets/modules/packs.js`
- docs still reference old UI validation/checklists

Recommendation:

- do not delete `ui/` casually
- create an explicit "Legacy UI retirement or freeze" task
- decide whether `/app` redirects to `/app-v2`, remains support-only, or becomes archived static reference

### Task backlog

The backlog has become too large and too mutable:

- `codex/` has 829 tracked files
- `codex/tasks` dominates the repo shape
- task package JSON files are currently both source-of-truth and mutable app data

Recommendation:

- protect `codex/tasks/backlog-*.json` from runtime writes
- move old completed task packages into an archive format only after validator supports it
- split "task package source-of-truth" from "UI listable Codex task record"

## Local/generated clutter

Repo working directory size:

- total: 3.4G
- `.venv`: 933M
- `.playwright`: 622M
- `.playwright-browsers`: 622M
- `ui-v2/node_modules`: 428M
- `.aegispt-artifacts`: 393M
- `ui/test-results`: 288M
- `codex/results`: 33M
- `workspace`: 1.3M

Most of this is local dependency/test/runtime material and should not be committed. The duplicate Playwright directories are a cleanup candidate if not both required.

Untracked local/dev files worth classifying:

- `.claude/scheduled_tasks.lock`
- `.diag-mythos-promise.py`
- `baseline.json`
- `scripts/exploit_xben_002_via_cpg_chain.py`
- `scripts/test_m*_directly.py`
- `scripts/drive_remote_target.py`
- `scripts/finalize_zombie_runs.py`
- `scripts/probe_chatgpt_model_params.py`
- `scripts/probe_chatgpt_picker_latency.py`
- `scripts/verify_vault_persist_inject.py`
- `workspace/aegispt-cpg-*`

Recommendation:

- convert useful direct scripts into proper `scripts/tests` or `docs/validation` artifacts
- add ignored scratch/runtime paths to `.gitignore` if missing
- remove or archive experiment scripts once their evidence has been captured

## Large modules / code smells

Largest Python files:

- `api/app/services/reports.py`: 7681 lines
- `api/app/services/assessment_loop.py`: 6680 lines
- `api/app/services/runs.py`: 5946 lines
- `workers/orchestration/tasks.py`: 5524 lines
- `workers/orchestration/findings.py`: 2538 lines
- `api/app/services/auth_discoverer.py`: 2405 lines

These files are too large for reliable agent-driven maintenance. The problem is not purely style: huge modules make it easy to hide broken imports, duplicate gates, and unrelated side effects.

Recommendation:

- split `assessment_loop.py` into provider, picker schema, specialist orchestration, loop-state, fallback, attack-state, and dispatch decision modules
- split `workers/orchestration/tasks.py` into registry, dispatch adapters, task lifecycle, vault persistence, and post-task AI callbacks
- split `reports.py` by report variant/rendering concern

## Recommended cleanup tasks

1. **Priority 0: Restore task-package integrity**
   - revert or repair the mass-normalized `codex/tasks/*.json`
   - remove write-back behavior from `api/app/services/codex_tasks.py`
   - create proper task packages for queue items 389/390 or remove those queue entries
   - acceptance: `python3 scripts/validate_backlog_tasks.py` passes

2. **Priority 1: Land or remove half-landed runtime work**
   - classify untracked modules imported by tracked files
   - either commit them with tests/task evidence or remove their tracked imports
   - acceptance: clean checkout can import API/workers without missing modules

3. **Priority 2: Backlog status reconciliation**
   - reconcile `TASK_QUEUE.md`, `NEXT_TASK.md`, `CURRENT_STATE.md`, and `DONE_LOG.md`
   - mark completed Mythos items consistently
   - decide whether items 345-384 are active future work, deferred, done, or superseded

4. **Priority 3: Legacy UI retirement/freeze**
   - decide `/app` vs `/app-v2` product authority
   - move remaining old UI tests/docs to archive or migration suite
   - acceptance: one documented UI authority and one validation lane

5. **Priority 4: Scratch/artifact cleanup policy**
   - add/verify ignores for local DBs, CPG workspace outputs, Playwright output, direct one-off scripts
   - add a `make clean-local` or documented cleanup script
   - acceptance: `git status --short` no longer shows generated/local-only artifacts after normal runs

6. **Priority 5: Split oversized modules**
   - start with `assessment_loop.py` and `workers/orchestration/tasks.py`
   - acceptance: no behavior change, focused unit tests still pass, import graph clearer

## Practical next move

Do not start a new feature task yet.

The next approved task should be a repository repair task:

> Restore backlog/task-package integrity and stop runtime task listing from mutating repo task JSON.

After that, run the validator and only then decide what the next product task is.
