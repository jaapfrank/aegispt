# Active Task

## Title

Fix Surface Map showing empty canvas after completed discovery run; improve empty state messaging

## Promoted From

`codex/tasks/backlog-163-surface-map-empty-after-discovery-run.json`

## Goal

When an engagement has a completed discovery run with an inventory snapshot containing hosts and services, the Surface Map canvas should visualize those hosts as nodes. If visualization is not feasible in this slice, at minimum improve the empty state so it explains why the map is empty and which run type populates it, for example: `Run a Passive Network Discovery scan to map your assets here`. The Asset Browser tabs should reflect available inventory counts from the snapshot.

## Scope

Implement the active backlog package `codex/tasks/backlog-163-surface-map-empty-after-discovery-run.json`.

Expected slice:

- inspect the Surface Map and inventory/mission data flow
- show discovered inventory hosts/services as map nodes when snapshot data is available
- make the no-inventory empty state context-aware and actionable
- make Asset Browser counts reflect available inventory host/service data
- avoid broad Surface Map redesign or unrelated Mission Control changes

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Fix only the specific bug described.
- Do not use this task for broad redesign.
- Do not install new tools.
- Do not run live customer or intrusive targets.
- Do not change unrelated schemas or prompts.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- If inventory snapshot has hosts/services: Surface Map canvas shows discovered hosts as nodes.
- If no inventory exists: empty state explains what run type would populate the map.
- Asset Browser reflects inventory host/service counts when data is available.
- No regression in surface map E2E tests.
