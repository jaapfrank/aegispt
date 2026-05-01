# Continuous Mode

## Purpose

This document defines the first recurring-validation foundation without widening into an arbitrary cron UI, calendar dashboard, or automatic runtime mutation.

## Current first slice

AegisPT now has an additive scheduled-run record under an engagement.
The current API surface supports:

- creating a scheduled run from an existing engagement scope and run profile
- listing scheduled runs for an engagement
- reading one scheduled run
- pausing and resuming a scheduled run
- launching due scheduled runs through an explicit API trigger

The first supported cadence presets are:

- `daily`, stored internally as `0 0 * * *`
- `weekly`, stored internally as `0 0 * * 1`

Schedule records keep:

- engagement lineage
- run profile name
- optional source inventory snapshot
- sanitized run configuration
- cadence and generated cron expression
- status, next run time, pause metadata, and last launched run reference

Due-run launch uses the existing run creation, approval, queueing, pack-binding, and dispatch helpers.
When a profile requires approvals, the scheduled launch creates a `pending_approval` run and does not dispatch tasks.
When a profile has no required approvals, the scheduled launch queues tasks and dispatches them through the configured dispatch mode.

After launch, the schedule advances `next_run_at` past the supplied due time so repeated launch requests for the same due window do not create duplicate runs.
Paused schedules and not-yet-due schedules are ignored by the due-launch path.

## Trend and delta review

AegisPT now has a first scheduled-validation trend and delta review slice on top of stored run history.

History / Comparison can compare a selected scheduled-validation run against a baseline run from the same `scheduled_run_id` lineage and show:

- new findings
- resolved findings, limited to findings absent from the newer stored run or explicitly marked resolved-like in the newer run
- persistent findings based on the existing finding title and target identity
- changed findings when stored severity or status changed for the same finding identity
- inventory drift across hosts, services, and endpoints

Report Center reuses the same selected current/baseline comparison to show whether the selected report posture is backed by a comparable scheduled-validation trend.

Comparability rules are intentionally strict:

- both runs must carry `configuration_json.schedule.source = scheduled-validation`
- both runs must share the same stored `scheduled_run_id`
- runs without schedule lineage, or runs from different schedule records, show an explicit `Trend unavailable` fallback
- trend output is a stored-data comparison only; it is not an absolute risk-reduction claim and does not launch, schedule, approve, or dispatch work

## Future capabilities

- recurring runs
- repeated adaptive pack refresh cycles

## Data reuse

Continuous mode should reuse:

- engagements
- runs
- findings
- inventory snapshots
- report comparison surfaces
- pack provenance
- future customer memory

## Non-goal

Continuous mode does not introduce:

- a background scheduler daemon
- background recurring jobs
- automatic runtime mutation
- arbitrary cron editing
- portfolio calendar or trend dashboards
- absolute risk-reduction guarantees
