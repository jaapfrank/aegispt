# Codex Tasks

Store structured task files here.

The active human-readable task remains in `NEXT_TASK.md`.

Backlog hardening rules:

- `TASK_QUEUE.md` must map one-to-one to the queued `backlog-*.json` task packages in this directory.
- queued backlog packages must stay decision-complete before they are allowed to promote into `NEXT_TASK.md`
- future work should not be added only in prose; it should land as a queue item plus a repo-backed task package
- queue reordering or promotion should be checked with `python3 scripts/validate_backlog_tasks.py`

Backlog package files should include:

- `id`
- `task_file`
- `title`
- `goal`
- `success_criteria`
- `likely_touched_files`
- `must_not_touch`
- `validation`
- `promotion_requirements`
- `out_of_scope`
