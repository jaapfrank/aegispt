# AegisPT Agents Guide

## Mission

AegisPT is an evidence-first, AI-assisted penetration testing platform. The repository is the single source of truth for future Codex-driven development, and the Codex build lane is the only place where autonomous change preparation is allowed.

## Hard constraints

- Treat Prompt 1 and Prompt 2 as complete and authoritative.
- Do not redefine PTES, OWASP WSTG, NIST SP 800-115, or optional ASVS mappings already present.
- Do not change existing finding schema fields unless a future task explicitly allows it.
- Do not bypass the existing capability pack registry, validation pipeline, approval flow, or runtime binding flow.
- No runtime self-modification during active assessments.
- No uncontrolled plugin installation.
- Prefer additive changes and reuse existing models, provenance fields, and reporting structures.
- Keep the runtime deterministic and safe.

## Required reading before work

Always read:

- `CURRENT_STATE.md`
- `NEXT_TASK.md`
- `DECISIONS.md`

Use these files to determine current architecture, constraints, and the exact active task. Do not infer a broad roadmap from memory when the repository already defines it.

## Required updates after work

Always update:

- `DONE_LOG.md`
- `CURRENT_STATE.md`

When the active task completes, also:

- move the next approved task from `TASK_QUEUE.md` into `NEXT_TASK.md`
- keep exactly one active task in `NEXT_TASK.md`

## Build-lane operating model

- Codex operates in the repository and supervised build lane only.
- Codex may generate patches, refine exported pack artifacts, improve tests, or prepare validation handoff.
- Codex must use the existing pack validation, approval, deployment, and runtime binding hooks rather than inventing a second lane.

## Safety boundaries

- Never install or execute new capabilities during active runs.
- Never change live runtime behavior from a Codex task.
- Never bypass scope or safety limits already enforced by the platform.
- Never overwrite protected Prompt 1 or Prompt 2 foundations with duplicative layers.

## Working conventions

- Use structured tasks from `docs/codex_task_interface.md`.
- Prefer repo-backed tasks under `codex/tasks/` and results under `codex/results/`.
- Record rationale and file impact in `DONE_LOG.md`.
- Keep decisions durable in `DECISIONS.md`.

## Architecture hooks

Future hooks for attack paths, identity-aware testing, risk scoring, continuous mode, customer memory, and integrations are placeholders only until explicitly activated by a future task.
