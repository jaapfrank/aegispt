# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Multi-agent coordinator (Layer 4) — meta-agent + 6 specialists + confidence-gated delegation + versioned prompt proposals — **Sprint mythos-exploitation-foundation, task 9 of 15**

## Goal

Per Codex Layer 4 + Cyber-AutoAgent meta-everything pattern: ONE meta-agent decides, delegates to specialists (Recon, Hypothesis, ExploitDev, Validator, Memorist, Reporter, Reflector) on confidence < 70%. Per Codex 'no runtime self-modification': prompt/meta-prompt changes are VERSIONED proposals with operator approval, not agent-self-rewrite. Per OpenClaw: per-agent tool allow/deny ACL.

## Sprint context

Task 9 van 15 in sprint `mythos-exploitation-foundation`. backlog-414 DONE — exploit-developer-agent registered and dispatchable. Tijd om alle specialists onder één coordinator te zetten: Recon, Hypothesis, ExploitDev (414), Validator (413), Memorist (410), Reporter, Reflector. Picker wordt de Meta-Coordinator die delegeert; specialists hebben elk eigen tool-ACL.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/agents/coordinator.py` met `MetaCoordinator` class + 6 specialist roles + per-agent tool ACL + `prompts/proposals/` directory voor versioned prompt changes met `approve_prompt_change()`. Delta-metric: ≥2 specialist agents leveren aantoonbaar betere chain-findings dan single picker op dezelfde XBOW subset.

## Scope

(1) `api/app/agents/coordinator.py`:
- `MetaCoordinator` met KNOW→THINK→TEST→VALIDATE loop.
- `delegate(specialist, context, hypothesis)` → routes to one of: Recon/Hypothesis/ExploitDev/Validator/Memorist/Reporter/Reflector.
- Per-specialist `SpecialistACL` met `tools_allow` / `tools_deny` (OpenClaw pattern).
- Confidence gating: `coordinator_confidence < 0.70` triggers delegation to the appropriate specialist instead of direct action.

(2) `api/app/agents/specialists/`:
- 6 module files (recon.py / hypothesis.py / exploit_dev.py / validator.py / memorist.py / reporter.py / reflector.py).
- Each specialist has its own prompt scope + tool ACL.
- ExploitDev specialist wraps backlog-414's composer; Validator wraps backlog-413; Memorist wraps backlog-410.

(3) `prompts/proposals/` directory:
- New file format: `prompts/proposals/{date}-{specialist}-rev{N}.md`.
- `approve_prompt_change(proposal_file, approver)` API endpoint — moves the proposal into `prompts/active/{specialist}.md` after operator approval.
- Runtime self-modification by agents FORBIDDEN — every prompt update goes through this gate.

(4) Tests `api/tests/test_coordinator.py`:
- Confidence-gated delegation routes to the expected specialist.
- Per-agent ACL blocks tools outside the allowlist.
- Versioned prompt proposal flow (write → review → approve → activate).
- Multi-agent vs single-picker on a synthetic chain (smoke).

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = ≥2 specialist agents produce demonstrably better chain-findings than single picker on the same XBOW subset.
- Per Rule 2: coordinator dispatched from `_claude_select_next_action` (or replaces it) in the same commit.
- Per Rule 3: where the picker previously did Recon+Hypothesis+ExploitDev inline, those paths route to specialists; cite diff.
- Per Rule 4: live verification via XBOW run with ≥1 coordinator-orchestrated chain.
- `no_runtime_self_modification`: agents NEVER overwrite their own prompts at runtime. All prompt changes go through `prompts/proposals/` + operator approval.

## Source Package

`codex/tasks/backlog-415-multi-agent-coordinator-versioned-prompts.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED: coordinator dispatched on live picker advance
- [ ] Delta-metric: ≥2 specialists produce better chain-findings than single picker (cite test or trace)
- [ ] Removed code: cite picker inline paths that moved to specialists
- [ ] Geen scope creep: coordinator + 6 specialist modules + proposals dir + tests
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: trace evidence link

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_coordinator.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/agents/`
- `git diff --check`
- Live: ≥1 XBOW challenge run uses ≥2 specialists end-to-end.
