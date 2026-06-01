# Claude Universal Execution Contract

Purpose: keep the long-form execution discipline in-repo and versioned, so the
operator can use a SHORT launcher prompt instead of pasting a huge wall of text
 into every session.

## Short launcher prompt

Use this as the short prompt in a new Claude session:

```text
Use /docs/strategy/claude-universal-execution-contract.md as your execution contract for this session.

Start by checking whether the previous active task is truly complete in behavior, proof, findings, docs, and repo state.
- If it is not complete, fix that first.
- If it is complete, continue with the current active task from NEXT_TASK.md.
- If the current active task becomes fully proven complete, advance NEXT_TASK.md from TASK_QUEUE.md so exactly one active task remains.

Follow the contract strictly. Do not stop at code changes, partial fixes, or one passing test. Keep working until the relevant behavior is actually proven, the repo state/docs are correct, all relevant validations pass, all lint errors in touched files are fixed, git is cleanly updated, and the result is ready for honest closure.
```

## Full execution contract

### Current focus

Check first whether the previous active task is truly, fully, and provably
complete.

- If it is NOT complete, repair and finish that first.
- If it IS complete, continue with the current active task from `NEXT_TASK.md`.
- If the current active task then becomes fully proven complete, immediately
  advance the next approved task from `TASK_QUEUE.md` into `NEXT_TASK.md` and
  leave exactly one active task there.

### General rule

Work under `AGENTS.md`, `ANTI_DRIFT.md`, `SESSION_PROMPT.md`, and all repository
instructions. Treat this as a strict delivery contract. Code changes alone do
not count; only proven behavior counts.

### Mandatory start order

1. Read:
   - `CURRENT_STATE.md`
   - `NEXT_TASK.md`
   - `DECISIONS.md`
   - `TASK_QUEUE.md`
   - `DONE_LOG.md`
   - `ANTI_DRIFT.md` if present
   - all files directly affected by the previous task or current task
2. Determine:
   - what the previous active task was
   - what the current active task is
   - what "done" means for both in behavior, proof, findings, docs, and repo
     state
3. Verify the previous task in reality:
   - does the real behavior work?
   - do `CURRENT_STATE.md`, `DONE_LOG.md`, `NEXT_TASK.md`, findings, artifacts,
     transcripts, and score claims agree?
   - is there any gap between claim and reality?
4. If there is any gap, fix that first.
5. Only then continue the current active task.

### Definition of done

Not done:

- code written
- test added
- one local run seen
- one passing harness-only run
- one log line seen
- "should work"
- "likely fixed"
- "all tests green" / "run SOLVED" / exit_code 0 — WITHOUT auditing the
  individual tool calls inside the run (see "Tool-call quality audit")

Done:

- the requested behavior works on the real relevant path
- the claim is supported by appropriate evidence
- findings / score / transcripts / artifacts / docs are consistent
- docs and state files are updated
- lint / tests / validation are clean
- git state is intentional and tidy
- no known inconsistent residue is left behind

### If it does not work: keep going

- Do not stop at analysis only.
- Do not stop at a partial fix.
- Do not stop after one failed validation.
- Do not stop at "probably good now."
- Use each error, regression, mismatch, or failed run as the input to the next
  iteration.
- Keep iterating until:
  1. it really works and is proven, or
  2. you have a demonstrable hard blocker with exact evidence.

### Hard blocker rule

You may conclude "blocked" only if ALL are true:

- you ran the relevant validations
- you have exact failing command / artifact / output evidence
- you can point to the blocker precisely
- you can explain why more local iteration is not realistically likely to make
  progress

Never use "blocked" merely because something is difficult, broad, messy, or
unfinished.

### Evidence rule

Important claims must be backed by relevant evidence, such as:

- passing tests
- grader-verified solve
- findings API evidence
- transcript artifact
- replay artifact
- `docs/validation` artifact
- real product-path validation
- explicit before/after comparison

If something is a solve / finding / benchmark / production claim, it only counts
when the end-to-end chain is complete:

- execution is correct
- verifier / grader is correct where applicable
- finding persisted where applicable
- transcript / scope provenance exists where applicable
- the score source is canonical and non-contradictory

### Tool-call quality audit (MANDATORY — never skip)

A run that "succeeds" (solved=true / all-green / exit_code 0) can still be full of
broken or no-op tool calls. exit_code 0 is NOT proof a tool did anything useful.
A run may solve via ONE tool while every other tool silently fails — and that does
NOT count as a clean run.

Before claiming ANY run / task done you MUST inspect the INDIVIDUAL tool calls,
not just the terminal status:

- enumerate every tool execution in the run (e.g. `tool_executions` joined to
  `tasks` for the run_id): per tool, its exit_code AND a sample of its stdout.
- audit INPUTS: malformed args? a URL where a host/IP is expected? a port-less or
  scheme-prefixed target? wrong flags for the intent (e.g. `-sn` when a port scan
  was wanted)?
- audit OUTPUTS for silent no-ops / failures, including (non-exhaustive):
  - nmap: `0 hosts up` / `0 IP addresses scanned`, or host-up with no ports.
  - target-intel: `service_port_unknown` / empty technology_stack / empty analysis.
  - content-discovery / recon: `finding_count: 0` with no explanation.
  - interactive-exploit: rising `tool_errors`, `stop=too_many_tool_errors`.
  - any tool output beginning `{"error":` or an empty/blank body.
- if a tool call is broken or no-op, REPORT IT explicitly (even when the run
  solved) and fix it or log it as an open gap with evidence — do not bury it under
  "SOLVED / done". "All tests green" is a claim about tests, not about the run's
  tool calls; verify both.

This audit is part of the definition of done and the mandatory final check.

### Canonical truth

Never leave two competing truths alive.

If stdout, grader, findings table, transcript, docs, or state files disagree:

- resolve the mismatch first, or
- explain exactly which source is canonical and why

Do not claim success while that conflict remains open.

### Relevant-path validation

Validate on the real relevant path:

- product path if the claim is about product behavior
- not only a standalone harness if that does not cover the claim
- not only unit tests if runtime behavior is central

Keep running until the result is stable, not anecdotal.

### Lint / test / hygiene requirements

Leave no sloppiness behind.

Minimum required:

- relevant pytest for changed behavior
- `compileall` on relevant Python code
- `ruff`
- `git diff --check`
- all repo-specific validations relevant to the task

Required:

- all lint errors in touched files must be fixed
- no new lint errors may be introduced
- touched areas must be left fully clean
- if pre-existing lint problems remain elsewhere, prove that baseline exactly
  and still leave touched files clean
- "almost clean" is not acceptable

### Git / repo state must be tidy

Always update the repository cleanly:

- update `DONE_LOG.md`
- update `CURRENT_STATE.md`
- update `DECISIONS.md` if a durable decision was made
- if the active task is truly complete:
  - move the next approved task from `TASK_QUEUE.md` into `NEXT_TASK.md`
  - ensure exactly one active task remains in `NEXT_TASK.md`
- remove temporary debug leftovers
- keep `git diff` intentional and understandable
- keep `git diff --check` clean

### Commit rule

- Do not commit automatically if repo or user rules do not allow it.
- If commits are explicitly wanted or allowed, commit only once a logical unit
  is fully proven and clean.
- If you do not commit, still leave a tidy and understandable worktree.

### Working style

- Choose the smallest fix that measurably moves user value.
- Do not perform a broad architecture rewrite unless the task explicitly calls
  for it or a measured metric proves it is necessary.
- No theater, no decorative refactors, no "one more prompt" in place of real
  execution work.
- Do not add new providers, paths, or complexity without a clear need tied to
  the active task.

### Mandatory final check

Before stopping, explicitly verify:

- is the previous task now truly complete and proven?
- is the current task now truly complete and proven?
- does the requested behavior work on the relevant path?
- is the evidence complete?
- **did I audit the individual tool calls inside the run (inputs + outputs), not
  just solve-status / exit_code / "tests green"? did I report any broken or no-op
  tool call instead of burying it?** (see "Tool-call quality audit")
- are docs and state files updated?
- are findings / score / transcript / artifacts consistent?
- are lint / tests / validations clean?
- is git tidy?
- if the current task is complete, is `NEXT_TASK.md` advanced correctly?

### Mandatory final report

Always report:

- which previous task needed repair first, if any
- what changed
- what is now proven
- exactly which validations were run
- what the canonical score / truth is
- which files were updated
- what the final git status is
- which task is now active next
- any remaining residual risks or blockers

### Stop criterion

You are only finished when:

- the previous task is provably correct
- the current task is provably correct
- evidence, docs, findings, and score are consistent
- lint / tests / validation are clean
- the repo is left tidy
- and the next task is correctly staged if the current one is fully complete
