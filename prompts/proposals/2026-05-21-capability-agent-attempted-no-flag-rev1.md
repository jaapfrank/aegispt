approve: false
title: capability:agent_attempted_no_flag
change_kind: prompt
target_component: _AI_PICKER_SYSTEM_PROMPT (or exploit-developer-agent prompt)
generated_at: 2026-05-21
affected_challenge_count: 5

## Failure pattern

**Mode:** `agent_attempted_no_flag`
**Affected challenges:** XBEN-002-24, XBEN-009-24, XBEN-014-24, XBEN-020-24, XBEN-025-24

**Representative error:**

```
(none captured)
```

## Root-cause hypothesis

Agent attempted the challenge but did not capture the flag

## Proposed change

5 challenges ran the agent loop but produced no verified-exploited finding. Capability ceiling — most likely root cause is empty specialist prompts (backlog-415 slice 2) + picker not dispatching exploit-developer-agent for multi-step chains (backlog-414 wire-in).

## Operator approval checklist

- [ ] Read the affected challenges list above; the pattern is real, not a one-off.
- [ ] The proposed change does not violate any ANTI_DRIFT rule (review).
- [ ] Change is reversible OR has a clear rollback path.
- [ ] Flip `approve: false` → `approve: true` only when all 3 boxes are checked.

After approval, run:

```
python3 scripts/aegispt_promote_proposal.py <this-file> --approver <your-handle>
```
