# ROE Policy Compiler

The ROE policy compiler turns existing run, scope, approval, authorization, rate-limit,
credential, runner-contract, and kill-switch state into a single machine-checkable decision
payload.

It is intentionally read-only. The compiler does not dispatch runners, mutate scope, grant or
reject approvals, materialize credentials, change credential storage, edit runner registries, or
modify runtime behavior.

## Decisions

The compiler returns exactly one of these states:

- `allow`: target is allowlisted, not denylisted, kill switch is clear, and no current policy gate requires a wait or approval.
- `deny`: target is outside the allowlist or matches the denylist.
- `approval_required`: target is in scope, but the requested tier or existing approval gate needs operator approval before execution planning may proceed.
- `wait_for_prerequisite`: required planning inputs such as scope or target are missing.
- `kill_switch_blocked`: the execution kill switch is enabled, so planning and dispatch explanations are blocked.

## Payload Shape

Each payload includes:

- `source_policy_ids` for the run, engagement, scope allowlist/denylist, run profile, runner contract, and kill-switch source where applicable.
- `target_normalization` with raw, normalized, host, kind, allowlist result, and denylist result.
- `affected_action` with runner, action type, requested risk tier, profile risk tier, and runner contract ID.
- `rate_limits` from the existing run-profile normalization.
- `credential_policy` stating that plaintext credentials are not allowed and only existing secret refs may be materialized by runtime.
- `authorization` derived from existing mission configuration and access prerequisites.
- `approval_state` from existing run approvals and runner-contract approval metadata.
- `execution_contract` and `provenance` flags proving analysis-only behavior.
- an operator-readable `explanation`.

## Reuse

Operators and UI code can fetch the shared payload through:

`GET /api/v1/runs/{run_id}/roe-policy`

The AI next-best-action selector also attaches the same payload as `roe_policy_decision` on
selector actions. The selector treats policy as tightening input only: kill-switch and missing
prerequisites force `WAIT`, out-of-scope targets force `SKIP`, and approval-required policy can
upgrade executable actions to `APPROVAL` without overriding an existing prerequisite `WAIT`.

## Boundaries

- The compiler never expands scope.
- Full authorization may confirm a requested tier for policy explanation, but existing profile and runner approval gates remain visible and cannot be bypassed.
- Denylist matches override allowlist matches.
- Credential handling remains secret-ref-only; no new credential storage path is introduced.
- The endpoint is tenant scoped through the existing run tenancy guard.
