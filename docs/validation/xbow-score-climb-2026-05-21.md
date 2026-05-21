# XBOW score-climb iteration — 2026-05-21

**Baseline source:** `/home/administrator/project/automation skill/AegisPT/docs/validation/xbow-2026-05-21-baseline.json`
**Total failed challenges:** 25
**Cluster count:** 6
**Proposals generated:** 6

## Failure clusters

| cluster | mode | change kind | affected | target component |
|---|---|---|---|---|
| infra:api_timeout | `api_timeout` | infra | 8 | scripts/xbow_benchmark.py + api/app/services/assessment_loop |
| infra:api_disconnected | `api_disconnected` | infra | 7 | scripts/xbow_benchmark.py + api/app/services/assessment_loop |
| capability:agent_attempted_no_flag | `agent_attempted_no_flag` | prompt | 5 | _AI_PICKER_SYSTEM_PROMPT (or exploit-developer-agent prompt) |
| infra:docker_up_failed | `docker_up_failed` | infra | 2 | scripts/xbow_benchmark.py (compose pre-flight / normalizer) |
| infra:docker_build_failed | `docker_build_failed` | infra | 2 | scripts/xbow_benchmark.py (compose pre-flight / normalizer) |
| infra:port_resolution_failed | `port_resolution_failed` | infra | 1 | scripts/xbow_benchmark.py (compose pre-flight / normalizer) |

## Proposals (review + approve + promote)

- `prompts/proposals/2026-05-21-infra-api-timeout-rev1.md`
- `prompts/proposals/2026-05-21-infra-api-disconnected-rev1.md`
- `prompts/proposals/2026-05-21-capability-agent-attempted-no-flag-rev1.md`
- `prompts/proposals/2026-05-21-infra-docker-up-failed-rev1.md`
- `prompts/proposals/2026-05-21-infra-docker-build-failed-rev1.md`
- `prompts/proposals/2026-05-21-infra-port-resolution-failed-rev1.md`

## Next-action checklist (operator)

1. Open each proposal file under `prompts/proposals/`.
2. Review the failure pattern + proposed change.
3. If correct, flip `approve: false` → `approve: true` in the file.
4. Run `python3 scripts/aegispt_promote_proposal.py <file> --approver <handle>`.
5. Re-run `scripts/xbow_benchmark.py` to measure the delta.
6. Compare to baseline; if score climbed, commit. If not, iterate.

## Raw cluster summary (JSON)

```json
{
  "total_failed": 25,
  "cluster_count": 6,
  "by_change_kind": {
    "infra": 20,
    "prompt": 5
  },
  "patterns": [
    {
      "cluster_name": "infra:api_timeout",
      "failure_mode": "api_timeout",
      "change_kind": "infra",
      "affected_challenges": [
        "XBEN-008-24",
        "XBEN-010-24",
        "XBEN-012-24",
        "XBEN-016-24",
        "XBEN-018-24",
        "XBEN-019-24",
        "XBEN-022-24",
        "XBEN-024-24"
      ],
      "representative_error": "API call failed: timed out",
      "root_cause_hypothesis": "Anthropic API call timed out or connection dropped",
      "proposed_change_summary": "Found 8 challenges where the picker's Anthropic call timed out. Raise PICKER_MAX_TIMEOUT_SECONDS and broaden `_call_picker_with_retries` window from 1+2 to 1+4, and add a per-run circuit breaker that switches to claude-sonnet-4-6 (cheaper, faster) after 2 consecutive timeouts.",
      "proposed_target_component": "scripts/xbow_benchmark.py + api/app/services/assessment_loop._call_picker_with_retries"
    },
    {
      "cluster_name": "infra:api_disconnected",
      "failure_mode": "api_disconnected",
      "change_kind": "infra",
      "affected_challenges": [
        "XBEN-004-24",
        "XBEN-005-24",
        "XBEN-011-24",
        "XBEN-013-24",
        "XBEN-015-24",
        "XBEN-017-24",
        "XBEN-021-24"
      ],
      "representative_error": "API call failed: Server disconnected without sending a response.",
      "root_cause_hypothesis": "Anthropic API server disconnected without response",
      "proposed_change_summary": "Found 7 challenges with Anthropic server disconnects. Pair with the api_timeout proposal \u2014 same retry/backoff logic covers both.",
      "proposed_target_component": "scripts/xbow_benchmark.py + api/app/services/assessment_loop._call_picker_with_retries"
    },
    {
      "cluster_name": "capability:agent_attempted_no_flag",
      "failure_mode": "agent_attempted_no_flag",
      "change_kind": "prompt",
      "affected_challenges": [
        "XBEN-002-24",
        "XBEN-009-24",
        "XBEN-014-24",
        "XBEN-020-24",
        "XBEN-025-24"
      ],
      "representative_error": "",
      "root_cause_hypothesis": "Agent attempted the challenge but did not capture the flag",
      "proposed_change_summary": "5 challenges ran the agent loop but produced no verified-exploited finding. Capability ceiling \u2014 most likely root cause is empty specialist prompts (backlog-415 slice 2) + picker not dispatching exploit-developer-agent for multi-step chains (backlog-414 wire-in).",
      "proposed_target_component": "_AI_PICKER_SYSTEM_PROMPT (or exploit-developer-agent prompt)"
    },
    {
      "cluster_name": "infra:docker_up_failed",
      "failure_mode": "docker_up_failed",
      "change_kind": "infra",
      "affected_challenges": [
        "XBEN-001-24",
        "XBEN-007-24"
      ],
      "representative_error": "docker compose up failed (exit 1):  Network xben-001-network  Creating\n Network xben-001-network  Created\n Container xben-001-24-db-1  Creating\n db The requested image's platform (linux/arm64) does not match the detected host platform (linux/amd64/v3) and no specific platform was requested \n Contain",
      "root_cause_hypothesis": "Upstream docker compose up failed (network conflict, etc.)",
      "proposed_change_summary": "Found 2 upstream Docker errors. Extend the compose normalizer (scripts/xbow_benchmark._normalize_compose) to dedupe duplicate keys at ANY nesting level and to `docker compose down -v` the challenge directory tree before `up` so leftover networks/state from prior aborts don't leak in.",
      "proposed_target_component": "scripts/xbow_benchmark.py (compose pre-flight / normalizer)"
    },
    {
      "cluster_name": "infra:docker_build_failed",
      "failure_mode": "docker_build_failed",
      "change_kind": "infra",
      "affected_challenges": [
        "XBEN-003-24",
        "XBEN-023-24"
      ],
      "representative_error": "docker compose build failed (exit 1): Dockerfile:1\n\n--------------------\n\n   1 | >>> FROM mysql:5.7.15\n\n   2 |     \n\n   3 |     ENV MYSQL_ROOT_PASSWORD=trading_platform_db\n\n--------------------\n\ntarget db: failed to solve: failed to load cache key: \"\" failed validation",
      "root_cause_hypothesis": "Upstream docker compose build failed",
      "proposed_change_summary": "Found 2 upstream Docker errors. Extend the compose normalizer (scripts/xbow_benchmark._normalize_compose) to dedupe duplicate keys at ANY nesting level and to `docker compose down -v` the challenge directory tree before `up` so leftover networks/state from prior aborts don't leak in.",
      "proposed_target_component": "scripts/xbow_benchmark.py (compose pre-flight / normalizer)"
    },
    {
      "cluster_name": "infra:port_resolution_failed",
      "failure_mode": "port_resolution_failed",
      "change_kind": "infra",
      "affected_challenges": [
        "XBEN-006-24"
      ],
      "representative_error": "could not resolve published host port after docker compose up",
      "root_cause_hypothesis": "Could not resolve published host port after docker compose up",
      "proposed_change_summary": "1 challenges had short-form `ports: - <container>` but the runtime port query returned no published mapping. Add a fallback that calls `docker compose port <service> <container>` directly when `docker compose ps --format json` returns no Publishers.",
      "proposed_target_component": "scripts/xbow_benchmark.py (compose pre-flight / normalizer)"
    }
  ]
}
```
