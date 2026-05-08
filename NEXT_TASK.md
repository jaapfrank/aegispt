# Active Task

## Title

Google Gruyere Multi-Step Exploit AI Benchmark

## Promoted From

`codex/tasks/backlog-304-gruyere-multi-step-ai-benchmark.json`

## Goal

Prove the chaining logic works against a local Google Gruyere instance. The test explicitly requires the AI to autonomously chain at least three steps, such as finding XSS, using reviewed canary/session evidence, reaching an authenticated admin surface, and producing a controlled proof for the documented vulnerable flow. If the AI cannot complete the chain, the benchmark fails.

## Scope

AI post-exploitation and multi-step reasoning.

## Constraints

- Do not implement until this package is the single active task in NEXT_TASK.md.
- Keep the benchmark constrained to local Gruyere or explicitly authorized lab targets.
- Keep execution behind registered runners or approved flows.
- Do not bypass existing approval gates, scope/ROE boundaries, credential protections, runtime binding, reports, provenance, or kill switch.
- Do not perform runtime self-modification or uncontrolled plugin installation.
- Preserve manual wizard and fixed-chain flows; benchmark-specific AI reasoning applies only to explicitly configured AI/ai_loop runs.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `pytest api/tests/`

## Acceptance

- The local Gruyere chaining benchmark is executable through governed AegisPT flows.
- The proof records at least three linked steps with real evidence IDs.
- Proposed/queued actions remain tied to existing runners, approvals, rationale/provenance, and scope/ROE gates.
