# Picker A/B Comparison

- Mode: `dry-run`
- Target: `dry-run://picker-ab-fixture`
- Evidence fixture: `picker-ab-dry-run-v1`
- Generated: `2026-05-21T15:09:24.208786+00:00`
- Winner claim: none; this report records measured deltas only.

## Provider Results

### claude

- Run ID: `dry-run-claude`
- Provider config: `{"llm_provider": "claude-opus-4-7"}`
- Findings: `1`
- High/Critical findings: `1`
- Canary delta: `1`
- Proof delta: `1`
- Failure reasons: `none`

| Step | Action | Tool | Target | Confidence | Failure reason |
|---:|---|---|---|---:|---|
| 1 | pick | target-intel | dry-run://picker-ab-fixture | 0.74 |  |
| 2 | exec_plan | exec-plan | dry-run://picker-ab-fixture | 0.68 |  |

### chatgpt_oauth

- Run ID: `dry-run-chatgpt-oauth`
- Provider config: `{"llm_provider": "chatgpt_oauth", "model": "gpt-5.4"}`
- Findings: `1`
- High/Critical findings: `1`
- Canary delta: `1`
- Proof delta: `1`
- Failure reasons: `none`

| Step | Action | Tool | Target | Confidence | Failure reason |
|---:|---|---|---|---:|---|
| 1 | pick | target-intel | dry-run://picker-ab-fixture | 0.71 |  |
| 2 | exec_plan | exec-plan | dry-run://picker-ab-fixture | 0.65 |  |

## Deltas

```json
{
  "canary_delta": {
    "absolute_delta": 0,
    "chatgpt_oauth": 1,
    "claude": 1
  },
  "failure_reasons_by_provider": {
    "chatgpt_oauth": [],
    "claude": []
  },
  "finding_count": {
    "absolute_delta": 0,
    "chatgpt_oauth": 1,
    "claude": 1
  },
  "high_or_critical_count": {
    "absolute_delta": 0,
    "chatgpt_oauth": 1,
    "claude": 1
  },
  "matched_decision_count": 2,
  "proof_delta": {
    "absolute_delta": 0,
    "chatgpt_oauth": 1,
    "claude": 1
  }
}
```

## Limitations

- No winner is claimed by this harness; it records comparable evidence only.
- Dry-run mode proves report generation and provider configuration shape, not model capability.
- Live/lab claims require recorded run IDs, explicit target authorization, and comparable evidence inputs.
