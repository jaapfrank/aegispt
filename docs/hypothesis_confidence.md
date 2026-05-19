# Hypothesis Confidence Engine

The hypothesis confidence engine is a defensive, review-only scoring layer built on the normalized evidence graph.

It does not run tools, create tasks, approve proposals, mutate scope, materialize secrets, use credentials, or access live targets. Its output is intended for operator review and evidence triage.

## Output

Each hypothesis includes:

- `confidence` and `confidence_label`
- `supporting_evidence`
- `contradicting_evidence`
- `missing_evidence`
- `next_safe_validation_step`
- a review-only recommendation contract

The first templates cover:

- IDOR / broken object authorization
- excessive OAuth scope exposure
- SSRF-to-cloud trust paths
- weak authentication controls
- SaaS connector data exposure paths

## Safety Contract

Every `next_safe_validation_step` is `action_type = operator_review` and explicitly records:

- `creates_tasks = false`
- `dispatches_work = false`
- `approves_proposals = false`
- `mutates_scope = false`
- `uses_credentials = false`
- `materializes_secrets = false`
- `accesses_live_targets = false`

The safest next validation step is framed as evidence review, such as reviewing imported OAuth consent records, existing redacted request/response evidence, or stored cloud identity context.
