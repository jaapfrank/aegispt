# Evidence-First Attack Story

The evidence-first attack story is a deterministic report section generated from stored AegisPT records only. It is designed to make narrative reports useful without letting prose drift beyond evidence.

## Source Rules

Every generated claim must include at least one source ledger entry. Allowed claim sources are:

- `finding_id`
- `runner_output_id`
- `approval_event_id`
- `graph_hypothesis_id`
- `graph_edge_id`

The builder may use evidence references and artifacts to decide whether a gap exists, but it does not use those values as standalone narrative claim sources. This keeps report prose tied to stable model records operators can audit.

## Gap Rules

Missing support is rendered as an explicit evidence gap instead of persuasive filler. Current gaps include:

- findings without an evidence reference
- tasks without runner output
- runner output without a replayable artifact record
- stored finding chains without component finding IDs
- runs with no narrative sources

Gap text is intentionally plain: it states what cannot be claimed and which record needs follow-up evidence.

## Runtime Boundary

The builder is analysis-only. It dispatches no runners, mutates no findings, changes no approvals, broadens no scope, and performs no runtime self-modification. Existing report routes render the section as part of technical and executive reporting, and attack-narrative aliases remain review-only report views.

