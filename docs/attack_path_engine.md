# Attack Path Engine

## Purpose

The attack path engine turns already-recorded run inventory and findings into evidence-backed path guidance.
This first slice is intentionally small: it produces run-scoped graph primitives, candidate paths, and choke-point summaries without adding a graph-rendering dependency or activating a second runtime workflow.

## Current inputs

- selected-run inventory snapshots
- findings already attached to the selected run
- host, service, and endpoint relationships already present in normalized inventory

If a run has inventory snapshots derived from that run, the service aggregates those snapshots first. If not, it falls back to the run's linked `source_inventory_snapshot_id`. If neither exists, findings can still be represented as low-confidence finding-only paths.

## Current outputs

- graph nodes for hosts, services, endpoints, and findings
- graph edges for host-service, service-endpoint or host-endpoint, and inventory-to-finding relationships
- candidate paths that end in a finding and include the strongest matching inventory context available
- choke-point summaries
- optional inferred attack-path context from stored identity, cloud, IAM, Kubernetes, and host/cloud inventory relationships

A choke point is any non-finding node that appears in three or more candidate paths. The run itself is not modeled as an attack node, so it cannot become a noisy universal choke point.

Confirmed edges remain the deterministic path basis. Inferred edges are marked with
`classification = inferred`, carry a confidence score, rationale, and inventory or evidence refs, and
are also copied into `inferred_edges` so the UI can render them separately. They are review-only
context; they do not create candidate paths, broaden scope, dispatch tasks, test credentials, pivot
laterally, or mutate identity, cloud, Kubernetes, or host resources.

## API contract

The first backend contract is:

- `GET /api/v1/runs/{run_id}/attack-paths`

The response includes:

- `status`: `ready`, `low_confidence`, or `empty`
- `sources`: inventory snapshot, aggregated snapshot count, source tools, inventory confidence, and finding count
- `summary`: node count, edge count, candidate path count, choke-point count, and a human-readable reason
- `nodes`
- `edges`, with `classification = confirmed` or `classification = inferred`
- `inferred_edges`, a convenience list containing only review-only inferred relationships
- `lateral_analysis`, including review notes and an explicit no-pivot/no-credential-test/no-dispatch boundary
- `candidate_paths`
- `choke_points`

## Low-data behavior

- Runs with no inventory and no findings return `empty` with no nodes, edges, paths, or choke points.
- Runs with findings that cannot be matched to selected-run inventory return low-confidence finding-only paths.
- Runs with inventory but no findings return `empty` and explicitly state that no findings are available for path derivation.

## Vulnerability chain detection baseline

The first vulnerability-chain slice is separate from attack-path inference. It materializes additive `finding_chains` records from findings already attached to the same run, then exposes matching chain context in Finding Theater.

Initial deterministic pattern list:

- `exposed-management-plus-credential-weakness`: requires one component finding with exposed management/admin surface signals and a separate component finding with credential, token, session, or authentication weakness signals.
- `injection-plus-sensitive-data-exposure`: requires one component finding with injection or execution signals and a separate component finding with sensitive-data, secret, token-leak, credential-disclosure, or information-disclosure signals.

Each chain record stores component finding ids, source evidence references, confidence, rationale, combined-impact copy, and guardrail metadata. Component findings remain canonical and are not rewritten. Chain detection does not auto-escalate severity and does not execute chained exploitation.

Unsupported or sparse behavior:

- If a finding cannot be paired with another finding that satisfies a known pattern, Finding Theater shows no-chain context with the reason instead of fabricating a narrative.
- If matched components are sparse, low-severity, or missing evidence refs, the chain may be stored as `low_confidence` with no evidence-ref embellishment.
- Unknown chain types are intentionally unsupported until a future task adds a documented pattern and validation coverage.

## Operator surface

The existing `Surface / Attack Map` review surface renders the selected run's attack-path summary alongside the inventory browser.
It shows candidate-path counts, graph primitive counts, the three-path choke-point threshold, top choke points, and up to four candidate paths so multi-host evidence remains visible without introducing D3, Cytoscape, or a second graph UI.

The surface now also includes a dependency-free relationship view. That view traces the existing API payload only:

- candidate path labels and `node_ids`
- node and confirmed-edge counts from the attack-path response
- confidence values supplied by the response
- evidence refs supplied on each candidate path
- choke-point labels and node ids supplied by the response

It highlights choke-point segments inside each rendered path chain, but it does not infer new paths, assign new risk scores, or claim certainty beyond the source confidence.

Inferred lateral-analysis context is rendered in a separate review-only panel. That panel shows
confidence, rationale, evidence refs, operator-review state, and runtime-effect boundaries so the
operator can distinguish inferred context from confirmed candidate-path data. The UI does not expose
any launch, pivot, credential, or scope-expansion action from this inferred panel.

When no inventory or finding evidence exists yet, the same surface renders the API's truthful empty-state reason instead of a blank placeholder.

## Current non-goals

- no D3, Cytoscape, or graph-library dependency
- no graph persistence table
- no identity-aware active pivoting, credential testing, or privilege-path execution
- no active cloud-to-on-prem chaining or exploitation
- no risk-scoring integration
- no runtime self-modification or pack-validation bypass
