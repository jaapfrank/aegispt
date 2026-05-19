# Evidence Graph Normalizer V1

The normalized evidence graph is a read-only layer over existing AegisPT run evidence. It does not execute tools, create tasks, approve proposals, mutate scope, materialize secrets, or access live targets.

## Source Data

The normalizer consumes stored records only:

- runs, scopes, tasks, executions, artifacts, findings, approvals, proposals, rationale entries, context documents, finding chains, and report evidence from the assessment graph
- inventory snapshot content such as assets, API endpoints, identities, SaaS connectors, OAuth scopes, and permissions
- run-scoped credential-vault references as redacted `credential_ref` nodes

## Normalized Nodes

Nodes use stable IDs and common fields:

- `type`
- `subtype`
- `source_ids`
- `label`
- `confidence`
- `evidence_refs`
- `data`

Current node types include `run`, `scope`, `asset`, `api`, `identity`, `finding`, `task`, `credential_ref`, `saas_connector`, `permission`, `evidence_ref`, `approval`, `proposal`, `runner_capability`, and `attack_path`.

## Normalized Edges

Every edge includes:

- source and target normalized node IDs
- relationship
- confidence
- evidence refs
- provenance

Provenance records whether the edge came from the existing assessment graph or from deterministic run-evidence normalization. Credential nodes expose only reference metadata and never plaintext secret material.

## API

`GET /api/v1/runs/{run_id}/evidence-graph` returns the normalized graph for the run visible to the current tenant.

