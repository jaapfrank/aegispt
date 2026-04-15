# Runtime Pack Binding

## Purpose

The runtime must know exactly which adaptive pack version it is using.

That requirement exists to preserve reproducibility and prevent hidden capability drift.

## Binding model

Runs now support explicit binding metadata:

- `bound_pack_id`
- `bound_pack_version`
- `bound_pack_deployment_id`
- `source_inventory_snapshot_id`

Task parameters also inherit a stable `capability_pack` block so the worker can record provenance without modifying the live runtime.

## Binding rules

- only deployed packs may bind to runs
- binding is explicit and auditable
- running or completed runs cannot be rebound
- task materialization preserves pack metadata into runtime evidence

## Rollback

Rollback does not mutate a run in place.

Instead:

- a prior deployment is promoted back to `deployed`
- the rolled-back pack becomes `superseded`
- future runs bind to the restored deployment

## Reporting impact

Run reports can now show:

- bound pack name and version
- deployment status
- inventory snapshot used
- relevance decision used
- threat intel references
- whether findings came from standard or adaptive coverage

