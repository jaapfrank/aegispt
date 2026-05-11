# Evidence Gap Report

The evidence gap report separates stored claims into four states:

- `confirmed`: supported by evidence refs and a confirming finding state
- `suspected`: plausible but not fully evidenced
- `untested`: explicitly not proven by stored coverage evidence
- `contradicted`: false-positive, resolved, or not-reproducible evidence

Every claim either maps to evidence refs or is marked unsupported with an exclusion reason. Unsupported suspected and untested claims are listed under `unsupported_claims_excluded_from_customer_report` and must not be rendered as customer-facing proof.

## Safety Contract

The report is read-only. It does not run scans, change findings, create tasks, dispatch runners, approve proposals, mutate scope, or modify runtime behavior.
