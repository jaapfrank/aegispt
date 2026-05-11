# Signal-to-Runner Contracts

Adaptive AI runner selection depends on runner contracts derived from the governed capability registry. The contract layer is analysis-only: it does not dispatch work, mutate scope, grant approvals, change credentials, or bypass kill-switch behavior.

## Contract Fields

Each adaptive runner contract declares:

- trigger signals, split into strong and weak signals
- prerequisites that must be present in the assessment graph
- blocker IDs that explain why a runner cannot be used
- risk tier and cost
- expected evidence keys
- approval requirements and approval reason IDs
- report mappings derived from expected evidence
- follow-up candidates

Contracts are normalized and validated by `api/app/services/runner_contracts.py`.

## Selector Boundary

The next-best-action selector loads a valid contract before ranking a runner. Missing or invalid contract data blocks adaptive use by returning a WAIT action with `missing_runner_contract` as a blocker reason ID. It is not eligible for RUN or APPROVAL selection until the contract is fixed.

WAIT and SKIP actions carry blocker reason IDs such as:

- `missing_prerequisite:<id>`
- `no_approved_target`
- `no_matching_trigger`
- `already_tested`
- `missing_runner_contract`

APPROVAL actions carry contract-derived approval reason IDs such as risk-tier or approval-count reasons. Existing manual and fixed-chain dispatch paths remain governed by their current run profile, approval, scope, ROE, runtime binding, and kill-switch checks.
