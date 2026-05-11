# Next Best Evidence Action Planner

The next best evidence action planner chooses the safest missing evidence to review for a scored hypothesis. It is deliberately not a next-runner selector.

The planner consumes hypothesis confidence output and runner capability contracts. Runner metadata is used only as a guide for what evidence type would be valuable, what risk/cost/approval friction exists, and which alternatives are lower value.

## Output

Each action contains:

- the hypothesis and confidence context
- the recommended missing evidence item
- the safest operator-review validation step
- runner capability metadata used as evidence-shape guidance
- lower-value alternatives with reasons
- supporting and contradicting evidence refs
- a no-runtime-action execution contract

## Safety Contract

The planner does not create tasks, dispatch runners, approve proposals, mutate scope, use credentials, materialize secrets, access live targets, or modify runtime behavior. Every suggested validation is `operator_evidence_review`.
