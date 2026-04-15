# Threat Model

## Objective

Protect AegisPT from becoming a high-privilege automation layer that can be abused, misconfigured or disconnected from evidence.

## Primary assets

- engagement definitions
- scope allowlists and denylists
- approval decisions
- secrets references
- raw evidence artifacts
- replay bundles
- reports
- runner images and tool configurations

## Trust boundaries

### Operator to API

Risk:

- invalid scope
- unauthorized runs
- malicious input embedded in task parameters

Mitigations:

- auth and RBAC
- schema validation
- audit logging
- policy engine

### API to worker

Risk:

- direct command injection
- bypass of approvals

Mitigations:

- structured messages only
- runner contract validation
- run profile checks
- target re-validation inside the worker

### Worker to tools

Risk:

- tool misconfiguration
- unapproved targets
- dangerous templates

Mitigations:

- approved configuration bundles
- allowlist enforcement
- template provenance checks
- rate limiting

### Worker to evidence store

Risk:

- raw secrets or PII stored centrally
- artifact tampering

Mitigations:

- redact before storage
- hash every artifact
- preserve immutable metadata
- limit retention

## Abuse cases

### Abuse case 1

A user attempts to run a scan outside the agreed target range.

Response:

- control plane blocks request
- worker re-checks targets if somehow queued
- audit event records the denied attempt

### Abuse case 2

A runner tries to execute a shell string derived from user input.

Response:

- runner interfaces only accept structured arguments
- wrapper code builds safe commands
- tests enforce the contract

### Abuse case 3

A report claims a finding without evidence.

Response:

- reporting requires linked evidence references
- findings remain non-reportable until evidence QA passes

## Non-goals

- autonomous propagation
- unrestricted exploit orchestration
- direct AI execution authority over tools
