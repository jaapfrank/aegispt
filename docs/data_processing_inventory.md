# AegisPT Data Processing Inventory

Last updated: 2026-04-28

This inventory describes the personal and sensitive data that AegisPT can process during an authorised assessment. It is an operational GDPR/AVG aid for controllers and processors; it is not legal advice or a certification statement.

## Role And Scope

- AegisPT is designed as a self-hosted assessment platform.
- The customer or operator normally acts as controller for engagement data.
- The party operating AegisPT on behalf of a customer normally acts as processor.
- AegisPT stores evidence-first assessment data so findings, reports, approvals, and audit history remain traceable.

## Data Categories

| Category | Examples | Purpose | Sensitivity |
| --- | --- | --- | --- |
| Engagement metadata | client name, ROE reference, engagement dates, tenant id | scope control and auditability | business confidential |
| Network identifiers | IP addresses, hostnames, domains, URLs, ports, service names | authorised discovery, enumeration, and reporting | personal data where linked to a person or household |
| Identity hints | usernames, email-like account names, LDAP/AD names, group names | authorised identity-aware assessment and evidence correlation | personal data |
| Vulnerability details | finding title, severity, target id, evidence reference, remediation text | security testing and risk reporting | sensitive security data |
| Service banners and inventory | product names, versions, protocols, cloud or directory metadata | exposure analysis and remediation guidance | sensitive technical data |
| Task and run metadata | run profile, task status, tool name, timestamps, bounded params | execution traceability and auditability | operational/security data |
| Evidence artifacts | artifact kind, URI, hash, redaction state, metadata | evidence lineage and report support | sensitive security data |
| Audit events | actor, action, object id, timestamp, non-secret metadata | accountability, access review, purge proof | operational/security data |
| Secret references | secret kind, purpose, display label, storage backend | safe runtime binding without exposing raw secret material | secret metadata only |

## Credential Material

Credential material must not be included in data exports. AegisPT stores direct secret material through the existing secret materialization path and exports only safe secret-reference metadata such as purpose, kind, display label, and storage backend.

Examples of material excluded from exports:

- passwords
- bearer tokens
- API keys
- cookies and sessions
- NTLM hashes or cracking candidates
- encrypted secret values
- vault pointers
- raw task output that may contain secrets

## Legal Basis

Common legal bases must be confirmed by the controller before use. Typical security-assessment bases are:

- legitimate interest for security testing, resilience validation, and vulnerability management
- contractual necessity where the assessment is part of a customer security service
- legal obligation where a regulation or formal assurance process requires security validation

The controller remains responsible for confirming the correct basis, scope, and data-subject information duties for each engagement.

## Retention

- Each engagement has a `retention_days` policy.
- The default retention period is 90 days.
- Run data older than the retention window is soft-deleted by the retention cleanup path.
- Manual cleanup is available from Settings > Data Retention.
- Irreversible purge requires typed confirmation and creates an audit event.

Data retained for accountability after a purge:

- the engagement shell
- audit events
- capability-pack lineage and integration settings
- pack-linked inventory or relevance records where deleting them would mutate pack provenance

## Data Export

`GET /api/v1/engagements/{id}/data-export` returns engagement data in JSON form for right-of-access, regulator, or customer handoff use. The export includes runs, tasks, findings, artifact metadata, inventory snapshots, scopes, secret-reference metadata, and audit events. It does not include credential material.

## Erasure

`DELETE /api/v1/engagements/{id}/purge` performs an irreversible hard purge of assessment data for the engagement after typed confirmation using:

```text
PURGE <engagement name>
```

The endpoint blocks while runs are still active. The purge records an audit event with timestamp, actor, counts, and retained-record rationale.

## Third Parties

By default, AegisPT is self-hosted and does not require third-party processors for stored assessment data.

Optional integrations may introduce separate processors depending on operator configuration, for example:

- Jira or webhook handoff targets
- external vaults
- OpenAI/ChatGPT provider features
- external threat-intelligence feeds
- licensed external tooling such as Burp Suite Enterprise

Operators must document enabled optional integrations in the engagement record or customer contract.

## Data Subject Rights

Controllers should be able to use AegisPT exports and purge controls to support:

- right of access
- right to rectification through corrected engagement metadata or report notes
- right to erasure where deletion does not conflict with legal/audit obligations
- right to restriction of processing by pausing or stopping runs
- right to object, assessed by the controller against the legal basis

## Technical And Organisational Measures

- engagement-scoped retention policy
- audit events for creation, cleanup, export, and purge
- typed confirmation for destructive purge
- secret material excluded from exports
- existing runtime binding and approval gates remain authoritative
- self-hosted deployment by default
- evidence artifact hashes and redaction state for traceability
- soft delete before hard purge for routine retention cleanup

## Operator Checklist

- Confirm engagement scope and legal basis before launch.
- Keep credentials out of reports and exports unless explicitly required by a separate secure process.
- Review Settings > Data Retention for each engagement.
- Use data export for regulator/customer/data-subject handoff.
- Use hard purge only after confirming contractual, legal, and audit retention obligations.
