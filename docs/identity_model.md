# Identity Model

## Purpose

This document prepares AegisPT for identity-aware testing and future internal validation paths.

The first implemented identity slice is intentionally narrow: a read-only LDAP / Active Directory enumeration runner for approved internal or directory targets.

The first implemented cloud-adjacent slice started as a read-only AWS inventory
runner that records account identity and resource metadata for approved AWS account ids. A follow-on
read-only analysis slice now reviews stored inventory for selected public exposure, security-group,
IAM policy, IAM trust-policy, and Kubernetes configuration signals where safe inventory inputs are
available. It does not mutate resources, execute privilege escalation, infer full privilege paths, or
connect cloud identities to on-premises attack paths.

## Implemented read-only LDAP / AD slice

`ldap-enum` is a worker runner that uses read-only LDAP search operations to collect:

- directory users
- directory groups
- direct privileged group memberships
- enabled user accounts with service principal names
- enabled user accounts that do not require Kerberos pre-authentication
- domain password-policy signals exposed by the directory root

The runner writes `ldap-enum-results.json` as evidence and marks the execution metadata as read-only. It does not request Kerberos service tickets, does not request AS-REP material, does not spray passwords, does not move laterally, and does not modify directory state.

The output feeds existing platform structures:

- inventory snapshots receive additive identity subject, identity group, and privileged membership entries inside `normalized_inventory_json`
- findings are created through the existing finding model for appropriate signals such as Kerberoastable indicators, AS-REP roastable indicators, privileged membership visibility, and weak password-policy signals
- run planning exposes the runner only through `passive-identity-ldap-enum`, not through public web profiles

Optional live bind settings can be supplied in run configuration under `ldap` with non-secret fields such as `base_dn`, `bind_dn`, `password_env`, `use_ssl`, and `page_size`. Raw directory passwords should not be stored in run configuration.

## Implemented controlled credential-attack slice

The next identity-aware slice is intentionally bounded and approval-gated. AegisPT now supports:

- `active-ad-kerberoast` for Kerberos service-ticket extraction from inventory-derived SPN accounts
- `active-ad-asreproast` for AS-REP roast extraction from inventory-derived no-preauth accounts
- `active-offline-hash-crack` for offline-only hashcat cracking of protected Kerberos or NTLM hash bundles
- `intrusive-ad-password-spray` for bounded password spraying with explicit lockout-policy confirmation

These runners stay inside the existing evidence-first and protected-secret model:

- roastable account candidates and lockout policy come from approved LDAP or BloodHound-derived inventory context
- Kerberoast and AS-REP material are stored only through encrypted `SecretRef` / protected-output bindings
- cracked or sprayed plaintext passwords are never returned in findings, logs, or API payloads and are stored only as encrypted password `SecretRef` records
- spraying is blocked unless the selected inventory snapshot carries a confirmed LDAP lockout threshold and the configured attempt count stays below that threshold
- the spray approval step is separate from the non-spray credential-attack approval step

This slice still does not dump LSASS, perform DCSync, establish persistence, move laterally, or mutate directory state. It turns already approved identity inventory and captured hash material into bounded credential-impact evidence only.

## Implemented read-only cloud / IAM / Kubernetes analysis slice

The cloud analysis baseline is intentionally review-only and snapshot-based. `GET
/api/v1/inventory/{inventory_id}/cloud-analysis` reads an existing inventory snapshot and returns
provider-scoped `analysis_findings`, explicit `limitations`, and summary counts. It does not create
database `Finding` records and does not change the finding schema.

The first supported cloud provider is AWS. The analysis currently covers:

- EC2 instances with stored public IP or public DNS metadata
- security groups with stored ingress rules that allow `0.0.0.0/0` or `::/0`
- IAM policies with allow statements that combine wildcard actions and wildcard resources
- IAM trust policies that allow wildcard principals to assume roles
- missing-permission or collection-error limitations from stored inventory error records

Kubernetes signals are included only when safe read-only Kubernetes inventory is already present in
the snapshot. The first signals cover public control-plane endpoints, disabled RBAC, anonymous API
authentication, disabled secrets encryption, and risky workload security settings such as privileged
containers, host networking, or root execution.

The AWS inventory runner still uses read-only AWS APIs only. It now preserves security-group ingress
and egress rule details already returned by `describe_security_groups` so exposure analysis can cite
stored evidence instead of relying on rule counts.

## Attack-path inferred context boundary

Stored identity, cloud, IAM, Kubernetes, and host/cloud inventory relationships can now contribute
review-only inferred edges to `GET /api/v1/runs/{run_id}/attack-paths`. These edges are separate from
confirmed candidate paths and carry confidence, rationale, source refs, and explicit operator-review
metadata.

This is still lateral-analysis context only by default. Confirmed candidate paths remain grounded in
selected-run inventory and finding evidence; inferred identity or cloud context is never treated as
permission to execute. Separate approval-gated credential-attack runners can now consume selected
inventory context, but attack-path inference itself still does not auto-dispatch password spraying,
credential reuse, lateral movement, cloud-to-on-prem exploitation, Kubernetes actions, or scope
expansion.

## Future concepts

- users
- roles
- permissions
- auth context mapping
- privilege boundaries
- deeper cloud principal and role relationships after a future approved IAM-graph task

## Placeholder schemas

Prompt 3 adds placeholder schemas for:

- subjects
- roles
- permissions
- auth context

These placeholders are additive only and do not introduce full directory integration.

## Later use cases

- model which identities can reach which assets
- map privilege escalation opportunities
- support internal validation scenarios that reason about access level transitions

## Out of scope

- identity graph storage
- live privilege collection
- full cloud IAM graph analysis beyond first-pass stored-policy review
- shadow AI discovery, uncontrolled LLM tool execution, secret extraction, and autonomous LLM exploit chaining
- LLM prompt-injection probing outside the separate `active-llm-application-probe` profile, which is limited to explicitly authorized LLM API endpoints and bounded safe probes
- exploitation, lateral movement, or directory writes
- AWS inventory resource metadata and first-pass read-only cloud analysis are implemented, but IAM attack-path inference, live Kubernetes testing, cloud exploitation, resource mutation, and cloud-to-on-prem chaining remain out of scope
