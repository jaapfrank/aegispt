# MSSP Multi-Tenant Readiness

## Purpose

This document is the first repo-owned readiness map for MSSP and multi-tenant operation.

It does not declare AegisPT hosted-SaaS ready. It records the isolation boundaries that must hold before any managed-service deployment can be claimed, and it documents the narrow first implementation slice now present in the API.

## First-Slice Implementation

The first foundation is intentionally small:

- `engagements.tenant_id` is an optional tenant label for engagement ownership.
- `X-Tenant-ID` is an optional request header that scopes API visibility when present.
- Existing single-operator/local workflows remain unchanged when `X-Tenant-ID` is absent.
- Engagement creation resolves tenant ownership from either `X-Tenant-ID` or the optional `tenant_id` payload field, and rejects mismatches.
- Engagement list/detail, scope, schedule, run, report catalog/export/draft, finding, inventory, task, and evidence-artifact content endpoints now deny mismatched tenant access with `404`.
- The operator console can forward `X-Tenant-ID` when `state.tenantId` is set by deployment glue, but this slice does not add a visible tenant switcher or MSSP portal.

This is an isolation foundation, not authentication or authorization. A real hosted deployment still needs identity, tenant membership, RBAC, session management, and operational controls before it can safely expose multiple tenants to external users.

## Enterprise Identity Foundation Slice

AegisPT now exposes the first governed enterprise identity administration surface in Settings and `/api/v1/auth/identity/status`.

Supported now:

- OIDC/SAML provider state is visible as `disabled`, `configured`, or `error`.
- Enterprise identity settings are tenant-scoped `InstanceSetting` records.
- OIDC client secrets and SAML signing certificate material are stored encrypted and returned only as masked configured indicators.
- Session timeout and logout redirect policy are explicit for operators.
- Logout, login-event recording, API-key creation/revocation, and enterprise identity settings changes write audit events.
- Local X-Actor fallback and API-key actors stay visible and are labeled separately from enterprise authentication.
- `/api/v1/auth/identity/status`, Settings, and readiness metadata now expose an enterprise boundary proof map for browser SSO, tenant membership, role enforcement, session expiry/logout, SCIM, and tenant-admin paths.
- API-key role enforcement is proven for admin-only identity/settings paths; non-admin API-key roles receive `403`.
- Readiness is deliberately `degraded`, not `ready`, when OIDC/SAML is configured but browser SSO, tenant membership, and server-side sessions are not enforced.

Still future work:

- browser SSO callback enforcement
- tenant membership and invitation flows
- SCIM provisioning
- hosted-SaaS RBAC and tenant switching
- external identity-provider metadata validation

### Enterprise Identity Proof Matrix

| Boundary | Current status | Proof / gate |
| --- | --- | --- |
| Browser SSO | `disabled` or `configured_not_enforced` | OIDC/SAML settings can be stored, but no browser SSO callback or enterprise session is active. Enterprise identity readiness must not claim `ready` from configuration alone. |
| Tenant membership | `blocked` | `X-Tenant-ID` narrows tenant-scoped records, but no authenticated tenant organization, membership, invitation, or tenant-admin model exists. |
| Role enforcement | `enforced` for API keys | `admin`, `operator`, and `reviewer` API-key roles are enforced by protected endpoints; admin-only identity/settings paths reject non-admin keys and write audit events for key lifecycle changes. |
| Session expiry/logout | `configured_not_enforced` | Timeout/logout policy is visible and logout is audit-backed. Local fallback has no server session, expiry is not enforced, and logout does not mutate active runs. |
| SCIM provisioning | `unsupported` | No SCIM connector or provisioning workflow is active. |
| Tenant administration | `unsupported` | No tenant switcher, invitation flow, or tenant-admin UI is active. |

## Tenant Boundary Map

| Boundary | Current anchor | First-slice rule | Remaining gap |
| --- | --- | --- | --- |
| Customer / tenant | `Engagement.tenant_id` | Optional tenant label is stored on engagements and used for header-scoped access. | No tenant organization model, membership table, invitation flow, or SSO mapping yet. |
| Engagements | `engagements` | List/detail/create/scope/schedule APIs can be scoped by `X-Tenant-ID`. | No tenant administration UI or tenant lifecycle workflow. |
| Runs | `runs.engagement_id` | Engagement-scoped run list/create and run-id read/action/report APIs reject mismatched tenant headers. | Background worker ownership is still inherited from the run's engagement, not a standalone tenant envelope. |
| Findings | `findings.run_id` | Finding list/detail/theater/evidence/remediation/retest/update APIs reject mismatched tenant headers through the source run's engagement. | Findings without a run remain unsuitable for hosted tenant use until an explicit tenant/engagement anchor exists. |
| Reports | Run report endpoints | Report catalog, report export, and report-draft endpoints reject mismatched tenant headers through the source run. | Persisted report-export storage paths still need tenant-partitioned storage policy for hosted deployments. |
| Inventory | `inventory_snapshots.engagement_id` | Inventory list/create/read/summary/cloud-analysis APIs reject mismatched tenant headers. | Cross-tenant aggregate inventory and MSSP portfolio views are intentionally not implemented. |
| Secrets | `secrets_refs.engagement_id` | Secret materialization remains engagement-scoped and raw values remain out of API/report/UI/MCP surfaces. | Secret administration, rotation, per-tenant KMS/vault policy, and tenant-specific broker configuration remain future work. |
| Enterprise identity | `InstanceSetting` keys under `identity.*`, `/api/v1/auth/identity/status` | OIDC/SAML settings, session timeout, logout policy, API-key role boundaries, and explicit blocked/unsupported identity gates are visible and sensitive values are encrypted. | Browser SSO enforcement, SCIM, tenant membership, tenant-admin UI, and hosted RBAC remain future work. |
| Evidence artifacts | `EvidenceArtifact -> ToolExecution -> Task -> Run -> Engagement` | Artifact content download rejects mismatched tenant headers before storage retrieval. | Pack artifacts and generated export storage need complete tenant partitioning before hosted SaaS. |
| Capability packs | `capability_packs.engagement_id` | Existing pack registry, validation, approval, deployment, and runtime binding gates remain unchanged and engagement-scoped. | This slice does not retrofit every pack endpoint with tenant-aware membership or MSSP catalog policy. |
| Codex build lane | repo task/result files and pack context | Codex remains a supervised build-lane feature and does not execute tenant runtime changes. | Codex task/result visibility needs a tenant-aware index before external MSSP operators can share one hosted control plane. |
| MCP surfaces | read-only MCP and controlled action tools | MCP context/action access remains bounded by existing engagement/run/finding checks where those APIs are used. | External MCP clients still need tenant-aware authentication and registration before hosted exposure. |
| Audit | `audit_events` | New engagement creation audit records include `tenant_id` when present. | Audit search, retention, and tenant-specific export are not implemented. |

## Tenant Header Semantics

`X-Tenant-ID` is a narrowing guard:

- absent header: preserve current local single-operator behavior
- present header: only tenant-matching records are visible
- invalid header syntax: HTTP 400
- creation payload/header mismatch: HTTP 409
- cross-tenant access attempts: HTTP 404 so object existence is not disclosed

Accepted tenant ids are 1-100 characters and may contain letters, numbers, `_`, `.`, `:`, or `-`.

## Explicit Non-Goals

This slice does not add:

- hosted SaaS launch
- billing or licensing
- full RBAC
- enforced browser SSO, SCIM, invitations, or tenant membership management
- cross-tenant reporting
- MSSP portfolio dashboards
- tenant switching UI
- tenant-aware pack marketplace policy
- customer-facing Codex task sharing
- new runtime behavior
- finding schema changes
- pack registry, validation, approval, deployment, or runtime binding bypasses

## Production Readiness Requirements

Before AegisPT can claim hosted MSSP or multi-tenant readiness, a later task must add and validate:

- an authenticated tenant membership model
- deny-by-default tenant enforcement across every API router, including packs, integrations, MCP, Codex, internal validation, relevance, and threat-intel surfaces
- tenant-partitioned artifact/report/Codex-result storage
- tenant-aware audit export and retention
- tenant administration UI with safe switching and clear active-tenant display
- tenant-scoped secret backend policy
- migration/backfill rules for existing unscoped engagements
- browser tests that prove tenant switching does not leak stale selected engagement, run, finding, report, artifact, pack, or Codex state

Until those requirements are implemented, the current state is `supported-with-gap` for a narrow API isolation foundation and not hosted-SaaS ready.
