# Integrations

## Purpose

This document defines the integration boundary for workflow handoff features without creating a
shadow runtime path.

## Implemented slice: Jira configuration, controlled webhook handoff, and named provider handoff

AegisPT supports storing one Jira integration configuration per engagement through the API:

- `GET /api/v1/engagements/{engagement_id}/integrations`
- `GET /api/v1/engagements/{engagement_id}/integrations/jira`
- `PUT /api/v1/engagements/{engagement_id}/integrations/jira`
- `GET /api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}`
- `PUT /api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}`
- `POST /api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}/sync`

The underlying model stores an `integration_type` for each engagement-scoped integration
configuration. Jira-specific endpoints still only accept `jira` payloads. Authentication material
must be referenced through `auth_ref`; raw secrets do not belong in the integration configuration
record.

The Jira finding-link endpoints attach an existing AegisPT finding to one Jira issue and retain the
issue key, issue URL, optional issue status, and AegisPT-owned sync state. The initial link state is
`not_synced`.

The on-demand sync endpoint reads the linked issue through Jira's issue API and updates only the
stored link state: issue status, sync result, sync timestamp, sync error, and a small non-secret sync
payload. This is an operator-triggered API action, not an automatic background worker. If `auth_ref`
uses `env://VARIABLE_NAME`, AegisPT can send the environment token as an authorization header without
persisting raw credential material in the integration record.

Finding Theater exposes the linked Jira issue in the existing remediation surface, including issue
key, issue URL, issue status, sync state, sync timestamp, sync error when present, and the operator
that last updated the link. The UI does not add a standalone integration administration screen.

## Implemented slice: controlled outbound webhook handoff

AegisPT also supports one controlled outbound webhook configuration per engagement:

- `GET /api/v1/engagements/{engagement_id}/integrations/webhook`
- `PUT /api/v1/engagements/{engagement_id}/integrations/webhook`
- `GET /api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}`
- `POST /api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}/handoff`

This is the selected workflow-handoff expansion slice. The webhook endpoint is stored as the
configuration `base_url`, optional authentication is referenced through `auth_ref`, and raw secret
material still does not belong in the integration record. If `auth_ref` uses `env://VARIABLE_NAME`,
AegisPT can attach that environment token as an authorization header at handoff time.

The webhook handoff is explicit and operator-triggered. It creates or updates one additive
`finding_integration_links` record for the finding/configuration pair, sends a small evidence-backed
finding payload to the configured endpoint, and stores only the link-level handoff result:

- handoff key / URL
- handoff status
- delivery state
- delivery timestamp
- delivery error when present
- non-secret response metadata such as HTTP status and remote reference fields

The endpoint does not run in the background, retry automatically, install plugins, or change finding
severity, status, evidence, methodology mappings, pack state, approvals, deployments, runtime binding,
or canonical finding schema fields. Delivery failures remain visible through the handoff read
endpoint and the existing Finding Theater integration block.

## Implemented slice: named provider handoff foundation

AegisPT now also represents the next named workflow providers through the same
`integration_configurations` and `finding_integration_links` tables:

- `GET /api/v1/engagements/{engagement_id}/integrations/{provider}`
- `PUT /api/v1/engagements/{engagement_id}/integrations/{provider}`
- `GET /api/v1/engagements/{engagement_id}/integrations/{provider}/findings/{finding_id}`
- `POST /api/v1/engagements/{engagement_id}/integrations/{provider}/findings/{finding_id}/handoff`

Supported named providers in this slice are:

- `slack`
- `teams`
- `servicenow`

The named provider path is intentionally a provider-interface foundation, not a delivery engine.
Operators can create a controlled finding-level handoff record for the configured provider, and the
link records the provider, reference key/URL, prepared/blocked/failed state, timestamp, operator, and
non-secret metadata. The implementation does not post to Slack, Teams, or ServiceNow directly, does
not retry in the background, and does not close tickets automatically.

Named provider handoff requires a protected `auth_ref` pointer such as `vault://...`, `env://...`,
`ref://...`, `secret://...`, or `aegispt://...`. Raw tokens are rejected at configuration time.
Missing credentials, missing routing settings, unsupported providers, and controlled provider
failures are recorded as explicit link states instead of being hidden:

- `prepared`: an operator-triggered handoff reference was prepared; no background delivery is running
- `blocked`: the handoff cannot proceed because protected credentials or required routing settings are missing
- `failed`: a configured provider/broker failure was recorded for operator review

The minimal routing settings for this first named-provider slice are:

- Slack: `settings_json.channel`
- Microsoft Teams: `settings_json.conversation`
- ServiceNow: `settings_json.table`

Finding Theater renders Jira separately and shows webhook, Slack, Teams, and ServiceNow references
under workflow handoffs. This keeps integration visibility close to remediation review without adding
a standalone integration administration screen.

## Implemented slice: repository integration foundation for GitHub and GitLab

AegisPT now supports engagement-scoped repository connections for GitHub and GitLab:

- `GET /api/v1/engagements/{engagement_id}/integrations/repositories`
- `GET /api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/authorize`
- `GET /api/v1/engagements/{engagement_id}/integrations/repositories/{provider}/callback`
- `POST /api/v1/findings/{finding_id}/repository/fix-pr`

Supported repository providers in this slice are:

- `github`
- `gitlab`

The authorization flow stores the temporary OAuth state and the exchanged access token set only
through encrypted `SecretRef` materialization. Token material is never returned in API responses,
UI state, logs, reports, or tests. Safe metadata may expose provider, repository URL/path,
connected account login, and `token_exposed = false`, but never raw access or refresh tokens.

Connected repository context is bounded to finding-linked operator evidence:

- AegisPT may resolve a finding to one repository file path and line range
- only the matched snippet needed for that finding is persisted through `finding_repo_links`
- full repository contents are not stored in the control plane

Finding Theater can render the matched code snippet, highlight the vulnerable line, and provide a
direct provider link to the file and line in GitHub or GitLab. When AutoFix output already exists
for the finding, AegisPT may also create a fix pull request through the provider API.

The fix-PR boundary is intentionally narrow:

- AegisPT always creates a new branch for the advisory patch
- the target branch remains the repository default branch already recorded on the integration
- auto-merge is never enabled
- AegisPT does not write directly to protected branches
- AegisPT does not store repository contents beyond the finding-linked snippet
- pull requests remain review-required operator artifacts, not silent runtime changes

## Implemented slice: read-only MCP operator context

AegisPT exposes a bounded MCP-style read-only operator context surface:

- `GET /api/v1/mcp/resources`
- `GET /api/v1/mcp/engagements/{engagement_id}/context`

The resource manifest lists only read-only resources for engagement/scope metadata, selected-run
metadata, finding summaries, report catalog metadata, evidence artifact metadata, and capability
pack metadata. It deliberately exposes no MCP tools and allows no write methods.

The context endpoint reuses persisted AegisPT state without launching scans or generating new
runtime behavior. It returns sanitized run configuration, approval summaries, task summaries,
finding metadata with pointers to the existing Finding Theater read view, report variant metadata,
evidence artifact URI/hash/redaction metadata, and capability pack validation/deployment/provenance
summaries. It does not expose raw secret material, pack artifact content, raw artifact content,
tool stdout/stderr, or approval/deployment actions.

Future action tools, if ever added, must be promoted through an explicit task package and must keep
approval, validation, deployment, runtime binding, and authorization on the existing platform paths.
The read-only MCP surface is not a shortcut around those controls.

## Implemented slice: CI/CD trigger foundation

AegisPT now supports an engagement-scoped CI/CD trigger foundation for deployment-driven validation:

- `GET /api/v1/engagements/{engagement_id}/triggers/cicd`
- `PUT /api/v1/engagements/{engagement_id}/triggers/cicd/{trigger_source}`
- `POST /api/v1/triggers/cicd`

Supported trigger sources in this slice are:

- `github`
- `gitlab`
- `generic`

Each trigger stores:

- one encrypted-at-rest webhook secret through `SecretRef`
- an enabled or disabled status
- one or more run profiles to launch on a matching event
- branch-filter glob patterns such as `main` or `release/*`
- whether a narrower in-scope target URL override is allowed
- pointers to the latest trigger time and most recent linked run

Trigger history is stored as additive event records and exposed in the Settings screen for the
selected engagement. The last 10 events show source, profile, branch, commit SHA, status, and any
linked run.

The receiver validates an HMAC SHA-256 signature before any run creation:

- GitHub: `X-Hub-Signature-256`
- GitLab: `X-Gitlab-Signature-256`
- Generic: `X-AegisPT-Signature-256`

If the signature is invalid, the payload is rejected. If the branch filter does not match, the
trigger is recorded as ignored and no run is created.

Triggered runs always reuse the existing approval-aware run path:

- profiles with zero required approvals are queued and dispatched through the existing dispatch lane
- approval-gated profiles become `pending_approval`
- no trigger can auto-approve a run
- no trigger can bypass the kill switch, scope limits, pack binding rules, or runtime controls

A copyable GitHub Actions template for this signed payload flow now lives at:

- `docs/cicd/aegispt-github-action.yml`

## Planned integration areas

- ticketing systems such as Jira
- SIEM platforms
- notifications
- CI/CD systems

## Planned usage

- open remediation tickets from confirmed findings
- push validated findings into security monitoring workflows
- notify operators when pack validation, approval, or deployment state changes
- trigger repo-side build-lane checks from CI

## Guardrail

Integrations must not become a shadow runtime path. They should support evidence, workflow, and visibility rather than bypassing the existing platform safety controls.

Current Jira, webhook, and named-provider handoff support does not introduce background sync workers,
standalone integration administration screens, runtime self-modification, or uncontrolled plugin
installation. Direct Slack/Teams/ServiceNow delivery, GitHub issue creation, SIEM-specific payloads,
bidirectional sync, retries, delivery queues, MCP action tools, and broader marketplace
administration remain future task-package work rather than implicit scope in this slice.
