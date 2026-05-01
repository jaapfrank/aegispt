# AegisPT Operator Manual

AegisPT is an evidence-first penetration testing workbench. It helps an operator create a scoped mission, run approved security checks, follow live execution, review findings, verify evidence, and produce reports.

It does not replace written authorization, professional judgement, customer communication, or legal approval. Treat the configured scope as the boundary for every action.

## Main Screens

### Dashboard

Use `Dashboard` as the command center for current work. It summarizes active runs, risk posture, open problems, recent activity, and setup readiness.

### Intake

Use `Intake` to create a mission.

The wizard asks for:

- assessment type
- target scope
- depth
- available access prerequisites
- final confirmation before launch

Typical assessment types include internal LAN, external web, API or application targets, infrastructure targets, and code or repository-oriented work where configured.

Depth controls how far AegisPT may go:

- `Phases 1 only`: safe discovery.
- `Phases 1-2`: discovery plus active enrichment.
- `Full - all 4 phases`: intrusive credential validation and exploitation confirmation when explicitly authorized.

For full-depth work, confirm the target exactly when prompted. If you do not have authorization for intrusive or exploitation phases, choose a shallower mode.

### Mission Control

Use `Mission Control` during a run.

It shows:

- selected run
- scan map
- task list
- selected task output
- current phase or chain state
- findings summary
- AI Signal or deterministic reasoning
- shortcuts to Agents, Findings, Reports, and Cinema Mode

When a phase is blocked, open the phase detail before continuing. A block can mean a runner failed, a prerequisite is missing, or a higher-risk phase needs explicit review.

### Agents

Use `Agents` to inspect live task execution.

Focus first on running cards. They show the active tool, target, status, command preview, and stdout stream when available. Queued cards explain what is waiting. Completed cards provide history.

### Findings

Use `Findings` to inspect confirmed or candidate issues.

A finding is useful when it has:

- clear target
- severity
- evidence reference
- tool and methodology context
- remediation guidance
- validation or integrity status where available

Do not treat an empty Findings screen as proof that the target is clean. Check Reports, Mission Control output, and the validation matrix state when making assurance claims.

### Problems

Use `Problems` for cross-run remediation work. It groups open and resolved issues, supports assignment and status changes where available, and helps track whether fixes need retesting.

### Reports

Use `Reports` to generate customer-facing output.

Common report types:

- Executive summary: management-ready risk story.
- Technical report: detailed remediation content.
- Attack narrative: readable chain of what happened during a run.
- SOC 2, ISO 27001, PCI DSS: technical evidence support, not certification.
- NIS2 and DORA: technical evidence support for regulated-context conversations, not legal signoff.

Reports are evidence-backed. When possible, verify evidence integrity before sending final output.

### Surface / Attack Map

Use `Surface / Attack Map` to understand discovered hosts, services, relationships, and attack-path context. Inferred paths are advisory unless explicitly supported by stored evidence.

### Packs

Use `Packs` to inspect capability-pack state. AegisPT only runs deployed and approved pack content through the normal validation and runtime binding flow.

### Settings

Use `Settings` to configure:

- AI provider and ChatGPT OAuth state
- default instance settings
- data retention controls
- integrations
- CVE/threat-intel sync status
- other operator preferences exposed by the current build

Sensitive values should be stored through protected references or encrypted local secret handling, not copied into notes or reports.

## First Scan Walkthrough

1. Open `Intake`.
2. Select the assessment type.
3. Enter the authorized target, such as `10.0.20.0/24` or `https://app.example.test`.
4. Choose the depth.
5. Select prerequisites honestly. If there are no credentials, choose the unauthenticated lane.
6. Review the mission preview, phases, tools, and authorization wording.
7. Launch the mission.
8. Watch progress in `Mission Control`.
9. Open `Agents` when you need live task output.
10. Review `Findings`.
11. Verify evidence where available.
12. Export the appropriate report from `Reports`.

## Understanding Findings

Severity describes likely impact, but evidence quality matters just as much.

Use this review order:

1. Confirm the target is in scope.
2. Read the evidence summary.
3. Check artifact and replay/integrity status.
4. Review methodology tags.
5. Read remediation guidance.
6. Decide whether validation or retest is needed.

If a finding has sparse evidence, treat it as a lead for review instead of a finished customer claim.

## Remediation Workflow

1. Assign or group findings in `Problems` where available.
2. Use report remediation guidance to plan fixes.
3. Track status changes.
4. Retest when the fix is deployed and authorized.
5. Use verified evidence or a retest result before closing the issue in a customer report.

## AI Features

AegisPT can use AI for assistance such as mission guidance, finding explanation, report drafting support, proposal review, and contextual remediation. AI output is advisory.

To connect ChatGPT:

1. Open `Settings`.
2. Open the AI provider section.
3. Connect ChatGPT.
4. Return to the mission or report workflow.

AI must not expand scope, approve dangerous work, mutate runtime behavior, install tools, or bypass the kill switch. If AI is disconnected, the deterministic product flow should still work.

## Authorization And Safety

Before running a mission, confirm:

- written authorization exists
- target scope is exact
- depth matches authorization
- credentials or hashes are approved for use
- intrusive testing is explicitly allowed before intrusive phases
- exploitation confirmation is explicitly allowed before exploitation tools run

Use the kill switch if the run leaves the expected boundary or the customer asks you to stop.

## Troubleshooting

### The Browser Shows An Old UI

Restart the local host and reload:

```bash
bash scripts/restart_local_inline_host.sh
```

### Mission Control Says A Task Is Queued

Queued means work is waiting for dispatch, approval, or a previous phase. If the selected run is already running, do not start unrelated work just to clear queued cards.

### A Phase Is Blocked

Open the detail. If the block is a runner failure, review the stdout/stderr and use the explicit continue action only when the remaining phases are still safe. If the block is missing authorization or credentials, add the prerequisite or start a mission with a lower depth.

### No Findings Appear

Check:

- whether the run completed
- whether tools produced evidence
- whether the selected profile matches the target type
- whether the target is actually vulnerable
- whether the validation matrix has current proof for that route

No findings is not the same as a clean bill of health.

### ChatGPT Keeps Showing Disconnected

Open `Settings` and check ChatGPT OAuth status. Existing reusable sessions can be reused into a new engagement when available. If the provider is disabled, AI panels should show deterministic fallback information.

### API Or Settings Fail To Load

Check health:

```bash
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
```

If health fails, check the service logs or restart the local inline host.

### A Tool Is Missing

Run:

```bash
bash scripts/verify_host.sh
```

On Kali, install or refresh the toolchain:

```bash
sudo bash scripts/install_security_tools.sh
```

## API Reference

Swagger/OpenAPI documentation is available when the server is running:

```text
http://127.0.0.1:8000/api/docs
```

Use the API reference for integration and automation work. The operator console remains the recommended path for normal engagements.
