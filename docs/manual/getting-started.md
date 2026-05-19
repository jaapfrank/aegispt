# AegisPT Getting Started

This guide gets a new operator from a fresh local install to a first report.

## 1. Install And Start AegisPT

Use the direct-host install on Kali or a Linux operator host:

```bash
git clone <YOUR-REPO-URL> /opt/aegispt/repo
cd /opt/aegispt/repo
sudo bash scripts/install_aegispt_host.sh
```

For Windows/WSL details, use `docs/install/windows-wsl.md`. For the full host-service path, use `docs/host_service_install.md`.

After installation, open:

```text
http://127.0.0.1:8000/app/
```

Health and API docs are available at:

```text
http://127.0.0.1:8000/health/live
http://127.0.0.1:8000/api/docs
```

## 2. Create Your First Mission

1. Open `Intake`.
2. Choose the assessment type, such as `Internal LAN`, `External Web`, or an API/web target.
3. Enter the approved target scope exactly as it appears in your authorization.
4. Choose the depth:
   - `Phases 1 only` for safe discovery.
   - `Phases 1-2` for discovery plus active enrichment.
   - `Full - all 4 phases` only when intrusive testing and exploitation confirmation are authorized.
5. Declare available access prerequisites, such as no credentials, known AD context, credential references, or intrusive authorization.
6. Review the mission preview.
7. Type the required target confirmation if prompted.
8. Launch the mission.

AegisPT stores the mission scope and only queues work that fits the approved boundary.

## 3. Watch The Run

Open `Mission Control` after launch.

Use it to check:

- current run status
- task cards and task output
- selected check details
- scan map progress
- AI Signal or deterministic guidance
- findings count and severity trend

For detailed live output, open `Agents`. The running task is the most useful card; queued and completed tasks are supporting history.

## 4. Review Findings

Open `Findings` when results appear.

For each finding, check:

- severity
- affected target
- evidence reference
- methodology tags
- remediation guidance
- validation or retest status when available

Use `Verify Evidence` when available before relying on a finding in a customer report.

## 5. Export The Report

Open `Reports`.

Choose the report type that matches the engagement:

- Executive summary for management.
- Technical report for remediation teams.
- SOC 2 / ISO 27001 / PCI DSS support packages for control evidence.
- NIS2 / DORA support packages where those obligations are relevant.
- Attack narrative when a readable run story is useful.

Export Markdown, HTML, or PDF as needed.

## 6. Common First-Run Problems

### The UI Loads But Nothing Starts

The local host may be running old code or manual dispatch mode. From the repo root:

```bash
bash scripts/restart_local_inline_host.sh
```

Reload `http://127.0.0.1:8000/app/`.

### LAN Scan Shows No Findings

That can be correct. Discovery and service enumeration may find hosts without confirmed vulnerabilities. Check `Mission Control`, `Agents`, and `Reports` for task output and inventory evidence.

### A Phase Is Blocked

Open the phase details. A block usually means one of these:

- a runner failed and needs review
- a required prerequisite was not supplied
- the selected phase needs explicit authorization
- no allowlisted finding exists for exploitation confirmation

Use the provided review or continue action only when the reason is understood.

### ChatGPT Shows Disconnected

Open `Settings`, connect ChatGPT, then return to the run. AI features are advisory and do not bypass scope, approvals, or the kill switch.

### A Tool Is Missing

Run:

```bash
bash scripts/verify_host.sh
```

On Kali, also use:

```bash
sudo bash scripts/install_security_tools.sh
```

## 7. Safety Reminder

Only scan systems that are explicitly authorized. Keep target ranges tight, use full-depth modes only when the authorization covers them, and keep the kill switch available during active work.
