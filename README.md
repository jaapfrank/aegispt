# AegisPT

AegisPT is an evidence-first penetration testing workbench for Kali/Linux operator hosts. It helps security consultants create scoped missions, run approved security checks, follow live execution, review evidence-backed findings, and produce customer reports.

The product is built around a simple principle: automation can help, but scope, approvals, evidence, and operator judgement stay in control.

## Start Here

- [Getting Started](docs/manual/getting-started.md): install, launch, first scan, first report.
- [Operator Manual](docs/manual/operator-manual.md): full user-facing workflow guide.
- [Host Service Install](docs/host_service_install.md): reproducible direct-host install.
- [Windows/WSL Install](docs/install/windows-wsl.md): Windows operator host notes.
- [Security Self-Assessment](docs/security_self_assessment.md): how AegisPT tests itself.

When the server is running:

- Operator console: `http://127.0.0.1:8000/app/`
- API reference: `http://127.0.0.1:8000/api/docs`
- Health check: `http://127.0.0.1:8000/health/live`

## What AegisPT Does

AegisPT supports:

- guided mission intake with explicit target scope and depth selection
- Mission Control for live run state, task output, scan map, and AI/operator context
- Live Agents view for active tool execution and stdout visibility
- findings review with evidence, methodology tags, remediation context, and validation state
- report generation for executive, technical, attack narrative, compliance-support, NIS2, and DORA outputs
- local threat-intel cache, CVE matching, and targeted follow-up testing where available
- evidence integrity checks with SHA-256-backed artifact verification
- data retention, export, and purge controls for assessment data
- optional ChatGPT-assisted explanations and proposals without bypassing approvals or scope
- Kali-focused toolchain support for common web, LAN, infrastructure, identity, and validation workflows

## What AegisPT Does Not Do Automatically

AegisPT does not:

- authorize tests for you
- expand scope without operator confirmation
- bypass approvals, deployment gates, or runtime binding
- run exploitation without the required authorization state
- treat AI advice as approval
- certify compliance by itself
- prove a target is clean just because no findings were produced

## Quick Install

Recommended direct-host install on Kali or a Linux operator host:

```bash
git clone <YOUR-REPO-URL> /opt/aegispt/repo
cd /opt/aegispt/repo
sudo bash scripts/install_aegispt_host.sh
```

Open:

```text
http://127.0.0.1:8000/app/
```

For local development without installing the system service:

```bash
bash scripts/setup_python_dev.sh
bash scripts/restart_local_inline_host.sh
```

## First Scan In Short

1. Open `Intake`.
2. Choose the assessment type.
3. Enter the authorized target scope.
4. Choose the depth.
5. Declare available prerequisites.
6. Review the mission preview.
7. Launch.
8. Watch `Mission Control` and `Agents`.
9. Review `Findings`.
10. Export from `Reports`.

The detailed version is in [Getting Started](docs/manual/getting-started.md).

## Repository Layout

```text
api/          FastAPI control plane
docs/         user, operator, install, and architecture documentation
infra/        compose and host deployment assets
migrations/   Alembic database migrations
requirements/ Python dependency lists
scripts/      install, validation, and maintenance helpers
ui/           browser operator console
workers/      bounded tool runners and orchestration
```

## Validation Commands

Common local checks:

```bash
source .venv/bin/activate
python -m pytest --capture=no api/tests/test_health.py
bash scripts/verify_host.sh
```

For product acceptance and benchmark validation, use the documented scripts in `scripts/` and the generated result artifacts from those runs.

## Safety

Only run AegisPT against targets you are explicitly authorized to test. Keep scope narrow, choose depth honestly, and stop the run if the target, customer instruction, or legal boundary changes.
