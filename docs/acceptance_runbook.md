# Acceptance Runbook

## Purpose

This runbook describes the controlled path for real product acceptance runs against safe targets only.

## Prerequisites

- FastAPI app is running locally
- the repo virtual environment is active
- the desired target exists in `codex/tasks/target_lab_matrix.json`
- the target is enabled and authorized

## List available safe scenarios

```bash
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000 \
  --list-scenarios
```

## Run the next required safe scenario

```bash
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000
```

The harness will:

1. choose the next unpassed enabled scenario
2. resolve its safe target from the catalog
3. materialize any approved local runtime fixture declared by that target
4. create an engagement and scope
5. seed inventory from the approved target definition
6. create the run with acceptance metadata
7. auto-apply required approval actors for approved lab scenarios
8. dispatch the run if enabled
9. collect findings, reports, inventory, packs, and task details
10. write a result JSON file under `codex/results/`

For active-safe training-lab scenarios, the harness now also preflights:

- local ZAP daemon reachability at `ZAP_BASE_URL`
- live target URL/API reachability before engagement/run creation

This keeps WebGoat/crAPI acceptance runs from silently creating half-broken dossiers when the required lab or ZAP prerequisite is absent.

## Run a specific scenario

```bash
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000 \
  --scenario-id juice-shop-baseline
```

```bash
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000 \
  --scenario-id webgoat-auth-safe
```

```bash
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000 \
  --scenario-id crapi-authenticated-safe
```

## Active-safe lab prerequisite

`active-web-safe` training-lab scenarios require a reachable local ZAP daemon in addition to the target lab itself. On the direct-host path validated on 2026-04-19, the daemon was started with:

```bash
/usr/local/bin/zap.sh \
  -daemon \
  -silent \
  -host 127.0.0.1 \
  -port 8080 \
  -config api.key=change-me-zap-key \
  -config api.addrs.addr.name=127.0.0.1 \
  -config api.addrs.addr.regex=false
```

WebGoat now uses a harness-owned Docker runtime fixture with isolated loopback ports, so it no longer conflicts with the local ZAP daemon on `127.0.0.1:8080`.

## Override the catalog target

Only do this with another safe catalog target:

```bash
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000 \
  --scenario-id local-app-smoke \
  --target-id local-aegispt-smoke
```

## Result output

Each run writes a JSON result that includes:

- pass/fail status
- scenario id
- target id and class
- run id and status
- output counts
- operator-console link
- direct HTML/PDF report links

## Practically validated baseline

The current repo-owned baseline has already been exercised in two real ways:

- `local-app-smoke` via a harness-owned loopback probe:
  - `codex/results/acceptance-local-app-smoke-20260417-111922.json`
- `local-app-smoke` against the real local host after the transient inline host rollout:
  - `codex/results/acceptance-local-app-smoke-20260418-093631.json`
- `local-app-smoke` against the repaired local transient host after the browser-path fix:
  - `codex/results/acceptance-local-app-smoke-20260418-184034.json`
- `juice-shop-baseline` via a live local OWASP Juice Shop container:
  - `codex/results/acceptance-juice-shop-baseline-20260417-112346.json`
- `crapi-authenticated-safe` via a live local OWASP crAPI stack plus local ZAP daemon:
  - `codex/results/acceptance-crapi-authenticated-safe-20260419-215821.json`
- `webgoat-auth-safe` via a harness-owned WebGoat Docker fixture plus local ZAP daemon:
  - `codex/results/acceptance-webgoat-auth-safe-20260419-215958.json`

These result files are the current reference outputs for the safe acceptance lane.

Important truth note for the current crAPI reference run:

- the acceptance scenario passed because task evidence, findings, and all 4 report variants were produced
- the underlying run status is still `completed_with_errors`
- the recorded task execution shows `http://127.0.0.1:8888/identity/api: [Errno 104] Connection reset by peer` while the primary crAPI surface still produced 21 findings plus the stored ZAP artifact

## Local smoke note

The `local-app-smoke` scenario now uses a harness-spawned loopback HTTP probe. This keeps the acceptance smoke run reproducible without making the control plane probe itself during inline dispatch.

If the chosen AegisPT host runs in `manual` dispatch mode without an active worker, the harness now fails fast with a clear message instead of waiting the full timeout on a permanently queued run.

If an active-safe scenario is chosen while the local ZAP daemon is absent, the harness now fails fast with a clear prerequisite error before engagement/run creation.

## Guardrails

- do not point the harness at arbitrary public websites
- do not enable disabled templates without filling in authorization first
- treat catalog edits as reviewed repo changes, not ad hoc runtime input
