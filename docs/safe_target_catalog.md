# Safe Target Catalog

## Purpose

Real-run validation must stay inside approved scope. The safe target catalog is the only supported source for automated acceptance targets.

## Allowed target classes

- `local_dev`
- `authorized_customer`
- `training_lab`

Targets outside those classes are rejected by the acceptance harness.

## Explicitly prohibited

- arbitrary public websites
- internet targets without recorded authorization
- disabled template entries that were not deliberately enabled
- targets marked `unauthorized_public: true`

## Seeded catalog entries

| Target | Class | Intent | Status |
| --- | --- | --- | --- |
| Local Acceptance Probe Target | `local_dev` | smoke validation for run creation, evidence, reports, and history via a harness-spawned loopback probe | enabled |
| OWASP Juice Shop | `training_lab` | passive-safe web validation | enabled |
| OWASP WebGoat | `training_lab` | approval-gated authenticated validation | enabled |
| OWASP crAPI | `training_lab` | API and adaptive-safe validation | enabled |
| Metasploitable 3 Template | `training_lab` | future internal-range lab | disabled template |
| Authorized Customer Target Template | `authorized_customer` | copy-and-fill template for real customer-owned scope | disabled template |

## Catalog storage

The machine-readable catalog lives at:

- `codex/tasks/target_lab_matrix.json`

This file is repo-owned and should be reviewed like code.

## Authorization requirements

Every enabled real target should record:

- `authorized: true`
- a real `authorization_ref`
- the correct scope entries
- the correct classification

Customer targets must be copied from the template and filled in with actual authorized scope before use.

## Operator rule

If a desired target is not already in the safe catalog, add it deliberately and review it first. Do not improvise a public target at runtime.

## Runtime fixtures

Reviewed runtime fixtures are now used for more than the local smoke path:

- `runtime_fixture: local_http_probe`
  - spawns the loopback smoke target used by `local-app-smoke`
- `runtime_fixture: docker_webgoat`
  - starts an isolated loopback WebGoat container, rewrites the catalog URL to the ephemeral assigned port, and removes the container after the run

This keeps acceptance scope deterministic without forcing static host-port collisions between training labs and local supporting services such as the ZAP daemon.

## Practical validation status

- `local-app-smoke`: practically validated on 2026-04-17 through the harness-owned loopback probe path
- `juice-shop-baseline`: practically validated on 2026-04-17 against a live local Juice Shop container
- `webgoat-auth-safe`: practically validated on 2026-04-19 through the harness-owned `docker_webgoat` runtime fixture plus a live local ZAP daemon
- `crapi-authenticated-safe`: practically validated on 2026-04-19 against a live local OWASP crAPI stack plus a live local ZAP daemon

The WebGoat and crAPI entries are still environment-dependent in one honest sense: active-safe validation only runs when the relevant lab stack and the supporting ZAP daemon are actually live where the harness is executed. The harness now checks those prerequisites up front instead of implying success.
