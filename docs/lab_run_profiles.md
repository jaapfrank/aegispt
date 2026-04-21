# Lab Run Profiles

## Purpose

This file maps seeded safe labs to realistic run profiles, module sets, and safety posture so acceptance runs stay reproducible.

## Profiles

| Lab / Scenario | Assessment Type | Run Profile | Module Intent | Safety Posture | Expected Outputs |
| --- | --- | --- | --- | --- | --- |
| Local Host Smoke Run | Website / Web App | `passive-web-baseline` | discovery, web crawling, SSL/TLS | passive-only, light depth, adaptive off | inventory, task evidence, reports, history |
| Juice Shop Baseline | Website / Web App | `passive-web-nuclei-audit` | discovery, web crawling, content discovery, nuclei, SSL/TLS | passive-only, standard depth, adaptive off | inventory, task evidence, reports, findings surface |
| WebGoat Authenticated Safe Validation | Authenticated App | `active-web-safe` | web crawling, auth flows, content discovery, business logic | guarded active, approval-gated, adaptive off | task evidence, reports, history |
| crAPI Authenticated Safe Validation | API | `active-web-safe` | discovery, auth flows, nuclei, business logic, adaptive testing | guarded active, deep depth, approval-gated, adaptive on | task evidence, reports, pack state |

## Usage notes

- `passive-web-baseline` is the safest default for local smoke checks
- the local smoke scenario now uses a harness-spawned loopback HTTP probe instead of probing the control-plane host directly
- `passive-web-nuclei-audit` is the preferred baseline for vulnerable web labs when active mutation is unnecessary
- the `juice-shop-baseline` scenario is now practically validated as the reference passive-safe training-lab run
- the `webgoat-auth-safe` scenario is now practically validated through a fixture-backed loopback WebGoat container, which avoids colliding with the local ZAP daemon port on direct-host runs
- the `crapi-authenticated-safe` scenario is now practically validated through a live local crAPI stack plus the local ZAP daemon
- `active-web-safe` is reserved for explicitly approved safe labs or customer-owned authorized scope, and the acceptance harness now preflights the ZAP daemon plus live target URLs before it creates the run
- disabled templates stay disabled until the target really exists and authorization is recorded
