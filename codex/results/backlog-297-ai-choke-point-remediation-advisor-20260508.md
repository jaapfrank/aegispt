# backlog-297 AI Choke-Point Remediation Advisor

Datum: 2026-05-08

## Gedrag

- Toegevoegd: `GET /api/v1/runs/{run_id}/remediation-advisor`.
- De advisor gebruikt de bestaande attack-path summary als enige graph source en bouwt daaruit deterministische choke-point aanbevelingen.
- Aanbevelingen rangschikken choke points op path impact, severity, affected findings en ingeschatte inspanning.
- Elk advies linkt terug naar echte candidate path IDs, finding IDs, evidence refs, bestaande remediation state en validation records.
- Proof-of-resolution blijft planning-only: de advisor maakt geen tasks, findings, runner dispatches, cloud acties of runtime mutaties.
- Drift context wordt alleen gelezen uit bestaande `RunDrift` records.
- Cloud/IAM/Kubernetes context wordt alleen gelezen uit attack-graph nodes en inferred edges.

## Veiligheidsgrenzen

- Geen bypass van runner registry, approval gates, scope, ROE, credentials, provenance of kill switch.
- Future proof runs moeten via bestaande geregistreerde runners en goedgekeurde flows lopen.
- Operator-facing copy gebruikt `controlled proof` en `session exposure risk`; de advisor queue't geen actieve acties.
- `ui-v2/` is niet aangeraakt.

## Validatie

- `python3 scripts/validate_backlog_tasks.py` passed voor implementatie.
- `.venv/bin/python -m py_compile api/app/services/remediation_advisor.py api/app/routers/runs.py api/tests/test_attack_paths.py` passed.
- `.venv/bin/python -m pytest api/tests/test_attack_paths.py -q` passed: 8 passed.
- `.venv/bin/python -m pytest api/tests/` passed: 522 passed, 4 warnings.
- Live API smoke on temporary port `http://127.0.0.1:8027` passed:
  - `GET /health/live` returned `200 OK`.
  - `GET /api/v1/runs/00000000-0000-0000-0000-000000000000/remediation-advisor` returned truthful `404 run not found`, proving route registration without seeding or mutating a run.
- Post-promotion `python3 scripts/validate_backlog_tasks.py` passed.
- Post-promotion `git diff --check` passed.

## Scope-notitie

Het backlog-297 package bevat brede success criteria voor choke points, micro-scanner replay, drift detection en cloud mapping. De queue splitst deze daarna uit in afzonderlijke taken:

- backlog-297: choke-point remediation advisor.
- backlog-298: one-click proof-of-resolution micro-scanner.
- backlog-299: continuous exposure drift detection.
- backlog-300: cloud-native identity and attack path graphing.

Deze slice implementeert daarom de advisor, leest bestaande drift/cloud context, en levert proof-of-resolution planning, maar dispatcht nog geen micro-scanner of cloud acties.

## Extra bewijs nodig

- Geen live lab run met echte artifact-fed attack graph, retest workflow en drift/cloud fixture is uitgevoerd in deze slice.
- Dit is vastgelegd in `extra_tests.md` XT-028 en `risico.md` R-020.
