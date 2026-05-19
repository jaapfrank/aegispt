# backlog-298 One-Click Proof of Resolution Micro-Scanner

Datum: 2026-05-08

## Gedrag

- Toegevoegd: `POST /api/v1/findings/{finding_id}/proof-of-resolution/micro-scan`.
- De endpoint vereist een opgeslagen `Finding.replay_recipe_json`; zonder replay recipe wordt geen micro-scan gefaket.
- De service maakt een proof-of-resolution run met een bestaande RunProfile, bestaande scopechecks, bestaande approval gates, bestaande queued Task lifecycle en bestaande `FindingValidationRecord`.
- `queue_run_tasks` past bij proof-of-resolution runs de opgeslagen replay params toe op de queued task, zodat approvals die later task queueing activeren dezelfde exacte replay-context gebruiken.
- Bij succesvolle proof, gedefinieerd als `validated_not_reproduced`, markeert de validator de finding als `resolved`, zet remediation op `verified`, wist `sla_breached`, en schrijft audit evidence.
- Als de originele evidence pattern nog reproduceerbaar is, blijft de finding open en wordt `finding.proof_of_resolution.not_verified` geaudit.

## Veiligheidsgrenzen

- Geen nieuwe runner is toegevoegd.
- Geen dispatch bypass: passive micro-scans worden alleen queued; actieve profielen blijven pending approval tot de bestaande run approval flow ze queue't.
- Geen scope/ROE/credential/provenance/runtime-binding/kill-switch bypass.
- Exact replay vereist bestaande replay metadata en huidige approved scope.
- `ui-v2/` is niet aangeraakt.

## Validatie

- `python3 scripts/validate_backlog_tasks.py` passed voor implementatie.
- `.venv/bin/python -m py_compile api/app/services/proof_of_resolution.py api/app/services/runs.py api/app/services/finding_validator.py api/app/routers/findings.py api/app/schemas/remediation.py api/tests/test_findings.py` passed.
- `.venv/bin/python -m pytest api/tests/test_findings.py -q` passed: 8 passed.
- `.venv/bin/python -m pytest api/tests/test_attack_paths.py api/tests/test_runs.py::test_active_run_requires_approval_before_queueing -q` passed: 9 passed.
- `.venv/bin/python -m pytest api/tests/` passed: 524 passed, 4 warnings.
- Live API smoke on temporary port `http://127.0.0.1:8028` passed:
  - `GET /health/live` returned `200 OK`.
  - `POST /api/v1/findings/00000000-0000-0000-0000-000000000000/proof-of-resolution/micro-scan` returned truthful `404 finding not found`, proving route registration without mutating data.

## Scope-notitie

Het backlog-298 package bevat opnieuw brede success criteria voor choke points, micro-scanner replay, drift detection en cloud mapping. De queue splitst deze daarna uit in afzonderlijke taken:

- backlog-298: one-click proof-of-resolution micro-scanner.
- backlog-299: continuous exposure drift detection.
- backlog-300: cloud-native identity and attack path graphing.

Deze slice implementeert de micro-scanner/replay/verification loop. Drift detection en cloud graphing blijven voor de volgende queued tasks.

## Extra bewijs nodig

- Geen live worker dispatch tegen WebGoat/DVWA/DVGA of een andere labtarget is uitgevoerd in deze slice.
- Dit is vastgelegd in `extra_tests.md` XT-029 en `risico.md` R-021.
