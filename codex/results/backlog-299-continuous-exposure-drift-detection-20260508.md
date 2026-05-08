# Backlog 299 - Continuous Exposure Drift Detection

Datum: 2026-05-08

## Gedrag

- `compute_run_drift` blijft de bestaande `RunDrift` finding/exposure samenvatting vullen, maar schrijft nu ook een deterministisch `configuration_json.continuous_exposure_drift` rapport.
- Het rapport vergelijkt de huidige run met de vorige completed/completed_with_errors run op dezelfde engagement/profile combinatie.
- Vergelijking gebruikt alleen bestaande run data:
  - open finding fingerprints en finding evidence refs
  - `InventorySnapshot.normalized_inventory_json`
  - de nieuwste `TargetContextDocument`
- Het rapport detecteert:
  - nieuwe en verdwenen services/poorten, inclusief `app.example.test:8080/tcp`
  - nieuwe en verdwenen endpoints
  - technology additions/removals en version changes, inclusief downgrade richting
  - context document drift
  - SOC/operator alerts voor shadow IT, unauthorized exposure drift, patch regressions, new findings en resolved findings
- Nieuw API-contract: `GET /api/v1/runs/{run_id}/continuous-exposure-drift`.

## Safety Boundaries

- Analyse-only: geen runner dispatch, geen task creation, geen approval wijzigingen, geen scope expansion, geen live target actions.
- Geen pack registry, runner registry, approval gate, ROE, credential, provenance, runtime binding, report, deployment of kill-switch bypass.
- Geen UI wijziging; `ui-v2/` bleef untouched voor deze taak.
- `http://127.0.0.1:8000` was niet nodig voor browservalidatie omdat dit backend/API/runtime drift gedrag is. Live smoke draaide op tijdelijke poort `http://127.0.0.1:8029` om de gedeelde 8000-host niet te verstoren.

## Validatie

- Preflight `python3 scripts/validate_backlog_tasks.py`: passed met exact één actieve taak.
- Prerequisite: `inputs.prerequisite_backlog` was `REQUIRES: backlog-296`; backlog-296 staat in `DONE_LOG.md`.
- `python3 -m py_compile api/app/services/run_drift.py api/app/routers/runs.py`: passed.
- `.venv/bin/python -m pytest api/tests/test_runs.py -k "run_drift or continuous_exposure_drift"`: 2 passed, 108 deselected.
- `.venv/bin/python -m pytest api/tests/`: 525 passed, 4 warnings.
- Live API smoke op `http://127.0.0.1:8029`:
  - `/health/live` returned `200 OK`.
  - `/api/v1/runs/00000000-0000-0000-0000-000000000000/continuous-exposure-drift` returned truthful `404 Not Found` without mutation.

## Bewijs

- Regression test bewijst:
  - nieuwe service `app.example.test:8080/tcp`
  - React downgrade van `18.2.0` naar `17.0.2`
  - nieuw context endpoint `https://app.example.test/admin`
  - new/resolved finding drift
  - `operator_alerts` en `soc_alerts`
  - execution contract blijft planning-only en bypass-vrij
- Full API-suite bewijst dat de bestaande run drift summary en omliggende API-contracten intact blijven.

## Scope Note

Het task package noemt ook choke-point remediation, micro-scanner en cloud graphing in de brede success criteria. Die zijn in de queue uitgesplitst:

- backlog-297 heeft choke-point remediation afgerond.
- backlog-298 heeft proof-of-resolution micro-scanner afgerond.
- backlog-300 blijft de volgende cloud-native attack path graphing slice.
