# Backlog 300 - Cloud-Native Identity & Attack Path Graphing

Datum: 2026-05-08

## Gedrag

- Attack-path summaries hebben nu `cloud_graph_model: read-only-cloud-native-attack-path-v1`.
- De bestaande attack graph blijft evidence-first en voegt nu cloud-native candidate paths toe wanneer:
  - een finding evidence wijst op SSRF/cloud metadata exposure;
  - de finding aan een approved web host/endpoint hangt;
  - bestaande inventory die host aan een cloud resource koppelt;
  - bestaande cloud inventory die resource aan IAM principal/policy context koppelt.
- Het resultaat toont een web/API finding naast traditionele nodes (`host`, `service`, `endpoint`, `finding`) en cloud nodes (`cloud_resource`, `cloud_iam_principal`, `cloud_iam_policy`) in dezelfde graph.
- `cloud_native_attack_paths` bevat alleen zulke evidence-backed paths.
- De remediation advisor cloud context toont `cloud_native_attack_path_count` en `cloud_native_attack_path_ids`.

## Safety Boundaries

- Alle cloud-native edges zijn `classification=inferred` en `operator_review_required=true`.
- Geen cloud API acties, metadata queries, role assumption, credential testing, pivoting, task dispatch, scope expansion of runtime mutation.
- Geen runner registry, approval gate, ROE, credential, provenance, runtime binding, report, deployment of kill-switch bypass.
- Geen UI wijziging; `ui-v2/` bleef untouched.
- `http://127.0.0.1:8000` was niet nodig voor browservalidatie omdat dit backend/API graph gedrag is. Live smoke draaide op tijdelijke poort `http://127.0.0.1:8030` om de gedeelde 8000-host niet te verstoren.

## Validatie

- Preflight `python3 scripts/validate_backlog_tasks.py`: passed met exact één actieve taak.
- Prerequisite: `inputs.prerequisite_backlog` was `REQUIRES: backlog-296`; backlog-296 staat in `DONE_LOG.md`.
- `python3 -m py_compile api/app/services/attack_paths.py api/app/services/remediation_advisor.py api/tests/test_attack_paths.py`: passed.
- `.venv/bin/python -m pytest api/tests/test_attack_paths.py -q`: passed.
- `.venv/bin/python -m pytest api/tests/`: 526 passed, 4 warnings.
- Live API smoke op `http://127.0.0.1:8030`:
  - `/health/live` returned `200 OK`.
  - `/api/v1/runs/00000000-0000-0000-0000-000000000000/attack-paths` returned truthful `404 Not Found` without mutation.

## Bewijs

- Regression proof creates an approved Website/Web App run with:
  - web endpoint `https://app.example.test/fetch`
  - finding `SSRF - Cloud Metadata Exposed`
  - AWS EC2 resource `web-instance`
  - IAM role `WebRole`
  - IAM policy `ReadSecrets`
- The test proves the graph exposes:
  - one `cloud_native_attack_path`
  - traditional web/finding nodes and cloud IAM nodes in one path
  - inferred edges for cloud-host context, resource-to-IAM-principal, IAM attachment, and metadata-finding-to-resource
  - review-only boundary fields: no active pivoting, credential testing, scope expansion or automatic dispatch
  - remediation advisor cloud context includes the cloud-native path ID

## Scope Note

Het task package noemt ook choke-point remediation, micro-scanner en drift detection in de brede success criteria. Die zijn in de queue uitgesplitst:

- backlog-297 heeft choke-point remediation afgerond.
- backlog-298 heeft proof-of-resolution micro-scanner afgerond.
- backlog-299 heeft continuous exposure drift afgerond.
- backlog-300 implementeerde alleen cloud-native identity/attack-path mapping.
