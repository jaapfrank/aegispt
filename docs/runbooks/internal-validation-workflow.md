# Internal Validation Workflow

## Doel

Deze runbook laat zien hoe je de curated internal validation scenarios op de Kali VM uitvoert via de draaiende Compose stack.

## Voorwaarden

- de stack draait via Docker Compose
- je werkt in `/opt/aegispt/repo`
- de API luistert op `http://127.0.0.1:8000`
- `jq` is beschikbaar om responsevelden uit te lezen

## Scenario-overzicht opvragen

```bash
curl http://127.0.0.1:8000/api/v1/internal-validations/scenarios
```

De huidige curated scenario's zijn:

- `curated-code-validation`
- `curated-web-validation`

Gebruik verschillende `X-Actor` waarden voor approvals als je meerdere reviewers wilt simuleren.

## 1. Stack controleren

```bash
cd /opt/aegispt/repo
bash scripts/verify_stack.sh
curl http://127.0.0.1:8000/health/ready
```

## 2. Curated code validation uitvoeren

Gebruik voor code-scopes altijd het pad zoals de worker dat ziet, dus onder `/workspace/repo/...`.

### Engagement en scope aanmaken

```bash
ENGAGEMENT_ID=$(
  curl -sS -X POST http://127.0.0.1:8000/api/v1/engagements \
    -H 'Content-Type: application/json' \
    -H 'X-Actor: operator' \
    -d '{
      "name": "Internal Validation Code",
      "client": "Acme Corp",
      "roe_ref": "ROE-2026-030"
    }' | jq -r '.id'
)

curl -sS -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/scope" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "allowlist_json": {
      "paths": ["/workspace/repo/api/tests/fixtures/semgrep_target"]
    },
    "denylist_json": {}
  }'
```

### Internal validation session starten

```bash
SESSION_JSON=$(
  curl -sS -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/internal-validations" \
    -H 'Content-Type: application/json' \
    -H 'X-Actor: operator' \
    -d '{"scenario_id":"curated-code-validation"}'
)

SESSION_ID=$(printf '%s' "$SESSION_JSON" | jq -r '.id')
printf '%s\n' "$SESSION_JSON" | jq '.preflight_state, .steps'
```

Verwacht:

- `preflight_state` is `passed`
- stap `semgrep-baseline` staat op `pending_approval`

### Stap approven en uitvoeren

```bash
curl -sS -X POST \
  "http://127.0.0.1:8000/api/v1/internal-validations/${SESSION_ID}/steps/semgrep-baseline/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-code-1' \
  -d '{"decision":"approved"}'

EXECUTE_JSON=$(
  curl -sS -X POST \
    "http://127.0.0.1:8000/api/v1/internal-validations/${SESSION_ID}/steps/semgrep-baseline/execute" \
    -H 'X-Actor: operator'
)

RUN_ID=$(printf '%s' "$EXECUTE_JSON" | jq -r '.launched_run_id')
```

### Run en evidence controleren

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}"

TASK_ID=$(curl -sS "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}" | jq -r '.tasks[0].id')
curl "http://127.0.0.1:8000/api/v1/tasks/${TASK_ID}"
curl "http://127.0.0.1:8000/api/v1/internal-validations/${SESSION_ID}"
```

Verwacht:

- de run eindigt op `completed`
- de session eindigt op `completed`
- de task bevat minimaal één artifact, doorgaans `semgrep-results.json`

## 3. Curated web validation uitvoeren

Gebruik bij Compose-webvalidatie `http://api:8000` als allowlisted target. Worker en ZAP daemon kunnen dat doel via het interne Compose-netwerk bereiken.

### Engagement en scope aanmaken

```bash
WEB_ENGAGEMENT_ID=$(
  curl -sS -X POST http://127.0.0.1:8000/api/v1/engagements \
    -H 'Content-Type: application/json' \
    -H 'X-Actor: operator' \
    -d '{
      "name": "Internal Validation Web",
      "client": "Acme Corp",
      "roe_ref": "ROE-2026-031"
    }' | jq -r '.id'
)

curl -sS -X POST "http://127.0.0.1:8000/api/v1/engagements/${WEB_ENGAGEMENT_ID}/scope" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "allowlist_json": {
      "urls": ["http://api:8000"]
    },
    "denylist_json": {}
  }'
```

### Session starten en stapvolgorde controleren

```bash
WEB_SESSION_JSON=$(
  curl -sS -X POST "http://127.0.0.1:8000/api/v1/engagements/${WEB_ENGAGEMENT_ID}/internal-validations" \
    -H 'Content-Type: application/json' \
    -H 'X-Actor: operator' \
    -d '{"scenario_id":"curated-web-validation"}'
)

WEB_SESSION_ID=$(printf '%s' "$WEB_SESSION_JSON" | jq -r '.id')
printf '%s\n' "$WEB_SESSION_JSON" | jq '.steps[] | {step_id, status, pending_approvals}'
```

Verwacht:

- `baseline-httpx` staat op `pending_approval`
- `zap-passive-review` en `zap-active-validation` staan op `pending_prerequisite`

### Stap 1: baseline-httpx

```bash
curl -sS -X POST \
  "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/baseline-httpx/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-web-1' \
  -d '{"decision":"approved"}'

STEP1_JSON=$(
  curl -sS -X POST \
    "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/baseline-httpx/execute" \
    -H 'X-Actor: operator'
)

STEP1_RUN_ID=$(printf '%s' "$STEP1_JSON" | jq -r '.launched_run_id')
```

Controleer daarna:

```bash
curl "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}"
```

Verwacht:

- stap 1 is `completed`
- stap 2 verschuift naar `pending_approval`
- stap 3 blijft `pending_prerequisite`

### Stap 2: zap-passive-review

```bash
curl -sS -X POST \
  "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/zap-passive-review/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-web-2' \
  -d '{"decision":"approved"}'

STEP2_JSON=$(
  curl -sS -X POST \
    "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/zap-passive-review/execute" \
    -H 'X-Actor: operator'
)

STEP2_RUN_ID=$(printf '%s' "$STEP2_JSON" | jq -r '.launched_run_id')
```

Verwacht na afronding:

- stap 2 is `completed`
- stap 3 verschuift naar `pending_approval`

### Stap 3: zap-active-validation

Deze stap vereist twee approvals.

```bash
curl -sS -X POST \
  "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/zap-active-validation/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-web-3' \
  -d '{"decision":"approved"}'

curl -sS -X POST \
  "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/zap-active-validation/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-web-4' \
  -d '{"decision":"approved"}'

STEP3_JSON=$(
  curl -sS -X POST \
    "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}/steps/zap-active-validation/execute" \
    -H 'X-Actor: operator'
)

STEP3_RUN_ID=$(printf '%s' "$STEP3_JSON" | jq -r '.launched_run_id')
```

### Finale controle

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${STEP1_RUN_ID}"
curl "http://127.0.0.1:8000/api/v1/runs/${STEP2_RUN_ID}"
curl "http://127.0.0.1:8000/api/v1/runs/${STEP3_RUN_ID}"
curl "http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID}"
```

Verwacht:

- alle drie runs eindigen op `completed`
- elke run bevat task-evidence via de task endpoint
- de web session eindigt op `completed`

## 4. Polling-tip voor async dispatch

Als `TASK_DISPATCH_MODE=dramatiq` actief is, kunnen runs kort op `queued` of `running` blijven staan. Poll dan de run of session totdat een finale status zichtbaar is:

```bash
watch -n 2 "curl -sS http://127.0.0.1:8000/api/v1/internal-validations/${WEB_SESSION_ID} | jq '.status, .steps[] | {step_id, status}'"
```

## Validatienotities

- Internal validation gebruikt geen vrije exploitplanner; alleen curated scenario's zijn beschikbaar.
- Elke stap lanceert een gewone run met dezelfde evidence-, artifact- en findingketen als handmatig aangevraagde runs.
- Een bestaande PostgreSQL database die al door `AUTO_CREATE_TABLES=true` is opgebouwd maar nog geen Alembic-state heeft, moet je eerst eenmalig met `alembic stamp head` synchroniseren.
