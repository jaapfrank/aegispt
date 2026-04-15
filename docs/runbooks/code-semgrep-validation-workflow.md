# Code Semgrep Validation Workflow

## Doel

Deze runbook laat zien hoe je op de Kali VM een passieve codevalidatie uitvoert met het profiel `passive-code-semgrep-audit`.

## Voorwaarden

- de stack draait via Docker Compose
- je werkt in `/opt/aegispt/repo`
- de API luistert op `http://127.0.0.1:8000`
- de code die je wilt scannen staat onder de repository die in de worker read-only gemount is als `/workspace/repo`

## Belangrijke padregel

Voor code-scans gebruik je in de scope het pad zoals de worker het ziet, dus onder `/workspace/repo/...`.

Voorbeelden:

- hostpad: `/opt/aegispt/repo/api/tests/fixtures/semgrep_target`
- workerpad in de scope: `/workspace/repo/api/tests/fixtures/semgrep_target`

## 1. Stack starten

```bash
cd /opt/aegispt/repo
docker-compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env up -d --build
```

## 2. Control plane en profiel controleren

```bash
curl http://127.0.0.1:8000/health/ready
curl http://127.0.0.1:8000/api/v1/run-profiles
```

Controleer dat `passive-code-semgrep-audit` in de profielijst staat.

## 3. Engagement aanmaken

```bash
curl -X POST http://127.0.0.1:8000/api/v1/engagements \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "name": "Acme Code Validation",
    "client": "Acme Corp",
    "roe_ref": "ROE-2026-020"
  }'
```

Bewaar de `id` uit de response als `ENGAGEMENT_ID`.

## 4. Scope met allowlisted paden vastleggen

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/scope" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "allowlist_json": {
      "paths": ["/workspace/repo/api/tests/fixtures/semgrep_target"]
    },
    "denylist_json": {}
  }'
```

## 5. Semgrep-run aanvragen

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/runs" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "profile_name": "passive-code-semgrep-audit"
  }'
```

Bewaar de `id` uit de response als `RUN_ID`.

## 6. Queued taak dispatchen

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/dispatch" \
  -H 'X-Actor: dispatcher'
```

Bij een Compose-stack met `TASK_DISPATCH_MODE=dramatiq` wordt de taak nu asynchroon door Redis naar de worker gestuurd.

## 7. Run en task pollen

Haal eerst `TASK_ID` uit de runresponse en controleer daarna run en task:

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}"
curl "http://127.0.0.1:8000/api/v1/tasks/${TASK_ID}"
```

Verwacht gedrag:

- de run eindigt op `completed`
- de task eindigt op `completed`
- de task toont een Semgrep execution met artifact metadata

## 8. Artifact en findings controleren

Download het artifact:

```bash
curl -OJ "http://127.0.0.1:8000/api/v1/artifacts/${ARTIFACT_ID}/content"
```

Vraag de genormaliseerde findings op:

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/findings"
```

Verwacht in de artifact metadata:

- `name: semgrep-results.json`
- `rule_source: aegispt-curated`
- `rule_sha256: <64 hex>`

Verwacht in findings:

- severity mapping naar het AegisPT-model
- targetpad van het gematchte bestand
- summary met een genormaliseerde AegisPT rule-id

## 9. Validatienotities

- De worker slaat Semgrep-evidence op in MinIO net als web-evidence.
- Als Semgrep gevoelige tekst zelf al gemaskeerd teruggeeft, kan `redaction_state` op `not_required` blijven staan.
- De stored finding blijft dan wel evidence-first gekoppeld aan hetzelfde artifact.
