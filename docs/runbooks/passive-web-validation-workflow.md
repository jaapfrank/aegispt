# Passive Web Validation Workflow

## Doel

Deze runbook laat zien hoe je op de Kali VM een eerste passive web-validatieflow uitvoert met de huidige AegisPT bootstrap.

## Voorwaarden

- de stack draait via Docker Compose
- je werkt in `/opt/aegispt/repo`
- de API luistert op `http://127.0.0.1:8000`

## 1. Stack starten

```bash
cd /opt/aegispt/repo
docker-compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env up -d --build
```

## 2. Beschikbare run-profielen bekijken

```bash
curl http://127.0.0.1:8000/api/v1/run-profiles
```

De huidige standaardprofielen zijn:

- `passive-web-baseline`
- `passive-web-nuclei-audit`
- `passive-code-semgrep-audit`
- `active-web-safe`
- `active-web-zap-active`
- `intrusive-validation`

Voor het codeprofiel `passive-code-semgrep-audit` gebruik je een pad-scope in plaats van domeinen of URL's; zie daarvoor `code-semgrep-validation-workflow.md`.

## 3. Engagement aanmaken

```bash
curl -X POST http://127.0.0.1:8000/api/v1/engagements \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "name": "Acme Passive Validation",
    "client": "Acme Corp",
    "roe_ref": "ROE-2026-010"
  }'
```

Bewaar de `id` uit de response als `ENGAGEMENT_ID`.

## 4. Scope as code vastleggen

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/scope" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "allowlist_json": {
      "domains": ["example.com"],
      "urls": ["https://example.com"]
    },
    "denylist_json": {
      "domains": ["admin.example.com"]
    }
  }'
```

## 5. Passive run aanvragen

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/runs" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "profile_name": "passive-web-baseline"
  }'
```

Verwacht gedrag:

- de run krijgt direct status `queued`
- AegisPT materialiseert de eerste `httpx`-taken op basis van de allowlist
- de run is nog niet uitgevoerd; dispatch gebeurt expliciet

Bewaar de `id` uit de response als `RUN_ID`.

## 6. Runstatus ophalen

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}"
```

## 7. Queued taken dispatchen

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/dispatch" \
  -H 'X-Actor: dispatcher'
```

Bij een Compose-stack met `TASK_DISPATCH_MODE=dramatiq` gaat de taak nu naar de worker via Redis.

## 8. Taskdetail en execution bekijken

Haal eerst het task-id uit de runresponse en vraag daarna de task op:

```bash
curl "http://127.0.0.1:8000/api/v1/tasks/${TASK_ID}"
```

Daar zie je:

- taskstatus
- opgeslagen executions
- artifact metadata met hash

Als het artifact in MinIO is opgeslagen kun je de ruwe inhoud ook terughalen:

```bash
curl -OJ "http://127.0.0.1:8000/api/v1/artifacts/${ARTIFACT_ID}/content"
```

De genormaliseerde findings van een run kun je daarna opvragen met:

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/findings"
```

Een findingstatus aanpassen kan daarna zo:

```bash
curl -X PATCH "http://127.0.0.1:8000/api/v1/findings/${FINDING_ID}" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: analyst-1' \
  -d '{
    "status": "resolved"
  }'
```

Een runrapport als Markdown of HTML exporteren kan zo:

```bash
curl -OJ "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/report?format=markdown"
curl -OJ "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/report?format=html"
```

## 9. Passive nuclei-run voorbeeld

Een passieve nuclei-run gebruikt het profiel `passive-web-nuclei-audit`:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/runs" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "profile_name": "passive-web-nuclei-audit"
  }'
```

Na dispatch maakt de worker een lokale nuclei-run met een pinned template en slaat de JSONL output als artifact metadata op.

## 10. Approval-gated ZAP-run voorbeeld

Een `active-web-safe` run blijft wachten op goedkeuring:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/runs" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "profile_name": "active-web-safe"
  }'
```

Goedkeuren van de launch-step:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-1' \
  -d '{
    "decision": "approved"
  }'
```

Daarna kan dezelfde run expliciet worden gedispatched:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/dispatch" \
  -H 'X-Actor: dispatcher'
```

In de huidige slice gebruikt de worker ZAP via de daemon-API voor een spider + passive alert verzameling. Dat houdt deze eerste ZAP-uitvoering controleerbaar en replayable; volledige active scan tuning volgt later.

## 11. Approval-gated actieve ZAP-run

Voor de approval-gated actieve variant gebruik je `active-web-zap-active`:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/engagements/${ENGAGEMENT_ID}/runs" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: operator' \
  -d '{
    "profile_name": "active-web-zap-active"
  }'
```

Daarna keur je dezelfde `run.launch` stap goed en dispatch je de run:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/approvals" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: approver-1' \
  -d '{
    "decision": "approved"
  }'

curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/dispatch" \
  -H 'X-Actor: dispatcher'
```

De worker voert dan een ZAP spider plus active scan uit en slaat het gebruikte `scan_mode` in execution metadata en artifacts op.

## 12. Run annuleren

Een geplande of lopende run kun je zo annuleren:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}/cancel" \
  -H 'X-Actor: operator'
```

Verwacht gedrag:

- queued runs gaan naar `cancelled`
- running runs gaan naar `cancelling`
- geannuleerde runs zijn niet meer dispatchable

## Notities

- Passive runs gaan direct naar `queued`.
- `passive-web-baseline` gebruikt de `httpx` runner.
- `passive-web-nuclei-audit` gebruikt de `nuclei` runner.
- `passive-code-semgrep-audit` gebruikt de `semgrep` runner en krijgt een eigen code-runbook.
- `active-web-safe` gebruikt nu de ZAP API-runner voor approval-gated spider + passive alert collection.
- `active-web-zap-active` gebruikt de ZAP API-runner voor approval-gated spider + active scan.
- `active-web-safe` consolideert ZAP-targets nu in één taak per run en dedupliceert overlappende scope seeds zoals `example.com` en `https://example.com`.
- `EXECUTION_KILL_SWITCH=true` blokkeert nieuwe dispatches globaal.
- Active runs vereisen momenteel één approval op `run.launch`.
- Intrusive runs vereisen momenteel twee approvals voordat taken worden aangemaakt.
- De eerste echte worker-executie dekt nu `httpx`, `nuclei`, `semgrep`, ZAP spider/passive en een approval-gated ZAP active-scanpad.
