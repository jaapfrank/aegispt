# Report Export Workflow

## Doel

Deze runbook laat zien hoe je een runrapport en de bijbehorende JSON-overzichten lokaal onder `/srv/aegispt/reports` wegschrijft.

## Voorwaarden

- de stack draait via Docker Compose
- je werkt in `/opt/aegispt/repo`
- de API luistert op `http://127.0.0.1:8000`
- de run die je wilt exporteren bestaat al

## 1. Run-id bepalen

Vraag eerst de run op of lijst de runs van een engagement:

```bash
curl "http://127.0.0.1:8000/api/v1/runs/${RUN_ID}"
```

## 2. Markdown export maken

```bash
cd /opt/aegispt/repo
bash scripts/export_run_report.sh "${RUN_ID}" markdown
```

Verwachte output:

- `run.json`
- `findings.json`
- `report.md`

Standaard komen deze bestanden terecht in:

```bash
/srv/aegispt/reports/${RUN_ID}
```

## 3. HTML export maken

```bash
cd /opt/aegispt/repo
bash scripts/export_run_report.sh "${RUN_ID}" html
```

Dan wordt `report.html` naast de JSON-bestanden geplaatst.

## 4. PDF export maken

Voor PDF-export moet Playwright Chromium beschikbaar zijn op de host:

```bash
python -m playwright install chromium
```

Daarna:

```bash
cd /opt/aegispt/repo
bash scripts/export_run_report.sh "${RUN_ID}" pdf
```

Dan wordt `report.pdf` naast de JSON-bestanden geplaatst.

## 5. Aangepaste outputmap gebruiken

```bash
cd /opt/aegispt/repo
bash scripts/export_run_report.sh "${RUN_ID}" markdown "/srv/aegispt/reports/customer-a/${RUN_ID}"
```

## Notities

- het script gebruikt standaard `http://127.0.0.1:${API_PORT:-8000}`
- je kunt dit overschrijven met `API_BASE_URL`
- de export leest alleen uit de API; het verandert geen runstatus of findings
- de PDF-export gebruikt dezelfde report-semantiek als markdown en HTML, maar rendert via Playwright Chromium
