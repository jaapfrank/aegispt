# backlog-207 AI Security Research Lab screen

## Outcome

Implemented a dedicated BUILD > Research screen for AI-assisted capability creation. Operators can generate detection-only Nuclei YAML from CVE threat-intel records through the existing CVE template-generation lane, preview YAML/diff/safety output, and open the staged result in Pack Forge review. The screen also includes a custom detection-idea workflow and a Research Proposals log.

## Safety boundaries

- Generated Nuclei templates are staged for Pack Forge review; they are not deployed directly.
- Existing pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, and kill-switch boundaries remain authoritative.
- `api/app/services/cve_template_generator.py` safety validation was not changed.
- No external template downloads, runtime self-modification, uncontrolled plugin installation, active exploit generation, or live target actions were added.
- Python detection-script ideas return a safe `blocked` state because the repo does not yet have a Python detection-script safety validator/lifecycle equivalent to the Nuclei path.

## Files

- `api/app/schemas/ai_research.py`
- `api/app/services/ai_research.py`
- `api/app/routers/ai_research.py`
- `api/app/services/packs.py`
- `api/app/main.py`
- `api/tests/test_ai_research.py`
- `ui/assets/modules/research.js`
- `ui/assets/modules/runtime.js`
- `ui/assets/app.js`
- `ui/assets/styles.css`
- `ui/index.html`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `codex/results/backlog-207-research-screen-8000.png`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m py_compile api/app/schemas/ai_research.py api/app/services/ai_research.py api/app/routers/ai_research.py api/app/services/packs.py api/app/main.py api/tests/test_ai_research.py` passed.
- `node --input-type=module --check < ui/assets/modules/research.js` passed.
- `node --input-type=module --check < ui/assets/app.js` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_research.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_cve_template_generator.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_research.py api/tests/test_cve_template_generator.py -q` passed.
- Focused operator-console smoke coverage for Research navigation, CVE generation, custom idea generation, proposal log, and no-marketing shell passed.
- Required `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` passed.
- Full `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q` passed.

## Localhost acceptance

`http://127.0.0.1:8000` was relevant. During validation it initially served a stale backend route state: `/health/live` was healthy, but `/api/v1/ai/research?engagement_id=not-a-uuid` returned `404`. The local Uvicorn process on port 8000 was restarted from the current repo code. After restart, `/health/live` was healthy and `/api/v1/ai/research?engagement_id=not-a-uuid` returned FastAPI UUID validation `422`, proving the current Research API route was loaded. Browser acceptance on `http://127.0.0.1:8000/app/` opened the Research screen without console/page errors.

Screenshot evidence: `codex/results/backlog-207-research-screen-8000.png`.

## Remaining risks

- Custom Python detection scripts remain blocked until a dedicated validator and Pack Forge lifecycle exist for that artifact type.
- ChatGPT OAuth/session availability is required for real AI generation; tests use deterministic/mocked generation.
- Generated packs still require operator validation, approval, deployment, and runtime binding before use.
- No live Gruyere/customer/public target was scanned by this build-lane slice.
