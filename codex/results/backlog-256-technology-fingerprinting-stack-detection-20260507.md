# Backlog 256 Evidence - Technology Fingerprinting / SignalProfile

Datum: 2026-05-07

## Scope

Backlog-256 voegde een passieve SignalProfile/TechStackProfile-laag toe op bestaande recondata. Er zijn geen extra fingerprinting-requests toegevoegd; de httpx-runner bewaart extra passieve data uit dezelfde al uitgevoerde response.

## Gedrag

- Inventory snapshots krijgen `normalized_inventory_json.signal_profile` met evidence-backed signalen.
- Inventory snapshots krijgen `normalized_inventory_json.tech_stack_profile` met server/language/CMS/JWT/GraphQL/Java/login/upload/parameter/SQL-error/serialized-cookie samenvatting.
- `summary_json` bevat `signal_count`, `signal_keys` en `tech_stack_profile`.
- Mission Control toont een Signal Profile panel wanneer een niet-seed inventory snapshot signalen bevat.
- httpx-resultaten bevatten nu passieve response headers, body excerpt, cookie metadata zonder cookie values, forms en links uit dezelfde response.

## Validatie

- `python3 scripts/validate_backlog_tasks.py` passed voor implementatie: 266 queued task packages en exact één actieve taak.
- `source .venv/bin/activate && python -m pytest api/tests/test_signal_fingerprinting.py -q` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_runner_contract.py -q` passed.
- `python3 -m compileall api/app/services/fingerprinting.py api/app/services/inventory.py workers/runners/httpx/runner.py` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed.
- `node --check --input-type=module < ui/assets/modules/mission-control.js` passed.
- Playwright acceptance against current-code temporary server `http://127.0.0.1:8017/app/` passed for 1440px, 1024px, 768px, and 375px.

## Browser Bewijs

Screenshots:

- `codex/results/backlog-256-signal-profile-ui-1440px-20260507.png`
- `codex/results/backlog-256-signal-profile-ui-1024px-20260507.png`
- `codex/results/backlog-256-signal-profile-ui-768px-20260507.png`
- `codex/results/backlog-256-signal-profile-ui-375px-20260507.png`

Acceptance assertions:

- Signal Profile panel zichtbaar in Mission Control.
- WordPress, JWT present en upload endpoint zichtbaar.
- Geen browser page errors.
- Geen horizontale document-overflow op de vier viewports.

## Grenzen

- Geen extra HTTP requests voor fingerprinting.
- Geen finding schema wijziging.
- Geen pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials of kill switch bypass.
- Geen runtime self-modification of uncontrolled plugin install.
