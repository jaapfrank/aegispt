# Kali VM Reuse Guide

## Doel

Deze handleiding beschrijft hoe de Kali VM als herbruikbare AegisPT operator node gebruikt wordt zonder opnieuw te hoeven improviseren.

## Vaste paden

- `/opt/aegispt/repo` bevat de broncode
- `/opt/aegispt/bootstrap` bevat host bootstrap-bestanden
- `/srv/aegispt/env` bevat env-bestanden en secret references
- `/srv/aegispt/postgres` bevat PostgreSQL data
- `/srv/aegispt/minio` bevat MinIO data
- `/srv/aegispt/reports` bevat rapportexports
- `/srv/aegispt/artifacts` bevat evidence en replay artefacten
- `/srv/aegispt/backups` bevat lokale exports en back-ups

## Actuele baseline

Op 15 april 2026 is de VM gevalideerd met:

- Docker en Docker Compose aanwezig
- ZAP, Nuclei, Semgrep, httpx-toolkit, ffuf, feroxbuster, testssl.sh en Metasploit aanwezig
- timezone op `Europe/Amsterdam`
- Python virtual environment werkend voor de repo
- `pytest` succesvol op de Kali host
- run-profielen en approval-gated runplanning actief in de API
- echte `httpx`, `nuclei`, `semgrep` en ZAP task-executie actief via worker dispatch
- een approval-gated actieve ZAP-variant is beschikbaar via `active-web-zap-active`
- artifacten landen in MinIO wanneer `ARTIFACTS_STORAGE_MODE=s3` actief is
- findings zijn per run opvraagbaar en kunnen via de API van status worden veranderd
- runrapporten kunnen als Markdown en HTML geëxporteerd worden naar `/srv/aegispt/reports`
- tekstuele runner-output en artifacts worden vóór opslag geredigeerd wanneer gevoelige waarden voorkomen
- Nuclei-evidence bevat curated template provenance via template id, source en digest
- Semgrep-evidence bevat curated rule provenance via rule id, source en digest
- curated internal validation scenarios zijn beschikbaar en live gevalideerd via code- en webworkflows
- `EXECUTION_KILL_SWITCH=true` blokkeert nieuwe dispatches globaal
- runs kunnen via de API naar `cancelled` of `cancelling` gezet worden

## Eerste controle na het openen van de VM

```bash
cd /opt/aegispt/repo
bash scripts/verify_host.sh
source .venv/bin/activate
pytest
```

## Nieuwe code of updates uitrollen

1. Werk de repository bij in `/opt/aegispt/repo`.
2. Activeer de virtuele omgeving.
3. Draai `pytest`.
4. Draai indien nodig `alembic upgrade head`.

```bash
cd /opt/aegispt/repo
source .venv/bin/activate
pytest
alembic upgrade head
```

Als deze VM al draaide voordat Alembic-state werd bijgehouden en `alembic upgrade head` klaagt over bestaande tabellen, controleer dan eerst of het schema al op de huidige code zit en stamp daarna eenmalig:

```bash
alembic stamp head
```

## Compose stack starten

Genereer een env-bestand zodra dat nog niet bestaat:

```bash
cd /opt/aegispt/repo
bash scripts/generate_compose_env.sh
```

Als je `.env` al ouder was dan deze update, controleer dan dat deze regel aanwezig is:

```bash
grep '^TASK_DISPATCH_MODE=' infra/compose/.env
```

Start daarna de stack:

```bash
docker-compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env up -d --build
```

Controleer vervolgens de services:

```bash
bash scripts/verify_stack.sh
curl http://127.0.0.1:8000/
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
```

## Stack stoppen

```bash
docker-compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env down
```

## Eerste operatorflow

Na het starten van de stack kun je de control plane direct gebruiken:

```bash
curl http://127.0.0.1:8000/api/v1/run-profiles
```

Voor een volledige voorbeeldflow:

- zie `docs/runbooks/passive-web-validation-workflow.md`
- zie `docs/runbooks/code-semgrep-validation-workflow.md`
- zie `docs/runbooks/internal-validation-workflow.md`

## Aanbevolen Hyper-V checkpoints

1. `kali-clean`
2. `aegispt-host-tools`
3. `aegispt-bootstrap`
4. `aegispt-mvp-working`

## Belangrijke notities

- Hostdata blijft onder `/srv/aegispt` en niet in de repo.
- Secrets worden lokaal in `infra/compose/.env` gegenereerd; beheer gevoelige waarden later desgewenst vanuit `/srv/aegispt/env`.
- De codebase mikt op Python 3.12+; de huidige Kali host draait Python 3.13.
- `zapd` expose't alleen intern in Compose; de worker spreekt de daemon via `ZAP_BASE_URL` en `ZAP_API_KEY`.
- Compose mount de repository read-only in de worker als `/workspace/repo`; gebruik dat pad in code-scope voor Semgrep-runs.
- Zet `EXECUTION_KILL_SWITCH=true` in `infra/compose/.env` als je tijdelijk elke nieuwe dispatch wilt blokkeren.
- Voor webgebaseerde internal validation in Compose kun je `http://api:8000` als allowlisted doel gebruiken, omdat worker en ZAP daemon de API via het interne Compose-netwerk zien.
