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

Op 15 april 2026 is de operator-baseline opnieuw gevalideerd met:

- een reproduceerbare direct-host installer via `scripts/install_aegispt_host.sh`
- een herhaalbare systemd refresh via `scripts/install_host_service.sh`
- Docker en Docker Compose aanwezig
- `python3-venv` en `python3-pip` aanwezig voor repo-local Python setup
- ZAP, Nuclei, Semgrep, httpx-toolkit, ffuf, feroxbuster en testssl.sh aanwezig
- native Linux Docker werkt ook op een Ubuntu 24.04 WSL2-host wanneer Docker Desktop-integratie ontbreekt
- een aparte Kali Rolling 2026.1 VM-validatie bevestigt dat `metasploit-framework 6.4.124-0kali1` daar via de standaard Kali-repository aanwezig is
- timezone op `Europe/Amsterdam`
- Python virtual environment werkend voor de repo
- `pytest` succesvol op de operator-host
- run-profielen en approval-gated runplanning actief in de API
- echte `httpx-toolkit`, `nuclei`, `semgrep` en ZAP task-executie actief via worker dispatch
- een approval-gated actieve ZAP-variant is beschikbaar via `active-web-zap-active`
- artifacten landen in MinIO wanneer `ARTIFACTS_STORAGE_MODE=s3` actief is
- findings zijn per run opvraagbaar en kunnen via de API van status worden veranderd
- runrapporten kunnen als Markdown, HTML en PDF geëxporteerd worden naar `/srv/aegispt/reports`
- tekstuele runner-output en artifacts worden vóór opslag geredigeerd wanneer gevoelige waarden voorkomen
- Nuclei-evidence bevat curated template provenance via template id, source en digest
- Semgrep-evidence bevat curated rule provenance via rule id, source en digest
- curated internal validation scenarios zijn beschikbaar en live gevalideerd via code- en webworkflows
- `EXECUTION_KILL_SWITCH=true` blokkeert nieuwe dispatches globaal
- runs kunnen via de API naar `cancelled` of `cancelling` gezet worden
- `metasploit-framework` blijft op Ubuntu/WSL optioneel, maar is op de aparte Kali-VM expliciet bevestigd als aanwezig via de standaard Kali-repository

## Snelle directe host-installatie

Voor de snelste reproduceerbare operator-node op een Kali host:

```bash
cd /opt/aegispt/repo
sudo bash scripts/install_aegispt_host.sh
```

Deze flow installeert de host-tools, bouwt de virtuele omgeving, zet Playwright Chromium klaar voor PDF-export, maakt een host env-bestand aan onder `/srv/aegispt/env/aegispt-host.env`, installeert `aegispt.service` en start de UI op `http://127.0.0.1:8000/app/`.

Voor details en een volledige copy-paste flow:

- zie `docs/host_service_install.md`

## Eerste controle na het openen van de VM

```bash
cd /opt/aegispt/repo
systemctl status aegispt.service --no-pager
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/app/
```

Voor een bredere host-baselinecontrole:

```bash
bash scripts/verify_host.sh
bash scripts/setup_python_dev.sh
source .venv/bin/activate
pytest
```

## Nieuwe code of updates uitrollen

1. Werk de repository bij in `/opt/aegispt/repo`.
2. Herinstalleer of refresh de directe host-service met `sudo bash scripts/install_host_service.sh`.
3. Draai `pytest` als je code of regressies mee wilt valideren.
4. Gebruik Compose alleen wanneer je expliciet de multi-service stack nodig hebt.

```bash
cd /opt/aegispt/repo
sudo bash scripts/install_host_service.sh
source .venv/bin/activate
pytest
```

## Als `/app/` wel draait maar `aegispt.service` ontbreekt

Dan draait er meestal nog een losse oude `uvicorn`-instantie op poort `8000` buiten de reproduceerbare service-lane. Dat is precies het soort situatie waarbij de UI nog zichtbaar is, maar `Start Validation` op oude `manual` dispatch kan blijven hangen.

Gebruik dan eerst de repo-helper:

```bash
cd /opt/aegispt/repo
bash scripts/restart_local_inline_host.sh
```

Die helper wacht nu ook expliciet op `/health/live` en toont direct de recente host-log als de nieuwe inline host niet gezond opkomt.

Voor een duurzamere lokale recovery kun je in plaats daarvan de transient systemd-unit helper gebruiken:

```bash
cd /opt/aegispt/repo
sudo bash scripts/restart_local_inline_host_systemd.sh
```

Die start `aegispt-inline-host.service`, wacht op `/health/live` en verwijst je bij fouten direct naar de juiste `journalctl`-uitvoer.

Beide lokale restart-helpers zorgen nu ook dat Playwright Chromium in het ingestelde `PLAYWRIGHT_BROWSERS_PATH` aanwezig is. Dat voorkomt dat HTML-export werkt terwijl PDF-export op de live host nog een `503` geeft door een browser-pad dat niet echt gevuld was.

En zet de host daarna weer terug op het duurzame pad:

```bash
cd /opt/aegispt/repo
sudo bash scripts/install_host_service.sh
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
- De direct-host service gebruikt standaard `/srv/aegispt/env/aegispt-host.env` en `aegispt.service`.
- Als `aegispt.service` ontbreekt maar poort `8000` wel bezet is, draai je waarschijnlijk nog een losse oude `uvicorn`-host; gebruik dan eerst `bash scripts/restart_local_inline_host.sh` of ga direct terug naar `sudo bash scripts/install_host_service.sh`.
- Secrets worden lokaal in `infra/compose/.env` gegenereerd; beheer gevoelige waarden later desgewenst vanuit `/srv/aegispt/env`.
- Voor de directe host-flow wordt standaard geen nieuwe `LOCAL_SECRET_ENCRYPTION_KEY` afgedwongen; zet die expliciet vóór `bash scripts/generate_host_env.sh` op een verse host als je meteen een eigen sleutel wilt gebruiken.
- De codebase mikt op Python 3.12+; de huidige Kali host draait Python 3.13.
- `bash scripts/verify_host.sh` controleert nu expliciet `python3`, `pip` en `venv`-ondersteuning zodat een kapotte Python hosttoolchain eerder opvalt.
- `bash scripts/install_security_tools.sh` gebruikt waar nodig pinned officiële release-archieven voor `nuclei`, `httpx-toolkit`, `feroxbuster` en ZAP, plus Java 17 voor ZAP runtime.
- `bash scripts/verify_host.sh` unset lege proxy-variabelen voordat Semgrep gevalideerd wordt; dat voorkomt valse host-fouten op sommige WSL shells.
- `zapd` expose't alleen intern in Compose; de worker spreekt de daemon via `ZAP_BASE_URL` en `ZAP_API_KEY`.
- Compose mount de repository read-only in de worker als `/workspace/repo`; gebruik dat pad in code-scope voor Semgrep-runs.
- Zet `EXECUTION_KILL_SWITCH=true` in `infra/compose/.env` als je tijdelijk elke nieuwe dispatch wilt blokkeren.
- Voor webgebaseerde internal validation in Compose kun je `http://api:8000` als allowlisted doel gebruiken, omdat worker en ZAP daemon de API via het interne Compose-netwerk zien.
