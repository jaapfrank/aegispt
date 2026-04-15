# AegisPT Implementation Runbook

## Doel

Dit document is de praktische bouwhandleiding voor AegisPT op een herbruikbare Kali Linux VM in Hyper-V.

Het doel is om de VM zo in te richten dat:

- de host later opnieuw te gebruiken is als AegisPT operator node
- de installatie reproduceerbaar is
- tooling en data netjes gescheiden blijven
- het project stap voor stap ontwikkeld kan worden zonder scope creep
- de security randvoorwaarden uit `AegisPT.md` leidend blijven

De repository levert inmiddels de eerste bruikbare implementatieslice: FastAPI control plane, worker-runners, Alembic-migratie, Docker Compose stack, host provisioning scripts, findings-normalisatie en rapportexport zijn aanwezig. Dit runbook blijft de leidende handleiding om die basis gecontroleerd uit te bouwen.

## Huidige status op 15 april 2026

De huidige baseline van AegisPT bestaat uit:

- host bootstrap scripts voor Kali
- security tool installatie voor ZAP, Nuclei, httpx-toolkit, ffuf, feroxbuster, testssl.sh en Semgrep, met optionele Metasploit-installatie wanneer package sources dat toelaten
- een FastAPI control plane met health, engagement, run profile en approval-gated run endpoints
- expliciete run dispatch en task inspection endpoints
- run cancellation en globale execution kill switch
- SQLAlchemy modellen en een eerste Alembic migratie
- een worker met uitvoerbare `httpx`, `nuclei`, `semgrep` en ZAP API runners
- Docker Compose voor API, worker, PostgreSQL, Redis, MinIO en ZAP daemon
- MinIO-backed artifact opslag met API download
- findings-normalisatie voor ZAP, Nuclei en Semgrep, inclusief statusworkflow
- Markdown- en HTML-rapportexport per run
- baseline redaction before storage voor tekstuele output en artifacts
- curated Nuclei template provenance in evidence metadata
- curated Semgrep rule provenance in evidence metadata
- approval-gated ZAP active scan profiel
- curated internal validation sessies met preflight checks en step approvals
- pytest dekking en CI bootstrap

Deze status geldt als afgeronde eerste slice plus afgeronde fase 5, 6 en 7. De onderdelen onder "Wat nu bewust niet in scope zit" blijven bewust voor latere fases.

## Leidende principes

Deze keuzes uit de projectbrief blijven leidend:

- Evidence-first: elke finding moet terug te leiden zijn naar ruwe artefacten, configuratie en replaybare stappen.
- Safe by default: geen directe AI-tool control zonder policy checks.
- Scope first: alle uitvoer moet hard aan allowlists, approvals en run profiles gebonden zijn.
- Reuse over improvisation: liever scripts, containers en snapshots dan handmatige one-off installaties.
- No autonomous worming: internal validation blijft stap-gebaseerd en human-in-the-loop.

## Gewenste eindsituatie

Na uitvoering van dit runbook moet de Kali-VM de volgende rol kunnen vervullen:

- herbruikbare development en operator VM voor AegisPT
- host voor Docker Compose services van AegisPT
- host met kern security tools voor de MVP pipeline
- basisplatform voor latere uitbreiding naar policy-verdieping en aanvullende internal validation runbooks

## Standaard indeling op de VM

Gebruik deze vaste paden zodat code, runtime data en backups gescheiden blijven:

```text
/opt/aegispt
  repo/              # git repository
  bootstrap/         # host setup scripts en checks

/srv/aegispt
  env/               # .env files en secrets references
  postgres/          # postgres data of bind mount target
  minio/             # object storage data
  reports/           # gegenereerde rapporten
  artifacts/         # export of replay bundles
  backups/           # lokale exports en back-ups

/var/log/aegispt
  app/               # optionele host logs
```

## VM reuse strategie

De VM moet als gelaagde bouwsteen behandeld worden. Niet alles in een checkpoint proppen.

Aanbevolen snapshots of exports:

1. `kali-clean`
   Een schone, gepatchte Kali-installatie met SSH en basis hardening.
2. `aegispt-host-tools`
   Na installatie van Docker, pipx en de security tools.
3. `aegispt-bootstrap`
   Na aanmaak van projectpaden, repo bootstrap, Compose en basis scripts.
4. `aegispt-mvp-working`
   Na eerste werkende pipeline.

Belangrijk:

- gebruik snapshots voor herstel op korte termijn
- gebruik scripts en documentatie voor herstel op lange termijn
- vertrouw niet alleen op Hyper-V checkpoints

## Technische keuzes voor MVP

Om discussie en vertraging te voorkomen, leggen we voor de eerste implementatie deze keuzes vast:

- API framework: FastAPI
- Python versie: 3.12+ voor de codebase, met Kali host runtime momenteel op Python 3.13
- ORM en migrations: SQLAlchemy 2 + Alembic
- Queue: Dramatiq met Redis
- Database: PostgreSQL 16
- Artifact store: MinIO
- Runtime: Docker Compose voor dev en single-node gebruik
- Container isolation: per service en runner, geen directe vrije shell vanuit de API
- Test stack: pytest
- Formatting en linting: ruff + black

Waarom Dramatiq in plaats van Celery voor MVP:

- eenvoudiger voor een nieuwe codebase
- minder configuratie-oppervlak
- goed genoeg voor task dispatch en retries in de eerste versies

## Host baseline op Kali

Deze stap maakt de VM veilig en bruikbaar als herbruikbare AegisPT node.

### Stap 1: basis hardening

Uitvoeren op de Kali host:

```bash
passwd
sudo apt update
sudo apt full-upgrade -y
sudo timedatectl set-timezone Europe/Amsterdam
```

Optioneel maar sterk aanbevolen zodra key-based SSH werkt:

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudoedit /etc/ssh/sshd_config
sudo systemctl restart ssh
```

Aanbevolen SSH instellingen:

- `PasswordAuthentication no`
- `PermitRootLogin no`
- `PubkeyAuthentication yes`

### Stap 2: host packages installeren

Installeer eerst generieke beheer- en buildtools:

```bash
sudo apt install -y \
  git curl wget jq unzip zip ca-certificates gnupg lsb-release \
  build-essential make tree tmux htop ripgrep \
  pipx python3 python3-venv python3-pip \
  docker.io docker-compose
```

Installeer daarna de host dependencies voor de MVP-tooling:

```bash
sudo apt install -y \
  curl unzip tar ca-certificates pipx \
  openjdk-17-jre-headless \
  nmap ffuf testssl.sh
```

Gebruik daarna de repo-installer voor de pinned security-tooling:

```bash
cd /opt/aegispt/repo
bash scripts/install_security_tools.sh
```

Opmerking:

- `scripts/install_security_tools.sh` installeert `nuclei`, `httpx-toolkit`, `feroxbuster` en ZAP via pinned officiële release-archieven wanneer distro-packages ontbreken.
- Semgrep wordt via `pipx` onder de operator-user geplaatst, niet via system pip.
- Playwright bij voorkeur in een runner container installeren, niet als host-level dependency van de VM.
- Metasploit alleen toevoegen als de huidige distro- of vendor-repository `metasploit-framework` levert; het hoort nog steeds niet in de eerste MVP pipeline.
- Op Kali Rolling zelf is `metasploit-framework` op 15 april 2026 expliciet bevestigd als aanwezig via de standaard Kali-repository (`6.4.124-0kali1`).

### Stap 3: Docker activeren

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker
```

### Stap 4: vaste directories maken

```bash
sudo mkdir -p /opt/aegispt/repo
sudo mkdir -p /opt/aegispt/bootstrap
sudo mkdir -p /srv/aegispt/{env,postgres,minio,reports,artifacts,backups}
sudo mkdir -p /var/log/aegispt/app
sudo chown -R "$USER":"$USER" /opt/aegispt
sudo chown -R "$USER":"$USER" /srv/aegispt
sudo chown -R "$USER":"$USER" /var/log/aegispt
```

### Stap 5: host verificatie

```bash
docker --version
docker-compose version
python3 --version
semgrep --version
nuclei -version
zaproxy -version
```

## Project bootstrap

De codebase moet niet direct in runtime directories gebouwd worden. Houd source en data gescheiden.

### Aanbevolen repository locatie op de VM

```text
/opt/aegispt/repo
```

### Hergebruik van de VM

Voor dagelijks gebruik op de vaste Kali-VM:

```bash
cd /opt/aegispt/repo
bash scripts/verify_host.sh
source .venv/bin/activate
pytest
```

Voor het starten van de lokale stack:

```bash
cd /opt/aegispt/repo
bash scripts/generate_compose_env.sh
docker-compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env up --build
```

De Compose-config gebruikt vaste hostpaden onder `/srv/aegispt`, zodat runtime data niet tussen de broncode terechtkomt.

### Eerste repository structuur

De eerste implementatie moet deze structuur krijgen:

```text
aegispt/
  README.md
  docs/
    architecture.md
    threat-model.md
    runbooks/
    AegisPT-Implementation-Runbook.md
  api/
    app/
      main.py
      config.py
      db.py
      models/
      routers/
      schemas/
      services/
      auth/
      policy/
    tests/
  workers/
    orchestration/
    runners/
      base/
      httpx/
      zap/
      nuclei/
      semgrep/
      playwright/
    tests/
  infra/
    compose/
      docker-compose.yml
      .env.example
    k8s/
      base/
      overlays/
  migrations/
  scripts/
    bootstrap_kali_host.sh
    install_security_tools.sh
    init_runtime_dirs.sh
    verify_host.sh
    verify_stack.sh
  .github/
    workflows/
      ci.yml
```

## Implementatievolgorde

De grootste fout bij dit soort projecten is te vroeg te veel tools aansluiten. Daarom is de volgorde hieronder verplicht.

### Fase 0: documentatie en basiskeuzes vastzetten

Doel:

- het project afbakenen
- de MVP kiezen
- de host en projectpaden standaardiseren

Deliverables:

- dit runbook
- `README.md`
- `docs/architecture.md`
- `docs/threat-model.md`

Definition of done:

- iedereen weet waar code hoort te staan
- host path conventions staan vast
- MVP scope is expliciet beperkt

### Fase 1: foundations

Doel:

- control plane skeleton bouwen
- CI, database en auth fundament neerzetten

Taken:

1. FastAPI app skeleton maken.
2. Config management toevoegen via environment variables.
3. PostgreSQL koppelen via SQLAlchemy 2.
4. Alembic migrations initialiseren.
5. Basale auth en RBAC basis toevoegen.
6. Audit logging model toevoegen.
7. Health endpoints toevoegen.

Minimale API endpoints in deze fase:

- `GET /health/live`
- `GET /health/ready`
- `POST /api/v1/engagements`
- `POST /api/v1/engagements/{id}/scope`
- `GET /api/v1/run-profiles`
- `POST /api/v1/engagements/{id}/runs`
- `GET /api/v1/runs/{id}`
- `POST /api/v1/runs/{id}/approvals`
- `POST /api/v1/runs/{id}/dispatch`
- `GET /api/v1/tasks/{id}`

Database tabellen die in fase 1 moeten bestaan:

- `engagements`
- `scopes`
- `run_profiles`
- `runs`
- `approvals`
- `audit_events`
- `secrets_refs`

Definition of done:

- Compose stack start lokaal op
- API kan verbinden met PostgreSQL
- migrations draaien schoon
- engagement en scope records zijn aan te maken
- standaard run-profielen worden automatisch beschikbaar
- passive runs queueen direct en active runs wachten op approval
- queued passive runs kunnen expliciet gedispatched worden

### Fase 2: queue, runners en evidence plane

Doel:

- veilige taakuitvoering en artefactopslag opzetten

Taken:

1. Dramatiq worker service toevoegen.
2. Runner interface vastleggen.
3. Task model en dispatch flow bouwen.
4. Artifact hashing toevoegen.
5. MinIO upload service bouwen.
6. Evidence metadata en redaction states modelleren.

Database tabellen die in fase 2 moeten bestaan:

- `tasks`
- `tool_executions`
- `evidence_artifacts`
- `findings`

Runner contract:

- input alleen als gestructureerde JSON
- targetvalidatie voor elke run
- geen vrije shell strings vanuit user input
- tool version en runner image digest altijd vastleggen
- stdout, stderr en exit code altijd bewaren
- output eerst redacteren, daarna opslaan

Definition of done:

- worker kan taken oppakken
- artefacten landen in MinIO
- hashes en metadata zijn zichtbaar in de database
- replay metadata bestaat voor een execution

### Fase 3: eerste werkende web pipeline

Doel:

- een end-to-end MVP leveren voor web/API validatie

Volgorde:

1. `httpx` runner
2. target normalisatie
3. ZAP passive scanning
4. Nuclei met goedgekeurde templates
5. findings normalisatie
6. eerste runner-executie
7. evidence packaging

Belangrijke regels:

- alleen approved target lists
- Nuclei templates alleen uit goedgekeurde bron
- ZAP alleen achter internal network en met API key
- begin met passive mode; active mode pas in latere fase

Definition of done:

- operator kan een run aanvragen
- control plane maakt `httpx` of `nuclei` taken aan op basis van het gekozen profiel
- worker kan gedispatchte `httpx` en `nuclei` taken uitvoeren
- execution metadata en artifact hashes zijn via de API inspecteerbaar
- mislukte taken zijn auditbaar

### Fase 4: reporting v1

Doel:

- bruikbare output genereren voor management en technische teams

Taken:

1. finding package model maken
2. severity mapping en statusflow toevoegen
3. executive summary template maken
4. technical appendix template maken
5. replay bundle export maken

Eis:

- geen finding in rapport zonder linked evidence

Definition of done:

- HTML en Markdown rapporten kunnen worden gegenereerd
- iedere finding verwijst naar artefacten, hashes en replay data

### Fase 5: code pipeline

Doel:

- SAST toevoegen zonder de web pipeline te verstoren

Taken:

1. repo import flow
2. Semgrep runner
3. JSON of SARIF opslag
4. findings normalisatie

Belangrijke regel:

- Semgrep via pipx of container, niet via system pip

Definition of done:

- een codebase kan gescand worden
- output wordt als evidence opgeslagen
- findings worden in hetzelfde model als web findings gepresenteerd

Status op 15 april 2026:

- afgerond
- `passive-code-semgrep-audit` is beschikbaar als run-profiel
- de worker scant allowlisted `paths` via de Compose mount `/workspace/repo`
- Semgrep JSON-evidence wordt in MinIO opgeslagen met `rule_id`, `rule_source` en `rule_sha256`
- findings worden genormaliseerd naar hetzelfde model als de web pipelines
- live gevalideerd op de Kali VM met een echte dispatch-run, artifact download en findingextractie

### Fase 6: active scans en approvals

Doel:

- gecontroleerde uitbreiding naar actions met meer impact

Taken:

1. policy engine uitbreiden
2. run classes afdwingen: `passive`, `active`, `intrusive`
3. approval workflow implementeren
4. kill switch en rate limiting toevoegen
5. ZAP active scan achter approval zetten

Definition of done:

- actieve scanstappen kunnen niet zonder approval starten
- limits en stopknop werken aantoonbaar

Status op 15 april 2026:

- afgerond
- `active-web-safe` blijft de approval-gated spider plus passive variant
- `active-web-zap-active` voegt een approval-gated actieve ZAP scan toe
- run classes en approvalvereisten worden centraal genormaliseerd in de policy engine
- `EXECUTION_KILL_SWITCH=true` blokkeert nieuwe dispatches
- `POST /api/v1/runs/{id}/cancel` kan queued runs stoppen en running runs op `cancelling` zetten
- op Kali gevalideerd met gerichte tests, een echte active ZAP run tegen de Compose API, volledige `pytest` en `bash scripts/verify_stack.sh`

### Fase 7: internal validation v1

Doel:

- alleen curated, approval-gated internal validation stappen toevoegen

Taken:

1. runbook model maken
2. step approvals modelleren
3. pre-flight checks implementeren
4. curated scenario library opzetten

Niet doen in deze fase:

- self-propagation
- autonome wormlogica
- vrije AI-driven exploit planning zonder menselijke approvals

Definition of done:

- een curated scenario kan stap voor stap uitgevoerd worden
- elke stap heeft approvals en evidence

Status op 15 april 2026:

- afgerond
- `curated-code-validation` en `curated-web-validation` zijn beschikbaar via de API
- preflight checks controleren scope, profielbeschikbaarheid en de staat van de globale kill switch
- elke internal validation stap lanceert een normale run en behoudt daarmee task-, artifact- en finding-evidence
- op Kali gevalideerd met gerichte pytest, volledige regressie, een live code-scenario en een live driestaps webscenario tegen de Compose API

## Service ontwerp voor Docker Compose

De single-node stack moet uit de volgende services bestaan:

- `api`
- `worker`
- `postgres`
- `redis`
- `minio`
- `zapd`

Optioneel later:

- `ui`
- `nginx` of `caddy`
- `playwright-runner`

### Host versus container verantwoordelijkheden

Op de host:

- Docker
- pipx
- Kali security tools die ook buiten containers nuttig zijn
- scripts voor verificatie en onderhoud

In containers:

- FastAPI app
- worker processen
- ZAP daemon
- Playwright runtime
- project-specifieke Python dependencies

## Verplichte host scripts

Om de VM later herbruikbaar te houden, moeten deze scripts in de repository komen:

- `scripts/bootstrap_kali_host.sh`
  Installeert algemene host packages.
- `scripts/install_security_tools.sh`
  Installeert de core security tools via apt plus pinned officiële release-archieven, en zet Semgrep via pipx onder de operator-user.
- `scripts/init_runtime_dirs.sh`
  Maakt `/opt/aegispt`, `/srv/aegispt` en `/var/log/aegispt` aan.
- `scripts/verify_host.sh`
  Controleert Docker, Python en tool versions, inclusief proxy-robuuste Semgrep-validatie.
- `scripts/verify_stack.sh`
  Controleert of Compose services gezond zijn.

Belangrijke regel:

- alles wat vaker dan een keer uitgevoerd wordt, moet uiteindelijk in een script terechtkomen

## Security eisen die vanaf dag 1 ingebouwd moeten worden

Deze eisen mogen niet tot "later" worden uitgesteld:

- scope allowlist op control plane niveau
- target re-validation in elke runner
- audit logging
- artifact hashing
- redaction before storage
- secrets alleen als references, niet als plaintext in de database
- ZAP API key afdwingen
- Nuclei template provenance afdwingen

## Acceptance criteria voor de eerste echte oplevering

De eerste bruikbare release is pas af als al het volgende klopt:

- Kali host is reproduceerbaar in te richten via scripts
- Docker Compose stack start schoon op
- API en worker communiceren met Postgres, Redis en MinIO
- engagement, scope en run profiel zijn via API vast te leggen
- `httpx`, ZAP API spider/passive en Nuclei draaien via de worker
- Semgrep code-scans draaien via de worker op allowlisted paden
- evidence artifacts kunnen naar MinIO worden weggeschreven en via de API worden teruggehaald
- findings worden nu genormaliseerd uit ZAP/Nuclei/Semgrep output, per run geteld en via de API beheerd
- findings bevatten linked evidence
- rapportage kan minimaal Markdown en HTML genereren
- de VM kan na snapshot of restore opnieuw als operator node gebruikt worden

Status van deze acceptance criteria:

- de eerste slice is op de Kali VM gevalideerd met `pytest`, `bash scripts/verify_stack.sh`, live run-dispatches en rapportexports
- fase 5 is aanvullend op de Kali VM gevalideerd met gerichte Semgrep-tests, een live `passive-code-semgrep-audit` dispatch en volledige regressiechecks
- fase 6 is aanvullend op de Kali VM gevalideerd met kill-switch tests, cancel-tests, een approval-gated live ZAP active scan en volledige regressiechecks
- fase 7 is aanvullend op de Kali VM gevalideerd met live `curated-code-validation` en `curated-web-validation` sessies plus volledige regressiechecks
- de resterende roadmap-items hieronder zijn bewust latere fases en blokkeren deze eerste slice plus fase 5, 6 en 7 niet

## Wat nu bewust niet in scope zit

Deze onderdelen zijn belangrijk, maar horen niet in de eerste bouwslice:

- Kubernetes deployment
- complexe multi-user UI
- geavanceerde external integrations
- vrije Metasploit orchestration
- geautomatiseerde lateral movement
- autonome AI agents die direct tools aansturen

## Aanbevolen uitvoervolgorde voor de komende werksessies

Sessie 1:

- host baseline afronden
- paden en scripts aanmaken
- repo structureren

Sessie 2:

- Compose stack opzetten
- FastAPI skeleton
- database en migrations

Sessie 3:

- worker framework
- MinIO evidence opslag
- artifact hashing

Sessie 4:

- `httpx` runner
- ZAP passive runner
- findings normalisatie

Sessie 5:

- Nuclei integratie
- rapportage v1

Sessie 6:

- Semgrep pipeline
- approvals en policy uitbreiding

Sessie 7:

- curated internal validation runbooks

Status van deze sessies op 15 april 2026:

- sessie 1 t/m 5 zijn afgerond
- sessie 6 is afgerond
- sessie 7 is afgerond

## Besluit

De juiste manier om AegisPT op deze Kali-VM te bouwen is niet "alles ineens installeren en dan hopen dat het bruikbaar blijft", maar een gecontroleerde opbouw:

1. de VM als herbruikbare host standaardiseren
2. de codebase netjes scaffolden
3. eerst control plane en evidence plane bouwen
4. daarna pas runners en rapportage uitbreiden
5. internal validation pas toevoegen nadat approvals en replayability bewezen werken

Dit document is vanaf nu de leidende uitvoeringstekst voor de opbouw van AegisPT op deze VM.
