# Host Service Install

## Purpose

This guide documents the smallest reproducible installation path for running AegisPT directly on a Kali or Linux host without first standing up the full Compose stack.

Use this path when you want:

- a local operator console at `http://127.0.0.1:8000/app/`
- direct host testing on a Kali VM
- a repeatable install that can be rerun after copying or cloning the repo elsewhere

Compose remains available for the multi-service stack. This guide is the simpler direct-host lane.

## Recommended install path

Keep the repository in a path without spaces. The recommended path is:

```text
/opt/aegispt/repo
```

## One-command install

From the repository root:

```bash
sudo bash scripts/install_aegispt_host.sh
```

This wrapper will:

- install the host packages and security tools
- create the runtime directories under `/opt/aegispt`, `/srv/aegispt`, and `/var/log/aegispt`
- build the repo-local Python virtual environment
- install Playwright Chromium for PDF export
- generate `/srv/aegispt/env/aegispt-host.env` when it does not exist
- run `alembic upgrade head`
- install and start `aegispt.service`

## Copy-paste install on a fresh Kali host

If the repository is not on the host yet, this is the shortest practical sequence:

```bash
sudo mkdir -p /opt/aegispt
sudo chown "$USER":"$USER" /opt/aegispt
git clone <YOUR-REPO-URL> /opt/aegispt/repo
cd /opt/aegispt/repo
sudo bash scripts/install_aegispt_host.sh
```

If you already copied the repository manually instead of cloning it, start from the `cd /opt/aegispt/repo` step.

## Host env file

The direct-host service uses:

```text
/srv/aegispt/env/aegispt-host.env
```

Generate it manually if you want to inspect or preseed it before service install:

```bash
bash scripts/generate_host_env.sh
```

Important defaults:

- `APP_PUBLIC_BASE_URL=http://127.0.0.1:8000`
- `AEGISPT_BIND_HOST=127.0.0.1`
- `AEGISPT_PORT=8000`
- `TASK_DISPATCH_MODE=inline`
- `DATABASE_URL=sqlite+pysqlite:///./aegispt.db`
- `AEGISPT_DB_KEY=` (blank means the local SQLite database stays plaintext)
- `ARTIFACTS_STORAGE_MODE=inline`
- `ARTIFACTS_S3_ENFORCE_SSE=false`

The direct-host runner now also falls back to `TASK_DISPATCH_MODE=inline` and `ARTIFACTS_STORAGE_MODE=inline` if an older env file forgot to define them, so `Start Validation` does not silently behave like a manual no-worker queue on host installs.

## Production deployment hardening

The default host install is development-grade: loopback HTTP, inline artifacts, local secret encryption, and direct/local egress. Do not treat that posture as enterprise production. Settings > Runtime Readiness and Support Diagnostics now expose a read-only `Production deployment hardening` status so operators can see the gap before rollout.

For production, put AegisPT behind a trusted TLS reverse proxy or ingress and set:

```bash
APP_ENV=production
APP_PUBLIC_BASE_URL=https://aegispt.example.com
DEPLOYMENT_TLS_TERMINATED_BY_PROXY=true
DEPLOYMENT_SECURE_COOKIES=true
```

`APP_PUBLIC_BASE_URL` must be an `https://` URL in production. Certificate private keys stay in the reverse proxy, load balancer, or ingress, not in AegisPT Settings or support bundles. If your enterprise uses a private CA for outbound TLS validation, set only the bundle path:

```bash
DEPLOYMENT_TRUSTED_CERTIFICATE_BUNDLE=/etc/aegispt/enterprise-ca.pem
```

Do not paste certificate private keys or proxy credentials into tickets, logs, screenshots, or support bundles.

For restricted egress, choose one of these modes:

```bash
# Controlled outbound proxy. Proxy URLs are treated as sensitive in Settings.
DEPLOYMENT_OUTBOUND_PROXY_URL=http://proxy.example.com:8080

# Or no-internet / air-gapped mode.
DEPLOYMENT_NO_INTERNET_MODE=true
DEPLOYMENT_OFFLINE_UPDATE_PATH=/srv/aegispt/offline/feeds
DEPLOYMENT_MANUAL_TOOL_UPDATE_PATH=/srv/aegispt/offline/tools
```

In air-gapped mode, feed, template, browser, and tool updates must be staged manually through the offline paths, then verified by the operator before production use. Threat-intel feeds, Nuclei templates, Playwright browsers, OS packages, and security tools are not downloaded live from the assessment host.

For encryption posture, production needs database encryption and evidence artifact encryption to be explicit:

```bash
# Direct-host SQLite encryption.
AEGISPT_DB_KEY=<generated-secret>

# If database/storage encryption is handled externally by PostgreSQL, disk, volume, KMS, or object storage,
# record that deployment proof has been verified:
DEPLOYMENT_DATABASE_ENCRYPTION_CONFIRMED=true
DEPLOYMENT_ARTIFACT_STORAGE_ENCRYPTION_CONFIRMED=true

# S3/MinIO artifact encryption enforcement when object storage is used:
ARTIFACTS_STORAGE_MODE=s3
ARTIFACTS_S3_ENFORCE_SSE=true
```

If any production hardening status is `blocked`, resolve it before using the host for enterprise customer assessments. A `degraded` production status means AegisPT is running, but a deployment owner still needs to confirm external controls such as CA trust, encrypted volumes, managed database encryption, proxy routing, or offline update handling.

## Production-like deployment proof drill

Use the proof drill when you need evidence that production assumptions are declared and fail closed before an enterprise rollout. The drill is safe-local: it does not install infrastructure, pull images, run customer targets, mutate active assessments, or expose secret material.

From the repository root:

```bash
source .venv/bin/activate
python scripts/run_production_deployment_proof.py \
  --output-json codex/results/production-deployment-proof-latest.json \
  --output-md codex/results/production-deployment-proof-latest.md
```

The proof output records:

- the current host deployment boundary, including whether it is only development-ready
- a production TLS/reverse-proxy/PostgreSQL/S3 fixture that must report ready
- an air-gapped/offline-update fixture that must report ready when both offline paths are configured
- an unsafe production fixture that must report blocked with exact reasons
- static Compose declarations for PostgreSQL, Redis, MinIO, ZAP, API, worker, persistence paths, and hardening env keys
- the safe local backup/restore drill with artifact hash, finding evidence reference, audit event, and secret-metadata verification
- a blocker for live Compose/PostgreSQL restore proof until an approved local Compose runtime is started and `pg_dump`/MinIO restore evidence is captured

Treat this proof as a gate input, not as a hosted production certification. If `enterprise_production_ready_claim_allowed` is `false`, the current host must not be called enterprise-production ready even when the fixture checks prove the configuration shape.

## Enterprise identity on a direct host

Fresh direct-host installs start with enterprise SSO disabled. Settings now shows the current identity state, the local-development fallback, API-key actors, and an explicit session timeout policy.

Supported in this host slice:

- OIDC/SAML configuration can be recorded and audited.
- Sensitive OIDC/SAML values are encrypted and masked.
- logout records an audit event and does not change active mission/run state.
- local X-Actor fallback remains available for supervised local use.

Not supported yet:

- enforced browser SSO login
- SCIM provisioning
- tenant membership administration
- hosted enterprise RBAC

Use API keys for scoped local automation until a later task enables enforced enterprise sign-in.

If you want the service reachable from another host, edit:

- `AEGISPT_BIND_HOST=0.0.0.0`
- `APP_PUBLIC_BASE_URL=http://<host-ip>:8000`

## Explicit secret key on new installs

To seed an explicit local secret encryption key for a fresh host:

```bash
export AEGISPT_LOCAL_SECRET_ENCRYPTION_KEY="$(python3 - <<'PY'
import base64
import os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
bash scripts/generate_host_env.sh
```

The installer does not force a new key automatically because older local test runs may still rely on the current development fallback key. Set it deliberately on fresh hosts or during a planned re-key.

## Deployment-key-backed secret materialization

Fresh host installs default to `SECRET_MATERIALIZATION_MODE=encrypted_local`. That keeps direct wizard-entered passwords, API keys, bearer tokens, and session material out of normal run configuration by encrypting them into `SecretRef` records with the local key.

To use a deployment-specific Fernet key for direct wizard-entered secrets:

```bash
export AEGISPT_SECRET_MATERIALIZATION_MODE=deployment_key
export AEGISPT_DEPLOYMENT_SECRET_ENCRYPTION_KEY="$(python3 - <<'PY'
import base64
import os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
bash scripts/generate_host_env.sh
```

If you want missing deployment-key configuration to block direct secret material instead of falling back to local encryption, also set:

```bash
export AEGISPT_REQUIRE_DEPLOYMENT_SECRET_ENCRYPTION_KEY=true
```

External references such as `vault://...` remain pointers and do not require the deployment key. The key is only needed when AegisPT has to encrypt direct secret material itself.

## Database encryption at rest

Direct-host installs use SQLite by default. To encrypt the SQLite database file with SQLCipher, set `AEGISPT_DB_KEY` before starting the service:

```bash
export AEGISPT_DB_KEY="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
sudo systemctl restart aegispt.service
```

For a fresh install, pass the key while generating the host env file:

```bash
export AEGISPT_DB_KEY="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
bash scripts/generate_host_env.sh
```

To encrypt an existing plaintext SQLite database, stop the service first, create an encrypted copy, then point `DATABASE_URL` at the encrypted file and set the same `AEGISPT_DB_KEY` in `/srv/aegispt/env/aegispt-host.env`:

```bash
sudo systemctl stop aegispt.service
source .venv/bin/activate
python scripts/encrypt_existing_db.py \
  --source ./aegispt.db \
  --output ./aegispt.encrypted.db \
  --key "$AEGISPT_DB_KEY"
```

Keep the key in the service env file or a managed secret store. If `APP_ENV` is not a development-like value and `AEGISPT_DB_KEY` is missing, AegisPT logs:

```text
Database is NOT encrypted. Set AEGISPT_DB_KEY environment variable to enable encryption at rest.
```

The encryption path is transparent to the application models and queries; only the SQLite driver changes when `AEGISPT_DB_KEY` is present.

## MinIO/S3 server-side encryption

When artifact storage uses S3 or MinIO, enable AegisPT's SSE-S3 upload flag:

```bash
ARTIFACTS_STORAGE_MODE=s3
ARTIFACTS_S3_ENFORCE_SSE=true
```

With MinIO, configure the deployment so the bucket accepts SSE-S3 (`x-amz-server-side-encryption: AES256`). AegisPT will add that header to artifact uploads when `ARTIFACTS_S3_ENFORCE_SSE=true`. Inline artifact storage is unaffected.

## Backup, restore, upgrade, and rollback drill

Before upgrading a host or Compose install, create a backup bundle and run the local restore drill. The drill is safe: it uses a seeded local fixture and does not touch live customer targets or active runs.

For the direct-host SQLite lane:

```bash
cd /opt/aegispt/repo
source .venv/bin/activate
python scripts/backup_aegispt.py \
  --database-url "$(grep '^DATABASE_URL=' /srv/aegispt/env/aegispt-host.env | cut -d= -f2-)" \
  --artifacts-dir /srv/aegispt/artifacts \
  --reports-dir /srv/aegispt/reports \
  --env-file /srv/aegispt/env/aegispt-host.env \
  --output-dir /srv/aegispt/backups/aegispt-$(date -u +%Y%m%dT%H%M%SZ)
python scripts/verify_restore.py --fixture safe-local
```

The backup bundle contains:

- `database/aegispt.sqlite3` for the SQLite database file
- `artifacts/inline/` for inline evidence artifacts
- `reports/` for generated report output when present
- `config/*.redacted.json` for env/config recovery metadata
- `backup-manifest.json` with file hashes and Alembic state

Secret-looking env values are redacted in manifests and logs. Preserve real deployment secrets, `AEGISPT_DB_KEY`, OAuth client secrets, API keys, and vault material through an external vault or encrypted operator backup. Do not paste plaintext secrets into support bundles.

To restore a bundle into a separate verification directory:

```bash
python scripts/restore_aegispt.py \
  --backup-dir /srv/aegispt/backups/<backup-id> \
  --restore-dir /srv/aegispt/backups/<backup-id>-restore
DATABASE_URL="sqlite+pysqlite:////srv/aegispt/backups/<backup-id>-restore/database/aegispt.sqlite3" \
ARTIFACTS_STORAGE_MODE=inline \
ARTIFACTS_INLINE_DIR="/srv/aegispt/backups/<backup-id>-restore/.aegispt-artifacts" \
AUTO_CREATE_TABLES=false \
python -m alembic current
```

For Compose/PostgreSQL installs, use the same manifest discipline but replace the SQLite database file step with a PostgreSQL dump taken while the stack is quiesced or under a consistent snapshot:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres \
  pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB" \
  > /srv/aegispt/backups/<backup-id>/database/aegispt-postgres.dump
```

Then back up the Compose env file, MinIO/S3 artifact bucket or bind mount, reports path, and the migration state (`python -m alembic current` plus `python -m alembic heads`). The restore target must run `alembic current` before service start and `alembic upgrade head` only after the backup has been verified and the rollback point is retained.

Upgrade preflight:

- stop or pause new assessment launches
- confirm `/health/live` is healthy before shutdown
- create the backup bundle
- run `python scripts/verify_restore.py --fixture safe-local`
- record `python -m alembic current` and `python -m alembic heads`
- keep the previous git tag/commit, env file, artifact storage, report path, and database backup together

Rollback:

- stop `aegispt.service` or the Compose stack
- restore the previous code revision and env/config
- restore the database and artifact/report paths from the matched backup
- run `python -m alembic current` against the restored database
- start AegisPT and verify `/health/live`, engagement list, one restored run, one artifact download, and report catalog access

## Updating an existing host install

After pulling or copying new code into the same repo path:

```bash
cd /opt/aegispt/repo
sudo bash scripts/install_host_service.sh
```

This refreshes the Python environment, keeps the existing host env file, reruns migrations, reinstalls the service definition, and restarts the service.

Operational notes:

- `scripts/setup_python_dev.sh` recreates the repo-local `.venv` with `python3 -m venv --clear .venv`, so copied environments from another host are replaced instead of reused accidentally.
- `scripts/install_host_service.sh` explicitly restarts an already-running `aegispt.service`, so updates to the repo path, UI bundle, or API code take effect immediately on the host.

## Support diagnostics bundle

Settings includes a **Support Diagnostics** panel for safe operator triage. Use it before reading raw shell logs when a run is stuck, a tool is missing, the feed sync is rate-limited, ChatGPT OAuth is disconnected, or the host is not behaving like the current repo revision.

The panel summarizes:

- app health and `/health/live` state
- database migration head and current Alembic revision
- worker or inline dispatch mode
- queue depth, active runs, and stuck-run signal
- pentest tool readiness and affected assessment families
- AI provider and ChatGPT OAuth readiness
- threat feed sync status
- recent failed tasks, failed runs, feed failures, and audit harness artifacts

Admins can export a redacted bundle from the same panel or from:

```bash
curl --fail --silent \
  -H 'X-Actor: support-admin' \
  -H 'X-Actor-Role: admin' \
  http://127.0.0.1:8000/api/v1/diagnostics/support-bundle \
  > /tmp/aegispt-support-bundle.json
```

The bundle is intended for support handoff and contains status snapshots, safe config shape, migration/readiness context, recent log excerpts, task IDs, run IDs, and validation artifact names. It does not include raw evidence payloads, task stdout/stderr, credential material, API tokens, passwords, secret values, or hash-looking long identifiers by default.

If the support bundle points to a failing subsystem, follow the `operator_next_step` field first. If the bundle itself cannot be generated, verify `/health/live`, restart the host service, and then re-open Settings after the service is healthy.

## Tool readiness repair and governed enablement

Fresh supported hosts should have the software pentest tool groups prepared by the official installer or the Compose image. Settings > Runtime Readiness reports each tracked software group separately and shows the exact missing command group when the host does not match the expected image.

Use the official host repair lane from the repo root:

```bash
sudo bash scripts/install_security_tools.sh && bash scripts/verify_host.sh
```

For Compose installs, rebuild the image after pulling the current repo:

```bash
docker compose -f infra/compose/docker-compose.yml build --no-cache
```

The readiness model separates software from hardware:

- missing software groups show a copyable install/repair command and affected assessment families
- WiFi software readiness is independent from wireless adapter hardware readiness
- no wireless adapter remains a hardware blocker until an authorized adapter is attached or a lab fixture is used
- risky or provider-backed capabilities can show Enable/Configure actions, but those actions only write Settings values

Enable/Configure actions do not run pentest tools, do not start scans, do not grant approvals, and do not bypass scope, ROE, pack validation, deployment, runtime binding, credential gates, or the kill switch.

## If port 8000 is occupied by an old ad-hoc Uvicorn process

If `http://127.0.0.1:8000/app/` is live but `systemctl status aegispt.service` says the unit does not exist, you are not using the reproducible host-service lane yet. In that case the most common symptom is:

- the UI loads
- `Start Validation` looks clickable
- the host is still running stale manual-dispatch behavior

Use the repo helper to replace that ad-hoc process with the current inline host runner:

```bash
cd /opt/aegispt/repo
bash scripts/restart_local_inline_host.sh
```

This helper now waits for `http://127.0.0.1:8000/health/live` and exits non-zero with the recent host log if the process fails to come up cleanly.

Then reload the browser and test again.

If you want a more durable local recovery path that survives the shell process more reliably, use the transient systemd-unit helper instead:

```bash
cd /opt/aegispt/repo
sudo bash scripts/restart_local_inline_host_systemd.sh
```

That helper starts the local host as a transient unit named `aegispt-inline-host.service`, waits for `/health/live`, and points you to the correct `journalctl` command if startup fails.

Both local restart helpers now also ensure Playwright Chromium in the configured `PLAYWRIGHT_BROWSERS_PATH` before the host comes up. This keeps live PDF export aligned with the path the service actually uses instead of only working in temporary test hosts.

For the durable path, move back to the documented service lane:

```bash
cd /opt/aegispt/repo
sudo bash scripts/install_host_service.sh
```

## Validation

After install:

```bash
systemctl status aegispt.service --no-pager
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/app/
```

Follow logs with:

```bash
journalctl -u aegispt.service -f
```

## Kali/local-host signoff packet

Use this packet after a fresh install, after copying the repo to a new Kali VM, or after pulling updates into an existing direct-host install. It is intentionally limited to the supported local host lane and does not replace the Compose stack or active-safe lab validation.

From the repository root on the host:

```bash
cd /opt/aegispt/repo
sudo bash scripts/install_host_service.sh
systemctl status aegispt.service --no-pager
curl --fail --silent http://127.0.0.1:8000/health/live
curl --fail --silent http://127.0.0.1:8000/app/ > /tmp/aegispt-app.html
grep -E 'Operator Console|assets/styles.css' /tmp/aegispt-app.html
grep -E 'type="module"|assets/app.js' /tmp/aegispt-app.html
source .venv/bin/activate
python scripts/run_acceptance_matrix.py \
  --base-url http://127.0.0.1:8000 \
  --scenario-id local-app-smoke
```

The first two `grep` commands are the static app freshness check for this lane. They confirm that the host is serving the current operator-console shell and module asset references from the repo after the service restart, instead of an older ad hoc Uvicorn process or stale static copy.

The `local-app-smoke` acceptance result must be written under `codex/results/` and should include direct HTML/PDF report links. Those links are the report-export signoff evidence for this minimal host packet.

If the durable service path is unavailable during local development, use the transient inline host recovery first and then rerun the same health, app, and smoke checks:

```bash
cd /opt/aegispt/repo
sudo bash scripts/restart_local_inline_host_systemd.sh
```

If `sudo` or `systemd-run` is unavailable in the current shell, the non-systemd fallback is:

```bash
cd /opt/aegispt/repo
bash scripts/restart_local_inline_host.sh
```

In a non-interactive shell where `/opt/aegispt/ms-playwright` is root-owned and `sudo` cannot prompt for a password, use a repo-local browser cache explicitly:

```bash
cd /opt/aegispt/repo
PLAYWRIGHT_BROWSERS_PATH="${PWD}/.cache/ms-playwright" bash scripts/restart_local_inline_host.sh
```

Expected failure modes to record honestly:

- `aegispt.service` is missing while port `8000` is occupied: replace the ad hoc host with `scripts/install_host_service.sh` or one of the inline restart helpers before signing off.
- `/health/live` fails: inspect `journalctl -u aegispt.service -f` for the durable service or `/tmp/aegispt-inline-host.log` for the non-systemd helper.
- `/app/` loads but the asset references look old: restart through the repo helper or durable installer, then hard-refresh the browser.
- PDF export fails while HTML export works: rerun the helper or installer so `scripts/ensure_playwright_chromium.sh` fills the configured `PLAYWRIGHT_BROWSERS_PATH`.
- `local-app-smoke` waits forever or fails as queued: the host is likely in `manual` dispatch mode without an active worker; the direct-host signoff lane expects inline dispatch.

## What this does not replace

This direct-host lane does not replace:

- the Compose stack in `infra/compose/`
- the full host verification lane in `scripts/verify_host.sh`
- the reusable VM guidance in `docs/Kali-VM-Reuse-Guide.md`

It gives you a reproducible, lower-friction path for getting a working operator console and report export on a Kali host.
