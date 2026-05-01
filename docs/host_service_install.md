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
