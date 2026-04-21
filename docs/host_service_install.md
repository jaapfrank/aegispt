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
- `ARTIFACTS_STORAGE_MODE=inline`

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

## What this does not replace

This direct-host lane does not replace:

- the Compose stack in `infra/compose/`
- the full host verification lane in `scripts/verify_host.sh`
- the reusable VM guidance in `docs/Kali-VM-Reuse-Guide.md`

It gives you a reproducible, lower-friction path for getting a working operator console and report export on a Kali host.
