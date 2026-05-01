# AegisPT Installation

This directory is the install entry point for a new evaluator or operator.
AegisPT now has three supported local install paths.

## Which Install Method Is Right For You?

Use Docker Compose when you want the fastest reproducible local stack. It starts
the API, worker, PostgreSQL, Redis, and a Kali-based tools container from the
repo root.

Use the Kali host installer when you want AegisPT to run as a systemd service on
a dedicated Kali, Debian, or Ubuntu machine with the security tools installed on
the host.

Use the Windows/WSL guide when the operator workstation is Windows and the Linux
runtime should live inside WSL2.

## Docker Compose

From the repository root:

```bash
bash scripts/generate_compose_env.sh
docker compose up --build
```

To manage values manually instead, copy `.env.example` to `.env` and replace
the placeholder secrets before starting Compose.

Open `http://127.0.0.1:8000/app/` after the `aegispt-api` health check is
green.

The root `docker-compose.yml` defines:

- `aegispt-api`: FastAPI app with database migrations before startup.
- `aegispt-worker`: Dramatiq worker bound to the same runtime settings.
- `aegispt-db`: PostgreSQL 16 with a persistent volume.
- `aegispt-redis`: Redis 7 with append-only persistence.
- `aegispt-tools`: Kali-based tools container that exposes ZAP for worker use.

For local source mounts, copy `docker-compose.override.yml.example` to
`docker-compose.override.yml`.

## One-Line Kali Installer

For a cloned repo on a Kali, Debian, or Ubuntu host:

```bash
bash scripts/install_aegispt_host.sh
```

The script bootstraps host packages, installs the security toolchain, generates
a host-local secret key when the env file is new, installs the systemd unit, and
prints the local UI and health URLs.

The future curl installer form is intentionally a placeholder and is not live:

```bash
curl -fsSL https://install.aegispt.io/install.sh | bash
```

## Windows/WSL

Use [windows-wsl.md](windows-wsl.md) for a step-by-step Windows workstation
setup with WSL2 and the same host installer scripts.

## Validation

For install-package changes, run:

```bash
python3 scripts/validate_backlog_tasks.py
docker compose config --quiet
source .venv/bin/activate && python -m pytest --capture=no api/tests/test_product_feature_matrix.py
git diff --check
```
