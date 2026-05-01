# Windows And WSL2 Setup

This guide runs AegisPT inside WSL2 while Windows remains the operator
workstation.

## Requirements

- Windows with WSL2 enabled.
- A Linux distribution installed in WSL2. Kali is preferred for security-tool
  coverage; Ubuntu or Debian can also use the host installer.
- Systemd enabled in the WSL distribution.
- Docker Desktop with WSL integration, or Docker installed inside the WSL
  distribution.

## 1. Prepare WSL

Open PowerShell as Administrator and make sure WSL is enabled:

```powershell
wsl --install
wsl --set-default-version 2
```

Restart Windows if WSL asks for it. Then open the Linux distribution.

If systemd is not enabled, edit `/etc/wsl.conf` inside WSL:

```ini
[boot]
systemd=true
```

Restart WSL from PowerShell:

```powershell
wsl --shutdown
```

Open the Linux distribution again and confirm systemd:

```bash
systemctl is-system-running
```

`running` or `degraded` is acceptable for WSL.

## 2. Put The Repo In A Linux Path

Keep the repository on the WSL filesystem, not under `/mnt/c`, so venv,
Playwright, Docker, and systemd file permissions stay predictable.

Recommended path:

```bash
sudo mkdir -p /opt/aegispt
sudo chown "$USER:$USER" /opt/aegispt
cd /opt/aegispt
git clone <YOUR-AEGISPT-REPO-URL> repo
cd repo
```

The placeholder `<YOUR-AEGISPT-REPO-URL>` must be replaced with your actual
repository URL.

## 3. Choose Docker Compose Or Host Service

For Docker Compose:

```bash
bash scripts/generate_compose_env.sh
docker compose up --build
```

Then open `http://127.0.0.1:8000/app/` from Windows or WSL.

For a WSL systemd service:

```bash
bash scripts/install_aegispt_host.sh
```

Then open `http://127.0.0.1:8000/app/` from Windows.

## 4. Validate The Install

Inside WSL:

```bash
curl --fail --silent http://127.0.0.1:8000/health/live
curl --fail --silent http://127.0.0.1:8000/app/
```

For the systemd install:

```bash
systemctl status aegispt.service
journalctl -u aegispt.service -f
```

For Docker Compose:

```bash
docker compose ps
docker compose logs -f aegispt-api aegispt-worker
```

## Notes

- Avoid paths with spaces. The systemd host installer rejects them because unit
  files and venv paths must remain deterministic.
- Keep the default bind host as `127.0.0.1` unless you explicitly intend to
  expose AegisPT beyond the local workstation.
- Do not run live external target actions from WSL unless the target is safe,
  local, or explicitly authorized in the AegisPT scope.
