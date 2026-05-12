@echo off
REM AegisPT — start alles in één keer
REM Dubbelklik dit bestand om de backend, ZAP en Playwright te starten.
REM Vereisten: WSL2 met Ubuntu, zie scripts/install_aegispt_host.sh voor installatie.

set WSL_DISTRO=ubuntu
set REPO_PATH=/home/administrator/project/automation skill/AegisPT

echo [AegisPT] Starten...
wsl -d %WSL_DISTRO% bash -lc "cd '%REPO_PATH%' && bash scripts/restart_local_inline_host.sh"

if %ERRORLEVEL% neq 0 (
    echo [AegisPT] FOUT: startup mislukt. Zie bovenstaande output voor details.
    pause
    exit /b 1
)

echo.
echo [AegisPT] Klaar. Open de UI op: http://localhost:8000/app/
echo [AegisPT] Dit venster kan worden gesloten.
pause
