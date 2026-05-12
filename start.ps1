# AegisPT — start alles in één keer
# Vereisten: WSL2 met Ubuntu, zie scripts/install_aegispt_host.sh voor installatie.

$WSL_DISTRO = "ubuntu"
$REPO_PATH = "/home/administrator/project/automation skill/AegisPT"

Write-Host "[AegisPT] Starten..." -ForegroundColor Cyan
wsl -d $WSL_DISTRO bash -lc "cd '$REPO_PATH' && bash scripts/restart_local_inline_host.sh"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[AegisPT] FOUT: startup mislukt." -ForegroundColor Red
    Read-Host "Druk Enter om te sluiten"
    exit 1
}

Write-Host ""
Write-Host "[AegisPT] Klaar!" -ForegroundColor Green
Write-Host "UI: http://localhost:8000/app/" -ForegroundColor Green
