param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ACDS_ROOT = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

Write-Host "=== ACDS Development Environment Setup ===" -ForegroundColor Cyan

# --- Python virtual environment ---
$venvPath = Join-Path $ACDS_ROOT ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "[1/6] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv $venvPath
} else {
    Write-Host "[1/6] Python virtual environment already exists." -ForegroundColor Green
}

# Activate venv
& "$venvPath\Scripts\Activate.ps1"

# --- Upgrade pip ---
Write-Host "[2/6] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# --- Install Python dependencies ---
Write-Host "[3/6] Installing Python dependencies..." -ForegroundColor Yellow
pip install -r (Join-Path $ACDS_ROOT "requirements.txt")
pip install black flake8 pytest pytest-asyncio isort pre-commit

# --- Copy .env if missing ---
$envFile = Join-Path $ACDS_ROOT ".env"
$envExample = Join-Path $ACDS_ROOT ".env.example"
if (-not (Test-Path $envFile)) {
    Write-Host "[4/6] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item $envExample $envFile
    Write-Host "  >> Edit .env to configure your environment." -ForegroundColor DarkYellow
} else {
    Write-Host "[4/6] .env already exists." -ForegroundColor Green
}

# --- Install pre-commit hooks ---
Write-Host "[5/6] Installing pre-commit hooks..." -ForegroundColor Yellow
pre-commit install

# --- Install frontend dependencies ---
$frontendPkg = Join-Path $ACDS_ROOT "frontend\package.json"
if (Test-Path $frontendPkg) {
    Write-Host "[6/6] Installing frontend dependencies..." -ForegroundColor Yellow
    Set-Location (Join-Path $ACDS_ROOT "frontend")
    npm install
    Set-Location $ACDS_ROOT
} else {
    Write-Host "[6/6] Skipping frontend (no package.json found)." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "=== Setup complete! ===" -ForegroundColor Cyan
Write-Host "Activate the virtual environment with:" -ForegroundColor White
Write-Host "  & `"$venvPath\Scripts\Activate.ps1`"" -ForegroundColor Yellow
Write-Host "Start the backend:" -ForegroundColor White
Write-Host "  uvicorn backend.main:app --reload --port 8000" -ForegroundColor Yellow
Write-Host "Start the frontend:" -ForegroundColor White
Write-Host "  cd frontend && npm run dev" -ForegroundColor Yellow
