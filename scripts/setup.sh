#!/usr/bin/env bash
set -euo pipefail

ACDS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ACDS_ROOT"

echo "=== ACDS Development Environment Setup ==="

# --- Python virtual environment ---
if [ ! -d ".venv" ]; then
    echo "[1/6] Creating Python virtual environment..."
    python3.10 -m venv .venv
else
    echo "[1/6] Python virtual environment already exists."
fi

source .venv/bin/activate

# --- Upgrade pip ---
echo "[2/6] Upgrading pip..."
pip install --upgrade pip

# --- Install Python dependencies ---
echo "[3/6] Installing Python dependencies..."
pip install -r requirements.txt
pip install black flake8 pytest pytest-asyncio isort pre-commit

# --- Copy .env if missing ---
if [ ! -f ".env" ]; then
    echo "[4/6] Creating .env from .env.example..."
    cp .env.example .env
    echo "  >> Edit .env to configure your environment."
else
    echo "[4/6] .env already exists."
fi

# --- Install pre-commit hooks ---
echo "[5/6] Installing pre-commit hooks..."
pre-commit install

# --- Install frontend dependencies ---
if [ -f "frontend/package.json" ]; then
    echo "[6/6] Installing frontend dependencies..."
    cd frontend && npm install && cd ..
else
    echo "[6/6] Skipping frontend (no package.json found)."
fi

echo ""
echo "=== Setup complete! ==="
echo "Activate the virtual environment with: source .venv/bin/activate"
echo "Start the backend: uvicorn backend.main:app --reload --port 8000"
echo "Start the frontend: cd frontend && npm run dev"
