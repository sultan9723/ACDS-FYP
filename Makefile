.PHONY: setup setup-py setup-frontend lint lint-py lint-frontend test test-py test-frontend run run-frontend docker-up docker-down clean help

help:
	@echo "ACDS Development Commands"
	@echo "========================"
	@echo "setup            - Install all dependencies (Python + Frontend)"
	@echo "setup-py         - Install Python dependencies"
	@echo "setup-frontend   - Install frontend dependencies"
	@echo "lint             - Run all linters"
	@echo "lint-py          - Run Python linters (black, flake8)"
	@echo "lint-frontend    - Run frontend linter (eslint)"
	@echo "test             - Run all tests"
	@echo "test-py          - Run Python tests (pytest)"
	@echo "test-frontend    - Run frontend tests"
	@echo "run              - Start backend dev server (uvicorn)"
	@echo "run-frontend     - Start frontend dev server (vite)"
	@echo "docker-up        - Start Docker services"
	@echo "docker-down      - Stop Docker services"
	@echo "clean            - Remove caches and build artifacts"

setup: setup-py setup-frontend

setup-py:
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install black flake8 pytest pytest-asyncio isort pre-commit

setup-frontend:
	cd frontend && npm install

lint: lint-py lint-frontend

lint-py:
	black --check backend/ ml_training/ tests/ test_cases/
	flake8 backend/ ml_training/ tests/ test_cases/
	isort --check-only backend/ ml_training/ tests/ test_cases/

lint-frontend:
	cd frontend && npm run lint

format:
	black backend/ ml_training/ tests/ test_cases/
	isort backend/ ml_training/ tests/ test_cases/

test: test-py

test-py:
	pytest tests/ backend/tests/ -v --tb=short

run:
	uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

run-frontend:
	cd frontend && npm run dev

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf backend/.pytest_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ipynb_checkpoints" -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/dist
