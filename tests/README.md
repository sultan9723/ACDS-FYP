# Tests — Quality Assurance and Validation

## Overview / Purpose
The tests module provides comprehensive validation of ACDS functionality through unit tests, integration tests, and end-to-end scenarios. Testing is integrated into the CI/CD pipeline via GitHub Actions to ensure code quality, prevent regressions, and maintain compliance with performance and security standards.

Key responsibilities:
- Unit testing of individual components (agents, models, utilities).
- Integration testing of multi-component workflows (backend → agents → database).
- End-to-end testing of full detection-to-response pipelines.
- Code quality checks (linting, formatting) via black and flake8.
- Coverage tracking to maintain and improve test coverage goals.

## Folder Structure
```
tests/
├─ test_placeholder.py              # Placeholder test (minimal example)
├─ unit/
│  ├─ test_detection_agent.py       # Unit tests for detection agent
│  ├─ test_response_agent.py        # Unit tests for response agent
│  ├─ test_ml_models.py             # Unit tests for ML model inference
│  └─ test_backend_utils.py         # Unit tests for backend utilities
├─ integration/
│  ├─ test_event_pipeline.py        # End-to-end event processing
│  ├─ test_backend_api.py           # API endpoint integration tests
│  └─ test_database_persistence.py  # MongoDB integration tests
├─ fixtures/
│  ├─ mock_events.json              # Sample event fixtures
│  ├─ mock_models.pkl               # Mock ML models for testing
│  └─ conftest.py                   # pytest configuration and shared fixtures
├─ README.md
└─ pytest.ini                        # pytest configuration file
```

## Testing Philosophy

ACDS follows a hierarchical testing approach:

1. Unit Tests: Isolated testing of individual functions and classes with mocked dependencies.
2. Integration Tests: Testing of multiple components together (agents + backend, backend + database).
3. End-to-End Tests: Full workflow testing from event ingestion to alert persistence.
4. Code Quality: Automated formatting (black) and linting (flake8).

## Test Coverage Goals

| Component | Target Coverage |
|---|---|
| Backend Core | 85% |
| Agents | 90% |
| ML Models | 80% |
| Utilities | 95% |
| Overall | 85% |

Current coverage is tracked via GitHub Actions and displayed in CI build logs.

## Setup and Execution Instructions

### Installation
```cmd
pip install -r requirements.txt
pytest  # pytest will be installed as a dependency
```

### Running Tests

Run all tests:
```cmd
pytest
```

Run tests with coverage report:
```cmd
pytest --cov=backend --cov=models --cov-report=html
```

Run specific test file:
```cmd
pytest tests/unit/test_detection_agent.py
```

Run tests matching a pattern:
```cmd
pytest -k "test_phishing"
```

Run tests with verbose output:
```cmd
pytest -v
```

### Code Quality Checks

Format code with black (auto-fixes formatting):
```cmd
black backend/ models/ tests/
```

Lint code with flake8:
```cmd
flake8 backend/ models/ tests/ --max-line-length=100 --ignore=E203,W503
```

Check formatting without modifying:
```cmd
black --check backend/ models/ tests/
```

## Example Unit Test
```python
# tests/unit/test_detection_agent.py
import pytest
from backend.agents.detection_agent import analyze

def test_phishing_detection():
    """Test detection of phishing email."""
    event = {
        "event_type": "email",
        "data": {
            "sender": "attacker@evil.com",
            "subject": "Verify your account",
            "body": "Click here to verify"
        }
    }
    result = analyze(event)
    assert result["detection_score"] > 0.7
    assert result["classification"] == "phishing"

def test_benign_email():
    """Test detection of legitimate email."""
    event = {
        "event_type": "email",
        "data": {
            "sender": "boss@company.com",
            "subject": "Meeting tomorrow",
            "body": "Let's meet at 10am"
        }
    }
    result = analyze(event)
    assert result["detection_score"] < 0.3
    assert result["classification"] == "benign"
```

## Example Integration Test
```python
# tests/integration/test_event_pipeline.py
import pytest
from backend.main import app
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    return TestClient(app)

def test_full_event_pipeline(client):
    """Test full event ingestion and processing."""
    event_payload = {
        "event_type": "email",
        "data": {
            "sender": "attacker@evil.com",
            "subject": "Urgent",
            "body": "Click here"
        }
    }
    response = client.post("/ingest", json=event_payload)
    assert response.status_code == 200
    assert "event_id" in response.json()
```

## CI/CD Integration

GitHub Actions automatically runs tests on:
- Push to develop branch
- Pull requests to main branch
- Scheduled nightly runs

CI Workflow Steps (in `.github/workflows/ci.yml`):
1. Install dependencies
2. Format check with black
3. Lint with flake8
4. Run unit tests with pytest
5. Run integration tests
6. Generate coverage report
7. Upload coverage to code coverage service (optional)

Example `.github/workflows/ci.yml` snippet:
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - run: pip install -r requirements.txt
      - run: black --check .
      - run: flake8 . --max-line-length=100
      - run: pytest --cov=backend --cov=models --cov-report=term-missing
```

## Future Enhancements
- Automated performance testing and benchmarking (pytest-benchmark).
- Security testing (bandit) integrated into CI.
- Load testing and stress testing for high-throughput scenarios.
- Property-based testing (hypothesis) for edge case discovery.
- Mutation testing to evaluate test quality.
- Test report dashboarding and historical trend tracking.
- Automated test generation for API endpoints (schemathesis).


