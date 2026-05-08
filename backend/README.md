# Backend — ACDS Core Orchestrator

## Overview / Purpose
The backend module is the central orchestration engine of ACDS. Built with FastAPI and Uvicorn, it serves as the unified control plane that connects the victim system (event sources), ML inference engine, autonomous agents, MongoDB persistence, and the Streamlit dashboard. The backend exposes REST and WebSocket endpoints for event ingestion, agent orchestration, model inference, and administrative services.

Key responsibilities:
- Ingestion of telemetry and logs from victim systems via API endpoints.
- Orchestration of SOAR-style automation rules that drive agent workflows.
- Exposure of ML model inference endpoints for real-time detection scoring.
- Coordination of agent communication (Detection → Response → Intel → Alert).
- Health monitoring, metrics collection, and administrative status endpoints.

## Folder Structure
```
backend/
├─ main.py                          # FastAPI application entry point
├─ api/                             # REST endpoint definitions
│  ├─ __init__.py
│  ├─ ingestion.py                  # /ingest, /events endpoints
│  ├─ inference.py                  # /predict, /train endpoints
│  └─ health.py                     # /health, /metrics endpoints
├─ core/                            # Core utilities and configuration
│  ├─ __init__.py
│  ├─ config_loader.py              # Configuration management (YAML, env vars)
│  ├─ logger.py                     # Centralized logging configuration
│  └─ utils.py                      # Helper functions and utilities
├─ orchestration/                   # SOAR rule engine
│  ├─ automation_rules.json         # Rule definitions (trigger, condition, action)
│  └─ rule_engine.py                # Rule evaluation and execution logic
├─ agents/                          # Agent module interface (see agents/ folder)
│  ├─ __init__.py
│  └─ (linked to ../agents/)
├─ ml/                              # ML model interfaces (see models/ folder)
│  ├─ phishing_model.py             # Phishing detection model wrapper
│  └─ preprocess.py                 # Preprocessing utilities
├─ logs/                            # Application logs directory
└─ requirements.txt                 # Backend-specific dependencies (inherited from root)
```

## Responsibilities and Workflow
The backend operates as a request–response hub:

1. Event Ingestion: The `/ingest` endpoint receives telemetry from victim systems (login events, email events, API calls). Events are normalized and queued for processing.

2. Rule Evaluation: The SOAR orchestration engine evaluates incoming events against defined rules (in `orchestration/automation_rules.json`). A rule consists of:
   - Trigger: event type (e.g., "login_event", "email_event")
   - Condition: boolean or threshold checks (e.g., event.score > 0.8)
   - Action: agent-driven response (e.g., invoke Detection Agent)

3. Agent Orchestration: Based on rule evaluation outcomes, the backend routes events to appropriate agents via function calls or WebSocket messages.

4. ML Inference: The `/predict` endpoint exposes model scoring for real-time classification of events (e.g., phishing email detection).

5. Persistence: Detection scores, agent decisions, and incidents are written to MongoDB via defined schemas.

6. Dashboard Interaction: The Streamlit dashboard queries the backend (and MongoDB) for display data and sends analyst feedback for labeling.

## Integration Points
- Victim System: Listens for telemetry via `/ingest` endpoint (REST or WebSocket).
- Agents: Imports agent modules from `../agents/` and calls agent functions or sends WebSocket messages.
- ML Engine: Loads trained models from `../models/` and calls inference methods.
- MongoDB: Writes incident records and retrieves historical data via database connection (configurable via `core/config_loader.py`).
- Dashboard: Serves the Streamlit frontend with REST endpoints for queries and feedback submission.
- CI/CD: GitHub Actions runs pytest tests on backend code; see `/tests/` for test fixtures and CI workflows.

## Setup and Execution Instructions

### Installation
1. Create a virtual environment:
```cmd
python -m venv .venv
.\.venv\Scripts\activate
```

2. Install dependencies:
```cmd
pip install -r requirements.txt
```

### Running the Backend
1. Start the FastAPI server:
```cmd
python backend/main.py
```
   The server listens on `http://localhost:8000` by default.

2. Access the interactive API documentation:
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

### Configuration
- Configuration is managed in `backend/core/config_loader.py`.
- Environment variables can override defaults (e.g., `MONGODB_URI`, `LOG_LEVEL`).
- SOAR rules are defined in `backend/orchestration/automation_rules.json` in JSON format:
```json
{
  "id": "rule-001",
  "name": "Block high-confidence phishing",
  "trigger": "detection.event",
  "condition": {
    "score_greater_than": 0.85,
    "source": "phishing_model"
  },
  "action": {
    "type": "response.block_sender",
    "parameters": {
      "notify_admin": true,
      "quarantine": true
    }
  }
}
```

### Example API Calls
- Ingest an event:
```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{"event_type": "email", "sender": "attacker@evil.com", "subject": "Urgent"}'
```

- Get health status:
```bash
curl http://localhost:8000/health
```

- Run ML inference:
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Click here to verify account"}'
```

## Future Enhancements
- WebSocket support for bidirectional real-time communication between agents and the backend.
- Advanced SOAR rule editor with a UI for non-technical analysts to define rules without code changes.
- Rate limiting and request throttling for production resilience.
- API versioning (v1, v2) for backward compatibility during updates.
- OpenTelemetry integration for distributed tracing and observability.
- gRPC endpoint support for high-throughput internal communication with agents.
