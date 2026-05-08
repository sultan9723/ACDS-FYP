# Agents — Autonomous Detection and Response

## Overview / Purpose
The agents module implements autonomous detection, response, intelligence enrichment, and alert generation. Agents operate as independent modules that communicate with the backend to process security events, execute remediation actions, and provide insights to analysts. Each agent type specializes in a specific operational function within the ACDS workflow.

Key agent types:
- Detection Agent: Analyzes events and assigns risk scores using ML models.
- Response Agent: Executes automated containment and remediation actions.
- Intel Agent: Enriches events with contextual information from internal and external sources.
- Alert Agent: Persists incidents and notifies analysts and external systems.

Key responsibilities:
- Process events routed from the backend orchestrator.
- Communicate asynchronously via REST or WebSocket endpoints.
- Maintain idempotency and safe state transitions.
- Log all actions for audit and forensic analysis.

## Folder Structure
```
backend/agents/
├─ detection_agent.py               # Detection agent implementation
├─ response_agent.py                # Response agent implementation
├─ intel_agent.py                   # Intelligence enrichment agent
├─ alert_agent.py                   # Alert generation and persistence
├─ __init__.py                      # Agent module initialization
└─ README.md
```

## Agent Types and Workflow

### 1. Detection Agent
Analyzes incoming events using ML models and rule-based heuristics.

**Input Event Schema:**
```json
{
  "event_id": "evt-12345",
  "event_type": "email",
  "timestamp": "2025-11-14T10:30:00Z",
  "source": "victim_system",
  "data": {
    "sender": "attacker@evil.com",
    "subject": "Urgent action required",
    "body": "Click here to verify...",
    "recipient": "victim@company.com"
  }
}
```

**Output (Detection Result):**
```json
{
  "event_id": "evt-12345",
  "detection_score": 0.87,
  "classification": "phishing",
  "confidence": "high",
  "model_version": "1.0",
  "timestamp": "2025-11-14T10:30:01Z",
  "features_used": ["sender_reputation", "subject_keywords", "link_domain"],
  "next_agent": "response"
}
```

### 2. Response Agent
Executes automated containment and remediation based on detection outcomes.

**Input (From Detection or Rule Engine):**
```json
{
  "action_type": "block_sender",
  "event_id": "evt-12345",
  "parameters": {
    "sender": "attacker@evil.com",
    "quarantine": true,
    "notify_admin": true
  }
}
```

**Output (Action Result):**
```json
{
  "action_id": "act-67890",
  "event_id": "evt-12345",
  "action_taken": "block_sender",
  "status": "success",
  "result": {
    "emails_blocked": 127,
    "admin_notified": true,
    "timestamp": "2025-11-14T10:30:02Z"
  },
  "next_agent": "intel"
}
```

### 3. Intel Agent
Enriches events with contextual threat intelligence.

**Input (From Detection or Response):**
```json
{
  "event_id": "evt-12345",
  "enrichment_request": {
    "sender": "attacker@evil.com",
    "domain": "evil.com",
    "ip_address": "192.0.2.1"
  }
}
```

**Output (Enriched Context):**
```json
{
  "event_id": "evt-12345",
  "enrichment": {
    "sender_reputation": "known_malicious",
    "domain_age_days": 3,
    "domain_registrar": "shadowy_registrar",
    "ip_geolocation": "Russia",
    "ip_threat_level": "critical",
    "similar_campaigns": ["campaign-xyz", "campaign-abc"]
  },
  "timestamp": "2025-11-14T10:30:03Z",
  "next_agent": "alert"
}
```

### 4. Alert Agent
Generates, persists, and routes alerts to analysts and external systems.

**Input (From Intel or Response):**
```json
{
  "event_id": "evt-12345",
  "alert_data": {
    "title": "High-confidence phishing campaign detected",
    "severity": "critical",
    "detection_score": 0.87,
    "affected_users": ["victim@company.com"],
    "action_taken": "block_sender",
    "enrichment": {...}
  }
}
```

**Output (Alert Persistence):**
```json
{
  "alert_id": "alert-11111",
  "event_id": "evt-12345",
  "severity": "critical",
  "status": "open",
  "timestamp_created": "2025-11-14T10:30:04Z",
  "persisted_to": "mongodb",
  "notification_sent": true
}
```

## Communication Flow (Backend to Agents)
1. Backend receives event via `/ingest` endpoint.
2. Event is evaluated against SOAR rules.
3. Matched rule triggers agent pipeline:
   - Backend calls `detection_agent.analyze(event)`
   - Detection agent returns detection result
   - Backend calls `response_agent.respond(detection_result)` if score > threshold
   - Response agent returns action result
   - Backend calls `intel_agent.enrich(action_result)`
   - Intel agent returns enriched data
   - Backend calls `alert_agent.create_alert(enriched_data)`
   - Alert agent persists to MongoDB and returns alert ID

Communication methods:
- Synchronous: Function calls within backend process (fast, simple).
- Asynchronous: WebSocket messages or message queue (decoupled, scalable).

## Integration Points
- Backend: Agents are imported and called by orchestration logic in `backend/main.py`.
- Database: Alert agent writes to MongoDB using connection from `backend/core/config_loader.py`.
- ML Models: Detection agent loads models from `backend/ml/` directory.
- External Systems: Alert agent can send webhooks or emails to external SIEM/ticketing systems.
- Logging: All agent actions log to centralized logger via `backend/core/logger.py`.

## Setup and Execution Instructions

### Running an Agent
Agents are invoked by the backend orchestrator. To test an agent directly:

```python
from backend.agents.detection_agent import analyze

event = {
    "event_type": "email",
    "data": {
        "sender": "attacker@evil.com",
        "subject": "Urgent action required",
        "body": "..."
    }
}

result = analyze(event)
print(result)  # Outputs detection score and classification
```

### Adding a Custom Agent
1. Create a new agent file in `backend/agents/custom_agent.py`:
```python
"""Handles custom logic for ACDS."""

def process(input_data):
    """Process input and return result."""
    # Custom logic
    return {"status": "success", "data": {...}}
```

2. Import and register in backend orchestrator:
```python
from backend.agents.custom_agent import process
```

3. Add to SOAR rules in `backend/orchestration/automation_rules.json` to trigger the agent.

## Event State Machine
Events transition through states as agents process them:
```
INGESTED → DETECTION → RESPONSE → ENRICHMENT → ALERTED → CLOSED
   ↓
 (REJECTED if low confidence)
```

## Future Enhancements
- Stateful agents with persistent context (e.g., tracking ongoing campaigns).
- Agent-to-agent communication without backend intermediation for faster feedback loops.
- Rollback capabilities: if a response action fails, automatically trigger remediation.
- Agent performance monitoring and health checks with alerting.
- Custom agent framework for security teams to plugin domain-specific logic.
- Collaborative agents that vote on classifications for improved accuracy.

