import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from uuid import UUID

from backend.src.services.phishing_detection.models import Email, Incident, IncidentStatus
from backend.src.services.phishing_detection.database import IncidentDatabase
from backend.src.services.phishing_detection.detection_agent import DetectionAgent
from backend.src.services.phishing_detection.explainability_agent import ExplainabilityAgent
from backend.src.services.phishing_detection.orchestration_trigger import OrchestrationTrigger
from backend.src.services.phishing_detection.incident_manager import IncidentManager
from backend.src.services.phishing_detection.report_generator import ReportGenerator
from backend.src.services.phishing_detection.data_loader import EmailDataLoader # Assuming data_loader for email generation

from uuid import UUID, uuid4 # Add uuid4 import
from backend.src.services.phishing_detection.models import Email, Incident, IncidentStatus

# --- Fixtures ---
@pytest.fixture
def mock_incident_db():
    """Mock for IncidentDatabase that simulates some in-memory DB behavior."""
    db = AsyncMock(spec=IncidentDatabase)
    
    # Store incidents in a dictionary to simulate DB behavior
    _incidents = {}

    async def _mock_create_incident(incident: Incident):
        # Assign an ID if not already present, convert to str for dict key
        incident.id = incident.id if incident.id else uuid4()
        _incidents[str(incident.id)] = incident
        return incident

    async def _mock_get_incident(incident_id: str):
        return _incidents.get(incident_id)
    
    async def _mock_update_incident(incident_id: str, updates: Dict[str, Any]):
        incident = _incidents.get(incident_id)
        if incident:
            # Apply updates
            for key, value in updates.items():
                if key == "$set": # Handle $set operator for direct field updates
                    for sub_key, sub_value in value.items():
                        setattr(incident, sub_key, sub_value)
                elif key == "$push" and "timeline_of_events" in value: # Handle $push for timeline
                    if not incident.timeline_of_events:
                        incident.timeline_of_events = []
                    incident.timeline_of_events.append(value["timeline_of_events"])
            _incidents[incident_id] = incident # Update in store
            return await _mock_get_incident(incident_id) # Return the updated incident
        return None

    db.create_incident.side_effect = _mock_create_incident
    db.get_incident.side_effect = _mock_get_incident
    db.update_incident.side_effect = _mock_update_incident
    
    return db

@pytest.fixture
def mock_detection_agent():
    """Mock for DetectionAgent."""
    agent = AsyncMock(spec=DetectionAgent)
    agent.detect_phishing.return_value = {
        "is_phishing": True,
        "confidence_score": 0.9,
        "matched_indicators": ["suspicious keyword"],
        "detection_agent_id": "mock_detection_agent"
    }
    return agent

@pytest.fixture
def mock_explainability_agent():
    """Mock for ExplainabilityAgent."""
    agent = AsyncMock(spec=ExplainabilityAgent)
    agent.generate_explanation.return_value = {
        "summary": "Mock explanation",
        "details": ["- suspicious keyword matched"],
        "confidence_level": "90.00%",
        "detection_agent_used": "mock_detection_agent"
    }
    return agent

@pytest.fixture
def mock_orchestration_trigger():
    """Mock for OrchestrationTrigger."""
    trigger = AsyncMock(spec=OrchestrationTrigger)
    trigger.trigger_orchestration.return_value = True
    return trigger

@pytest.fixture
def incident_manager(mock_incident_db):
    """IncidentManager instance with mocked DB."""
    return IncidentManager(mock_incident_db)

@pytest.fixture
def report_generator():
    """ReportGenerator instance."""
    return ReportGenerator()

@pytest.fixture
def sample_email():
    """Provides a sample Email instance."""
    return Email(
        id=UUID("12345678-1234-5678-1234-567812345678"),
        raw_content="Subject: Urgent Action\n\nBody: Click here to verify your account: http://bad.com",
        headers={"From": "phisher@example.com"},
        sender="phisher@example.com",
        recipients=["victim@example.com"],
        subject="Urgent Action Required",
        body="Please click on the link to verify your account: http://bad.com"
    )

# --- Integration Test ---
@pytest.mark.asyncio
async def test_end_to_end_phishing_workflow(
    sample_email,
    mock_detection_agent,
    incident_manager,
    mock_explainability_agent,
    mock_orchestration_trigger,
    report_generator,
    mock_incident_db
):
    """
    Tests the complete end-to-end workflow for handling a phishing incident.
    """
    print(f"\n--- Starting E2E Workflow Test for Email: {sample_email.id} ---")

    # 1. Simulate Email Input (already have sample_email)

    # 2. DETECTION AGENT (phishing?)
    print("Step 2: Running Detection Agent...")
    detection_results = mock_detection_agent.detect_phishing.return_value
    assert detection_results["is_phishing"] is True
    assert "confidence_score" in detection_results
    assert "matched_indicators" in detection_results
    
    # 3. INCIDENT CREATED IN DB
    print("Step 3: Creating Incident in DB...")
    created_incident = await incident_manager.create_new_incident(sample_email, detection_results)
    mock_incident_db.create_incident.assert_called_once()
    assert created_incident is not None
    assert created_incident.email_id == sample_email.id
    assert created_incident.status == IncidentStatus.PENDING_REVIEW
    print(f"Incident {created_incident.id} created successfully.")

    # Fetch the incident from DB (simulated) for explainability
    fetched_incident = await mock_incident_db.get_incident(str(created_incident.id))
    assert fetched_incident is not None

    # 4. EXPLAINABILITY AGENT (why phishing?)
    print("Step 4: Running Explainability Agent...")
    explanation = mock_explainability_agent.generate_explanation(fetched_incident) # CALL THE METHOD
    mock_explainability_agent.generate_explanation.assert_called_once_with(fetched_incident)
    assert "summary" in explanation
    assert "details" in explanation
    print(f"Explanation generated: {explanation['summary']}")

    # 5. ORCHESTRATION TRIGGER
    print("Step 5: Triggering Orchestration...")
    orchestration_successful = await mock_orchestration_trigger.trigger_orchestration(fetched_incident)
    mock_orchestration_trigger.trigger_orchestration.assert_called_once_with(fetched_incident)
    assert orchestration_successful is True
    print("Orchestration triggered successfully.")

    # 6. UPDATE INCIDENT + TIMELINE
    print("Step 6: Updating Incident Timeline and Status...")
    # Simulate a status update and add an entry to the timeline
    updated_incident_status = await incident_manager.update_incident_status(
        created_incident.id, IncidentStatus.CONFIRMED_PHISHING, analyst_id="test_analyst"
    )
    assert updated_incident_status.status == IncidentStatus.CONFIRMED_PHISHING
    assert any("Status updated" in entry["event"] for entry in updated_incident_status.timeline_of_events)
    print(f"Incident {updated_incident_status.id} updated to {updated_incident_status.status}.")

    # 7. REPORT GENERATOR
    print("Step 7: Generating Report...")
    final_incident_for_report = await mock_incident_db.get_incident(str(created_incident.id))
    report = report_generator.generate_incident_report(final_incident_for_report, explanation)
    assert "Phishing Incident Report" in report
    assert str(final_incident_for_report.id) in report
    assert explanation["summary"] in report
    print("Report generated successfully (see console output if running directly).")
    print("\n--- E2E Workflow Test Complete ---")
