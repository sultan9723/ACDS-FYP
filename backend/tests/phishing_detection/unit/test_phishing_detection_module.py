import pytest
from datetime import datetime, timezone
from uuid import UUID
from backend.src.services.phishing_detection.models import Email, Incident, IncidentStatus
from backend.src.services.phishing_detection.detection_agent import DetectionAgent, PHISHING_KEYWORDS, SUSPICIOUS_URL_PATTERNS
import asyncio

# --- Tests for Models ---
def test_email_model_creation():
    email_data = {
        "raw_content": "Subject: Test\n\nBody",
        "headers": {"From": "test@example.com"},
        "sender": "test@example.com",
        "recipients": ["to@example.com"],
        "subject": "Test Email",
        "body": "This is a test body.",
    }
    email = Email(**email_data)
    assert isinstance(email.id, UUID)
    assert email.sender == "test@example.com"
    assert email.received_at is not None

def test_incident_model_creation():
    incident_data = {
        "email_id": UUID("12345678-1234-5678-1234-567812345678"),
        "status": IncidentStatus.PENDING_REVIEW,
        "detection_agent_id": "test_agent",
        "explanation_details": {"confidence_score": 0.9, "matched_indicators": ["keyword_match"]}
    }
    incident = Incident(**incident_data)
    assert isinstance(incident.id, UUID)
    assert incident.status == IncidentStatus.PENDING_REVIEW
    assert incident.explanation_details["confidence_score"] == 0.9

# --- Tests for DetectionAgent (Rule-based) ---
@pytest.fixture
def detection_agent():
    return DetectionAgent(use_ml=False)

def test_detection_agent_no_phishing(detection_agent):
    email = Email(
        raw_content="Subject: Hello\n\nBody",
        headers={"From": "safe@example.com"},
        sender="safe@example.com",
        recipients=["me@example.com"],
        subject="Legitimate Email",
        body="This is a legitimate email with no suspicious content."
    )
    results = detection_agent.detect_phishing(email)
    assert not results["is_phishing"]
    assert results["confidence_score"] == 0.0
    assert not results["matched_indicators"]

def test_detection_agent_phishing_keywords(detection_agent):
    email = Email(
        raw_content="Subject: Urgent Action Required\n\nBody: Please verify your account now.",
        headers={"From": "scam@example.com"},
        sender="scam@example.com",
recipients=["me@example.com"],
        subject="Urgent Action Required",
        body="Please verify your account now to avoid suspension."
    )
    results = detection_agent.detect_phishing(email)
    assert results["is_phishing"]
    assert results["confidence_score"] > 0.0
    assert any(kw in results["matched_indicators"][0] for kw in ["urgent action required", "verify your account"])

def test_detection_agent_phishing_urls(detection_agent):
    email = Email(
        raw_content="Subject: Your payment failed\n\nBody: Click here: http://192.168.1.1/login",
        headers={"From": "scam@example.com"},
        sender="scam@example.com",
        recipients=["me@example.com"],
        subject="Your payment failed",
        body="Your payment failed. Click here to update: http://192.168.1.1/login"
    )
    results = detection_agent.detect_phishing(email)
    assert results["is_phishing"]
    assert results["confidence_score"] > 0.0
    # Check that the matched_indicators list contains a string that includes the expected URL
    assert any("http://192.168.1.1/login" in indicator_str for indicator_str in results["matched_indicators"])
def test_detection_agent_ml_placeholder(detection_agent):
    # Test with ML enabled, ensuring it still provides results
    ml_detection_agent = DetectionAgent(use_ml=True)
    email = Email(
        raw_content="Subject: Normal email\n\nBody: This is a normal email.",
        headers={"From": "normal@example.com"},
        sender="normal@example.com",
        recipients=["me@example.com"],
        subject="Normal Email",
        body="This is a normal email with no suspicious content."
    )
    results = ml_detection_agent.detect_phishing(email)
    assert isinstance(results["is_phishing"], bool)
    assert isinstance(results["confidence_score"], float)
    assert len(results["matched_indicators"]) >= 0 # ML placeholder might add indicators
    assert results["detection_agent_id"] == "RuleBased_ML_Placeholder_Agent"
