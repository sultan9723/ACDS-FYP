from enum import Enum
from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

# Email Model (T012)
class Email(BaseModel):
    """
    Represents an email processed by the Phishing Detection Module.
    """
    id: UUID = Field(default_factory=uuid4, description="Unique identifier for the email.")
    raw_content: str = Field(..., description="Full raw content of the email.")
    headers: Dict[str, str] = Field(default_factory=dict, description="Parsed email headers.")
    sender: str = Field(..., description="Email address of the sender.")
    recipients: List[str] = Field(default_factory=list, description="List of recipient email addresses.")
    subject: str = Field(..., description="Subject line of the email.")
    body: str = Field(..., description="Body content of the email.")
    attachments: List[Dict[str, Any]] = Field(default_factory=list, description="List of attachment metadata (e.g., filename, size, hash).")
    received_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp when the email was received/processed.")

# Incident Model (T013)
class IncidentStatus(str, Enum):
    """
    Status of a detected phishing incident.
    """
    PENDING_REVIEW = "pending_review"
    CONFIRMED_PHISHING = "confirmed_phishing"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"

class Incident(BaseModel):
    """
    Represents a detected phishing incident.
    """
    id: UUID = Field(default_factory=uuid4, description="Unique identifier for the incident (UUID).")
    email_id: UUID = Field(..., description="ID of the associated email.")
    status: IncidentStatus = Field(default=IncidentStatus.PENDING_REVIEW, description="Current status of the incident.")
    detection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of phishing detection.")
    detection_agent_id: str = Field(..., description="Identifier of the detection agent that flagged the email.")
    explanation_details: Dict[str, Any] = Field(..., description="Details explaining the detection, including confidence score and matched indicators.")
    related_emails: List[UUID] = Field(default_factory=list, description="List of IDs of related emails (e.g., similar phishing attempts).")
    timeline_of_events: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological log of actions and updates for the incident.")
    assigned_analyst: Optional[str] = Field(None, description="Name or ID of the analyst assigned to the incident.")
