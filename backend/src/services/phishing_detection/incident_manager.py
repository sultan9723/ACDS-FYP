import logging
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from .models import Incident, Email, IncidentStatus
from .database import get_incident_db, IncidentDatabase # Assuming get_incident_db is available

logger = logging.getLogger(__name__)

class IncidentManager:
    """
    Manages the creation and updating of phishing incidents in the database.
    """
    def __init__(self, db: IncidentDatabase):
        self.db = db
        logger.info("IncidentManager initialized.")

    async def create_new_incident(self, email: Email, detection_results: Dict[str, Any]) -> Optional[Incident]:
        """
        Creates a new incident record in the database based on detection results.
        
        Args:
            email: The Email object that triggered the detection.
            detection_results: A dictionary containing the output from the DetectionAgent,
                               including 'is_phishing', 'confidence_score', 'matched_indicators',
                               and 'detection_agent_id'.
        
        Returns:
            The created Incident object, or None if creation failed.
        """
        if not detection_results.get("is_phishing"):
            logger.info(f"Email {email.id} not classified as phishing, no incident created.")
            return None

        try:
            new_incident = Incident(
                email_id=email.id,
                status=IncidentStatus.PENDING_REVIEW,
                detection_timestamp=email.received_at, # Use email's received_at as detection time
                detection_agent_id=detection_results.get("detection_agent_id", "unknown"),
                explanation_details={
                    "confidence_score": detection_results.get("confidence_score"),
                    "matched_indicators": detection_results.get("matched_indicators")
                },
                timeline_of_events=[
                    {
                        "timestamp": detection_results.get("detection_timestamp") if detection_results.get("detection_timestamp") else email.received_at,
                        "event": "Detected as phishing by Detection Agent",
                        "details": detection_results
                    }
                ]
            )
            created_incident = await self.db.create_incident(new_incident)
            logger.info(f"Incident {created_incident.id} created for email {email.id}.")
            return created_incident
        except Exception as e:
            logger.error(f"Failed to create incident for email {email.id}: {e}")
            return None

    async def update_incident_status(self, incident_id: UUID, new_status: IncidentStatus, analyst_id: Optional[str] = None) -> Optional[Incident]:
        """
        Updates the status of an existing incident.
        """
        updates = {"status": new_status}
        if analyst_id:
            updates["assigned_analyst"] = analyst_id
        
        # Add an entry to the timeline
        timeline_entry = {
            "timestamp": datetime.utcnow(),
            "event": f"Status updated to {new_status.value}",
            "details": {"updated_by": analyst_id} if analyst_id else {}
        }
        
        try:
            # Append to timeline_of_events using $push
            updated_incident = await self.db.update_incident(
                str(incident_id),
                {"$set": updates, "$push": {"timeline_of_events": timeline_entry}}
            )
            if updated_incident:
                logger.info(f"Incident {incident_id} status updated to {new_status.value}.")
            return updated_incident
        except Exception as e:
            logger.error(f"Failed to update incident {incident_id} status: {e}")
            return None
            
    async def add_timeline_entry(self, incident_id: UUID, event_description: str, details: Optional[Dict[str, Any]] = None) -> Optional[Incident]:
        """
        Adds a new entry to an incident's timeline.
        """
        timeline_entry = {
            "timestamp": datetime.utcnow(),
            "event": event_description,
            "details": details if details is not None else {}
        }
        
        try:
            updated_incident = await self.db.update_incident(
                str(incident_id),
                {"$push": {"timeline_of_events": timeline_entry}}
            )
            if updated_incident:
                logger.info(f"Timeline updated for incident {incident_id}: {event_description}.")
            return updated_incident
        except Exception as e:
            logger.error(f"Failed to add timeline entry for incident {incident_id}: {e}")
            return None
            
async def get_incident_manager() -> IncidentManager:
    """Returns a singleton-like instance of the IncidentManager."""
    db_instance = await get_incident_db()
    return IncidentManager(db_instance)

