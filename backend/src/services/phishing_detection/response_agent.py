import logging
from typing import Dict, Any, Optional

from .models import Incident, IncidentStatus

logger = logging.getLogger(__name__)

class ResponseAgent:
    def __init__(self):
        logger.info("ResponseAgent initialized (placeholder).")

    async def take_action(self, incident: Incident) -> Dict[str, Any]:
        """
        Placeholder method for the Response Agent to take action on an incident.
        For MVP, this simply logs the intended action.
        """
        if incident.status == IncidentStatus.DETECTED or incident.status == IncidentStatus.INVESTIGATING:
            action_summary = f"Simulating response action for incident {incident.id}: quarantining email and alerting SOC."
            logger.info(action_summary)
            return {"status": "success", "action_taken": "simulated_quarantine_alert"}
        else:
            action_summary = f"No response action taken for incident {incident.id} with status {incident.status.value}."
            logger.info(action_summary)
            return {"status": "no_action", "action_taken": "none"}

_response_agent_instance: Optional[ResponseAgent] = None

def get_response_agent() -> ResponseAgent:
    global _response_agent_instance
    if _response_agent_instance is None:
        _response_agent_instance = ResponseAgent()
    return _response_agent_instance