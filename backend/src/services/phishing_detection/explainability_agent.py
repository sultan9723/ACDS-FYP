import logging
from typing import Dict, Any, List, Optional
from uuid import UUID

from .models import Incident

logger = logging.getLogger(__name__)

class ExplainabilityAgent:
    """
    Agent responsible for generating human-readable explanations
    for phishing detections based on incident details.
    """
    def __init__(self):
        logger.info("ExplainabilityAgent initialized.")

    def generate_explanation(self, incident: Incident) -> Dict[str, Any]:
        """
        Generates an explanation for why an email was classified as phishing.
        
        Args:
            incident: The Incident object containing detection details.
            
        Returns:
            A dictionary containing a structured explanation.
        """
        explanation = {
            "summary": "This email was detected as a potential phishing attempt based on the following indicators:",
            "details": [],
            "confidence_level": f"{incident.explanation_details.get('confidence_score', 0.0)*100:.2f}%",
            "detection_agent_used": incident.detection_agent_id
        }

        matched_indicators = incident.explanation_details.get("matched_indicators", [])
        
        if not matched_indicators:
            explanation["details"].append("No specific indicators were found in the explanation details.")
        else:
            for indicator in matched_indicators:
                explanation["details"].append(f"- {indicator}")
        
        if incident.explanation_details.get('confidence_score', 0.0) < 0.5:
             explanation["summary"] += " The confidence in this detection is relatively low, further manual review is recommended."
        elif incident.explanation_details.get('confidence_score', 0.0) < 0.8:
            explanation["summary"] += " The confidence in this detection is moderate."
        else:
            explanation["summary"] += " The confidence in this detection is high."

        logger.info(f"Generated explanation for incident {incident.id}.")
        return explanation

def get_explainability_agent() -> ExplainabilityAgent:
    """Returns a singleton-like instance of the ExplainabilityAgent."""
    return ExplainabilityAgent()
