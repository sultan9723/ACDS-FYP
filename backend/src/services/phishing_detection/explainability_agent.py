from typing import Dict, Any, List, Optional
import logging

from .models import Incident, ExplanationDetails

logger = logging.getLogger(__name__)

class ExplainabilityAgent:
    def __init__(self):
        logger.info("ExplainabilityAgent initialized.")

    def generate_explanation(self, incident: Incident) -> ExplanationDetails:
        summary_parts = []
        details_list = []

        if incident.explanation_details and incident.explanation_details.matched_indicators:
            summary_parts.append("Phishing detected due to matched indicators.")
            details_list.append(f"Matched Indicators: {', '.join(incident.explanation_details.matched_indicators)}")
            details_list.append(f"Confidence Score: {incident.explanation_details.confidence_score:.2f}")
        else:
            summary_parts.append("No specific explanation details available or not a phishing incident.")
        
        # Add more logic here to generate richer explanations based on incident data
        # For MVP, we use the explanation_details already part of the incident

        final_summary = " ".join(summary_parts) if summary_parts else "Explanation not available."

        return ExplanationDetails(
            summary=final_summary,
            confidence_score=incident.explanation_details.confidence_score if incident.explanation_details else 0.0,
            matched_indicators=incident.explanation_details.matched_indicators if incident.explanation_details else []
        )

_explainability_agent_instance: Optional[ExplainabilityAgent] = None

def get_explainability_agent() -> ExplainabilityAgent:
    global _explainability_agent_instance
    if _explainability_agent_instance is None:
        _explainability_agent_instance = ExplainabilityAgent()
    return _explainability_agent_instance