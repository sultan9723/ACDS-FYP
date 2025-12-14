import logging
from typing import Dict, Any
from uuid import UUID
from datetime import datetime
import json

from .models import Incident

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates summary reports for phishing incidents.
    """
    def __init__(self):
        logger.info("ReportGenerator initialized.")

    def generate_incident_report(self, incident: Incident, explanation: Dict[str, Any]) -> str:
        """
        Generates a human-readable summary report for a given incident.
        
        Args:
            incident: The Incident object.
            explanation: The structured explanation from the ExplainabilityAgent.
            
        Returns:
            A string containing the formatted report.
        """
        report_lines = []
        report_lines.append(f"--- Phishing Incident Report ---")
        report_lines.append(f"Incident ID: {incident.id}")
        report_lines.append(f"Detected On: {incident.detection_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append(f"Status: {incident.status.value.replace('_', ' ').title()}")
        report_lines.append(f"Associated Email ID: {incident.email_id}")
        report_lines.append(f"Detection Agent: {incident.detection_agent_id}")
        report_lines.append(f"Assigned Analyst: {incident.assigned_analyst or 'Unassigned'}")
        report_lines.append("\n--- Detection Details ---")
        report_lines.append(f"Confidence Score: {float(explanation.get('confidence_level', '0%').replace('%','')):.2f}%") # Assuming % in explanation
        report_lines.append(f"Summary: {explanation.get('summary', 'N/A')}")
        report_lines.append("Matched Indicators:")
        for detail in explanation.get('details', []):
            report_lines.append(f"  {detail}")

        report_lines.append("\n--- Timeline of Events ---")
        if not incident.timeline_of_events:
            report_lines.append("No timeline events recorded.")
        else:
            for event in incident.timeline_of_events:
                timestamp = event.get('timestamp', datetime.min).strftime('%Y-%m-%d %H:%M:%S UTC')
                event_desc = event.get('event', 'Unknown Event')
                details_str = json.dumps(event.get('details', {}))
                report_lines.append(f"- {timestamp}: {event_desc} (Details: {details_str})")
        
        # Placeholder for response actions if they were explicitly recorded in incident.details
        # For now, it's implicitly part of the timeline
        
        report_lines.append(f"\n--- End of Report ---")
        
        logger.info(f"Generated report for incident {incident.id}.")
        return "\n".join(report_lines)

def get_report_generator() -> ReportGenerator:
    """Returns a singleton-like instance of the ReportGenerator."""
    return ReportGenerator()
