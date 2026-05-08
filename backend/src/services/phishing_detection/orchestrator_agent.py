import logging
from typing import Dict, Any, Optional

from .models import Email, Incident, IncidentStatus, ExplanationDetails
from .detection_agent import DetectionAgent, get_detection_agent
from .incident_manager import IncidentManager, get_incident_manager
from .explainability_agent import ExplainabilityAgent, get_explainability_agent
from .response_agent import ResponseAgent, get_response_agent
from .report_generator import ReportGenerator, get_report_generator
from .database import IncidentDatabase # Import for passing to ReportGenerator

logger = logging.getLogger(__name__)

class OrchestratorAgent:
    def __init__(self,
                 detection_agent: DetectionAgent,
                 incident_manager: IncidentManager,
                 explainability_agent: ExplainabilityAgent,
                 response_agent: ResponseAgent,
                 report_generator: ReportGenerator):
        self.detection_agent = detection_agent
        self.incident_manager = incident_manager
        self.explainability_agent = explainability_agent
        self.response_agent = response_agent
        self.report_generator = report_generator
        logger.info("OrchestratorAgent initialized.")

    async def process_email_workflow(self, email: Email) -> Optional[Incident]:
        logger.info(f"Orchestrator: Starting workflow for email {email.id} (Subject: {email.subject}).")
        incident = None

        try:
            # 1. Detect Phishing
            detection_results = self.detection_agent.detect_phishing(email)
            logger.info(f"Orchestrator: Email {email.id} detection result: Is Phishing? {detection_results['is_phishing']}, Confidence: {detection_results['confidence_score']:.2f}")

            if detection_results["is_phishing"]:
                # 2. Create Incident
                incident = await self.incident_manager.create_new_incident(email, detection_results)
                if incident:
                    logger.info(f"Orchestrator: Incident {incident.id} created for email {email.id}.")

                    # 3. Explain Phishing
                    # The explanation is now generated from the incident object, which already contains explanation_details
                    explanation_output = self.explainability_agent.generate_explanation(incident)
                    logger.info(f"Orchestrator: Explanation generated for incident {incident.id}: {explanation_output.summary}")
                    
                    # Update incident with the generated explanation if it was not already fully populated
                    if not incident.explanation_details:
                        incident.explanation_details = explanation_output
                        await self.incident_manager.update_incident_status(
                            str(incident.id),
                            incident.status, # Keep current status
                            "Orchestrator",
                            {"explanation_updated": True}
                        )

                    # 4. Trigger Response Agent (placeholder for MVP)
                    response_action_results = await self.response_agent.take_action(incident)
                    logger.info(f"Orchestrator: Response agent action for incident {incident.id}: {response_action_results}")
                    
                    # 5. Update Incident + Timeline with response action
                    await self.incident_manager.add_timeline_entry(
                        str(incident.id),
                        f"Response action simulated: {response_action_results.get('action_taken', 'unknown')}",
                        response_action_results
                    )
                    # Update incident status to 'INVESTIGATING' or 'REMEDIATED' based on response action
                    # For MVP, we'll mark it as investigating or remediated
                    new_status = IncidentStatus.REMEDIATED if response_action_results.get('action_taken') == 'simulated_quarantine_alert' else IncidentStatus.INVESTIGATING
                    incident = await self.incident_manager.update_incident_status(str(incident.id), new_status, "Orchestrator")


                    # 6. Generate Report
                    if incident:
                        pdf_output_path = f"reports/incident_report_{incident.id}.pdf"
                        # Re-fetch incident to ensure latest timeline and status
                        latest_incident = await self.incident_manager.get_incident(str(incident.id))
                        if latest_incident:
                            await self.report_generator.generate_incident_report_pdf(latest_incident, email, explanation_output.model_dump(), pdf_output_path)
                            logger.info(f"Orchestrator: PDF report saved for incident {incident.id} to {pdf_output_path}")
                        else:
                            logger.error(f"Orchestrator: Failed to re-fetch incident {incident.id} for report generation.")
                else:
                    logger.error(f"Orchestrator: Failed to create incident for email {email.id}.")
            else:
                logger.info(f"Orchestrator: Email {email.id} is not detected as phishing. No incident created.")

        except Exception as e:
            logger.error(f"Orchestrator: Error processing email {email.id}: {e}", exc_info=True)
            if incident: # If incident was created before error
                await self.incident_manager.add_timeline_entry(
                    str(incident.id),
                    "Workflow processing failed",
                    {"error": str(e)}
                )
                await self.incident_manager.update_incident_status(
                    str(incident.id),
                    IncidentStatus.FAILED,
                    "Orchestrator_Error"
                )
            return None
        
        return incident

_orchestrator_agent_instance: Optional[OrchestratorAgent] = None

async def get_orchestrator_agent(incident_db: IncidentDatabase) -> OrchestratorAgent:
    global _orchestrator_agent_instance
    if _orchestrator_agent_instance is None:
        # Initialize dependencies
        detection_agent = get_detection_agent()
        incident_manager = await get_incident_manager(incident_db)
        explainability_agent = get_explainability_agent()
        response_agent = get_response_agent()
        report_generator = await get_report_generator(incident_db) # Pass incident_db here
        
        _orchestrator_agent_instance = OrchestratorAgent(
            detection_agent,
            incident_manager,
            explainability_agent,
            response_agent,
            report_generator
        )
    return _orchestrator_agent_instance