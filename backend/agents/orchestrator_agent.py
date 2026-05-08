"""
Orchestrator Agent
==================
Central coordinator for the phishing detection pipeline.
Manages incident lifecycle and coordinates all other agents.

Incident Lifecycle States:
    detected → analyzing → responded → resolved → reported

Standard Output Contract:
{
    "agent": "orchestrator",
    "status": "success" | "error",
    "incident_id": str,
    "email_id": str,
    "lifecycle_state": "detected" | "analyzing" | "responded" | "resolved" | "reported",
    "pipeline_results": {
        "detection": {...},
        "explainability": {...},
        "response": {...}
    },
    "risk_score": int (0-100),
    "severity": "LOW" | "MEDIUM" | "HIGH",
    "actions_taken": [str],
    "timestamp": ISO8601 str,
    "processing_time_ms": int,
    "error": str | null
}

Version: 2.0.0
"""

import os
import json
import uuid
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

# Import agents
try:
    from agents.detection_agent import DetectionAgent, get_detection_agent
    from agents.explainability_agent import ExplainabilityAgent, get_explainability_agent
    from agents.response_agent import ResponseAgent, get_response_agent
    from core.logger import get_logger
except ImportError:
    try:
        from backend.agents.detection_agent import DetectionAgent, get_detection_agent
        from backend.agents.explainability_agent import ExplainabilityAgent, get_explainability_agent
        from backend.agents.response_agent import ResponseAgent, get_response_agent
        from backend.core.logger import get_logger
    except ImportError:
        try:
            from .detection_agent import DetectionAgent, get_detection_agent
            from .explainability_agent import ExplainabilityAgent, get_explainability_agent
            from .response_agent import ResponseAgent, get_response_agent
            from ..core.logger import get_logger
        except ImportError:
            # Development fallbacks - agents will be None
            logging.basicConfig(level=logging.INFO)
            
            def get_logger(name):
                return logging.getLogger(name)
            
            def get_detection_agent():
                return None
            
            def get_explainability_agent():
                return None
            
            def get_response_agent():
                return None


# Incident database path
INCIDENTS_DB_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'data', 'incidents.json'
)


@dataclass
class OrchestratorResult:
    """Dataclass for orchestrator output."""
    agent: str = "orchestrator"
    status: str = "success"
    incident_id: str = ""
    email_id: str = ""
    lifecycle_state: str = "detected"
    pipeline_results: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    severity: str = "LOW"
    actions_taken: List[str] = field(default_factory=list)
    timestamp: str = ""
    processing_time_ms: int = 0
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


class OrchestratorAgent:
    """
    Orchestrator Agent - Central pipeline coordinator.
    
    Manages the full incident lifecycle:
    1. Detection: Classify email as phishing/safe
    2. Explainability: Extract IOCs and generate explanations
    3. Response: Determine and execute response actions
    4. Reporting: Track and store incident data
    """
    
    AGENT_NAME = "orchestrator"
    VERSION = "2.0.0"
    
    # Lifecycle states
    STATE_DETECTED = "detected"
    STATE_ANALYZING = "analyzing"
    STATE_RESPONDED = "responded"
    STATE_RESOLVED = "resolved"
    STATE_REPORTED = "reported"
    
    VALID_STATES = [STATE_DETECTED, STATE_ANALYZING, STATE_RESPONDED, STATE_RESOLVED, STATE_REPORTED]
    
    def __init__(self, incidents_db_path: Optional[str] = None):
        """
        Initialize the Orchestrator Agent.
        
        Args:
            incidents_db_path: Optional custom path to incidents database
        """
        self.logger = get_logger(__name__)
        self.incidents_db_path = incidents_db_path or INCIDENTS_DB_PATH
        
        # Initialize sub-agents
        self._detection_agent = None
        self._explainability_agent = None
        self._response_agent = None
        
        # Statistics
        self.stats = {
            'total_incidents': 0,
            'phishing_incidents': 0,
            'safe_emails': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'errors': 0,
            'avg_processing_time_ms': 0
        }
        
        # Ensure data directory exists
        self._ensure_data_directory()
    
    def _ensure_data_directory(self) -> None:
        """Ensure the data directory and incidents file exist."""
        try:
            data_dir = os.path.dirname(self.incidents_db_path)
            if not os.path.exists(data_dir):
                os.makedirs(data_dir, exist_ok=True)
            
            if not os.path.exists(self.incidents_db_path):
                with open(self.incidents_db_path, 'w') as f:
                    json.dump({"incidents": [], "schema_version": "2.0.0"}, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Could not initialize incidents database: {e}")
    
    @property
    def detection_agent(self):
        """Lazy-load detection agent."""
        if self._detection_agent is None:
            try:
                self._detection_agent = get_detection_agent()
            except Exception as e:
                self.logger.error(f"Failed to load detection agent: {e}")
        return self._detection_agent
    
    @property
    def explainability_agent(self):
        """Lazy-load explainability agent."""
        if self._explainability_agent is None:
            try:
                self._explainability_agent = get_explainability_agent()
            except Exception as e:
                self.logger.error(f"Failed to load explainability agent: {e}")
        return self._explainability_agent
    
    @property
    def response_agent(self):
        """Lazy-load response agent."""
        if self._response_agent is None:
            try:
                self._response_agent = get_response_agent()
            except Exception as e:
                self.logger.error(f"Failed to load response agent: {e}")
        return self._response_agent
    
    def process_email(self, email_content: str, email_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Process an email through the full detection pipeline.
        
        Args:
            email_content: Raw email content
            email_id: Optional email identifier
            
        Returns:
            Complete orchestrator result with all pipeline results
        """
        start_time = time.time()
        
        # Generate IDs
        incident_id = f"INC_{uuid.uuid4().hex[:12].upper()}"
        email_id = email_id or f"email_{uuid.uuid4().hex[:12]}"
        
        result = OrchestratorResult(
            incident_id=incident_id,
            email_id=email_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            lifecycle_state=self.STATE_DETECTED
        )
        
        self.stats['total_incidents'] += 1
        actions_taken = []
        
        try:
            # ===== Stage 1: Detection =====
            result.lifecycle_state = self.STATE_DETECTED
            actions_taken.append("Initiated detection analysis")
            
            detection_result = None
            if self.detection_agent:
                detection_result = self.detection_agent.analyze(email_content, email_id)
                result.pipeline_results['detection'] = detection_result
                
                result.risk_score = detection_result.get('risk_score', 0)
                result.severity = detection_result.get('severity', 'LOW')
                
                actions_taken.append(f"Detection complete: {'PHISHING' if detection_result.get('is_phishing') else 'SAFE'}")
            else:
                actions_taken.append("Detection agent unavailable - skipped")
            
            # ===== Stage 2: Explainability =====
            result.lifecycle_state = self.STATE_ANALYZING
            actions_taken.append("Started explainability analysis")
            
            if self.explainability_agent:
                explain_result = self.explainability_agent.analyze(
                    email_content, email_id, detection_result
                )
                result.pipeline_results['explainability'] = explain_result
                actions_taken.append(f"Explainability complete: {len(explain_result.get('evidence', []))} evidence items")
            else:
                actions_taken.append("Explainability agent unavailable - skipped")
            
            # ===== Stage 3: Response =====
            is_phishing = detection_result.get('is_phishing', False) if detection_result else False
            
            if is_phishing and self.response_agent:
                result.lifecycle_state = self.STATE_RESPONDED
                actions_taken.append("Initiating response actions")
                
                response_result = self.response_agent.generate_response(
                    incident_id=incident_id,
                    email_id=email_id,
                    severity=result.severity,
                    risk_score=result.risk_score,
                    detection_result=detection_result,
                    explain_result=result.pipeline_results.get('explainability')
                )
                result.pipeline_results['response'] = response_result
                
                response_actions = response_result.get('actions_executed', [])
                actions_taken.extend([f"Response: {a}" for a in response_actions])
            else:
                if not is_phishing:
                    actions_taken.append("No response needed - email is safe")
                    result.lifecycle_state = self.STATE_RESOLVED
            
            # ===== Stage 4: Finalize =====
            if is_phishing:
                result.lifecycle_state = self.STATE_RESPONDED
                self.stats['phishing_incidents'] += 1
            else:
                result.lifecycle_state = self.STATE_RESOLVED
                self.stats['safe_emails'] += 1
            
            # Update severity stats
            if result.severity == 'HIGH':
                self.stats['high_severity'] += 1
            elif result.severity == 'MEDIUM':
                self.stats['medium_severity'] += 1
            else:
                self.stats['low_severity'] += 1
            
            # Store incident
            self._store_incident(result, email_content)
            actions_taken.append("Incident recorded in database")
            result.lifecycle_state = self.STATE_REPORTED
            
            result.actions_taken = actions_taken
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            self.stats['errors'] += 1
            self.logger.error(f"Orchestrator error for {incident_id}: {e}")
        
        # Calculate processing time
        processing_time = int((time.time() - start_time) * 1000)
        result.processing_time_ms = processing_time
        
        # Update average processing time
        total = self.stats['total_incidents']
        self.stats['avg_processing_time_ms'] = (
            (self.stats['avg_processing_time_ms'] * (total - 1) + processing_time) / total
        )
        
        self.logger.info(
            f"Orchestrator [{incident_id}]: severity={result.severity}, "
            f"state={result.lifecycle_state}, time={processing_time}ms"
        )
        
        return result.to_dict()
    
    def _store_incident(self, result: OrchestratorResult, email_content: str) -> None:
        """
        Store incident in the JSON database.
        
        Args:
            result: Orchestrator result
            email_content: Original email content
        """
        try:
            # Load existing incidents
            incidents_data = {"incidents": [], "schema_version": "2.0.0"}
            if os.path.exists(self.incidents_db_path):
                with open(self.incidents_db_path, 'r') as f:
                    incidents_data = json.load(f)
            
            # Create incident record
            incident_record = {
                "incident_id": result.incident_id,
                "email_id": result.email_id,
                "status": result.lifecycle_state,
                "severity": result.severity,
                "risk_score": result.risk_score,
                "is_phishing": result.pipeline_results.get('detection', {}).get('is_phishing', False),
                "created_at": result.timestamp,
                "updated_at": result.timestamp,
                "processing_time_ms": result.processing_time_ms,
                "actions_taken": result.actions_taken,
                # Store truncated content for reference
                "email_preview": email_content[:500] if email_content else ""
            }
            
            # Append to incidents list
            incidents_data['incidents'].append(incident_record)
            
            # Keep only last 1000 incidents
            if len(incidents_data['incidents']) > 1000:
                incidents_data['incidents'] = incidents_data['incidents'][-1000:]
            
            # Save back
            with open(self.incidents_db_path, 'w') as f:
                json.dump(incidents_data, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Failed to store incident: {e}")
    
    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve an incident by ID.
        
        Args:
            incident_id: Incident identifier
            
        Returns:
            Incident record or None if not found
        """
        try:
            if os.path.exists(self.incidents_db_path):
                with open(self.incidents_db_path, 'r') as f:
                    data = json.load(f)
                
                for incident in data.get('incidents', []):
                    if incident.get('incident_id') == incident_id:
                        return incident
        except Exception as e:
            self.logger.error(f"Error retrieving incident: {e}")
        
        return None
    
    def get_recent_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent incidents.
        
        Args:
            limit: Maximum number of incidents to return
            
        Returns:
            List of incident records
        """
        try:
            if os.path.exists(self.incidents_db_path):
                with open(self.incidents_db_path, 'r') as f:
                    data = json.load(f)
                
                incidents = data.get('incidents', [])
                return incidents[-limit:][::-1]  # Return most recent first
        except Exception as e:
            self.logger.error(f"Error retrieving recent incidents: {e}")
        
        return []
    
    def update_incident_state(self, incident_id: str, new_state: str) -> bool:
        """
        Update an incident's lifecycle state.
        
        Args:
            incident_id: Incident identifier
            new_state: New lifecycle state
            
        Returns:
            True if update successful
        """
        if new_state not in self.VALID_STATES:
            self.logger.error(f"Invalid state: {new_state}")
            return False
        
        try:
            if os.path.exists(self.incidents_db_path):
                with open(self.incidents_db_path, 'r') as f:
                    data = json.load(f)
                
                for incident in data.get('incidents', []):
                    if incident.get('incident_id') == incident_id:
                        incident['status'] = new_state
                        incident['updated_at'] = datetime.now(timezone.utc).isoformat()
                        
                        with open(self.incidents_db_path, 'w') as f:
                            json.dump(data, f, indent=2)
                        
                        return True
        except Exception as e:
            self.logger.error(f"Error updating incident state: {e}")
        
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            'agents_available': {
                'detection': self.detection_agent is not None,
                'explainability': self.explainability_agent is not None,
                'response': self.response_agent is not None
            },
            **self.stats
        }


# Factory function
def create_orchestrator_agent(incidents_db_path: Optional[str] = None) -> OrchestratorAgent:
    """Create an OrchestratorAgent instance."""
    return OrchestratorAgent(incidents_db_path)


# Module-level singleton
_agent_instance: Optional[OrchestratorAgent] = None


def get_orchestrator_agent() -> OrchestratorAgent:
    """Get or create orchestrator agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = OrchestratorAgent()
    return _agent_instance


# Direct execution for testing
if __name__ == "__main__":
    agent = OrchestratorAgent()
    
    test_email = """
    URGENT: Your account has been suspended!
    
    Dear Customer,
    
    We noticed unusual activity in your bank account. Your account will be terminated 
    within 24 hours unless you verify your identity immediately.
    
    Click here to verify: http://suspicious-link.com/verify
    Enter your password and credit card to confirm.
    
    Best regards,
    Security Team
    """
    
    result = agent.process_email(test_email)
    
    print("=" * 60)
    print("ORCHESTRATOR RESULT")
    print("=" * 60)
    print(f"Incident ID: {result['incident_id']}")
    print(f"Email ID: {result['email_id']}")
    print(f"Status: {result['status']}")
    print(f"Lifecycle State: {result['lifecycle_state']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Severity: {result['severity']}")
    print(f"Processing Time: {result['processing_time_ms']}ms")
    print(f"\nActions Taken:")
    for action in result.get('actions_taken', []):
        print(f"  - {action}")
    
    print(f"\nPipeline Results Available:")
    for key in result.get('pipeline_results', {}).keys():
        print(f"  - {key}")
