"""
Ransomware Orchestrator Agent
==============================
Central coordinator for the ransomware detection pipeline.
Manages incident lifecycle and coordinates all ransomware agents.

Incident Lifecycle States:
    detected → analyzing → responded → resolved → reported

Standard Output Contract:
{
    "agent": "ransomware_orchestrator",
    "status": "success" | "error",
    "incident_id": str,
    "command_id": str,
    "lifecycle_state": "detected" | "analyzing" | "responded" | "resolved" | "reported",
    "pipeline_results": {
        "detection": {...},
        "explainability": {...},
        "response": {...}
    },
    "risk_score": int (0-100),
    "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "actions_taken": [str],
    "timestamp": ISO8601 str,
    "processing_time_ms": int,
    "error": str | null
}

Version: 1.0.0
"""

import uuid
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

# Import all three ransomware agents
try:
    from agents.ransomware_detection_agent import RansomwareDetectionAgent, get_ransomware_detection_agent
    from agents.ransomware_explainability_agent import RansomwareExplainabilityAgent, get_ransomware_explainability_agent
    from agents.ransomware_response_agent import RansomwareResponseAgent, get_ransomware_response_agent
    from agents.alert_agent import get_alert_agent
    from core.logger import get_logger
except ImportError:
    try:
        from backend.agents.ransomware_detection_agent import RansomwareDetectionAgent, get_ransomware_detection_agent
        from backend.agents.ransomware_explainability_agent import RansomwareExplainabilityAgent, get_ransomware_explainability_agent
        from backend.agents.ransomware_response_agent import RansomwareResponseAgent, get_ransomware_response_agent
        from backend.agents.alert_agent import get_alert_agent
        from backend.core.logger import get_logger
    except ImportError:
        try:
            from .ransomware_detection_agent import RansomwareDetectionAgent, get_ransomware_detection_agent
            from .ransomware_explainability_agent import RansomwareExplainabilityAgent, get_ransomware_explainability_agent
            from .ransomware_response_agent import RansomwareResponseAgent, get_ransomware_response_agent
            from .alert_agent import get_alert_agent
            from ..core.logger import get_logger
        except ImportError:
            logging.basicConfig(level=logging.INFO)

            def get_logger(name):
                return logging.getLogger(name)

            def get_ransomware_detection_agent():
                return None

            def get_ransomware_explainability_agent():
                return None

            def get_ransomware_response_agent():
                return None

            def get_alert_agent():
                return None


@dataclass
class RansomwareOrchestratorResult:
    """Dataclass for ransomware orchestrator output."""
    agent: str = "ransomware_orchestrator"
    status: str = "success"
    incident_id: str = ""
    command_id: str = ""
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


class RansomwareOrchestratorAgent:
    """
    Ransomware Orchestrator Agent - Central pipeline coordinator.

    Manages the full ransomware incident lifecycle:
    1. Detection    : Classify command as ransomware/safe
    2. Explainability: Extract IOCs and generate explanations
    3. Response     : Determine and execute response actions
    4. Reporting    : Log to MongoDB via alert agent
    """

    AGENT_NAME = "ransomware_orchestrator"
    VERSION = "1.0.0"

    # Lifecycle states — identical to phishing orchestrator pattern
    STATE_DETECTED  = "detected"
    STATE_ANALYZING = "analyzing"
    STATE_RESPONDED = "responded"
    STATE_RESOLVED  = "resolved"
    STATE_REPORTED  = "reported"

    VALID_STATES = [
        STATE_DETECTED, STATE_ANALYZING,
        STATE_RESPONDED, STATE_RESOLVED, STATE_REPORTED
    ]

    def __init__(self):
        """Initialize the Ransomware Orchestrator Agent."""
        self.logger = get_logger(__name__)

        # Sub-agents (lazy-loaded)
        self._detection_agent = None
        self._explainability_agent = None
        self._response_agent = None
        self._alert_agent = None

        # Statistics
        self.stats = {
            'total_incidents': 0,
            'ransomware_incidents': 0,
            'safe_commands': 0,
            'critical_severity': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'errors': 0,
            'avg_processing_time_ms': 0
        }

    # =========================================================================
    # Lazy-loaded sub-agents (same pattern as phishing orchestrator)
    # =========================================================================

    @property
    def detection_agent(self):
        """Lazy-load detection agent."""
        if self._detection_agent is None:
            try:
                from agents.ransomware_detection_agent import get_ransomware_detection_agent
                self._detection_agent = get_ransomware_detection_agent()
            except Exception as e:
                self.logger.error(f"Failed to load ransomware detection agent: {e}")
        return self._detection_agent


    @property
    def explainability_agent(self):
        """Lazy-load explainability agent."""
        if self._explainability_agent is None:
            try:
                from agents.ransomware_explainability_agent import get_ransomware_explainability_agent
                self._explainability_agent = get_ransomware_explainability_agent()
            except Exception as e:
                self.logger.error(f"Failed to load ransomware explainability agent: {e}")
        return self._explainability_agent

    @property
    def response_agent(self):
        """Lazy-load response agent."""
        if self._response_agent is None:
            try:
                from agents.ransomware_response_agent import get_ransomware_response_agent
                self._response_agent = get_ransomware_response_agent()
            except Exception as e:
                self.logger.error(f"Failed to load ransomware response agent: {e}")
        return self._response_agent

    @property
    def alert_agent(self):
        """Lazy-load shared alert agent."""
        if self._alert_agent is None:
            try:
                from agents.alert_agent import get_alert_agent
                self._alert_agent = get_alert_agent()
            except Exception as e:
                self.logger.error(f"Failed to load alert agent: {e}")
        return self._alert_agent

    # =========================================================================
    # Main Pipeline
    # =========================================================================

    def process_command(
        self,
        command: str,
        command_id: Optional[str] = None,
        source_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a command through the full ransomware detection pipeline.

        Args:
            command: Raw process command or system call string
            command_id: Optional command identifier
            source_host: Optional hostname where command originated

        Returns:
            Complete orchestrator result with all pipeline results
        """
        start_time = time.time()

        # Generate IDs
        incident_id = f"RAN_{uuid.uuid4().hex[:12].upper()}"
        command_id = command_id or f"cmd_{uuid.uuid4().hex[:12]}"

        result = RansomwareOrchestratorResult(
            incident_id=incident_id,
            command_id=command_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            lifecycle_state=self.STATE_DETECTED
        )

        self.stats['total_incidents'] += 1
        actions_taken = []

        try:
            # =================================================================
            # Stage 1: Detection
            # =================================================================
            result.lifecycle_state = self.STATE_DETECTED
            actions_taken.append("Initiated ransomware detection analysis")

            detection_result = None
            if self.detection_agent:
                detection_result = self.detection_agent.analyze(command, command_id)
                result.pipeline_results['detection'] = detection_result

                result.risk_score = detection_result.get('risk_score', 0)
                result.severity = detection_result.get('severity', 'LOW')

                label = 'RANSOMWARE' if detection_result.get('is_ransomware') else 'SAFE'
                actions_taken.append(
                    f"Detection complete: {label} "
                    f"(confidence: {detection_result.get('confidence', 0):.0%})"
                )
            else:
                actions_taken.append("Detection agent unavailable — skipped")

            # =================================================================
            # Stage 2: Explainability
            # =================================================================
            result.lifecycle_state = self.STATE_ANALYZING
            actions_taken.append("Started explainability analysis")

            if self.explainability_agent:
                explain_result = self.explainability_agent.analyze(
                    command, command_id, detection_result
                )
                result.pipeline_results['explainability'] = explain_result

                behavior_count = len(explain_result.get('behavior_categories', []))
                ioc_count = len(explain_result.get('evidence', []))
                actions_taken.append(
                    f"Explainability complete: {behavior_count} behavior(s), "
                    f"{ioc_count} evidence item(s) found"
                )
            else:
                actions_taken.append("Explainability agent unavailable — skipped")

            # =================================================================
            # Stage 3: Response (only if ransomware detected)
            # =================================================================
            is_ransomware = (
                detection_result.get('is_ransomware', False)
                if detection_result else False
            )

            if is_ransomware and self.response_agent:
                result.lifecycle_state = self.STATE_RESPONDED
                actions_taken.append("Initiating automated response actions")

                response_result = self.response_agent.generate_response(
                    incident_id=incident_id,
                    command_id=command_id,
                    severity=result.severity,
                    risk_score=result.risk_score,
                    detection_result=detection_result,
                    explain_result=result.pipeline_results.get('explainability')
                )
                result.pipeline_results['response'] = response_result

                response_actions = response_result.get('actions_executed', [])
                actions_taken.extend([f"Response: {a}" for a in response_actions])

            else:
                if not is_ransomware:
                    actions_taken.append("No response needed — command is safe")
                    result.lifecycle_state = self.STATE_RESOLVED

            # =================================================================
            # Stage 4: Alert / Finalize
            # =================================================================
            if is_ransomware:
                result.lifecycle_state = self.STATE_RESPONDED
                self.stats['ransomware_incidents'] += 1

                # Log to MongoDB via shared alert agent
                if self.alert_agent:
                    try:
                        self.alert_agent.create_alert({
                            'type': 'ransomware',
                            'incident_id': incident_id,
                            'command_id': command_id,
                            'severity': result.severity,
                            'risk_score': result.risk_score,
                            'source_host': source_host or 'unknown',
                            'command_preview': command[:200],
                            'timestamp': result.timestamp,
                            'behaviors': result.pipeline_results.get(
                                'explainability', {}
                            ).get('behavior_categories', [])
                        })
                        actions_taken.append("Alert logged to MongoDB")
                    except Exception as e:
                        self.logger.warning(f"Alert logging failed: {e}")
            else:
                result.lifecycle_state = self.STATE_RESOLVED
                self.stats['safe_commands'] += 1

            # Update severity stats
            self._update_severity_stats(result.severity)

            actions_taken.append("Incident processing complete")
            result.lifecycle_state = self.STATE_REPORTED
            result.actions_taken = actions_taken

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.actions_taken = actions_taken
            self.stats['errors'] += 1
            self.logger.error(f"Orchestrator error for {incident_id}: {e}")

        # Calculate and record processing time
        processing_time = int((time.time() - start_time) * 1000)
        result.processing_time_ms = processing_time
        self._update_avg_time(processing_time)

        self.logger.info(
            f"Orchestrator [{incident_id}]: severity={result.severity}, "
            f"state={result.lifecycle_state}, time={processing_time}ms"
        )

        return result.to_dict()

    # =========================================================================
    # Helpers
    # =========================================================================

    def _update_severity_stats(self, severity: str) -> None:
        """Update severity statistics."""
        severity_map = {
            'CRITICAL': 'critical_severity',
            'HIGH':     'high_severity',
            'MEDIUM':   'medium_severity',
            'LOW':      'low_severity',
        }
        key = severity_map.get(severity.upper())
        if key:
            self.stats[key] += 1

    def _update_avg_time(self, processing_time: int) -> None:
        """Update rolling average processing time."""
        total = self.stats['total_incidents']
        self.stats['avg_processing_time_ms'] = (
            (self.stats['avg_processing_time_ms'] * (total - 1) + processing_time) / total
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            'agents_available': {
                'detection':       self.detection_agent is not None,
                'explainability':  self.explainability_agent is not None,
                'response':        self.response_agent is not None,
                'alert':           self.alert_agent is not None,
            },
            **self.stats
        }


# =========================================================================
# Singleton — same pattern as phishing orchestrator
# =========================================================================

_agent_instance: Optional[RansomwareOrchestratorAgent] = None


def get_ransomware_orchestrator_agent() -> RansomwareOrchestratorAgent:
    """Get or create ransomware orchestrator agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = RansomwareOrchestratorAgent()
    return _agent_instance


# =========================================================================
# Direct execution for testing
# =========================================================================

if __name__ == "__main__":
    agent = RansomwareOrchestratorAgent()

    test_commands = [
        "vssadmin delete shadows /all /quiet",
        "bcdedit /set {default} recoveryenabled No && wbadmin delete catalog -quiet",
        "notepad.exe C:\\Users\\user\\document.txt",
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    ]

    print("=" * 60)
    print("RANSOMWARE ORCHESTRATOR TEST")
    print("=" * 60)

    for cmd in test_commands:
        result = agent.process_command(cmd)

        print(f"\nCommand     : {cmd[:60]}")
        print(f"Incident ID : {result['incident_id']}")
        print(f"Severity    : {result['severity']}")
        print(f"Risk Score  : {result['risk_score']}")
        print(f"State       : {result['lifecycle_state']}")
        print(f"Time        : {result['processing_time_ms']}ms")
        print(f"Actions:")
        for action in result.get('actions_taken', []):
            print(f"  - {action}")

    print("\n" + "=" * 60)
    print("STATS:", agent.get_stats())
