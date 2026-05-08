"""
ACDS Agents Module
==================
Autonomous agents for phishing detection, analysis, and response.

Agent Pipeline:
    Detection → Explainability → Orchestrator → Response

Version: 2.0.0

Standard JSON Output Contract:
    All agents output dictionaries with consistent fields:
    - agent: str (agent name)
    - status: "success" | "error"
    - email_id: str (email identifier)
    - timestamp: ISO8601 str
    - error: str | null (only present on error)
"""

from .detection_agent import (
    DetectionAgent,
    DetectionResult,
    create_detection_agent,
    get_detection_agent
)

from .explainability_agent import (
    ExplainabilityAgent,
    ExplainabilityResult,
    create_explainability_agent,
    get_explainability_agent
)

from .orchestrator_agent import (
    OrchestratorAgent,
    OrchestratorResult,
    create_orchestrator_agent,
    get_orchestrator_agent
)

from .response_agent import (
    ResponseAgent,
    ResponseAction,
    create_response_agent,
    get_response_agent
)

# Legacy agents (kept for backward compatibility)
# Using try/except to handle missing dependencies
try:
    from .alert_agent import AlertAgent
except ImportError:
    AlertAgent = None

try:
    from .intel_agent import IntelAgent
except ImportError:
    IntelAgent = None

__all__ = [
    # Core pipeline agents
    'DetectionAgent',
    'ExplainabilityAgent',
    'OrchestratorAgent',
    'ResponseAgent',
    
    # Result dataclasses
    'DetectionResult',
    'ExplainabilityResult',
    'OrchestratorResult',
    'ResponseAction',
    
    # Factory functions
    'create_detection_agent',
    'create_explainability_agent',
    'create_orchestrator_agent',
    'create_response_agent',
    
    # Singleton getters
    'get_detection_agent',
    'get_explainability_agent',
    'get_orchestrator_agent',
    'get_response_agent',
    
    # Legacy
    'AlertAgent',
    'IntelAgent',
]

__version__ = '2.0.0'
