"""
Ransomware Detection Agent
==========================
ML-based detection agent for ransomware commands and behaviors.
Uses trained TF-IDF + Random Forest model to classify commands.

Standard Output Contract:
{
    "agent": "ransomware_detection",
    "status": "success" | "error",
    "command_id": str,
    "is_ransomware": bool,
    "confidence": float (0.0 - 1.0),
    "risk_score": int (0-100),
    "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "model_used": "ml_model" | "rule_based",
    "features": {
        "shadow_keywords": int,
        "boot_keywords": int,
        "service_kill_keywords": int,
        "persistence_keywords": int,
        "lateral_keywords": int,
        "obfuscation_keywords": int,
        "credential_keywords": int,
        "ransom_note_keywords": int,
        "suspicious_keywords": [str]
    },
    "processing_time_ms": int,
    "timestamp": ISO8601 str,
    "error": str | null
}

Version: 1.0.0
"""

import time
import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

# Import ML service and preprocessor
try:
    from ml.ransomware_service import RansomwareDetectionService, get_ransomware_service
    from ml.ransomware_preprocess import extract_command_features, get_severity
    from core.logger import get_logger
except ImportError:
    try:
        from backend.ml.ransomware_service import RansomwareDetectionService, get_ransomware_service
        from backend.ml.ransomware_preprocess import extract_command_features, get_severity
        from backend.core.logger import get_logger
    except ImportError:
        logging.basicConfig(level=logging.INFO)

        def get_logger(name):
            return logging.getLogger(name)

        def get_ransomware_service():
            return None

        def extract_command_features(cmd):
            return {}

        def get_severity(score):
            return "LOW"


@dataclass
class DetectionResult:
    """Dataclass for ransomware detection output."""
    agent: str = "ransomware_detection"
    status: str = "success"
    command_id: str = ""
    is_ransomware: bool = False
    confidence: float = 0.0
    risk_score: int = 0
    severity: str = "LOW"
    model_used: str = "ml_model"
    features: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: int = 0
    timestamp: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


class RansomwareDetectionAgent:
    """
    Ransomware Detection Agent.

    Classifies process commands and system calls as ransomware
    or benign using the trained ML model.
    Falls back to rule-based detection if model is unavailable.
    """

    AGENT_NAME = "ransomware_detection"
    VERSION = "1.0.0"

    # Severity thresholds based on confidence
    SEVERITY_CRITICAL = 0.90
    SEVERITY_HIGH = 0.75
    SEVERITY_MEDIUM = 0.60
    SEVERITY_LOW = 0.50

    def __init__(self):
        """Initialize the Ransomware Detection Agent."""
        self.logger = get_logger(__name__)
        self._service = None

        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'ransomware_detected': 0,
            'safe_commands': 0,
            'critical_severity': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'ml_model_used': 0,
            'rule_based_used': 0,
            'errors': 0,
            'avg_processing_time_ms': 0
        }

    @property
    def service(self):
        """Lazy-load ML service."""
        if self._service is None:
            try:
                self._service = get_ransomware_service()
            except Exception as e:
                self.logger.error(f"Failed to load ransomware service: {e}")
        return self._service

    def is_model_loaded(self) -> bool:
        """Check if ML model is loaded and ready."""
        try:
            svc = self.service
            return svc is not None and svc.is_model_loaded()
        except Exception:
            return False

    def analyze(self, command: str, command_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a command string for ransomware behavior.

        Args:
            command: Process command or system call string
            command_id: Optional command identifier

        Returns:
            Detection result dictionary matching standard output contract
        """
        start_time = time.time()
        command_id = command_id or f"cmd_{uuid.uuid4().hex[:12]}"

        result = DetectionResult(
            command_id=command_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        self.stats['total_analyzed'] += 1

        try:
            # Extract features regardless of model
            features = extract_command_features(command)
            result.features = features

            if self.service and self.is_model_loaded():
                # === ML Model Path ===
                prediction = self.service.predict(command)

                result.is_ransomware = prediction.get('is_ransomware', False)
                result.confidence = prediction.get('confidence', 0.0)
                result.risk_score = prediction.get('risk_score', 0)
                result.model_used = "ml_model"
                self.stats['ml_model_used'] += 1

            else:
                # === Rule-Based Fallback ===
                result.is_ransomware, result.confidence, result.risk_score = (
                    self._rule_based_detection(features)
                )
                result.model_used = "rule_based"
                self.stats['rule_based_used'] += 1

            # Determine severity from confidence
            result.severity = self._get_severity_from_confidence(
                result.confidence, result.is_ransomware
            )

            # Update stats
            if result.is_ransomware:
                self.stats['ransomware_detected'] += 1
            else:
                self.stats['safe_commands'] += 1

            self._update_severity_stats(result.severity)

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            self.stats['errors'] += 1
            self.logger.error(f"Detection error for {command_id}: {e}")

        # Finalize timing
        processing_time = int((time.time() - start_time) * 1000)
        result.processing_time_ms = processing_time
        self._update_avg_time(processing_time)

        self.logger.info(
            f"Detection [{command_id}]: ransomware={result.is_ransomware}, "
            f"confidence={result.confidence:.2f}, severity={result.severity}, "
            f"time={processing_time}ms"
        )

        return result.to_dict()

    def analyze_batch(self, commands: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple commands in batch.

        Args:
            commands: List of command strings

        Returns:
            List of detection result dictionaries
        """
        return [self.analyze(cmd) for cmd in commands]

    def _rule_based_detection(self, features: Dict[str, Any]):
        """
        Rule-based fallback detection using keyword features.

        Returns:
            Tuple of (is_ransomware, confidence, risk_score)
        """
        # Count total suspicious keyword hits across all categories
        category_scores = {
            'shadow_keywords': 3.0,       # Very high weight — shadow copy deletion = ransomware
            'boot_keywords': 2.5,          # High weight — boot config changes
            'service_kill_keywords': 2.0,  # Medium-high — killing AV/backup services
            'persistence_keywords': 1.5,   # Medium — persistence mechanisms
            'lateral_keywords': 1.5,       # Medium — lateral movement
            'obfuscation_keywords': 2.0,   # Medium-high — obfuscation
            'credential_keywords': 1.5,    # Medium — credential theft
            'ransom_note_keywords': 3.0,   # Very high weight — explicit ransom behavior
        }

        weighted_score = 0.0
        for category, weight in category_scores.items():
            count = features.get(category, 0)
            weighted_score += count * weight

        # Normalize to 0-1 confidence
        confidence = min(weighted_score / 10.0, 1.0)
        is_ransomware = confidence >= 0.40
        risk_score = int(confidence * 100)

        return is_ransomware, confidence, risk_score

    def _get_severity_from_confidence(self, confidence: float, is_ransomware: bool) -> str:
        """Map confidence score to severity level."""
        if not is_ransomware:
            return "LOW"
        if confidence >= self.SEVERITY_CRITICAL:
            return "CRITICAL"
        elif confidence >= self.SEVERITY_HIGH:
            return "HIGH"
        elif confidence >= self.SEVERITY_MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"

    def _update_severity_stats(self, severity: str) -> None:
        """Update severity statistics."""
        severity_map = {
            'CRITICAL': 'critical_severity',
            'HIGH': 'high_severity',
            'MEDIUM': 'medium_severity',
            'LOW': 'low_severity'
        }
        key = severity_map.get(severity)
        if key:
            self.stats[key] += 1

    def _update_avg_time(self, processing_time: int) -> None:
        """Update rolling average processing time."""
        total = self.stats['total_analyzed']
        self.stats['avg_processing_time_ms'] = (
            (self.stats['avg_processing_time_ms'] * (total - 1) + processing_time) / total
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get detection agent statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            'model_loaded': self.is_model_loaded(),
            **self.stats
        }


# Module-level singleton
_agent_instance: Optional[RansomwareDetectionAgent] = None


def get_ransomware_detection_agent() -> RansomwareDetectionAgent:
    """Get or create ransomware detection agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = RansomwareDetectionAgent()
    return _agent_instance


# Direct execution for testing
if __name__ == "__main__":
    agent = RansomwareDetectionAgent()

    test_commands = [
        "vssadmin delete shadows /all /quiet",
        "bcdedit /set {default} recoveryenabled No",
        "net stop 'Volume Shadow Copy'",
        "notepad.exe",
        "powershell -enc SQBFAFgA...",
    ]

    print("=" * 60)
    print("RANSOMWARE DETECTION AGENT TEST")
    print("=" * 60)

    for cmd in test_commands:
        result = agent.analyze(cmd)
        print(f"\nCommand : {cmd[:60]}")
        print(f"Ransomware : {result['is_ransomware']}")
        print(f"Confidence : {result['confidence']:.2f}")
        print(f"Severity   : {result['severity']}")
        print(f"Model Used : {result['model_used']}")
