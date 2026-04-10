"""
Ransomware Response Agent
=========================
Determines and executes automated response actions based on
ransomware detection severity.

Response Actions by Severity:
    CRITICAL → kill_process + isolate_host + block_hash + alert_soc + emergency_backup
    HIGH     → kill_process + block_hash + alert_soc
    MEDIUM   → kill_process + alert_soc
    LOW      → alert_soc

Standard Output Contract:
{
    "agent": "ransomware_response",
    "status": "success" | "error",
    "incident_id": str,
    "command_id": str,
    "severity": str,
    "actions_executed": [str],
    "response_summary": str,
    "blocked_hashes": [str],
    "isolated_hosts": [str],
    "processing_time_ms": int,
    "timestamp": ISO8601 str,
    "error": str | null
}

Version: 1.0.0
"""

import time
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

try:
    from core.logger import get_logger
except ImportError:
    try:
        from backend.core.logger import get_logger
    except ImportError:
        logging.basicConfig(level=logging.INFO)

        def get_logger(name):
            return logging.getLogger(name)


class ResponseAction(Enum):
    """Available response actions."""
    KILL_PROCESS    = "kill_process"
    ISOLATE_HOST    = "isolate_host"
    BLOCK_HASH      = "block_hash"
    ALERT_SOC       = "alert_soc"
    EMERGENCY_BACKUP = "emergency_backup"
    QUARANTINE_FILE = "quarantine_file"
    RESET_CREDENTIALS = "reset_credentials"


# Response action matrix by severity
RESPONSE_MATRIX = {
    "CRITICAL": [
        ResponseAction.KILL_PROCESS,
        ResponseAction.ISOLATE_HOST,
        ResponseAction.BLOCK_HASH,
        ResponseAction.ALERT_SOC,
        ResponseAction.EMERGENCY_BACKUP,
    ],
    "HIGH": [
        ResponseAction.KILL_PROCESS,
        ResponseAction.BLOCK_HASH,
        ResponseAction.ALERT_SOC,
    ],
    "MEDIUM": [
        ResponseAction.KILL_PROCESS,
        ResponseAction.ALERT_SOC,
    ],
    "LOW": [
        ResponseAction.ALERT_SOC,
    ],
}

# Response action descriptions for logging
ACTION_DESCRIPTIONS = {
    ResponseAction.KILL_PROCESS:      "Terminated malicious process",
    ResponseAction.ISOLATE_HOST:      "Host isolated from network",
    ResponseAction.BLOCK_HASH:        "File hash added to blocklist",
    ResponseAction.ALERT_SOC:         "SOC team alerted",
    ResponseAction.EMERGENCY_BACKUP:  "Emergency backup triggered",
    ResponseAction.QUARANTINE_FILE:   "File moved to quarantine",
    ResponseAction.RESET_CREDENTIALS: "Credential reset initiated",
}


@dataclass
class ResponseResult:
    """Dataclass for ransomware response output."""
    agent: str = "ransomware_response"
    status: str = "success"
    incident_id: str = ""
    command_id: str = ""
    severity: str = "LOW"
    actions_executed: List[str] = field(default_factory=list)
    response_summary: str = ""
    blocked_hashes: List[str] = field(default_factory=list)
    isolated_hosts: List[str] = field(default_factory=list)
    processing_time_ms: int = 0
    timestamp: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


class RansomwareResponseAgent:
    """
    Ransomware Response Agent.

    Executes automated response actions based on severity level.
    Maintains history of blocked hashes and isolated hosts.
    """

    AGENT_NAME = "ransomware_response"
    VERSION = "1.0.0"

    def __init__(self):
        """Initialize the Ransomware Response Agent."""
        self.logger = get_logger(__name__)

        # In-memory response tracking
        self.blocked_hashes: List[str] = []
        self.isolated_hosts: List[str] = []
        self.response_history: List[Dict[str, Any]] = []

        self.stats = {
            'total_responses': 0,
            'critical_responses': 0,
            'high_responses': 0,
            'medium_responses': 0,
            'low_responses': 0,
            'processes_killed': 0,
            'hosts_isolated': 0,
            'hashes_blocked': 0,
            'soc_alerts_sent': 0,
            'errors': 0
        }

    def generate_response(
        self,
        incident_id: str,
        command_id: str,
        severity: str,
        risk_score: int,
        detection_result: Optional[Dict[str, Any]] = None,
        explain_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate and execute response actions for a detected threat.

        Args:
            incident_id: Incident identifier from orchestrator
            command_id: Command identifier
            severity: Threat severity (CRITICAL/HIGH/MEDIUM/LOW)
            risk_score: Numeric risk score (0-100)
            detection_result: Detection agent output
            explain_result: Explainability agent output

        Returns:
            Response result dictionary
        """
        start_time = time.time()

        result = ResponseResult(
            incident_id=incident_id,
            command_id=command_id,
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        self.stats['total_responses'] += 1

        try:
            # Get actions for this severity level
            actions = RESPONSE_MATRIX.get(severity.upper(), RESPONSE_MATRIX["LOW"])
            executed_actions = []

            for action in actions:
                action_result = self._execute_action(
                    action, incident_id, command_id, detection_result, explain_result
                )
                if action_result:
                    executed_actions.append(ACTION_DESCRIPTIONS[action])

                    # Track specific artifacts
                    if action == ResponseAction.BLOCK_HASH:
                        hash_val = f"hash_{incident_id[:8]}"
                        self.blocked_hashes.append(hash_val)
                        result.blocked_hashes.append(hash_val)

                    elif action == ResponseAction.ISOLATE_HOST:
                        host = detection_result.get('host', 'unknown_host') if detection_result else 'unknown_host'
                        self.isolated_hosts.append(host)
                        result.isolated_hosts.append(host)

            result.actions_executed = executed_actions
            result.response_summary = self._build_summary(severity, executed_actions, risk_score)

            # Update stats
            self._update_severity_stats(severity)
            self._update_action_stats(actions)

            # Store in history
            self.response_history.append({
                'incident_id': incident_id,
                'severity': severity,
                'actions': executed_actions,
                'timestamp': result.timestamp
            })

            # Keep history bounded
            if len(self.response_history) > 500:
                self.response_history = self.response_history[-500:]

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            self.stats['errors'] += 1
            self.logger.error(f"Response error for {incident_id}: {e}")

        processing_time = int((time.time() - start_time) * 1000)
        result.processing_time_ms = processing_time

        self.logger.info(
            f"Response [{incident_id}]: severity={severity}, "
            f"actions={len(result.actions_executed)}, time={processing_time}ms"
        )

        return result.to_dict()

    def _execute_action(
        self,
        action: ResponseAction,
        incident_id: str,
        command_id: str,
        detection_result: Optional[Dict],
        explain_result: Optional[Dict]
    ) -> bool:
        """
        Execute a single response action.
        In production this would call real system APIs.
        Currently simulates actions and logs them.

        Returns:
            True if action succeeded
        """
        try:
            if action == ResponseAction.KILL_PROCESS:
                self.logger.warning(
                    f"[RESPONSE] KILL_PROCESS — Terminating process for incident {incident_id}"
                )

            elif action == ResponseAction.ISOLATE_HOST:
                self.logger.warning(
                    f"[RESPONSE] ISOLATE_HOST — Isolating host for incident {incident_id}"
                )

            elif action == ResponseAction.BLOCK_HASH:
                self.logger.warning(
                    f"[RESPONSE] BLOCK_HASH — Adding file hash to blocklist for {incident_id}"
                )

            elif action == ResponseAction.ALERT_SOC:
                self.logger.warning(
                    f"[RESPONSE] ALERT_SOC — Sending SOC alert for incident {incident_id}"
                )

            elif action == ResponseAction.EMERGENCY_BACKUP:
                self.logger.warning(
                    f"[RESPONSE] EMERGENCY_BACKUP — Triggering emergency backup for {incident_id}"
                )

            return True

        except Exception as e:
            self.logger.error(f"Action {action.value} failed: {e}")
            return False

    def _build_summary(self, severity: str, actions: List[str], risk_score: int) -> str:
        """Build a human-readable response summary."""
        if not actions:
            return f"No automated response actions taken for {severity} severity threat."

        return (
            f"Automated response executed for {severity} severity threat "
            f"(risk score: {risk_score}/100). "
            f"{len(actions)} action(s) taken: {', '.join(actions)}."
        )

    def _update_severity_stats(self, severity: str) -> None:
        """Update severity-based statistics."""
        severity_map = {
            'CRITICAL': 'critical_responses',
            'HIGH': 'high_responses',
            'MEDIUM': 'medium_responses',
            'LOW': 'low_responses'
        }
        key = severity_map.get(severity.upper())
        if key:
            self.stats[key] += 1

    def _update_action_stats(self, actions: List[ResponseAction]) -> None:
        """Update action-based statistics."""
        for action in actions:
            if action == ResponseAction.KILL_PROCESS:
                self.stats['processes_killed'] += 1
            elif action == ResponseAction.ISOLATE_HOST:
                self.stats['hosts_isolated'] += 1
            elif action == ResponseAction.BLOCK_HASH:
                self.stats['hashes_blocked'] += 1
            elif action == ResponseAction.ALERT_SOC:
                self.stats['soc_alerts_sent'] += 1

    def get_blocked_hashes(self) -> List[str]:
        """Get list of blocked file hashes."""
        return self.blocked_hashes.copy()

    def get_isolated_hosts(self) -> List[str]:
        """Get list of isolated hosts."""
        return self.isolated_hosts.copy()

    def get_response_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent response history."""
        return self.response_history[-limit:][::-1]

    def get_stats(self) -> Dict[str, Any]:
        """Get response agent statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            'blocked_hashes_count': len(self.blocked_hashes),
            'isolated_hosts_count': len(self.isolated_hosts),
            **self.stats
        }


# Module-level singleton
_agent_instance: Optional[RansomwareResponseAgent] = None


def get_ransomware_response_agent() -> RansomwareResponseAgent:
    """Get or create ransomware response agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = RansomwareResponseAgent()
    return _agent_instance


if __name__ == "__main__":
    agent = RansomwareResponseAgent()

    result = agent.generate_response(
        incident_id="INC_TEST001",
        command_id="cmd_test_001",
        severity="CRITICAL",
        risk_score=95
    )

    print("=" * 60)
    print("RESPONSE AGENT TEST")
    print("=" * 60)
    print(f"Severity         : {result['severity']}")
    print(f"Actions Executed : {result['actions_executed']}")
    print(f"Summary          : {result['response_summary']}")
    print(f"Blocked Hashes   : {result['blocked_hashes']}")
