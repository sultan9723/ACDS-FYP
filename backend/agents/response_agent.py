"""
Autonomous Response Agent for ACDS
===================================
Handles automated threat response actions including quarantine,
sender blocking, notifications, and remediation.

Standard Output Contract:
{
    "agent": "response",
    "status": "success" | "error",
    "incident_id": str,
    "email_id": str,
    "severity": "LOW" | "MEDIUM" | "HIGH",
    "actions_executed": [str],
    "actions_pending": [str],
    "response_details": {
        "quarantined": bool,
        "sender_blocked": bool,
        "admin_notified": bool
    },
    "recommendation": str,
    "timestamp": ISO8601 str,
    "error": str | null
}

Version: 2.0.0
"""

import os
import json
import shutil
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict, field

try:
    from backend.config.settings import (
        AUTO_QUARANTINE_ENABLED, AUTO_BLOCK_SENDER_ENABLED,
        AUTO_NOTIFY_ADMIN_ENABLED, QUARANTINE_FOLDER, BLOCKED_SENDERS_FILE,
        THREAT_SEVERITY_LEVELS
    )
    from backend.core.logger import get_logger
except ImportError:
    try:
        from config.settings import (
            AUTO_QUARANTINE_ENABLED, AUTO_BLOCK_SENDER_ENABLED,
            AUTO_NOTIFY_ADMIN_ENABLED, QUARANTINE_FOLDER, BLOCKED_SENDERS_FILE,
            THREAT_SEVERITY_LEVELS
        )
        from core.logger import get_logger
    except ImportError:
        AUTO_QUARANTINE_ENABLED = True
        AUTO_BLOCK_SENDER_ENABLED = True
        AUTO_NOTIFY_ADMIN_ENABLED = True
        QUARANTINE_FOLDER = "data/quarantine"
        BLOCKED_SENDERS_FILE = "data/blocked_senders.json"
        THREAT_SEVERITY_LEVELS = {
            "HIGH": {"min_confidence": 0.7, "priority": 1, "auto_response": True},
            "MEDIUM": {"min_confidence": 0.4, "priority": 2, "auto_response": True},
            "LOW": {"min_confidence": 0.0, "priority": 3, "auto_response": False},
        }
        logging.basicConfig(level=logging.INFO)
        def get_logger(name):
            return logging.getLogger(name)


class ResponseAction(Enum):
    """Enumeration of possible response actions."""
    QUARANTINE = "quarantine"
    BLOCK_SENDER = "block_sender"
    DELETE = "delete"
    NOTIFY_ADMIN = "notify_admin"
    NOTIFY_USER = "notify_user"
    RATE_LIMIT = "rate_limit"
    LOCK_ACCOUNT = "lock_account"
    ISOLATE_HOST = "isolate_host"
    NO_ACTION = "no_action"


class ResponseAgent:
    """
    Agent responsible for autonomous threat response actions.
    Implements the response workflow based on threat severity and configuration.
    """
    
    def __init__(self):
        """Initialize the Response Agent."""
        self.logger = get_logger(__name__)
        self.quarantine_folder = QUARANTINE_FOLDER
        self.blocked_senders_file = BLOCKED_SENDERS_FILE
        self.blocked_senders = self._load_blocked_senders()
        
        # Ensure quarantine folder exists
        os.makedirs(self.quarantine_folder, exist_ok=True)
        
        # Response history
        self.response_history: List[Dict] = []
        
        # Statistics
        self.stats = {
            'total_responses': 0,
            'quarantined': 0,
            'senders_blocked': 0,
            'notifications_sent': 0,
            'auto_responses': 0,
            'manual_responses': 0,
        }
        
        self.logger.info("ResponseAgent initialized successfully")
    
    def _load_blocked_senders(self) -> set:
        """Load blocked senders list from file."""
        if os.path.exists(self.blocked_senders_file):
            try:
                with open(self.blocked_senders_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('senders', []))
            except Exception as e:
                self.logger.error(f"Error loading blocked senders: {e}")
        return set()
    
    def _save_blocked_senders(self) -> bool:
        """Save blocked senders list to file."""
        try:
            os.makedirs(os.path.dirname(self.blocked_senders_file), exist_ok=True)
            with open(self.blocked_senders_file, 'w') as f:
                json.dump({
                    'senders': list(self.blocked_senders),
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'count': len(self.blocked_senders)
                }, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Error saving blocked senders: {e}")
            return False
    
    def respond(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a threat and execute appropriate response actions.
        
        Args:
            threat_data: Dictionary containing threat information including:
                - is_phishing: bool
                - confidence: float
                - severity: str
                - sender: str (optional)
                - file_path: str (optional)
                - email_id: str (optional)
        
        Returns:
            Dictionary with response details and actions taken
        """
        self.stats['total_responses'] += 1
        
        response_result = {
            'response_id': f"resp_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'threat_id': threat_data.get('id', 'unknown'),
            'actions_taken': [],
            'actions_pending': [],
            'success': True,
            'auto_response': False,
            'message': '',
        }
        
        if not threat_data.get('is_phishing', False):
            response_result['message'] = "No threat detected. No action required."
            response_result['actions_taken'].append({
                'action': ResponseAction.NO_ACTION.value,
                'status': 'completed',
                'reason': 'Not identified as phishing'
            })
            return response_result
        
        confidence = threat_data.get('confidence', 0)
        severity = threat_data.get('severity', 'MEDIUM')
        
        # Determine if auto-response is enabled for this severity
        severity_config = THREAT_SEVERITY_LEVELS.get(severity, {})
        auto_response_enabled = severity_config.get('auto_response', False)
        
        if auto_response_enabled:
            response_result['auto_response'] = True
            self.stats['auto_responses'] += 1
        else:
            self.stats['manual_responses'] += 1
        
        # Execute response actions based on severity and configuration
        actions_to_take = self._determine_actions(threat_data, severity, auto_response_enabled)
        
        for action in actions_to_take:
            action_result = self._execute_action(action, threat_data)
            if action_result.get('executed', False):
                response_result['actions_taken'].append(action_result)
            else:
                response_result['actions_pending'].append(action_result)
        
        # Generate summary message
        response_result['message'] = self._generate_response_message(
            response_result['actions_taken'],
            response_result['actions_pending'],
            severity
        )
        
        # Store in history
        self.response_history.append(response_result)
        
        # Keep history manageable (last 1000 responses)
        if len(self.response_history) > 1000:
            self.response_history = self.response_history[-1000:]
        
        return response_result
    
    def _determine_actions(
        self, 
        threat_data: Dict, 
        severity: str, 
        auto_response: bool
    ) -> List[ResponseAction]:
        """Determine which actions to take based on threat and configuration."""
        actions = []
        
        # Critical and High severity threats
        if severity in ['CRITICAL', 'HIGH']:
            if AUTO_QUARANTINE_ENABLED and threat_data.get('file_path'):
                actions.append(ResponseAction.QUARANTINE)
            
            if AUTO_BLOCK_SENDER_ENABLED and threat_data.get('sender'):
                actions.append(ResponseAction.BLOCK_SENDER)
            
            if AUTO_NOTIFY_ADMIN_ENABLED:
                actions.append(ResponseAction.NOTIFY_ADMIN)
        
        # Medium severity threats
        elif severity == 'MEDIUM':
            if AUTO_NOTIFY_ADMIN_ENABLED:
                actions.append(ResponseAction.NOTIFY_ADMIN)
            
            # Queue quarantine for manual approval
            if threat_data.get('file_path'):
                actions.append(ResponseAction.QUARANTINE)
        
        # Always notify user if email is suspicious
        if threat_data.get('email_id') or threat_data.get('recipient'):
            actions.append(ResponseAction.NOTIFY_USER)
        
        return actions
    
    def _execute_action(
        self, 
        action: ResponseAction, 
        threat_data: Dict
    ) -> Dict[str, Any]:
        """Execute a single response action."""
        result = {
            'action': action.value,
            'executed': False,
            'status': 'pending',
            'details': '',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            if action == ResponseAction.QUARANTINE:
                result = self._quarantine_file(threat_data.get('file_path'), result)
            
            elif action == ResponseAction.BLOCK_SENDER:
                result = self._block_sender(threat_data.get('sender'), result)
            
            elif action == ResponseAction.NOTIFY_ADMIN:
                result = self._notify_admin(threat_data, result)
            
            elif action == ResponseAction.NOTIFY_USER:
                result = self._notify_user(threat_data, result)
            
            elif action == ResponseAction.DELETE:
                result = self._delete_threat(threat_data, result)
            
        except Exception as e:
            result['status'] = 'error'
            result['details'] = str(e)
            self.logger.error(f"Error executing action {action.value}: {e}")
        
        return result
    
    def _quarantine_file(self, file_path: Optional[str], result: Dict) -> Dict:
        """Move a file to quarantine."""
        if not file_path or not os.path.exists(file_path):
            result['status'] = 'skipped'
            result['details'] = 'File not found or path not provided'
            return result
        
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.quarantine_folder, quarantine_name)
            
            shutil.move(file_path, quarantine_path)
            
            result['executed'] = True
            result['status'] = 'completed'
            result['details'] = f'File quarantined to {quarantine_path}'
            self.stats['quarantined'] += 1
            
            self.logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            
        except Exception as e:
            result['status'] = 'error'
            result['details'] = f'Quarantine failed: {str(e)}'
        
        return result
    
    def _block_sender(self, sender: Optional[str], result: Dict) -> Dict:
        """Add a sender to the blocked list."""
        if not sender:
            result['status'] = 'skipped'
            result['details'] = 'No sender provided'
            return result
        
        sender = sender.lower().strip()
        
        if sender in self.blocked_senders:
            result['status'] = 'skipped'
            result['details'] = 'Sender already blocked'
            return result
        
        self.blocked_senders.add(sender)
        
        if self._save_blocked_senders():
            result['executed'] = True
            result['status'] = 'completed'
            result['details'] = f'Sender {sender} added to blocklist'
            self.stats['senders_blocked'] += 1
            self.logger.info(f"Sender blocked: {sender}")
        else:
            result['status'] = 'error'
            result['details'] = 'Failed to save blocklist'
        
        return result
    
    def _notify_admin(self, threat_data: Dict, result: Dict) -> Dict:
        """Send notification to admin about the threat."""
        # In production, this would send email/webhook/slack notification
        # For now, we log and mark as completed
        
        notification = {
            'type': 'admin_alert',
            'threat_id': threat_data.get('id', 'unknown'),
            'severity': threat_data.get('severity', 'UNKNOWN'),
            'confidence': threat_data.get('confidence', 0),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message': f"Phishing threat detected with {threat_data.get('confidence', 0)*100:.1f}% confidence"
        }
        
        self.logger.warning(f"ADMIN NOTIFICATION: {json.dumps(notification)}")
        
        result['executed'] = True
        result['status'] = 'completed'
        result['details'] = 'Admin notification sent (logged)'
        self.stats['notifications_sent'] += 1
        
        return result
    
    def _notify_user(self, threat_data: Dict, result: Dict) -> Dict:
        """Send notification to affected user."""
        # In production, this would send user notification
        
        result['executed'] = True
        result['status'] = 'completed'
        result['details'] = 'User notification queued'
        
        return result
    
    def _delete_threat(self, threat_data: Dict, result: Dict) -> Dict:
        """Delete the threat source (use with caution)."""
        file_path = threat_data.get('file_path')
        
        if not file_path or not os.path.exists(file_path):
            result['status'] = 'skipped'
            result['details'] = 'File not found'
            return result
        
        try:
            os.remove(file_path)
            result['executed'] = True
            result['status'] = 'completed'
            result['details'] = f'File deleted: {file_path}'
            self.logger.warning(f"Threat file deleted: {file_path}")
        except Exception as e:
            result['status'] = 'error'
            result['details'] = f'Delete failed: {str(e)}'
        
        return result
    
    def _generate_response_message(
        self, 
        actions_taken: List[Dict], 
        actions_pending: List[Dict],
        severity: str
    ) -> str:
        """Generate a human-readable response message."""
        taken_count = len(actions_taken)
        pending_count = len(actions_pending)
        
        if taken_count == 0 and pending_count == 0:
            return "No response actions were required."
        
        message_parts = []
        
        if taken_count > 0:
            action_names = [a['action'] for a in actions_taken if a.get('executed')]
            message_parts.append(f"Executed {len(action_names)} action(s): {', '.join(action_names)}")
        
        if pending_count > 0:
            pending_names = [a['action'] for a in actions_pending]
            message_parts.append(f"Pending approval: {', '.join(pending_names)}")
        
        return f"[{severity}] " + ". ".join(message_parts)
    
    def is_sender_blocked(self, sender: str) -> bool:
        """Check if a sender is on the blocklist."""
        return sender.lower().strip() in self.blocked_senders
    
    def unblock_sender(self, sender: str) -> bool:
        """Remove a sender from the blocklist."""
        sender = sender.lower().strip()
        if sender in self.blocked_senders:
            self.blocked_senders.remove(sender)
            self._save_blocked_senders()
            self.logger.info(f"Sender unblocked: {sender}")
            return True
        return False
    
    def get_blocked_senders(self) -> List[str]:
        """Get list of all blocked senders."""
        return list(self.blocked_senders)
    
    def get_quarantined_files(self) -> List[Dict]:
        """Get list of quarantined files."""
        files = []
        if os.path.exists(self.quarantine_folder):
            for filename in os.listdir(self.quarantine_folder):
                filepath = os.path.join(self.quarantine_folder, filename)
                files.append({
                    'filename': filename,
                    'path': filepath,
                    'size': os.path.getsize(filepath),
                    'quarantine_time': os.path.getctime(filepath)
                })
        return files
    
    def restore_from_quarantine(self, filename: str, destination: str) -> bool:
        """Restore a file from quarantine."""
        quarantine_path = os.path.join(self.quarantine_folder, filename)
        if not os.path.exists(quarantine_path):
            return False
        
        try:
            shutil.move(quarantine_path, destination)
            self.logger.info(f"File restored from quarantine: {filename} -> {destination}")
            return True
        except Exception as e:
            self.logger.error(f"Error restoring file: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get response agent statistics."""
        return {
            **self.stats,
            'blocked_senders_count': len(self.blocked_senders),
            'quarantined_files_count': len(self.get_quarantined_files()),
            'recent_responses': len(self.response_history),
        }
    
    def get_response_history(self, limit: int = 50) -> List[Dict]:
        """Get recent response history."""
        return self.response_history[-limit:]


# Legacy function for backward compatibility
def respond(alert: Dict) -> Dict[str, Any]:
    """Legacy respond function - wraps ResponseAgent."""
    agent = ResponseAgent()
    return agent.respond(alert)


@dataclass
class ResponseResult:
    """Dataclass for response agent standard output."""
    agent: str = "response"
    status: str = "success"
    incident_id: str = ""
    email_id: str = ""
    severity: str = "LOW"
    actions_executed: List[str] = field(default_factory=list)
    actions_pending: List[str] = field(default_factory=list)
    response_details: Dict[str, bool] = field(default_factory=dict)
    recommendation: str = ""
    timestamp: str = ""
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


# Add generate_response method to ResponseAgent for standard contract
def _generate_response_standard(
    self,
    incident_id: str,
    email_id: str,
    severity: str,
    risk_score: int,
    detection_result: Optional[Dict[str, Any]] = None,
    explain_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate standardized response output.
    
    Args:
        incident_id: Incident identifier
        email_id: Email identifier
        severity: Severity level (LOW/MEDIUM/HIGH)
        risk_score: Risk score (0-100)
        detection_result: Results from detection agent
        explain_result: Results from explainability agent
        
    Returns:
        Standard response agent output
    """
    result = ResponseResult(
        incident_id=incident_id,
        email_id=email_id,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        response_details={
            'quarantined': False,
            'sender_blocked': False,
            'admin_notified': False
        }
    )
    
    try:
        # Build threat data from detection result
        threat_data = {
            'id': incident_id,
            'email_id': email_id,
            'is_phishing': detection_result.get('is_phishing', False) if detection_result else False,
            'confidence': detection_result.get('confidence', 0) if detection_result else 0,
            'severity': severity,
            'sender': None,  # Would be extracted from email headers
            'file_path': None
        }
        
        # Execute response
        response_result = self.respond(threat_data)
        
        # Map to standard output
        executed = []
        pending = []
        
        for action in response_result.get('actions_taken', []):
            if action.get('executed', False):
                executed.append(action.get('action', ''))
                
                # Track response details
                if action.get('action') == 'quarantine':
                    result.response_details['quarantined'] = True
                elif action.get('action') == 'block_sender':
                    result.response_details['sender_blocked'] = True
                elif action.get('action') == 'notify_admin':
                    result.response_details['admin_notified'] = True
        
        for action in response_result.get('actions_pending', []):
            pending.append(action.get('action', ''))
        
        result.actions_executed = executed
        result.actions_pending = pending
        
        # Generate recommendation
        result.recommendation = self._generate_recommendation(severity, executed, pending)
        
    except Exception as e:
        result.status = "error"
        result.error = str(e)
        self.logger.error(f"Response error for {incident_id}: {e}")
    
    return result.to_dict()


def _generate_recommendation(self, severity: str, executed: List[str], pending: List[str]) -> str:
    """Generate response recommendation."""
    if severity == 'HIGH':
        if 'quarantine' in executed:
            return "Email quarantined. Review sender patterns and consider organization-wide block."
        return "HIGH severity threat. Immediate quarantine and sender block recommended."
    elif severity == 'MEDIUM':
        return "Moderate threat detected. Review email content and monitor sender activity."
    else:
        return "Low risk. Standard monitoring in place."


# Attach method to ResponseAgent class
ResponseAgent.generate_response = _generate_response_standard
ResponseAgent._generate_recommendation = _generate_recommendation


# Factory function
def create_response_agent() -> ResponseAgent:
    """Create a ResponseAgent instance."""
    return ResponseAgent()


# Module-level singleton
_agent_instance: Optional[ResponseAgent] = None


def get_response_agent() -> ResponseAgent:
    """Get or create response agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = ResponseAgent()
    return _agent_instance


