"""
Safe ransomware response orchestration service.

This service records SOC-style response recommendations and simulated actions.
It never kills processes, changes firewall state, deletes files, or moves files.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from database.connection import get_collection
except ImportError:
    try:
        from backend.database.connection import get_collection
    except ImportError:
        get_collection = None


BACKEND_ROOT = Path(__file__).resolve().parents[1]
AUDIT_LOG_PATH = BACKEND_ROOT / "data" / "ransomware_response_audit.json"


class RansomwareResponseOrchestrationService:
    """Build recommendations, simulate response actions, and persist audit records."""

    ACTIONS: Dict[str, Dict[str, str]] = {
        "quarantine_file": {
            "label": "Track file in quarantine",
            "mode": "tracked",
            "description": "Record the sample as quarantined and preserve it for analysis.",
        },
        "isolate_file": {
            "label": "Mark file isolated",
            "mode": "tracked",
            "description": "Record file isolation state without moving or deleting the file.",
        },
        "terminate_process": {
            "label": "Simulate process termination",
            "mode": "simulated",
            "description": "Create a process termination ticket without killing the process.",
        },
        "recommend_network_isolation": {
            "label": "Recommend network isolation",
            "mode": "recommended",
            "description": "Recommend host isolation for SOC approval without changing network state.",
        },
        "block_hash": {
            "label": "Track hash block recommendation",
            "mode": "tracked",
            "description": "Record the SHA256 as a candidate block indicator.",
        },
        "alert_soc": {
            "label": "Alert SOC",
            "mode": "simulated",
            "description": "Record a SOC alert dispatch event for analyst review.",
        },
    }

    SEVERITY_ACTIONS: Dict[str, List[str]] = {
        "CRITICAL": [
            "quarantine_file",
            "isolate_file",
            "terminate_process",
            "recommend_network_isolation",
            "block_hash",
            "alert_soc",
        ],
        "HIGH": [
            "quarantine_file",
            "isolate_file",
            "terminate_process",
            "block_hash",
            "alert_soc",
        ],
        "MEDIUM": [
            "quarantine_file",
            "block_hash",
            "alert_soc",
        ],
        "LOW": ["alert_soc"],
    }

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.audit_log_path = AUDIT_LOG_PATH
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.actions: List[Dict[str, Any]] = self._load_audit_log()
        self.file_isolations: Dict[str, Dict[str, Any]] = {}
        self.quarantine_records: Dict[str, Dict[str, Any]] = {}
        self.blocked_hashes: List[str] = []

    def build_recommendations(self, threat_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return deterministic recommendations for a detection result."""
        severity = self._derive_severity(threat_context)
        action_types = self.SEVERITY_ACTIONS.get(severity, self.SEVERITY_ACTIONS["LOW"])
        recommendations = []
        for priority, action_type in enumerate(action_types, start=1):
            action = self.ACTIONS[action_type]
            recommendations.append({
                "action_type": action_type,
                "label": action["label"],
                "description": action["description"],
                "mode": action["mode"],
                "priority": priority,
                "severity": severity,
                "safe_mode": True,
                "requires_analyst_approval": action_type in {
                    "terminate_process",
                    "recommend_network_isolation",
                },
            })
        return recommendations

    def execute_action(
        self,
        action_type: str,
        threat_context: Dict[str, Any],
        requested_by: str = "soc-operator",
    ) -> Dict[str, Any]:
        """Simulate or track a single safe response action."""
        if action_type not in self.ACTIONS:
            raise ValueError(f"Unsupported ransomware response action: {action_type}")

        started = time.time()
        now = datetime.now(timezone.utc).isoformat()
        incident_id = self._incident_id(threat_context)
        severity = self._derive_severity(threat_context)
        action = self.ACTIONS[action_type]
        action_id = f"RACT-{uuid.uuid4().hex[:10].upper()}"

        record = {
            "action_id": action_id,
            "incident_id": incident_id,
            "action_type": action_type,
            "label": action["label"],
            "description": action["description"],
            "status": action["mode"],
            "severity": severity,
            "safe_mode": True,
            "requested_by": requested_by,
            "timestamp": now,
            "processing_time_ms": 0,
            "target": self._target_summary(threat_context),
            "timeline_event": self._timeline_message(action_type, threat_context),
        }

        self._track_action_state(action_type, record, threat_context)
        record["processing_time_ms"] = round((time.time() - started) * 1000, 2)
        self.actions.append(record)
        self.actions = self.actions[-1000:]
        self._persist_audit_record(record)

        self.logger.warning(
            "[RANSOMWARE_RESPONSE] %s recorded for incident %s in %s mode",
            action_type,
            incident_id,
            action["mode"],
        )
        return record

    def orchestrate(
        self,
        threat_context: Dict[str, Any],
        action_types: Optional[List[str]] = None,
        requested_by: str = "soc-operator",
    ) -> Dict[str, Any]:
        """Return recommendations and optionally execute selected safe actions."""
        recommendations = self.build_recommendations(threat_context)
        executed = []
        for action_type in action_types or []:
            executed.append(self.execute_action(action_type, threat_context, requested_by))

        return {
            "success": True,
            "incident_id": self._incident_id(threat_context),
            "status": "actions_recorded" if executed else "recommendations_ready",
            "safe_mode": True,
            "recommendations": recommendations,
            "actions": executed,
            "timeline": self.get_timeline(self._incident_id(threat_context)),
        }

    def get_history(
        self,
        incident_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return recent response audit records."""
        records = self.actions
        if incident_id:
            records = [item for item in records if item.get("incident_id") == incident_id]
        return records[-limit:][::-1]

    def get_timeline(self, incident_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return incident response timeline entries."""
        timeline = []
        for item in self.get_history(incident_id=incident_id, limit=limit):
            timeline.append({
                "timestamp": item["timestamp"],
                "action_id": item["action_id"],
                "action_type": item["action_type"],
                "status": item["status"],
                "description": item["timeline_event"],
                "safe_mode": True,
            })
        return timeline[::-1]

    def get_state(self) -> Dict[str, Any]:
        """Return tracked safe response state."""
        return {
            "safe_mode": True,
            "audit_records": len(self.actions),
            "file_isolations": list(self.file_isolations.values()),
            "quarantine_records": list(self.quarantine_records.values()),
            "blocked_hashes": self.blocked_hashes.copy(),
        }

    def _track_action_state(
        self,
        action_type: str,
        record: Dict[str, Any],
        threat_context: Dict[str, Any],
    ) -> None:
        file_path = self._extract_file_path(threat_context)
        sha256 = self._extract_sha256(threat_context)

        if action_type == "quarantine_file":
            key = sha256 or file_path or record["incident_id"]
            self.quarantine_records[key] = {
                "incident_id": record["incident_id"],
                "file_path": file_path,
                "sha256": sha256,
                "status": "quarantine_tracked",
                "timestamp": record["timestamp"],
            }
        elif action_type == "isolate_file":
            key = file_path or sha256 or record["incident_id"]
            self.file_isolations[key] = {
                "incident_id": record["incident_id"],
                "file_path": file_path,
                "sha256": sha256,
                "status": "isolation_tracked",
                "timestamp": record["timestamp"],
            }
        elif action_type == "block_hash" and sha256 and sha256 not in self.blocked_hashes:
            self.blocked_hashes.append(sha256)

    def _persist_audit_record(self, record: Dict[str, Any]) -> None:
        self._write_audit_file()
        if get_collection is None:
            return
        try:
            collection = get_collection("ransomware_response_actions")
            if collection is not None:
                collection.insert_one(record.copy())
        except Exception as exc:
            self.logger.warning("Unable to persist ransomware response action to database: %s", exc)

    def _write_audit_file(self) -> None:
        try:
            with self.audit_log_path.open("w", encoding="utf-8") as handle:
                json.dump(self.actions, handle, indent=2)
        except OSError as exc:
            self.logger.warning("Unable to write ransomware response audit log: %s", exc)

    def _load_audit_log(self) -> List[Dict[str, Any]]:
        if not self.audit_log_path.exists():
            return []
        try:
            with self.audit_log_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                return data[-1000:]
        except (OSError, json.JSONDecodeError):
            return []
        return []

    def _derive_severity(self, threat_context: Dict[str, Any]) -> str:
        severity = threat_context.get("severity") or threat_context.get("risk_level")
        if severity:
            return str(severity).upper()
        try:
            confidence = float(threat_context.get("detection_confidence") or threat_context.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0
        if confidence > 1:
            confidence = confidence / 100
        if confidence >= 0.85:
            return "CRITICAL"
        if confidence >= 0.65:
            return "HIGH"
        if confidence >= 0.4:
            return "MEDIUM"
        return "LOW"

    def _incident_id(self, threat_context: Dict[str, Any]) -> str:
        return str(
            threat_context.get("incident_id")
            or threat_context.get("threat_id")
            or threat_context.get("scan_id")
            or threat_context.get("sample", {}).get("sha256")
            or f"RAN-INC-{uuid.uuid4().hex[:8].upper()}"
        )

    def _target_summary(self, threat_context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source_host": threat_context.get("source_host"),
            "process_name": threat_context.get("process_name"),
            "process_pid": threat_context.get("process_pid"),
            "file_path": self._extract_file_path(threat_context),
            "sha256": self._extract_sha256(threat_context),
        }

    def _extract_file_path(self, threat_context: Dict[str, Any]) -> Optional[str]:
        return (
            threat_context.get("file_path")
            or threat_context.get("binary_path")
            or threat_context.get("sample", {}).get("path")
            or threat_context.get("layers", {}).get("layer2_pe_header", {}).get("binary_path")
        )

    def _extract_sha256(self, threat_context: Dict[str, Any]) -> Optional[str]:
        return (
            threat_context.get("sha256")
            or threat_context.get("sample", {}).get("sha256")
            or threat_context.get("layers", {}).get("layer2_static_executable_analysis", {}).get("sha256")
            or threat_context.get("iocs", {}).get("sha256")
        )

    def _timeline_message(self, action_type: str, threat_context: Dict[str, Any]) -> str:
        if action_type == "terminate_process":
            process = threat_context.get("process_name") or "unknown process"
            pid = threat_context.get("process_pid") or "unknown pid"
            return f"Simulated process termination requested for {process} ({pid})."
        if action_type == "recommend_network_isolation":
            host = threat_context.get("source_host") or "unknown host"
            return f"Network isolation recommended for {host}; no network changes applied."
        if action_type == "quarantine_file":
            return "Quarantine state recorded for the suspect file; file contents were not modified."
        if action_type == "isolate_file":
            return "File isolation state recorded for analyst workflow; file was not moved or deleted."
        if action_type == "block_hash":
            return "SHA256 block recommendation recorded for downstream controls."
        return "SOC alert event recorded for analyst review."


_service_instance: Optional[RansomwareResponseOrchestrationService] = None


def get_ransomware_response_orchestration_service() -> RansomwareResponseOrchestrationService:
    """Return the singleton safe ransomware response orchestration service."""
    global _service_instance
    if _service_instance is None:
        _service_instance = RansomwareResponseOrchestrationService()
    return _service_instance
