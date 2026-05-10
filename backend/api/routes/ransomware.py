"""
Ransomware Detection API Routes
=================================
API endpoints for ransomware command scanning and detection.

Version: 1.0.0 - Orchestrator-based pipeline
Pipeline: Detection → Explainability → Orchestrator → Response
"""

import time
import random
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

# =============================================================================
# Request / Response Models
# =============================================================================

class CommandScanRequest(BaseModel):
    command: str = Field(..., description="Process command or system call to scan")
    command_id: Optional[str] = Field(None, description="Optional command identifier")
    source_host: Optional[str] = Field(None, description="Hostname where command originated")
    process_name: Optional[str] = Field(None, description="Name of the process")
    user: Optional[str] = Field(None, description="User account that ran the command")

class CommandScanBatchRequest(BaseModel):
    commands: List[CommandScanRequest]

class QuickScanRequest(BaseModel):
    command: str = Field(..., min_length=1, description="Command string to analyze")


class FileActivityRequest(BaseModel):
    """File activity event for mass-encryption detection."""
    path: str = Field(..., description="File system path")
    operation: str = Field(..., description="Operation type: create, modify, delete, rename, read")
    extension: str = Field(..., description="File extension")
    process_pid: int = Field(..., description="Process ID")
    process_name: str = Field(..., description="Process executable name")
    source_host: Optional[str] = Field(None, description="Hostname source")


class ThreeLayerDetectionRequest(BaseModel):
    """Request for three-layer ransomware detection."""
    command: Optional[str] = Field(None, description="Process command for Layer 1")
    binary_path: Optional[str] = Field(None, description="Path to executable for Layer 2 PE header analysis")
    file_activities: Optional[List[FileActivityRequest]] = Field(None, description="File activities for Layer 3")
    process_name: Optional[str] = Field(None, description="Process name")
    process_pid: Optional[int] = Field(None, description="Process ID")
    source_host: Optional[str] = Field(None, description="Source host")
    user: Optional[str] = Field(None, description="User account")


# =============================================================================
# Import Services — Orchestrator-based architecture
# =============================================================================

try:
    from ml.ransomware_service import get_ransomware_service
    from ml.pe_service import get_pe_detection_service
    from agents.ransomware_orchestrator_agent import get_ransomware_orchestrator_agent
    from agents.ransomware_detection_agent import get_ransomware_detection_agent
    from agents.ransomware_explainability_agent import get_ransomware_explainability_agent
    from agents.ransomware_response_agent import get_ransomware_response_agent
    from orchestration.encryption_detector import MassEncryptionDetector, FileActivity
except ImportError:
    try:
        from backend.ml.ransomware_service import get_ransomware_service
        from backend.ml.pe_service import get_pe_detection_service
        from backend.agents.ransomware_orchestrator_agent import get_ransomware_orchestrator_agent
        from backend.agents.ransomware_detection_agent import get_ransomware_detection_agent
        from backend.agents.ransomware_explainability_agent import get_ransomware_explainability_agent
        from backend.agents.ransomware_response_agent import get_ransomware_response_agent
        from backend.orchestration.encryption_detector import MassEncryptionDetector, FileActivity
    except ImportError:
        get_ransomware_service = None
        get_pe_detection_service = None
        get_ransomware_orchestrator_agent = None
        get_ransomware_detection_agent = None
        get_ransomware_explainability_agent = None
        get_ransomware_response_agent = None
        MassEncryptionDetector = None
        FileActivity = None


router = APIRouter(prefix="/ransomware", tags=["Ransomware Detection"])

BACKEND_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_BINARY_DIR = (BACKEND_ROOT / "data" / "quarantine").resolve()


def resolve_safe_binary_path(binary_path: str) -> str:
    """Resolve PE analysis paths inside the quarantine directory only."""
    requested_path = Path(binary_path).expanduser()
    if not requested_path.is_absolute():
        requested_path = ALLOWED_BINARY_DIR / requested_path

    resolved_path = requested_path.resolve(strict=False)
    try:
        resolved_path.relative_to(ALLOWED_BINARY_DIR)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="binary_path must point to a file inside backend/data/quarantine",
        )

    if not resolved_path.exists():
        raise HTTPException(status_code=400, detail="binary_path does not exist")
    if not resolved_path.is_file():
        raise HTTPException(status_code=400, detail="binary_path is not a file")

    return str(resolved_path)


# =============================================================================
# Database helpers
# =============================================================================

try:
    from database.connection import get_collection
    USE_DATABASE = True
except ImportError:
    USE_DATABASE = False
    get_collection = None


def save_scan_to_database(scan_data: dict) -> Optional[str]:
    """Save ransomware scan result to database and return scan_id."""
    if not USE_DATABASE or not get_collection:
        return None
    try:
        collection = get_collection("ransomware_scans")
        if collection is not None:
            scan_doc = {
                "scan_id": f"RSCAN-{random.randint(10000, 99999)}",
                "command_preview": scan_data.get("command", "")[:500],
                "source_host": scan_data.get("source_host"),
                "process_name": scan_data.get("process_name"),
                "user": scan_data.get("user"),
                "is_ransomware": scan_data.get("is_ransomware", False),
                "confidence": scan_data.get("confidence", 0),
                "risk_level": scan_data.get("severity", "LOW"),
                "iocs": scan_data.get("iocs", {}),
                "behavior_categories": scan_data.get("behavior_categories", []),
                "processing_time_ms": scan_data.get("processing_time_ms", 0),
                "model_version": "1.0.0",
                "scanned_at": datetime.now(timezone.utc)
            }
            collection.insert_one(scan_doc)
            return scan_doc["scan_id"]
    except Exception as e:
        print(f"Error saving ransomware scan: {e}")
    return None


def save_threat_to_database(threat_data: dict) -> Optional[str]:
    """Save detected ransomware threat to database and return threat_id."""
    if not USE_DATABASE or not get_collection:
        return None
    try:
        collection = get_collection("threats")
        if collection is not None:
            threat_doc = {
                "threat_id": f"RAN-{random.randint(1000, 9999)}",
                "threat_type": "ransomware",
                "severity": threat_data.get("severity", "HIGH"),
                "status": "active",
                "confidence": threat_data.get("confidence", 0),
                "source_host": threat_data.get("source_host"),
                "process_name": threat_data.get("process_name"),
                "user": threat_data.get("user"),
                "command_preview": threat_data.get("command", "")[:200],
                "iocs": threat_data.get("iocs", {}),
                "behavior_categories": threat_data.get("behavior_categories", []),
                "mitre_tactics": threat_data.get("mitre_tactics", []),
                "attack_stage": threat_data.get("attack_stage"),
                "action_taken": threat_data.get("action_taken"),
                "detected_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            collection.insert_one(threat_doc)
            return threat_doc["threat_id"]
    except Exception as e:
        print(f"Error saving ransomware threat: {e}")
    return None


# =============================================================================
# SCAN ENDPOINTS
# =============================================================================

@router.post("/scan")
async def scan_command(request: CommandScanRequest):
    """
    Scan a command through the full ransomware orchestrator pipeline.

    Pipeline: Detection -> Explainability -> Response

    Returns comprehensive analysis with:
    - Detection results (is_ransomware, confidence, risk_score, severity)
    - Explainability (IOCs, behavior categories, MITRE ATT&CK, explanation)
    - Response actions (if ransomware detected)
    - Incident tracking (incident_id for follow-up)
    """
    start_time = time.time()

    if not get_ransomware_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Ransomware orchestrator not available")

    try:
        orchestrator = get_ransomware_orchestrator_agent()
        result = orchestrator.process_command(
            request.command,
            request.command_id,
            request.source_host
        )

        if request.source_host:
            result['source_host'] = request.source_host
        if request.process_name:
            result['process_name'] = request.process_name
        if request.user:
            result['user'] = request.user

        processing_time = (time.time() - start_time) * 1000
        result['processing_time_ms'] = round(processing_time, 2)

        detection = result.get('pipeline_results', {}).get('detection', {})
        explain = result.get('pipeline_results', {}).get('explainability', {})
        is_ransomware = detection.get('is_ransomware', False)

        scan_data = {
            "command": request.command,
            "source_host": request.source_host,
            "process_name": request.process_name,
            "user": request.user,
            "is_ransomware": is_ransomware,
            "confidence": detection.get('confidence', 0),
            "severity": result.get('severity', 'LOW'),
            "processing_time_ms": result['processing_time_ms'],
            "iocs": explain.get('iocs', {}),
            "behavior_categories": explain.get('behavior_categories', [])
        }
        scan_id = save_scan_to_database(scan_data)
        if scan_id:
            result['scan_id'] = scan_id

        if is_ransomware:
            threat_data = {
                "severity": result.get('severity', 'HIGH'),
                "confidence": detection.get('confidence', 0),
                "source_host": request.source_host,
                "process_name": request.process_name,
                "user": request.user,
                "command": request.command,
                "iocs": explain.get('iocs', {}),
                "behavior_categories": explain.get('behavior_categories', []),
                "mitre_tactics": explain.get('mitre_tactics', []),
                "attack_stage": explain.get('attack_stage'),
                "action_taken": result.get('pipeline_results', {}).get(
                    'response', {}
                ).get('actions_executed', [None])[0]
            }
            threat_id = save_threat_to_database(threat_data)
            if threat_id:
                result['threat_id'] = threat_id

        return {"success": True, "result": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/batch")
async def scan_commands_batch(request: CommandScanBatchRequest):
    """
    Scan multiple commands in batch through the orchestrator pipeline.
    """
    start_time = time.time()

    if not get_ransomware_orchestrator_agent:
        raise HTTPException(status_code=503, detail="Ransomware orchestrator not available")

    try:
        orchestrator = get_ransomware_orchestrator_agent()
        results = []

        for cmd_req in request.commands:
            result = orchestrator.process_command(
                cmd_req.command,
                cmd_req.command_id,
                cmd_req.source_host
            )
            if cmd_req.source_host:
                result['source_host'] = cmd_req.source_host
            if cmd_req.process_name:
                result['process_name'] = cmd_req.process_name
            results.append(result)

        processing_time = (time.time() - start_time) * 1000

        ransomware_count = sum(
            1 for r in results
            if r.get('pipeline_results', {}).get('detection', {}).get('is_ransomware')
        )
        critical_count = sum(1 for r in results if r.get('severity') == 'CRITICAL')
        high_count = sum(1 for r in results if r.get('severity') == 'HIGH')
        medium_count = sum(1 for r in results if r.get('severity') == 'MEDIUM')

        return {
            "success": True,
            "summary": {
                "total_scanned": len(results),
                "ransomware_detected": ransomware_count,
                "safe_detected": len(results) - ransomware_count,
                "critical_severity": critical_count,
                "high_severity": high_count,
                "medium_severity": medium_count,
                "low_severity": len(results) - critical_count - high_count - medium_count
            },
            "results": results,
            "processing_time_ms": round(processing_time, 2)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/quick")
async def quick_scan(request: QuickScanRequest):
    """Quick detection-only scan without full pipeline."""
    if not get_ransomware_detection_agent:
        raise HTTPException(status_code=503, detail="Detection agent not available")

    try:
        detection_agent = get_ransomware_detection_agent()
        result = detection_agent.analyze(request.command)

        return {
            "success": True,
            "result": {
                "is_ransomware": result.get('is_ransomware'),
                "confidence": result.get('confidence'),
                "risk_score": result.get('risk_score'),
                "severity": result.get('severity'),
                "model_used": result.get('model_used')
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/explain")
async def scan_with_explanation(request: CommandScanRequest):
    """Scan with detailed explainability output. No response actions."""
    if not get_ransomware_detection_agent or not get_ransomware_explainability_agent:
        raise HTTPException(status_code=503, detail="Agent services not available")

    try:
        detection_agent = get_ransomware_detection_agent()
        detection_result = detection_agent.analyze(request.command, request.command_id)

        explainability_agent = get_ransomware_explainability_agent()
        explain_result = explainability_agent.analyze(
            request.command,
            detection_result['command_id'],
            detection_result
        )

        return {
            "success": True,
            "detection": detection_result,
            "explainability": explain_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# LIST / HISTORY ENDPOINTS
# =============================================================================

@router.get("/list")
async def list_ransomware_threats(
    limit: int = Query(50, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    """List all detected ransomware threats with optional filtering."""
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("threats")
            if collection is not None:
                query = {"threat_type": "ransomware"}
                if severity:
                    query["severity"] = severity.upper()
                if status:
                    query["status"] = status.lower()

                cursor = collection.find(query).sort("detected_at", -1).limit(limit)
                threats = []
                for threat in cursor:
                    threats.append({
                        "id": threat.get("threat_id", str(threat.get("_id"))),
                        "type": "Ransomware",
                        "severity": threat.get("severity", "HIGH"),
                        "confidence": threat.get("confidence", 0),
                        "status": threat.get("status", "active").title(),
                        "source_host": threat.get("source_host", "unknown"),
                        "process_name": threat.get("process_name", "unknown"),
                        "attack_stage": threat.get("attack_stage", "unknown"),
                        "behavior_categories": threat.get("behavior_categories", []),
                        "detected_at": threat.get("detected_at").isoformat()
                            if threat.get("detected_at") else datetime.now(timezone.utc).isoformat(),
                        "description": threat.get("command_preview") or "Ransomware command detected"
                    })

                total = collection.count_documents(query)
                return {"success": True, "threats": threats, "total": total, "data_source": "database"}
        except Exception as e:
            print(f"Database error: {e}")

    # Fallback mock
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    stages = ["impact", "lateral_movement", "defense_evasion", "persistence"]
    threats = []
    for i in range(min(limit, 20)):
        sev = severity or random.choice(severities)
        threats.append({
            "id": f"RAN-{1000 + i}",
            "type": "Ransomware",
            "severity": sev,
            "confidence": round(random.uniform(75, 99), 1),
            "status": "Active",
            "source_host": f"WORKSTATION-{i:03d}",
            "process_name": random.choice(["cmd.exe", "powershell.exe", "wscript.exe"]),
            "attack_stage": random.choice(stages),
            "behavior_categories": ["shadow_deletion", "boot_modification"],
            "detected_at": (datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 72))).isoformat(),
            "description": "Ransomware behavior detected in process command"
        })

    return {"success": True, "threats": threats, "total": len(threats), "data_source": "mock"}


@router.get("/scans/list")
async def list_ransomware_scans(
    limit: int = Query(50, le=200),
    is_ransomware: Optional[bool] = None
):
    """List all ransomware scan history."""
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("ransomware_scans")
            if collection is not None:
                query = {}
                if is_ransomware is not None:
                    query["is_ransomware"] = is_ransomware

                cursor = collection.find(query).sort("scanned_at", -1).limit(limit)
                scans = []
                for scan in cursor:
                    scans.append({
                        "id": scan.get("scan_id", str(scan.get("_id"))),
                        "command_preview": scan.get("command_preview", "")[:100],
                        "source_host": scan.get("source_host", "unknown"),
                        "process_name": scan.get("process_name", "unknown"),
                        "prediction": "Ransomware" if scan.get("is_ransomware") else "Safe",
                        "confidence": round(
                            scan.get("confidence", 0) * 100
                            if scan.get("confidence", 0) <= 1
                            else scan.get("confidence", 0), 1
                        ),
                        "severity": scan.get("risk_level", "LOW"),
                        "behavior_categories": scan.get("behavior_categories", []),
                        "scanned_at": scan.get("scanned_at").isoformat()
                            if scan.get("scanned_at") else datetime.now(timezone.utc).isoformat()
                    })

                total = collection.count_documents(query)
                return {"success": True, "scans": scans, "total": total, "data_source": "database"}
        except Exception as e:
            print(f"Database error fetching scans: {e}")

    # Fallback mock
    mock_scans = []
    for i in range(min(limit, 10)):
        is_ran = random.random() > 0.5
        mock_scans.append({
            "id": f"RSCAN-{10000 + i}",
            "command_preview": "vssadmin delete shadows /all" if is_ran else "notepad.exe doc.txt",
            "source_host": f"WORKSTATION-{i:03d}",
            "process_name": "cmd.exe" if is_ran else "explorer.exe",
            "prediction": "Ransomware" if is_ran else "Safe",
            "confidence": round(random.uniform(80, 99) if is_ran else random.uniform(5, 30), 1),
            "severity": random.choice(["CRITICAL", "HIGH"]) if is_ran else "LOW",
            "behavior_categories": ["shadow_deletion"] if is_ran else [],
            "scanned_at": (datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48))).isoformat()
        })

    return {"success": True, "scans": mock_scans, "total": len(mock_scans), "data_source": "mock"}


@router.get("/alerts")
async def get_ransomware_alerts(limit: int = Query(50, le=200)):
    """Get ransomware alerts logged to MongoDB."""
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("alerts")
            if collection is not None:
                cursor = collection.find({"type": "ransomware"}).sort("timestamp", -1).limit(limit)
                alerts = []
                for alert in cursor:
                    alerts.append({
                        "id": str(alert.get("_id")),
                        "incident_id": alert.get("incident_id"),
                        "severity": alert.get("severity", "HIGH"),
                        "risk_score": alert.get("risk_score", 0),
                        "source_host": alert.get("source_host", "unknown"),
                        "behaviors": alert.get("behaviors", []),
                        "timestamp": alert.get("timestamp")
                    })
                return {"success": True, "alerts": alerts, "total": len(alerts), "data_source": "database"}
        except Exception as e:
            print(f"Database error fetching alerts: {e}")

    return {"success": True, "alerts": [], "total": 0, "data_source": "unavailable"}


@router.get("/blocked-hashes")
async def get_blocked_hashes():
    """Get list of blocked file hashes."""
    if not get_ransomware_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    response = get_ransomware_response_agent()
    hashes = response.get_blocked_hashes()
    return {"success": True, "blocked_hashes": hashes, "count": len(hashes)}


@router.get("/isolated-hosts")
async def get_isolated_hosts():
    """Get list of isolated hosts."""
    if not get_ransomware_response_agent:
        raise HTTPException(status_code=503, detail="Response agent not available")
    response = get_ransomware_response_agent()
    hosts = response.get_isolated_hosts()
    return {"success": True, "isolated_hosts": hosts, "count": len(hosts)}


@router.get("/stats")
async def get_ransomware_stats():
    """Get comprehensive ransomware pipeline statistics."""
    stats = {
        "orchestrator": {},
        "detection": {},
        "explainability": {},
        "response": {},
        "ml_service": {}
    }
    try:
        if get_ransomware_orchestrator_agent:
            stats["orchestrator"] = get_ransomware_orchestrator_agent().get_stats()
        if get_ransomware_detection_agent:
            stats["detection"] = get_ransomware_detection_agent().get_stats()
        if get_ransomware_explainability_agent:
            stats["explainability"] = get_ransomware_explainability_agent().get_stats()
        if get_ransomware_response_agent:
            stats["response"] = get_ransomware_response_agent().get_stats()
        if get_ransomware_service:
            stats["ml_service"] = get_ransomware_service().get_stats()

        return {"success": True, "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model/info")
async def get_model_info():
    """Get information about the loaded ransomware ML model."""
    try:
        if not get_ransomware_service:
            raise HTTPException(status_code=503, detail="Ransomware service not available")
        service = get_ransomware_service()
        return {"success": True, "model_info": service.get_model_info()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def ransomware_health():
    """Health check for the ransomware detection module."""
    try:
        model_loaded = False
        if get_ransomware_detection_agent:
            agent = get_ransomware_detection_agent()
            model_loaded = agent.is_model_loaded()

        orchestrator_ready = get_ransomware_orchestrator_agent is not None
        status = "healthy" if (model_loaded and orchestrator_ready) else (
            "degraded" if orchestrator_ready else "unavailable"
        )

        return {
            "success": True,
            "status": status,
            "model_loaded": model_loaded,
            "orchestrator_ready": orchestrator_ready,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "status": "unavailable",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@router.get("/layers/status")
async def get_detection_layers_status():
    """Get status for command, PE-header, and mass-encryption detection layers."""
    status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layers": {
            "layer1_command_behavior": {
                "name": "Runtime Command Behavior Detection",
                "model": "TF-IDF + Random Forest",
                "status": "ready" if get_ransomware_detection_agent else "unavailable",
            },
            "layer2_pe_header": {
                "name": "Static PE Header Binary Detection",
                "model": "Gradient Boosting Classifier",
                "status": "ready" if get_pe_detection_service else "unavailable",
                "filtering": "ransomware-only (no generic malware)",
            },
            "layer3_mass_encryption": {
                "name": "Mass-Encryption Orchestrator",
                "model": "Rule-based threshold analysis",
                "status": "ready" if MassEncryptionDetector else "unavailable",
                "features": [
                    "File modification rate analysis",
                    "Extension change detection",
                    "Known ransomware extension matching",
                    "Shadow copy context analysis",
                    "Backup-safe filtering",
                ],
            },
        },
    }
    status["overall_status"] = (
        "operational"
        if get_ransomware_detection_agent and MassEncryptionDetector
        else "degraded"
    )
    return {"success": True, "status": status}


@router.get("/{threat_id}")
async def get_ransomware_threat(threat_id: str):
    """Get detailed information about a specific ransomware threat."""
    if USE_DATABASE and get_collection:
        try:
            collection = get_collection("threats")
            if collection is not None:
                threat = collection.find_one({"threat_id": threat_id})
                if threat:
                    return {
                        "success": True,
                        "threat": {
                            "id": threat.get("threat_id", str(threat.get("_id"))),
                            "type": "Ransomware",
                            "severity": threat.get("severity", "HIGH"),
                            "confidence": threat.get("confidence", 0),
                            "status": threat.get("status", "active").title(),
                            "source_host": threat.get("source_host", "unknown"),
                            "process_name": threat.get("process_name", "unknown"),
                            "user": threat.get("user", "unknown"),
                            "attack_stage": threat.get("attack_stage"),
                            "behavior_categories": threat.get("behavior_categories", []),
                            "mitre_tactics": threat.get("mitre_tactics", []),
                            "iocs": threat.get("iocs", {}),
                            "command_preview": threat.get("command_preview", ""),
                            "action_taken": threat.get("action_taken"),
                            "detected_at": threat.get("detected_at").isoformat()
                                if threat.get("detected_at") else None,
                            "recommendations": [
                                "Isolate the affected host immediately",
                                "Check for encrypted files on the system",
                                "Review process tree for parent/child processes",
                                "Capture memory dump before remediation",
                                "Restore from clean backup if encryption confirmed"
                            ]
                        },
                        "data_source": "database"
                    }
        except Exception as e:
            print(f"Database error: {e}")

    # Fallback mock
    return {
        "success": True,
        "threat": {
            "id": threat_id,
            "type": "Ransomware",
            "severity": "CRITICAL",
            "confidence": 97.3,
            "status": "Active",
            "source_host": "WORKSTATION-042",
            "process_name": "cmd.exe",
            "user": "user@domain.com",
            "attack_stage": "impact",
            "behavior_categories": ["shadow_deletion", "boot_modification"],
            "mitre_tactics": ["T1490: Inhibit System Recovery", "T1542: Pre-OS Boot"],
            "command_preview": "vssadmin delete shadows /all /quiet",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "recommendations": [
                "Isolate the affected host immediately",
                "Check for encrypted files on the system",
                "Review process tree for parent/child processes",
                "Capture memory dump before remediation",
                "Restore from clean backup if encryption confirmed"
            ]
        },
        "data_source": "mock"
    }


@router.post("/detect-layers")
async def detect_three_layers(request: ThreeLayerDetectionRequest):
    """Run command, PE-header, and file-activity ransomware detection layers."""
    start_time = time.time()
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layers": {},
        "overall_verdict": "BENIGN",
        "detection_confidence": 0.0,
        "source_host": request.source_host,
        "process_name": request.process_name,
        "process_pid": request.process_pid,
        "user": request.user,
    }

    try:
        if request.command and get_ransomware_detection_agent:
            detection_agent = get_ransomware_detection_agent()
            layer_result = detection_agent.analyze(request.command)
            result["layers"]["layer1_command_behavior"] = {
                "status": "success",
                "is_ransomware": layer_result.get("is_ransomware", False),
                "confidence": float(layer_result.get("confidence", 0)),
                "risk_score": float(layer_result.get("risk_score", 0)),
                "severity": layer_result.get("severity", "LOW"),
                "detected_patterns": layer_result.get("behavior_categories", []),
                "iocs": layer_result.get("iocs", {}),
            }

        if request.binary_path and get_pe_detection_service:
            pe_service = get_pe_detection_service()
            safe_binary_path = resolve_safe_binary_path(request.binary_path)
            pe_result = pe_service.predict(safe_binary_path)
            result["layers"]["layer2_pe_header"] = {
                "status": "success" if not pe_result.get("error") else "error",
                "is_ransomware": pe_result.get("is_ransomware", False),
                "confidence": float(pe_result.get("confidence", 0.0)),
                "model": "Gradient Boosting Classifier (ransomware-only filtered)",
                "binary_path": safe_binary_path,
                "features_extracted": pe_result.get("features_extracted", 0),
            }
            if pe_result.get("error"):
                result["layers"]["layer2_pe_header"]["error"] = pe_result["error"]
        else:
            result["layers"]["layer2_pe_header"] = {
                "status": "ready",
                "note": "Layer 2 requires binary_path parameter for PE header extraction",
                "model": "Gradient Boosting Classifier (ransomware-only filtered)",
                "confidence": 0.0,
            }

        if request.file_activities and MassEncryptionDetector and FileActivity:
            detector = MassEncryptionDetector()
            if request.command:
                detector.add_command(request.command)

            for activity in request.file_activities:
                detector.add_activity(FileActivity(
                    timestamp=time.time(),
                    path=activity.path,
                    operation=activity.operation,
                    extension=activity.extension,
                    process_pid=activity.process_pid,
                    process_name=activity.process_name,
                ))

            alert = detector.detect()
            if alert:
                result["layers"]["layer3_mass_encryption"] = {
                    "status": "threat_detected",
                    "threat_level": alert.threat_level,
                    "confidence": float(alert.confidence),
                    "indicators": alert.detected_indicators,
                    "affected_files": alert.affected_files_count,
                    "process_name": alert.process_name,
                    "process_pid": alert.process_pid,
                    "recommended_action": alert.recommended_action,
                    "is_backup_safe": alert.backup_safe,
                }
            else:
                result["layers"]["layer3_mass_encryption"] = {
                    "status": "monitoring",
                    "confidence": 0.0,
                    "note": "File activity tracked but no threats detected",
                }

        layer1 = result["layers"].get("layer1_command_behavior", {})
        layer2 = result["layers"].get("layer2_pe_header", {})
        layer3 = result["layers"].get("layer3_mass_encryption", {})

        active_layers = []
        confidences = []
        if layer1.get("is_ransomware"):
            active_layers.append("Layer 1: Command Behavior")
            confidences.append(float(layer1.get("confidence", 0)))
        if layer2.get("status") == "success" and layer2.get("is_ransomware"):
            active_layers.append("Layer 2: PE Header")
            confidences.append(float(layer2.get("confidence", 0)))
        if layer3.get("status") == "threat_detected":
            active_layers.append("Layer 3: Mass-Encryption")
            confidences.append(float(layer3.get("confidence", 0)))

        if len(active_layers) >= 2:
            result["overall_verdict"] = "RANSOMWARE_DETECTED"
            result["detection_confidence"] = min(1.0, sum(confidences) / len(confidences))
        elif active_layers:
            result["overall_verdict"] = "SUSPICIOUS"
            result["detection_confidence"] = max(confidences)
        result["triggered_layers"] = active_layers

        if result["overall_verdict"] == "RANSOMWARE_DETECTED":
            threat_id = save_threat_to_database({
                "severity": "CRITICAL" if result["detection_confidence"] > 0.8 else "HIGH",
                "confidence": result["detection_confidence"],
                "source_host": request.source_host,
                "process_name": request.process_name,
                "user": request.user,
                "command": request.command or "Layer 3: File activity",
                "behavior_categories": active_layers,
                "action_taken": "SOAR response recommended",
            })
            if threat_id:
                result["threat_id"] = threat_id

        result["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)
        return {"success": True, "result": result}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"3-layer detection error: {exc}")


@router.post("/monitor-encryption")
async def monitor_file_encryption(file_activities: List[FileActivityRequest]):
    """Monitor file activity for rapid modification and mass-encryption patterns."""
    if not MassEncryptionDetector or not FileActivity:
        raise HTTPException(status_code=503, detail="Encryption detector not available")

    try:
        detector = MassEncryptionDetector()
        for activity in file_activities:
            detector.add_activity(FileActivity(
                timestamp=time.time(),
                path=activity.path,
                operation=activity.operation,
                extension=activity.extension,
                process_pid=activity.process_pid,
                process_name=activity.process_name,
            ))

        alert = detector.detect()
        if not alert:
            return {
                "success": True,
                "alert_raised": False,
                "message": "File activity monitored - no threats detected",
                "files_tracked": len(file_activities),
            }

        return {
            "success": True,
            "alert_raised": True,
            "alert": {
                "threat_level": alert.threat_level,
                "confidence": float(alert.confidence),
                "detected_indicators": alert.detected_indicators,
                "affected_files_count": alert.affected_files_count,
                "process_name": alert.process_name,
                "process_pid": alert.process_pid,
                "detection_method": alert.detection_method,
                "recommended_action": alert.recommended_action,
                "is_backup_safe": alert.backup_safe,
                "timestamp": alert.timestamp,
            },
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Encryption monitoring error: {exc}")
