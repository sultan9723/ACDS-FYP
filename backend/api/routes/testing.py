"""
Automated Testing API Routes
=============================
API endpoints for running automated tests using sample phishing data.
"""

import time
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

# Import test data loader
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from tests.test_data_loader import get_test_data_loader
except ImportError:
    from backend.tests.test_data_loader import get_test_data_loader

# Import services
try:
    from ml.phishing_service import get_phishing_service
    from agents.response_agent import ResponseAgent
except ImportError:
    try:
        from backend.ml.phishing_service import get_phishing_service
        from backend.agents.response_agent import ResponseAgent
    except ImportError:
        # If all imports fail, set to None - will use fallback
        get_phishing_service = None
        ResponseAgent = None
        print("Warning: Could not import phishing service or response agent")

router = APIRouter(prefix="/testing", tags=["Automated Testing"])

# In-memory storage for test sessions and logs
test_sessions = {}
test_logs = []
generated_reports = []

# Initialize services
response_agent = ResponseAgent() if ResponseAgent else None


class TestSession(BaseModel):
    session_id: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    total_samples: int
    processed: int
    results: List[dict] = []
    summary: Optional[dict] = None


# ==================== TEST DATA ENDPOINTS ====================

@router.get("/samples")
async def get_test_samples(
    sample_type: str = Query("mixed", description="Type: phishing, legitimate, or mixed"),
    count: int = Query(5, le=20)
):
    """
    Get sample emails for testing.
    
    Returns phishing, legitimate, or mixed email samples from the test dataset.
    """
    loader = get_test_data_loader()
    
    if sample_type == "phishing":
        samples = loader.get_random_phishing(count)
    elif sample_type == "legitimate":
        samples = loader.get_random_legitimate(count)
    else:
        samples = loader.get_mixed_batch(count)
    
    return {
        "success": True,
        "sample_type": sample_type,
        "count": len(samples),
        "samples": samples
    }


@router.get("/samples/all")
async def get_all_samples():
    """Get all available test samples."""
    loader = get_test_data_loader()
    return {
        "success": True,
        **loader.get_all_samples()
    }


# ==================== AUTOMATED TEST ENDPOINTS ====================

@router.post("/run")
async def run_automated_test(
    background_tasks: BackgroundTasks,
    count: int = Query(10, le=50, description="Number of emails to test"),
    include_response: bool = Query(True, description="Include threat response actions")
):
    """
    Run an automated test session.
    
    Scans a batch of test emails and records results, logs, and generates a report.
    """
    session_id = str(uuid.uuid4())[:8]
    loader = get_test_data_loader()
    
    # Create test session
    session = {
        "session_id": session_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "total_samples": count,
        "processed": 0,
        "results": [],
        "logs": [],
        "threats_detected": [],
        "actions_taken": [],
        "summary": None
    }
    test_sessions[session_id] = session
    
    # Get mixed batch of samples
    samples = loader.get_mixed_batch(count)
    
    # Process each sample
    for i, sample in enumerate(samples):
        start_time = time.time()
        
        try:
            # Run detection
            service = get_phishing_service()
            prediction = service.predict(sample["content"])
            
            # Add metadata
            prediction["sender"] = sample.get("sender")
            prediction["subject"] = sample.get("subject")
            
            # Record result
            result = loader.record_test_result(sample, prediction)
            result["sample_id"] = i + 1
            result["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)
            
            session["results"].append(result)
            
            # Log the scan
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "event": "email_scanned",
                "sample_id": i + 1,
                "subject": sample.get("subject", "")[:50],
                "is_phishing_detected": prediction.get("is_phishing"),
                "confidence": prediction.get("confidence"),
                "severity": prediction.get("severity"),
                "correct_prediction": result["correct"]
            }
            session["logs"].append(log_entry)
            test_logs.append(log_entry)
            
            # If threat detected and response requested
            if prediction.get("is_phishing") and include_response:
                threat_data = {
                    "id": f"THR-{session_id}-{i+1}",
                    "type": "Phishing",
                    "severity": prediction.get("severity", "HIGH"),
                    "confidence": prediction.get("confidence"),
                    "sender": sample.get("sender"),
                    "subject": sample.get("subject"),
                    "detected_at": datetime.now(timezone.utc).isoformat()
                }
                session["threats_detected"].append(threat_data)
                
                # Execute response actions
                if response_agent:
                    response_result = response_agent.respond(prediction)
                    action = {
                        "threat_id": threat_data["id"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "actions": response_result.get("actions_taken", []),
                        "success": response_result.get("success", False)
                    }
                    session["actions_taken"].append(action)
                    
                    # Log response action
                    action_log = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "session_id": session_id,
                        "event": "threat_response",
                        "threat_id": threat_data["id"],
                        "actions": response_result.get("actions_taken", []),
                        "status": "completed" if response_result.get("success") else "failed"
                    }
                    session["logs"].append(action_log)
                    test_logs.append(action_log)
            
            session["processed"] = i + 1
            
        except Exception as e:
            error_log = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "event": "error",
                "sample_id": i + 1,
                "error": str(e)
            }
            session["logs"].append(error_log)
            test_logs.append(error_log)
    
    # Generate summary
    session["summary"] = loader.get_test_summary()
    session["status"] = "completed"
    session["completed_at"] = datetime.now(timezone.utc).isoformat()
    
    # Generate report
    report = generate_test_report(session)
    generated_reports.append(report)
    session["report_id"] = report["report_id"]
    
    # Log completion
    completion_log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "event": "test_completed",
        "total_processed": session["processed"],
        "accuracy": session["summary"].get("accuracy", 0),
        "threats_found": len(session["threats_detected"])
    }
    session["logs"].append(completion_log)
    test_logs.append(completion_log)
    
    return {
        "success": True,
        "session_id": session_id,
        "status": "completed",
        "summary": session["summary"],
        "threats_detected": len(session["threats_detected"]),
        "actions_taken": len(session["actions_taken"]),
        "report_id": report["report_id"]
    }


@router.get("/session/{session_id}")
async def get_test_session(session_id: str):
    """Get details of a specific test session."""
    if session_id not in test_sessions:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return {
        "success": True,
        "session": test_sessions[session_id]
    }


@router.get("/sessions")
async def list_test_sessions(limit: int = Query(10, le=50)):
    """List all test sessions."""
    sessions = list(test_sessions.values())[-limit:]
    return {
        "success": True,
        "sessions": sessions,
        "total": len(test_sessions)
    }


# ==================== LOGS ENDPOINTS ====================

@router.get("/logs")
async def get_test_logs(
    session_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(50, le=200)
):
    """
    Get test logs.
    
    Filter by session_id or event_type (email_scanned, threat_response, error, test_completed).
    """
    logs = test_logs.copy()
    
    if session_id:
        logs = [l for l in logs if l.get("session_id") == session_id]
    
    if event_type:
        logs = [l for l in logs if l.get("event") == event_type]
    
    return {
        "success": True,
        "logs": logs[-limit:],
        "total": len(logs)
    }


@router.delete("/logs")
async def clear_test_logs():
    """Clear all test logs."""
    global test_logs
    count = len(test_logs)
    test_logs = []
    return {
        "success": True,
        "message": f"Cleared {count} log entries"
    }


# ==================== REPORTS ENDPOINTS ====================

def generate_test_report(session: dict) -> dict:
    """Generate a detailed test report."""
    report_id = f"RPT-{session['session_id']}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    summary = session.get("summary", {})
    confusion = summary.get("confusion_matrix", {})
    
    report = {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session["session_id"],
        "report_type": "automated_test",
        "title": f"Phishing Detection Test Report - Session {session['session_id']}",
        
        "executive_summary": {
            "test_date": session.get("started_at"),
            "total_emails_tested": session.get("total_samples"),
            "threats_detected": len(session.get("threats_detected", [])),
            "accuracy": f"{summary.get('accuracy', 0) * 100:.1f}%",
            "precision": f"{summary.get('precision', 0) * 100:.1f}%",
            "recall": f"{summary.get('recall', 0) * 100:.1f}%",
            "f1_score": f"{summary.get('f1_score', 0) * 100:.1f}%",
        },
        
        "performance_metrics": {
            "confusion_matrix": confusion,
            "true_positives": confusion.get("true_positives", 0),
            "false_positives": confusion.get("false_positives", 0),
            "false_negatives": confusion.get("false_negatives", 0),
            "true_negatives": confusion.get("true_negatives", 0),
        },
        
        "threat_analysis": {
            "total_threats": len(session.get("threats_detected", [])),
            "severity_breakdown": categorize_by_severity(session.get("threats_detected", [])),
            "threats": session.get("threats_detected", [])[:10]  # Top 10
        },
        
        "response_actions": {
            "total_actions": len(session.get("actions_taken", [])),
            "actions": session.get("actions_taken", [])
        },
        
        "detailed_results": session.get("results", [])[:20],  # First 20
        
        "recommendations": generate_recommendations(summary),
        
        "logs_summary": {
            "total_logs": len(session.get("logs", [])),
            "errors": len([l for l in session.get("logs", []) if l.get("event") == "error"])
        }
    }
    
    return report


def categorize_by_severity(threats: List[dict]) -> dict:
    """Categorize threats by severity level."""
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for threat in threats:
        sev = threat.get("severity", "MEDIUM")
        if sev in severity_count:
            severity_count[sev] += 1
    return severity_count


def generate_recommendations(summary: dict) -> List[str]:
    """Generate recommendations based on test results."""
    recommendations = []
    
    accuracy = summary.get("accuracy", 0)
    precision = summary.get("precision", 0)
    recall = summary.get("recall", 0)
    
    if accuracy < 0.9:
        recommendations.append("Model accuracy is below 90%. Consider retraining with more diverse samples.")
    
    if precision < 0.85:
        recommendations.append("High false positive rate detected. Review detection thresholds.")
    
    if recall < 0.9:
        recommendations.append("Some phishing emails are being missed. Consider lowering detection threshold.")
    
    if accuracy >= 0.95:
        recommendations.append("Model is performing excellently. Continue monitoring for drift.")
    
    recommendations.append("Regular testing with fresh samples is recommended.")
    recommendations.append("Review flagged emails periodically to improve model accuracy.")
    
    return recommendations


@router.get("/reports")
async def list_reports(limit: int = Query(10, le=50)):
    """List all generated test reports."""
    return {
        "success": True,
        "reports": generated_reports[-limit:],
        "total": len(generated_reports)
    }


@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    """Get a specific test report."""
    report = next((r for r in generated_reports if r["report_id"] == report_id), None)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "success": True,
        "report": report
    }


# ==================== QUICK TEST ENDPOINTS ====================

@router.post("/quick-scan")
async def quick_scan_sample(
    sample_type: str = Query("phishing", description="phishing or legitimate")
):
    """
    Quick test: Scan a single random sample and return results.
    
    Useful for quick verification that the system is working.
    """
    loader = get_test_data_loader()
    
    if sample_type == "phishing":
        samples = loader.get_random_phishing(1)
    else:
        samples = loader.get_random_legitimate(1)
    
    sample = samples[0]
    
    try:
        service = get_phishing_service()
        prediction = service.predict(sample["content"])
        
        result = {
            "sample": {
                "subject": sample.get("subject"),
                "sender": sample.get("sender"),
                "content_preview": sample.get("content", "")[:200] + "...",
                "actual_label": "PHISHING" if sample.get("is_phishing") else "LEGITIMATE",
                "indicators": sample.get("indicators", [])
            },
            "prediction": {
                "is_phishing": prediction.get("is_phishing"),
                "predicted_label": "PHISHING" if prediction.get("is_phishing") else "LEGITIMATE",
                "confidence": prediction.get("confidence"),
                "severity": prediction.get("severity"),
            },
            "correct": sample.get("is_phishing") == prediction.get("is_phishing"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Log this quick test
        test_logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": "quick-scan",
            "event": "quick_scan",
            "subject": sample.get("subject", "")[:50],
            "correct": result["correct"]
        })
        
        return {
            "success": True,
            **result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_testing_status():
    """Get overall testing system status."""
    loader = get_test_data_loader()
    all_samples = loader.get_all_samples()
    summary = loader.get_test_summary()
    
    return {
        "success": True,
        "status": "operational",
        "available_samples": {
            "phishing": all_samples["total_phishing"],
            "legitimate": all_samples["total_legitimate"],
            "total": all_samples["total_phishing"] + all_samples["total_legitimate"]
        },
        "test_sessions_run": len(test_sessions),
        "total_logs": len(test_logs),
        "reports_generated": len(generated_reports),
        "cumulative_results": summary if summary.get("total_tests", 0) > 0 else None
    }


@router.post("/reset")
async def reset_testing_system():
    """Reset all test data, logs, and reports."""
    global test_sessions, test_logs, generated_reports
    
    loader = get_test_data_loader()
    loader.clear_results()
    
    test_sessions = {}
    test_logs = []
    generated_reports = []
    
    return {
        "success": True,
        "message": "Testing system reset successfully"
    }
