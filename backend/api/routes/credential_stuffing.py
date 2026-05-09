"""
Credential Stuffing Detection API Routes
========================================
Phase 1 rule-based endpoints for suspicious login behavior.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

try:
    from services.credential_stuffing_service import get_credential_stuffing_service
except ImportError:
    from backend.services.credential_stuffing_service import get_credential_stuffing_service


router = APIRouter(prefix="/credential-stuffing", tags=["Credential Stuffing Detection"])


class LoginEventRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Local account username involved in the login event")
    ip_address: str = Field(..., min_length=1, description="Source IP address observed by ACDS")
    success: bool = Field(default=False, description="Whether the login succeeded")
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp; defaults to current UTC time")
    user_agent: Optional[str] = Field(default=None, description="Observed user agent")
    country: Optional[str] = Field(default=None, description="Observed country or geo label")


class AnalyzeRequest(BaseModel):
    events: List[LoginEventRequest] = Field(..., min_length=1, description="One or more login events to analyze")


class FeedbackRequest(BaseModel):
    alert_id: str = Field(..., min_length=1)
    feedback: str = Field(..., description="true_positive, false_positive, or needs_review")
    analyst: Optional[str] = None
    notes: Optional[str] = None


class SimulateAttackRequest(BaseModel):
    source_ip: str = Field(default="198.51.100.25", min_length=1)
    username_prefix: str = Field(default="demo_user", min_length=1)
    count: int = Field(default=12, ge=1, le=50)


@router.get("/health")
async def credential_stuffing_health():
    """Return module health and storage status."""
    try:
        service = get_credential_stuffing_service()
        return service.health()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/login-event")
async def submit_login_event(request: LoginEventRequest):
    """Store a login event, analyze recent behavior, and return the detection result."""
    try:
        service = get_credential_stuffing_service()
        return service.process_login_event(request.dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_login_events(request: AnalyzeRequest):
    """Analyze one or more login events with Phase 1 rule-based detection."""
    try:
        service = get_credential_stuffing_service()
        events = [event.dict() for event in request.events]
        return service.analyze_events(events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def list_credential_stuffing_alerts(
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Optional severity filter: LOW, MEDIUM, HIGH"),
):
    """Return stored credential stuffing alerts."""
    try:
        service = get_credential_stuffing_service()
        return service.list_alerts(limit=limit, severity=severity)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback")
async def submit_credential_stuffing_feedback(request: FeedbackRequest):
    """Store analyst feedback for a credential stuffing alert."""
    try:
        service = get_credential_stuffing_service()
        return service.submit_feedback(
            alert_id=request.alert_id,
            feedback=request.feedback,
            analyst=request.analyst,
            notes=request.notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/retraining-data")
async def get_credential_stuffing_retraining_data(limit: int = Query(500, ge=1, le=2000)):
    """Return labeled records generated from alerts and analyst feedback."""
    try:
        service = get_credential_stuffing_service()
        return service.get_retraining_data(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{alert_id}")
async def download_credential_stuffing_report(alert_id: str):
    """Generate and download a PDF incident report for a credential stuffing alert."""
    try:
        service = get_credential_stuffing_service()
        report_path = service.generate_alert_pdf_report(alert_id)
        return FileResponse(
            path=str(report_path),
            media_type="application/pdf",
            filename=report_path.name,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate credential stuffing PDF report: {e}")


@router.post("/simulate-attack")
async def simulate_credential_stuffing_attack(request: SimulateAttackRequest = SimulateAttackRequest()):
    """
    Generate local synthetic login events for demo/testing only.

    This endpoint does not perform real login attempts or contact external systems.
    """
    try:
        service = get_credential_stuffing_service()
        return service.simulate_attack(
            source_ip=request.source_ip,
            username_prefix=request.username_prefix,
            count=request.count,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
