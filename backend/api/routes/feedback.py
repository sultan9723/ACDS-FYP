"""
Feedback API Routes
====================
API endpoints for feedback submission and management.
"""

from typing import Optional
from enum import Enum
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

# Local model definitions
class FeedbackType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CORRECT_DETECTION = "correct_detection"
    SEVERITY_ADJUSTMENT = "severity_adjustment"
    GENERAL_FEEDBACK = "general_feedback"

class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FeedbackCreate(BaseModel):
    scan_id: str
    feedback_type: FeedbackType
    correct_label: Optional[bool] = None
    correct_severity: Optional[ThreatSeverity] = None
    comment: Optional[str] = None
    email_content: Optional[str] = None

class FeedbackReview(BaseModel):
    approved: bool
    review_notes: Optional[str] = None

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None

class FeedbackSummary(BaseModel):
    total_feedback: int
    pending_review: int
    by_type: dict
    retrain_recommended: bool

# Import services
try:
    from services.feedback_service import get_feedback_service
except ImportError:
    try:
        from backend.services.feedback_service import get_feedback_service
    except ImportError:
        get_feedback_service = None

router = APIRouter(prefix="/feedback", tags=["Feedback"])


@router.post("/", response_model=APIResponse)
async def submit_feedback(feedback: FeedbackCreate):
    """
    Submit feedback for a detection result.
    
    Use this to report false positives, false negatives,
    or confirm correct detections. This data is used to
    improve the ML model.
    """
    try:
        service = get_feedback_service()
        
        result = service.submit_feedback(
            scan_id=feedback.scan_id,
            feedback_type=feedback.feedback_type.value,
            original_prediction={},  # Would come from the scan result
            correct_label=feedback.correct_label,
            correct_severity=feedback.correct_severity.value if feedback.correct_severity else None,
            user_comment=feedback.comment,
            email_content=feedback.email_content
        )
        
        if result['success']:
            return {
                "success": True,
                "message": "Feedback submitted successfully",
                "data": {
                    "feedback_id": result['feedback_id'],
                    "retrain_recommended": result.get('retrain_recommended', False)
                }
            }
        else:
            raise HTTPException(status_code=400, detail=result.get('error', 'Failed to submit feedback'))
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/")
async def get_feedback_list(
    status: Optional[str] = Query(None, description="Filter by status (pending_review, approved, rejected)"),
    feedback_type: Optional[str] = Query(None, description="Filter by feedback type"),
    limit: int = Query(50, le=200)
):
    """
    Get list of feedback entries.
    
    Optionally filter by status or feedback type.
    """
    try:
        service = get_feedback_service()
        
        if status == "pending_review":
            feedback_list = service.get_pending_feedback(limit)
        else:
            # Get all feedback (would need to implement full listing)
            feedback_list = service.get_pending_feedback(limit)
        
        return {
            "success": True,
            "feedback": feedback_list,
            "count": len(feedback_list)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{feedback_id}")
async def get_feedback(feedback_id: str):
    """Get a specific feedback entry."""
    try:
        service = get_feedback_service()
        feedback = service.get_feedback(feedback_id)
        
        if not feedback:
            raise HTTPException(status_code=404, detail="Feedback not found")
        
        return {
            "success": True,
            "feedback": feedback
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{feedback_id}/review")
async def review_feedback(feedback_id: str, review: FeedbackReview):
    """
    Review and approve/reject a feedback entry.
    
    Admin only - used to validate user feedback before
    using it for model retraining.
    """
    try:
        service = get_feedback_service()
        
        result = service.review_feedback(
            feedback_id=feedback_id,
            approved=review.approved,
            reviewer="admin",  # Would come from auth
            review_notes=review.review_notes
        )
        
        if result['success']:
            return {
                "success": True,
                "message": f"Feedback {result['status']}",
                "feedback_id": feedback_id,
                "status": result['status']
            }
        else:
            raise HTTPException(status_code=400, detail=result.get('error', 'Review failed'))
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary/stats", response_model=FeedbackSummary)
async def get_feedback_summary():
    """
    Get feedback statistics summary.
    
    Returns aggregated metrics about feedback including
    accuracy estimates and feedback distribution.
    """
    try:
        service = get_feedback_service()
        summary = service.get_feedback_summary()
        
        return summary
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/retraining/data")
async def get_retraining_data():
    """
    Get approved feedback data for model retraining.
    
    Admin only - returns data formatted for model training.
    """
    try:
        service = get_feedback_service()
        data = service.get_retraining_data()
        
        return {
            "success": True,
            "retraining_data": data
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/retraining/mark-used")
async def mark_feedback_used(feedback_ids: list):
    """
    Mark feedback entries as used for retraining.
    
    Called after model retraining to track which
    feedback has been incorporated.
    """
    try:
        service = get_feedback_service()
        count = service.mark_used_for_retraining(feedback_ids)
        
        return {
            "success": True,
            "message": f"Marked {count} feedback entries as used",
            "count": count
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/service")
async def get_service_stats():
    """Get feedback service statistics."""
    try:
        service = get_feedback_service()
        stats = service.get_stats()
        
        return {
            "success": True,
            "stats": stats
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
