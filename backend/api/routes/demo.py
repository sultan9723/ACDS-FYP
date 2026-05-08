"""
Demo API Routes
================
API endpoints for demo mode and automated testing.
Controls the demo scheduler for presentations and testing.
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/demo", tags=["Demo Mode"])


class DemoStartRequest(BaseModel):
    interval_seconds: int = Field(default=300, ge=30, le=3600, description="Interval between batches in seconds")
    batch_size: int = Field(default=5, ge=1, le=20, description="Number of emails per batch")


class ManualBatchRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=50, description="Number of emails to process")


@router.post("/start")
async def start_demo_mode(request: DemoStartRequest = DemoStartRequest()):
    """
    Start the demo scheduler.
    
    This will begin automatically processing sample emails at regular intervals.
    Useful for demonstrations and testing the system's capabilities.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        
        # Set interval if specified
        if request.interval_seconds:
            scheduler.set_interval(request.interval_seconds)
        
        result = await scheduler.start()
        
        return {
            "success": True,
            "message": f"Demo mode started. Processing {request.batch_size} emails every {request.interval_seconds} seconds.",
            "status": result["status"],
            "interval_seconds": scheduler.interval_seconds,
            "next_run": (datetime.now(timezone.utc).replace(microsecond=0)).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_demo_mode():
    """
    Stop the demo scheduler.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        result = await scheduler.stop()
        
        return {
            "success": True,
            "message": "Demo mode stopped.",
            "status": result["status"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_demo_status():
    """
    Get the current status of the demo scheduler.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        stats = scheduler.stats
        
        return {
            "success": True,
            "running": scheduler.running,
            "interval_seconds": scheduler.interval_seconds,
            "stats": {
                "total_processed": stats["total_processed"],
                "phishing_detected": stats["phishing_detected"],
                "legitimate_detected": stats["legitimate_detected"],
                "last_run": stats["last_run"],
                "next_run": stats["next_run"]
            },
            "recent_sessions": stats["sessions"][-5:]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run-batch")
async def run_manual_batch(request: ManualBatchRequest = ManualBatchRequest()):
    """
    Manually trigger a batch of email processing.
    
    Use this to immediately process emails without waiting for the scheduler.
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        result = await scheduler.process_batch(count=request.count)
        
        return {
            "success": True,
            "message": f"Processed {request.count} emails",
            "session_id": result["session_id"],
            "summary": result["summary"],
            "results": result["results"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/set-interval")
async def set_demo_interval(interval_seconds: int = Query(..., ge=30, le=3600)):
    """
    Set the interval between demo batches.
    
    Args:
        interval_seconds: Time between batches (30-3600 seconds)
    """
    try:
        from services.demo_scheduler import get_demo_scheduler
        
        scheduler = get_demo_scheduler()
        result = scheduler.set_interval(interval_seconds)
        
        return {
            "success": True,
            "message": f"Interval set to {interval_seconds} seconds",
            "interval_seconds": result["interval_seconds"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
