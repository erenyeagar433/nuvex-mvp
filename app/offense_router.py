# app/offense_router.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.agents.main_agent import handle_offense

router = APIRouter()

class OffenseRequest(BaseModel):
    offense_id: str
    source_ips: List[str]
    description: str
    destination_ips: Optional[List[str]] = []
    magnitude: Optional[int] = 0
    log_sources: Optional[List[str]] = []
    username: Optional[str] = "Unknown"
    start_time: Optional[str] = None
    event_count: Optional[int] = 0
    events: Optional[List[dict]] = []

@router.post("/ingest-offense")
async def ingest_offense(data: OffenseRequest):
    try:
        result = await handle_offense(data.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing offense: {str(e)}")
