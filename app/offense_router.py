# app/offense_router.py
from fastapi import APIRouter, Request, HTTPException
from app.agents.main_agent import handle_offense

router = APIRouter()

@router.post("/ingest-offense")
async def ingest_offense(request: Request):
    try:
        data = await request.json()
        required_keys = ["offense_id", "source_ips", "description"]
        if not all(key in data for key in required_keys):
            raise HTTPException(status_code=400, detail="Missing required fields: offense_id, source_ips, description")
        result = await handle_offense(data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing offense: {str(e)}")
