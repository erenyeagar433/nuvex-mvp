from fastapi import APIRouter, Request
from app.agents.main_agent import handle_offense

router = APIRouter()

@router.post("/ingest-offense")
async def ingest_offense(request: Request):
    data = await request.json()
    result = await handle_offense(data)
    return result

