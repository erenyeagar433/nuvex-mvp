# nuvex-mvp/app/main.py
from fastapi import FastAPI, Request
from app.offense_router import router as offense_router

app = FastAPI(title="NuVex SOC Copilot")
app.include_router(offense_router)

@app.get("/")
def read_root():
    return {"message": "NuVex AI Agent is running."}
