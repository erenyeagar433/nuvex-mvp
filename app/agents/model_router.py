# app/agents/model_router.py

import os
from dotenv import load_dotenv
load_dotenv()

from app.agents.openai_agent import generate_response as openai_response
from app.agents.gemini_agent import generate_response as gemini_response

MODEL_PROVIDER = os.getenv("MODEL_PROVIDER", "openai")

def generate_dynamic_prompt(prompt: str) -> str:
    if MODEL_PROVIDER == "gemini":
        return gemini_response(prompt)
    else:
        return openai_response(prompt)
