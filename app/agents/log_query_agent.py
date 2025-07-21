# app/agents/log_query_agent.py

from app.agents.model_router import generate_dynamic_prompt

def generate_log_instructions(offense_data: dict) -> str:
    prompt = f"""
You are a SOC Analyst assistant. Given the following offense metadata, generate log investigation steps that an L1 analyst should take to gather more evidence.

Offense Details:
{offense_data}

Respond with clear and actionable steps in bullet points.
"""
    return generate_dynamic_prompt(prompt)
