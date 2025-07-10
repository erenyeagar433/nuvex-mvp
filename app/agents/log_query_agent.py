# app/agents/log_query_agent.py

from app.agents.model_router import generate_dynamic_prompt

def generate_log_instructions(offense_summary: str, offense_details: dict) -> str:
    prompt = f"""
You are a SOC Analyst assistant. Given the following offense summary and metadata, generate log investigation steps that an L1 analyst should take to gather more evidence.

Offense Summary:
{offense_summary}

Offense Details:
{offense_details}

Respond with clear and actionable steps in bullet points.
"""
    return generate_dynamic_prompt(prompt)
