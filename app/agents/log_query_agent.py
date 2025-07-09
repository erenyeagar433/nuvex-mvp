# app/agents/log_query_agent.py

import os
import openai
from dotenv import load_dotenv
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

def generate_log_instructions(offense_summary: str, offense_details: dict) -> str:
    prompt = f"""
You are a SOC Analyst assistant. Given the following offense summary and metadata, generate log investigation steps that an L1 analyst should take to gather more evidence.

Offense Summary:
{offense_summary}

Offense Details:
{offense_details}

Respond with actionable steps in plain text.
"""

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity L1 log analysis assistant."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.5,
        max_tokens=300
    )

    return response.choices[0].message["content"].strip()
