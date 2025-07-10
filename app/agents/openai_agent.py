# app/agents/openai_agent.py

import os
import openai

openai.api_key = os.getenv("OPENAI_API_KEY")

def generate_response(prompt: str) -> str:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity assistant."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.5,
        max_tokens=300
    )
    return response.choices[0].message["content"].strip()
