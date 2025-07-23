# app/agents/openai_agent.py
import os
from openai import OpenAI
import httpx

def generate_response(prompt: str) -> str:
    """
    Generates a response from OpenAI's GPT model for a given prompt.
    
    Args:
        prompt (str): The input prompt for the model.
    
    Returns:
        str: The generated response or an error message if the query fails.
    """
    try:
        # Use httpx client with proxy from environment if set
        proxy = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        http_client = httpx.Client(proxies=proxy) if proxy else None

        client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            http_client=http_client
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"OpenAI query failed: {e}")
        return "Error: Unable to query OpenAI"
