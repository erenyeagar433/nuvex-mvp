# app/agents/openai_agent.py
import os
from openai import OpenAI

def generate_response(prompt: str) -> str:
    """
    Generates a response from OpenAI's GPT model for a given prompt.
    
    Args:
        prompt (str): The input prompt for the model.
    
    Returns:
        str: The generated response or an error message if the query fails.
    """
    try:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return "Error: OPENAI_API_KEY not found in environment variables"

        # Simple client initialization without proxy handling
        client = OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant specializing in SOC analysis and incident response."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
            max_tokens=300
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        error_msg = str(e).lower()
        if "api_key" in error_msg or "authentication" in error_msg:
            return "Error: Invalid or missing OpenAI API key"
        elif "quota" in error_msg or "billing" in error_msg:
            return "Error: OpenAI quota exceeded or billing issue"
        elif "rate_limit" in error_msg:
            return "Error: OpenAI rate limit exceeded"
        else:
            print(f"OpenAI query failed: {e}")
            return f"Error: OpenAI request failed - {str(e)}"
