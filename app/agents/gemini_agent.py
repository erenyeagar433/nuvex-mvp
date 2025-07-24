# app/agents/gemini_agent.py
import os
import time
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# Rate limiting ONLY for Gemini free tier (15 requests per minute)
last_request_time = 0
min_request_interval = 4.1  # Slightly over 4 seconds to stay under 15/min

def generate_response(prompt: str) -> str:
    """
    Generates a response from Google's Gemini model with rate limiting for free tier.
    
    Args:
        prompt (str): The input prompt for the model.
    
    Returns:
        str: The generated response or an error message if the query fails.
    """
    global last_request_time
    
    try:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return "Error: GEMINI_API_KEY not found in environment variables"
        
        # Rate limiting ONLY for Gemini (free tier constraint)
        current_time = time.time()
        time_since_last = current_time - last_request_time
        if time_since_last < min_request_interval:
            sleep_time = min_request_interval - time_since_last
            print(f"[Gemini] Rate limiting: sleeping for {sleep_time:.1f}s")
            time.sleep(sleep_time)
        
        genai.configure(api_key=api_key)
        
        # Use current Gemini model
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={
                "temperature": 0.5,
                "top_p": 0.9,
                "top_k": 40,
                "max_output_tokens": 300,
            },
            # Cybersecurity-optimized safety settings
            safety_settings={
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
            }
        )
        
        last_request_time = time.time()
        response = model.generate_content(prompt)
        
        # Check if response was blocked by safety filters
        if hasattr(response, 'candidates') and response.candidates:
            finish_reason = response.candidates[0].finish_reason
            if hasattr(finish_reason, 'name') and finish_reason.name == "SAFETY":
                return "Error: Response blocked by Gemini safety filters"
        
        # Check if response is empty
        if not response.text:
            return "Error: Empty response from Gemini"
            
        return response.text.strip()
        
    except Exception as e:
        error_msg = str(e).lower()
        if "quota" in error_msg or "rate" in error_msg:
            print(f"[Gemini] Rate limit hit: {e}")
            return "Error: Gemini rate limit exceeded (free tier). Please wait and try again."
        elif "resource_exhausted" in error_msg:
            print(f"[Gemini] Quota exhausted: {e}")
            return "Error: Gemini daily quota exhausted (free tier)."
        else:
            print(f"Gemini query failed: {e}")
            return f"Error: Unable to query Gemini - {str(e)}"
