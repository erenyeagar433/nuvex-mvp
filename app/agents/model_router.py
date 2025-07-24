# app/agents/model_router.py
import os
from dotenv import load_dotenv
load_dotenv()

from app.agents.openai_agent import generate_response as openai_response
from app.agents.gemini_agent import generate_response as gemini_response

# Configuration from environment
MODEL_PROVIDER = os.getenv("MODEL_PROVIDER", "openai").lower()
ENABLE_FALLBACK = os.getenv("ENABLE_MODEL_FALLBACK", "true").lower() == "true"

def generate_dynamic_prompt(prompt: str) -> str:
    """
    Generate response using the configured model provider.
    Handles both OpenAI (no rate limiting) and Gemini (with rate limiting).
    Fallback support between providers if enabled.
    """
    primary_provider = MODEL_PROVIDER
    
    print(f"[ModelRouter] Using primary provider: {primary_provider}")
    
    # Try primary provider first
    response = try_provider(primary_provider, prompt)
    
    # If primary failed and fallback is enabled, try alternative
    if ENABLE_FALLBACK and response.startswith("Error:"):
        fallback_provider = "openai" if primary_provider == "gemini" else "gemini"
        print(f"[ModelRouter] Primary provider ({primary_provider}) failed, trying fallback ({fallback_provider})")
        fallback_response = try_provider(fallback_provider, prompt)
        
        # Use fallback response if it's successful
        if not fallback_response.startswith("Error:"):
            print(f"[ModelRouter] Fallback successful with {fallback_provider}")
            return fallback_response
        else:
            print(f"[ModelRouter] Both providers failed. Primary: {response[:50]}..., Fallback: {fallback_response[:50]}...")
    
    return response

def try_provider(provider: str, prompt: str) -> str:
    """
    Try a specific model provider.
    
    Args:
        provider (str): "openai" or "gemini"
        prompt (str): The prompt to send
        
    Returns:
        str: Response or error message
    """
    try:
        if provider == "gemini":
            # Gemini has built-in rate limiting in its agent
            return gemini_response(prompt)
        elif provider == "openai":
            # OpenAI has no rate limiting (paid tier)
            return openai_response(prompt)
        else:
            return f"Error: Unknown provider '{provider}'. Use 'openai' or 'gemini'"
            
    except Exception as e:
        return f"Error: {provider} provider failed - {str(e)}"

def get_current_provider() -> str:
    """Get the currently configured primary provider"""
    return MODEL_PROVIDER

def is_fallback_enabled() -> bool:
    """Check if fallback is enabled"""
    return ENABLE_FALLBACK
