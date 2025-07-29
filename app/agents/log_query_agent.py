# app/agents/log_query_agent.py

from app.agents.model_router import generate_dynamic_prompt, get_current_provider

def generate_log_instructions(offense_data: dict) -> str:
    """
    Generate log investigation instructions using the configured AI provider.
    Works seamlessly with both OpenAI and Gemini through the model router.
    """
    
    # Extract key information for log investigation
    offense_type = offense_data.get('offense_type', 'Unknown')
    description = offense_data.get('description', '')
    source_ips = offense_data.get('source_ips', [])
    dest_ips = offense_data.get('destination_ips', [])
    username = offense_data.get('username', 'N/A')
    log_sources = offense_data.get('log_sources') or [offense_data.get('log_source', 'Unknown')]
    event_count = offense_data.get('event_count', 0)
    magnitude = offense_data.get('magnitude', 0)
    
    # Handle log sources format
    if isinstance(log_sources, str):
        log_sources = [log_sources]
    
    # Create events context
    events = offense_data.get('events', [])
    event_types = list(set([e.get('event_type', 'Unknown') for e in events[:5]]))
    protocols = list(set([e.get('protocol', 'Unknown') for e in events[:5]]))
    
    prompt = f"""
You are a Level 1 SOC Analyst using QRadar or a similar SIEM. Based on the offense below, write 6–8 specific log investigation actions that you personally perform to gather evidence and validate the incident.

Do not give advice or explain. Do not act as an assistant. You are the analyst. Each step must be operational, technical, and directly executable in a SOC environment.

OFFENSE DETAILS:
- Type: {offense_type}
- Description: {description}
- Source IPs: {', '.join(map(str, source_ips))}
- Destination IPs: {', '.join(map(str, dest_ips))}
- Username: {username}
- Event Count: {event_count}
- Magnitude: {magnitude}
- Log Sources: {', '.join(log_sources)}
- Event Types: {', '.join(event_types)}
- Protocols: {', '.join(protocols)}

Provide 6-8 specific, actionable log investigation steps in bullet point format. Include:
1. Specific log sources to check
2. Time ranges to investigate
3. Key fields to search for
4. Correlation queries to run
5. Additional context to gather

Format as clear bullet points starting with action verbs (e.g., "Check", "Search", "Correlate").
"""
    
    try:
        current_provider = get_current_provider()
        print(f"[LogQueryAgent] Generating log instructions using {current_provider}")
        
        response = generate_dynamic_prompt(prompt)
        
        # Validate response
        if response.startswith("Error:"):
            print(f"[LogQueryAgent] AI log instructions failed: {response}")
            return generate_fallback_instructions(offense_data)
        
        return response
        
    except Exception as e:
        print(f"[LogQueryAgent] Error generating log instructions: {e}")
        return generate_fallback_instructions(offense_data)

def generate_fallback_instructions(offense_data: dict) -> str:
    """
    Generate basic log investigation instructions when AI fails.
    Provider-agnostic fallback logic.
    """
    source_ips = offense_data.get('source_ips', [])
    dest_ips = offense_data.get('destination_ips', [])
    username = offense_data.get('username', 'N/A')
    offense_type = offense_data.get('offense_type', 'Unknown')
    
    instructions = f"""
MANUAL LOG INVESTIGATION STEPS (AI generation failed):

• Check firewall logs for connections from source IPs: {', '.join(map(str, source_ips))}
• Search proxy/web logs for HTTP/HTTPS traffic to destination IPs: {', '.join(map(str, dest_ips))}
• Review authentication logs for user: {username}
• Examine DNS logs for domain resolution patterns from source IPs
• Check network flow data for data volume and connection patterns
• Search endpoint logs on systems involved in the {offense_type} incident
• Review email security logs if applicable to this offense type
• Correlate timeline of events across all relevant log sources
• Check for similar patterns in historical logs (past 30 days)
"""
    
    return instructions.strip()

def validate_log_instructions(instructions: str) -> bool:
    """
    Validate that the generated log instructions are useful.
    Returns True if instructions appear valid, False otherwise.
    """
    if not instructions or len(instructions.strip()) < 50:
        return False
    
    # Check for key investigation terms
    key_terms = ['check', 'search', 'review', 'examine', 'correlate', 'logs', 'investigate']
    instructions_lower = instructions.lower()
    
    found_terms = sum(1 for term in key_terms if term in instructions_lower)
    
    # Should have at least 3 key investigation terms
    return found_terms >= 3
