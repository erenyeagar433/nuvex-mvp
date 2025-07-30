# app/agents/offense_analyzer.py
from app.utils.reputation import get_reputation
from app.agents.log_query_agent import generate_log_instructions
from app.utils.log_writer import save_log_instructions
from app.agents.model_router import generate_dynamic_prompt, get_current_provider

def generate_offense_summary(offense_data: dict, reputation_results: list) -> str:
    """
    Generate a comprehensive analysis summary of the offense.
    Works with both OpenAI and Gemini through the model router.
    """
    
    # Extract key information with better handling
    offense_type = offense_data.get('offense_type', 'Unknown')
    description = offense_data.get('description', '')
    source_ips = offense_data.get('source_ips', [])
    dest_ips = offense_data.get('destination_ips', [])
    username = offense_data.get('username', 'N/A')
    event_count = offense_data.get('event_count', 0)
    magnitude = offense_data.get('magnitude', 0)
    
    # Handle both log_source and log_sources
    log_sources = offense_data.get('log_sources') or [offense_data.get('log_source', 'Unknown')]
    if isinstance(log_sources, str):
        log_sources = [log_sources]
    
    # Create events summary
    events = offense_data.get('events', [])
    events_summary = []
    for i, event in enumerate(events[:3]):
        event_type = event.get('event_type', 'Unknown')
        protocol = event.get('protocol', 'N/A')
        events_summary.append(f"Event {i+1}: {event_type} ({protocol})")
    
    # Create reputation summary
    rep_summary = []
    for rep in reputation_results:
        ip = rep.get('ioc', 'Unknown')
        abuse_conf = rep.get('abuseipdb', {}).get('abuse_confidence', 0)
        mal_votes = rep.get('virustotal', {}).get('malicious_votes', 0)
        rep_summary.append(f"IP {ip}: AbuseIPDB {abuse_conf}%, VirusTotal {mal_votes} malicious votes")
    
    # Unified prompt that works well with both OpenAI and Gemini
    prompt = f"""
You are a SOC cybersecurity analyst. Analyze the following security offense and write a clear, professional summary.

OFFENSE DETAILS:
- Type: {offense_type}
- Description: {description}
- Source IPs: {', '.join(map(str, source_ips))}
- Destination IPs: {', '.join(map(str, dest_ips))}
- Username: {username}
- Event Count: {event_count}
- Magnitude: {magnitude}
- Log Sources: {', '.join(log_sources)}

EVENTS SUMMARY:
{chr(10).join(events_summary) if events_summary else 'No events available'}

IP REPUTATION ANALYSIS:
{chr(10).join(rep_summary) if rep_summary else 'No reputation data available'}

Instructions:
Write a concise 3–4 sentence summary of the offense, covering:
1. What type of incident this likely is and its severity
2. The potential risk and business impact
3. Notable indicators of compromise or suspicious activity
4. Any urgent concerns needing immediate attention

Use only the information provided above. If any detail is missing or marked as unavailable, do not reference it. This summary will be shared with a client team, so keep it accurate, readable, and professional — suitable for inclusion in an incident review report.
"""
    
    try:
        current_provider = get_current_provider()
        print(f"[OffenseAnalyzer] Generating summary using {current_provider}")
        
        response = generate_dynamic_prompt(prompt)
        
        # Validate response
        if response.startswith("Error:"):
            print(f"[OffenseAnalyzer] AI analysis failed: {response}")
            return f"Analysis failed: {response}. Manual review required for {offense_type} from {', '.join(map(str, source_ips))}."
        
        return response
        
    except Exception as e:
        print(f"[OffenseAnalyzer] Error generating offense summary: {e}")
        return f"Analysis failed: {str(e)}. Manual review required for {offense_type} from {', '.join(map(str, source_ips))}."

def assess_risk_level(offense_data: dict, reputation_results: list) -> str:
    """
    Assess the risk level based on various factors.
    Provider-agnostic risk assessment logic.
    """
    risk_score = 0
    factors = []
    
    # Check magnitude
    magnitude = offense_data.get('magnitude', 0)
    if magnitude >= 8:
        risk_score += 3
        factors.append(f"High magnitude ({magnitude})")
    elif magnitude >= 5:
        risk_score += 2
        factors.append(f"Medium magnitude ({magnitude})")
    
    # Check reputation
    for rep in reputation_results:
        abuse_conf = rep.get('abuseipdb', {}).get('abuse_confidence', 0)
        mal_votes = rep.get('virustotal', {}).get('malicious_votes', 0)
        
        if abuse_conf > 75 or mal_votes > 5:
            risk_score += 3
            factors.append(f"High-risk IP {rep.get('ioc')}")
        elif abuse_conf > 25 or mal_votes > 0:
            risk_score += 1
            factors.append(f"Suspicious IP {rep.get('ioc')}")
    
    # Check event count
    event_count = offense_data.get('event_count', 0)
    if event_count > 100:
        risk_score += 2
        factors.append(f"High event volume ({event_count})")
    elif event_count > 10:
        risk_score += 1
        factors.append(f"Medium event volume ({event_count})")
    
    # Determine risk level
    if risk_score >= 6:
        level = "CRITICAL"
    elif risk_score >= 4:
        level = "HIGH"
    elif risk_score >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return f"{level} (Score: {risk_score}, Factors: {', '.join(factors) if factors else 'None detected'})"

def enrich_offense(offense_data: dict) -> dict:
    """
    Enriches offense with reputation data, analysis summary, and log instructions.
    Works seamlessly with both OpenAI and Gemini providers.
    """
    
    try:
        source_ips = offense_data.get("source_ips", [])
        offense_id = offense_data.get("offense_id", "unknown")
        current_provider = get_current_provider()
        
        print(f"[OffenseAnalyzer] Enriching offense {offense_id} using {current_provider} with {len(source_ips)} source IPs")
        
        # Get reputation data for all source IPs
        reputation_results = []
        for ip in source_ips:
            try:
                rep_result = get_reputation(ip)
                reputation_results.append(rep_result)
                print(f"[OffenseAnalyzer] Got reputation for {ip}")
            except Exception as e:
                print(f"[OffenseAnalyzer] Failed to get reputation for {ip}: {e}")
                # Add placeholder result to maintain list consistency
                reputation_results.append({
                    "ioc": ip,
                    "abuseipdb": {"abuse_confidence": 0, "reports": 0},
                    "virustotal": {"malicious_votes": 0, "suspicious_votes": 0}
                })
        
        # Generate comprehensive analysis summary (works with both providers)
        print(f"[OffenseAnalyzer] Generating analysis summary using {current_provider}...")
        summary = generate_offense_summary(offense_data, reputation_results)
        
        # Assess risk level (provider-agnostic)
        risk_assessment = assess_risk_level(offense_data, reputation_results)
        
        # Generate log investigation instructions
        print(f"[OffenseAnalyzer] Generating log instructions using {current_provider}...")
        log_instructions = generate_log_instructions(offense_data)
        
        # Save log instructions to file
        try:
            save_log_instructions(offense_id, log_instructions)
            print(f"[OffenseAnalyzer] Saved log instructions for {offense_id}")
        except Exception as e:
            print(f"[OffenseAnalyzer] Failed to save log instructions: {e}")
        
        # Create enriched data copy
        enriched_data = offense_data.copy()
        enriched_data.update({
            "reputation": reputation_results,
            "summary": summary,
            "risk_assessment": risk_assessment,
            "log_instructions": log_instructions,
            "enrichment_status": "success",
            "ai_provider_used": current_provider
        })
        
        print(f"[OffenseAnalyzer] Successfully enriched offense {offense_id} using {current_provider}")
        return enriched_data
        
    except Exception as e:
        print(f"[OffenseAnalyzer] Error enriching offense: {e}")
        # Return original data with error info
        enriched_data = offense_data.copy()
        enriched_data.update({
            "reputation": [],
            "summary": f"Enrichment failed: {str(e)}",
            "risk_assessment": "UNKNOWN (Analysis failed)",
            "log_instructions": "Manual investigation required due to analysis failure",
            "enrichment_status": "failed",
            "enrichment_error": str(e),
            "ai_provider_used": get_current_provider()
        })
        return enriched_data
