# app/agents/incident_reporter.py

import os
from app.agents.model_router import generate_dynamic_prompt, get_current_provider

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def select_main_event(events, offense_type):
    """Select the most relevant event for the report"""
    if not events:
        return None
    
    # Try to find event matching offense type
    for event in events:
        event_desc = event.get("event_description", "").lower()
        event_type = event.get("event_type", "").lower()
        if offense_type.lower() in event_desc or offense_type.lower() in event_type:
            return event
    
    # Return first event with most complete data
    for event in events:
        if event.get("source_address") or event.get("source_ip"):
            return event
    
    return events[0]

def generate_analysis_summary(offense, reputation_results):
    """
    Generate AI-powered analysis summary.
    Works with both OpenAI and Gemini through the model router.
    """
    prompt = f"""
You are a SOC analyst. Analyze this security offense and provide a concise summary.

Offense Type: {offense.get('offense_type', 'Unknown')}
Description: {offense.get('description', '')}
Source IPs: {offense.get('source_ips', [])}
Destination IPs: {offense.get('destination_ips', [])}
Username: {offense.get('username', 'N/A')}
Event Count: {offense.get('event_count', 0)}
Magnitude: {offense.get('magnitude', 0)}

IP Reputation Summary:
{[f"IP {r.get('ioc')}: AbuseIPDB {r.get('abuseipdb', {}).get('abuse_confidence', 0)}%, VT {r.get('virustotal', {}).get('malicious_votes', 0)}" for r in reputation_results]}

Provide a 2-3 sentence analysis of the security implications and risk level.
"""
    
    try:
        current_provider = get_current_provider()
        print(f"[IncidentReporter] Generating analysis summary using {current_provider}")
        response = generate_dynamic_prompt(prompt)
        
        if response.startswith("Error:"):
            return f"AI analysis failed ({current_provider}): {response}"
        
        return response
    except Exception as e:
        print(f"[IncidentReporter] Error generating analysis summary: {e}")
        return f"Analysis generation failed: {str(e)}"

def generate_recommendations(offense, analysis_summary, reputation_results):
    """
    Generate AI-powered security recommendations.
    Works with both OpenAI and Gemini through the model router.
    """
    
    # Extract risk indicators
    risk_indicators = []
    for rep in reputation_results:
        abuse_conf = rep.get('abuseipdb', {}).get('abuse_confidence', 0)
        mal_votes = rep.get('virustotal', {}).get('malicious_votes', 0)
        if abuse_conf > 25 or mal_votes > 0:
            risk_indicators.append(f"IP {rep.get('ioc')}: AbuseIPDB {abuse_conf}%, VT {mal_votes}")
    
    prompt = f"""
You are a senior SOC analyst. Based on this security offense analysis, provide exactly 5 actionable, specific recommendations.

OFFENSE ANALYSIS:
- Type: {offense.get('offense_type', 'Unknown')}
- Analysis: {analysis_summary}
- Username: {offense.get('username', 'N/A')}
- Source IPs: {offense.get('source_ips', [])}
- Event Count: {offense.get('event_count', 0)}
- Magnitude: {offense.get('magnitude', 0)}

RISK INDICATORS:
{chr(10).join(risk_indicators) if risk_indicators else 'No significant risk indicators detected'}

SIMILAR CASES: {len(offense.get('similar_cases', []))} found

Provide 5 specific, actionable recommendations prioritized by urgency. Each should be 1-2 sentences.
Format as numbered list (1., 2., 3., 4., 5.) without bullets or special characters.
Focus on immediate actions, containment, investigation steps, and prevention.
"""
    
    try:
        current_provider = get_current_provider()
        print(f"[IncidentReporter] Generating recommendations using {current_provider}")
        response = generate_dynamic_prompt(prompt)
        
        if response.startswith("Error:"):
            print(f"[IncidentReporter] AI recommendations failed: {response}")
            return [
                "Monitor affected systems for additional suspicious activity",
                "Review firewall logs for related connections",
                "Check user account activity for compromise indicators", 
                "Validate system integrity and patch status",
                "Document incident details for future reference"
            ]
        
        # Parse recommendations into list
        recommendations = []
        for line in response.split('\n'):
            line = line.strip()
            if line and not line.startswith('-') and not line.startswith('*'):
                # Remove numbering if present
                if line[0].isdigit() and '.' in line[:3]:
                    line = line.split('.', 1)[1].strip()
                if line:  # Only add non-empty lines
                    recommendations.append(line)
        
        # Ensure we have exactly 5 recommendations
        while len(recommendations) < 5:
            recommendations.append("Monitor for additional suspicious activity")
        
        return recommendations[:5]
        
    except Exception as e:
        print(f"[IncidentReporter] Error generating recommendations: {e}")
        return [
            "Monitor affected systems for additional suspicious activity",
            "Review firewall logs for related connections", 
            "Check user account activity for compromise indicators",
            "Validate system integrity and patch status",
            "Document incident details for future reference"
        ]

def generate_incident_report(offense_id, offense, analysis):
    """
    Generates a comprehensive incident report for the given offense.
    Works seamlessly with both OpenAI and Gemini providers.
    """
    try:
        current_provider = get_current_provider()
        print(f"[IncidentReporter] Generating incident report using {current_provider}")
        
        report_path = os.path.join(REPORTS_DIR, f"offense_{offense_id}.txt")

        # Extract basic offense info
        offense_type = offense.get("offense_type", "Unknown")
        description = offense.get("description", "No description")
        source_ips = offense.get("source_ips", ["N/A"])
        destination_ips = offense.get("destination_ips", ["N/A"])
        username = offense.get("username", "N/A")
        
        # Handle both log_source and log_sources
        log_source = offense.get("log_source") or ", ".join(offense.get("log_sources", ["Unknown"]))
        events = offense.get("events", [])

        # Get reputation and generate analysis
        ip_reputation = analysis.get("reputation", [])
        
        # Generate AI analysis if not present or use existing summary
        summary = analysis.get("summary")
        if not summary or summary == "No summary" or summary.startswith("Analysis failed"):
            summary = generate_analysis_summary(offense, ip_reputation)
        
        # Generate recommendations using AI
        recommendations = generate_recommendations(offense, summary, ip_reputation)

        # Select and format main event
        main_event = select_main_event(events, offense_type)
        
        if main_event:
            sample_event = "\n".join([
                f"Time: {main_event.get('start_time', main_event.get('timestamp', 'N/A'))}",
                f"Source IP: {main_event.get('source_address', main_event.get('source_ip', 'N/A'))}",
                f"Destination IP: {main_event.get('destination_address', main_event.get('destination_ip', 'N/A'))}",
                f"Username: {main_event.get('username', username)}",
                f"Log Source: {main_event.get('log_source', log_source)}",
                f"Protocol: {main_event.get('protocol', 'N/A')}",
                f"Event Type: {main_event.get('event_type', 'N/A')}"
            ])
            raw_payload = main_event.get("payload", "N/A")
        else:
            sample_event = "No event details available"
            raw_payload = "N/A"

        # Create short summary for offense line
        short_summary = description.split("|")[0].strip() if "|" in description else description.strip()
        
        # Build offense details
        offense_details = (
            f"A {offense_type} incident was detected from source IP(s) {', '.join(map(str, source_ips))} "
            f"targeting destination IP(s) {', '.join(map(str, destination_ips))} "
            f"via log source '{log_source}'. "
            f"The incident involved user '{username}' with {offense.get('event_count', 0)} total events "
            f"and a magnitude rating of {offense.get('magnitude', 0)}."
        )

        # Format IP reputation for display
        if ip_reputation:
            rep_display = []
            for rep in ip_reputation:
                ip = rep.get('ioc', 'Unknown')
                abuse_conf = rep.get('abuseipdb', {}).get('abuse_confidence', 0)
                mal_votes = rep.get('virustotal', {}).get('malicious_votes', 0)
                rep_display.append(f"IP {ip}: AbuseIPDB confidence {abuse_conf}%, VirusTotal malicious votes {mal_votes}")
            reputation_text = "\n".join(rep_display)
        else:
            reputation_text = "No reputation data available"

        content = f"""Hi Team,

Offense: {short_summary}

Offense Details:
{offense_details}

Analysis:
{summary}

IP Reputation:
{reputation_text}

Sample Event:
{sample_event}

Payload:
{raw_payload}

Recommendations:
- {recommendations[0]}
- {recommendations[1]}
- {recommendations[2]}
- {recommendations[3]}
- {recommendations[4]}

Similar Cases Found: {len(analysis.get('similar_cases', []))}
Decision: {analysis.get('decision', 'Unknown').upper()}
Reasoning: {', '.join(analysis.get('reasoning', ['No reasoning provided']))}
Risk Assessment: {analysis.get('risk_assessment', 'Not assessed')}
AI Provider Used: {current_provider.upper()}
"""

        with open(report_path, "w") as f:
            f.write(content.strip())

        print(f"[IncidentReporter] Successfully generated incident report using {current_provider}")
        return report_path, content.strip()
        
    except Exception as e:
        print(f"[IncidentReporter] Error generating incident report for offense {offense_id}: {e}")
        return None, None
