# app/agents/incident_reporter.py

def generate_incident_report(offense_id: str, offense: dict, analysis: dict) -> str:
    """
    Create an L1-style incident report for escalation.
    """
    header = f"Hi Team,\n\nAn offense (ID: {offense_id}) has been escalated for further investigation.\n"
    
    # Offense summary
    summary = f"📝 Offense Summary:\n- Pattern: {analysis.get('pattern', 'N/A')}\n" \
              f"- Behavior: {analysis.get('behavior', 'N/A')}\n" \
              f"- Log types involved: {', '.join(analysis.get('log_types', []))}\n" \
              f"- Source IPs: {', '.join(offense.get('source_ips', []))}\n" \
              f"- Destination IPs: {', '.join(offense.get('destination_ips', []))}\n" \
              f"- Event Count: {offense.get('event_count', 'N/A')}\n"

    # Sample event (if available)
    sample_event = ""
    if offense.get("events"):
        event = offense["events"][0]
        sample_event = f"\n📌 Sample Event:\n- Category: {event.get('category', 'N/A')}\n" \
                       f"- Payload: {event.get('payload', 'N/A')}\n" \
                       f"- Action Taken: {event.get('action', 'N/A')}\n" \
                       f"- Username: {event.get('username', 'N/A')}\n" \
                       f"- Event Name: {event.get('event_name', 'N/A')}"

    # Reasoning
    reasons = "\n🔍 Reason for Escalation:\n" + "\n".join(f"- {r}" for r in analysis.get("reasoning", []))

    # Recommendations
    recommendations = "\n🛠️ Recommended Next Steps:\n" \
                      "- Investigate related user activity around the offense time.\n" \
                      "- Review firewall and endpoint logs for deeper context.\n" \
                      "- Correlate with threat intel to validate IOC severity.\n" \
                      "- Update incident tracker or ticketing system if necessary.\n"

    return f"{header}\n{summary}\n{sample_event}\n{reasons}\n{recommendations}"
