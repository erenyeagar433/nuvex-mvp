# app/agents/incident_reporter.py

import os

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def select_main_event(events, offense_type):
    # Simple selector: pick first event matching offense type, else first event
    for event in events:
        if offense_type.lower() in event.get("event_description", "").lower():
            return event
    return events[0] if events else None

def generate_incident_report(offense_id, offense, analysis):
    """
    Generates an incident report for the given offense and saves it to a file.
    
    Args:
        offense_id (str): Unique identifier for the offense.
        offense (dict): Offense data containing details like source_ips, destination_ips, etc.
        analysis (dict): Analysis data containing reputation, summary, and recommendations.
    
    Returns:
        tuple: (report_path, content) or (None, None) if an error occurs.
    """
    try:
        report_path = os.path.join(REPORTS_DIR, f"offense_{offense_id}.txt")

        # Extract from offense
        offense_type = offense.get("offense_type", "Unknown")
        description = offense.get("description", "No description")
        source_ips = offense.get("source_ips", ["N/A"])
        destination_ips = offense.get("destination_ips", ["N/A"])
        username = offense.get("username", "N/A")
        log_source = offense.get("log_source", "Unknown")
        events = offense.get("events", [])

        # Extract from analysis
        ip_reputation = analysis.get("reputation", [])
        summary = analysis.get("summary", "No summary")
        recommendations = analysis.get("recommendations", ["N/A"] * 5)

        # Select key event
        main_event = select_main_event(events, offense_type)

        short_summary = description.split("|")[0].strip() if "|" in description else description.strip()
        offense_details = (
            f"Summary: A {offense_type} event was detected from source IPs {', '.join(source_ips)} "
            f"targeting destination IPs {', '.join(destination_ips)} "
            f"via log source '{log_source}', involving user '{username if username else 'N/A'}'."
        )

        sample_event = "\n".join([
            f"Time: {main_event.get('start_time', 'N/A')}",
            f"Source IP: {main_event.get('source_address', 'N/A')}",
            f"Destination IP: {main_event.get('destination_address', 'N/A')}",
            f"Username: {main_event.get('username', 'N/A')}",
            f"Log Source: {main_event.get('log_source', 'N/A')}"
        ]) if main_event else "N/A"

        raw_payload = main_event.get("payload", "N/A") if main_event else "N/A"

        content = f"""
Hi Team,

Offense: {short_summary}

Offense Details:
{offense_details}

Analysis:
{summary}

IP Reputation:
{ip_reputation or 'N/A'}

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
"""

        with open(report_path, "w") as f:
            f.write(content.strip())

        return report_path, content.strip()
    except OSError as e:
        print(f"Error writing report for offense {offense_id}: {e}")
        return None, None
