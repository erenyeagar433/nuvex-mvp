import os
from datetime import datetime

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def select_main_event(events, offense_type):
    keywords = {
        "Brute Force": ["failed login", "authentication failed", "invalid password"],
        "Data Exfiltration": ["large download", "file transfer", "external upload"],
        "Reconnaissance": ["port scan", "nmap", "enumeration"],
        "Malware": ["malicious", "trojan", "exploit", "payload"],
        "Access Violation": ["unauthorized", "privilege escalation", "access denied"]
    }

    offense_keywords = keywords.get(offense_type, [])
    matching_events = [
        e for e in events
        if any(kw.lower() in e.get("payload", "").lower() for kw in offense_keywords)
    ]
    return matching_events[0] if matching_events else (events[0] if events else None)

def generate_incident_report(offense_id, offense_type, description, source_ip, destination_ip,
                              username, log_source, events, ip_reputation, summary, analysis, recommendations):

    report_path = os.path.join(REPORTS_DIR, f"offense_{offense_id}.txt")
    main_event = select_main_event(events, offense_type)

    short_summary = description.split("|")[0].strip() if "|" in description else description.strip()
    offense_details = (
        f"Summary: A {offense_type} event was detected from source IP {source_ip} targeting destination IP {destination_ip} "
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
{analysis}

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
