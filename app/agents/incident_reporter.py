import datetime

def generate_incident_report(offense_id: str, offense: dict, analysis: dict) -> str:
    """
    Generate a structured incident report for an escalated offense.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = f"""
============================================
         NuVex SOC Analyst Report
============================================
Report Generated: {timestamp}
Offense ID      : {offense_id}
Description     : {offense.get('description', 'N/A')}
Log Source      : {offense.get('log_source', 'Unknown')}
Event Name      : {offense.get('event_name', 'Unknown')}
"""

    summary = f"""
--- Summary ---
{analysis.get('summary', 'No summary available.')}
"""

    event_sample = ""
    if "events" in offense and offense["events"]:
        sample = offense["events"][0]
        event_sample = f"""
--- Sample Event ---
Source IP       : {sample.get('source_ip', 'N/A')}
Destination IP  : {sample.get('destination_ip', 'N/A')}
Username        : {sample.get('username', 'N/A')}
Payload         : {sample.get('payload', 'N/A')}
"""

    reasoning = "\n".join(f"- {r}" for r in analysis.get("reasoning", []))

    similar_cases = ""
    for case in analysis.get("similar_cases", []):
        similar_cases += f"""
    - [{case.get('similarity_score', '?')}] {case.get('description')} | Source: {', '.join(case.get('source_ips', []))} → Dest: {', '.join(case.get('destination_ips', []))} | Tags: {', '.join(case.get('tags', []))}
"""

    reputation_notes = ""
    for entry in analysis.get("reputation", []):
        if "ip" in entry and entry.get("abuse_confidence", 0) > 0:
            reputation_notes += f"- IP {entry['ip']} has abuse score {entry['abuse_confidence']} (Reports: {entry.get('reports', 0)})\n"

    recommendations = f"""
--- Recommendations ---
• Investigate further for lateral movement attempts or privilege escalation.
• Correlate with other log sources like VPN, endpoint detection, or IAM logs.
• Consider blocking the source IP {offense.get('source_ips', ['N/A'])[0]} if confirmed malicious.
• Review firewall rules for any unintended exposures.
"""

    conclusion = f"""
--- Final Notes ---
Decision    : {analysis.get('decision', 'N/A')}
Reasoning   : 
{reasoning or 'N/A'}

Similar Past Cases:
{similar_cases or 'None'}

Reputation Flags:
{reputation_notes or 'None'}

Log Analysis Instructions:
{analysis.get('log_request', 'No log instructions provided.')}
"""

    report = header + summary + event_sample + conclusion + recommendations
    return report
