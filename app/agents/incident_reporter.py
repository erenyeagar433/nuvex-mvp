import os
from datetime import datetime

def generate_incident_report(offense_id: str, offense: dict, analysis: dict) -> str:
    """
    Generate a structured incident report for an escalated offense.
    Saves it as a .txt file and simulates sending an email.
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    offense_summary = offense.get("description", "No description provided.")
    source_ips = ", ".join(offense.get("source_ips", []))
    dest_ips = ", ".join(offense.get("destination_ips", []))
    log_source = offense.get("log_source", "unknown")

    reputation = analysis.get("reputation", {})
    similar_cases = analysis.get("similar_cases", [])
    reasoning = analysis.get("reasoning", "No reasoning available.")
    recommendations = analysis.get("recommendations", ["No recommendations provided."])

    report_lines = [
        f"=== NuVex Incident Report ===",
        f"Timestamp: {timestamp}",
        f"Offense ID: {offense_id}",
        f"Offense Summary: {offense_summary}",
        f"Source IPs: {source_ips}",
        f"Destination IPs: {dest_ips}",
        f"Log Source: {log_source}",
        "",
        f"--- Threat Reputation Check ---",
        f"  Malicious IPs: {', '.join(reputation.get('malicious', [])) or 'None'}",
        f"  Suspicious IPs: {', '.join(reputation.get('suspicious', [])) or 'None'}",
        f"  Clean IPs: {', '.join(reputation.get('clean', [])) or 'None'}",
        "",
        f"--- Similar Past Offenses ---",
    ]

    if similar_cases:
        for i, case in enumerate(similar_cases, 1):
            report_lines.append(
                f"  [{i}] {case['description']} | Score: {case['similarity_score']}, "
                f"Source: {', '.join(case['source_ips'])}, Log Source: {case['log_source']}"
            )
    else:
        report_lines.append("  None found.")

    report_lines.extend([
        "",
        f"--- NuVex Decision & Reasoning ---",
        f"  Decision: {analysis.get('decision', 'N/A').upper()}",
        f"  Reasoning: {reasoning}",
        "",
        f"--- Recommendations ---",
    ])
    for rec in recommendations:
        report_lines.append(f"  - {rec}")

    report = "\n".join(report_lines)

    # Save report to file
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/offense_{offense_id}.txt"
    with open(filename, "w") as f:
        f.write(report)

    print(f"[NuVex] Incident report saved to: {filename}")
    print(f"[NuVex] Simulated email sent to soc_team@example.com")

    return report
