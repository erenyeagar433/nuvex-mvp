# app/agents/decision_agent.py

import datetime
import os

from app.agents.model_router import generate_dynamic_prompt

FALSE_POSITIVE_LOG = "reports/false_positive_notes.txt"  # Updated path

def save_false_positive_note(reasons: list, offense_id: str = "Unknown") -> None:
    """
    Save a note to a text file when an offense is marked as a false positive.
    """
    # Ensure the reports/ directory exists
    os.makedirs(os.path.dirname(FALSE_POSITIVE_LOG), exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    note = f"[{timestamp}] Offense ID: {offense_id}\nReason(s):\n"
    for r in reasons:
        note += f"- {r}\n"
    note += "\n"

    with open(FALSE_POSITIVE_LOG, "a") as f:
        f.write(note)

def make_decision(reputation_results, similar_cases, offense_id: str = "Unknown") -> dict:
    """
    Given reputation data and memory results, decide whether the offense
    should be escalated or marked as false positive. Returns decision + reason.
    """
    decision = "false_positive"
    reasons = []

    # Rule 1: Any IOC with high malicious or abuse score
    for r in reputation_results:
        if r.get("malicious_votes", 0) > 1:
            decision = "escalate"
            reasons.append(f"Malicious score > 1 for {r.get('ioc', r.get('ip', 'unknown'))}")
        if r.get("abuse_confidence", 0) > 50:
            decision = "escalate"
            reasons.append(f"AbuseIPDB confidence > 50 for {r.get('ip', 'unknown')}")

    # Rule 2: Past cases tagged as critical behavior
    if similar_cases:
        tag_matches = [c for c in similar_cases if "Data Exfiltration" in c.get("tags", [])]
        if tag_matches:
            decision = "escalate"
            reasons.append("Similar past cases tagged as Data Exfiltration")

    # Dynamic reasoning if no strong indicators found
    if not reasons:
        reputation_summary = "\n".join([str(r) for r in reputation_results]) or "None"
        memory_summary = "\n".join([f"Offense ID: {c.get('offense_id', 'N/A')}, Tags: {c.get('tags', [])}" for c in similar_cases]) or "None"
        prompt = f"""
You are a SOC analyst agent. The following offense was analyzed, and no immediate high-risk indicators were detected.
Provide a human-readable justification for why this offense could be marked as a false positive.

Reputation Results:
{reputation_summary}

Memory Matches:
{memory_summary}

Give 1-2 lines of reasoning based on the above, as if explaining to a security analyst.
"""
        response = generate_dynamic_prompt(prompt).strip()
        reasons.append(response)

    if decision == "false_positive":
        save_false_positive_note(reasons, offense_id)

    return {
        "decision": decision,
        "reasoning": reasons
    }
