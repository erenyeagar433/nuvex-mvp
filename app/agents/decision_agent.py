# app/agents/decision_agent.py

import datetime
import os

from app.agents.model_router import get_model_response  # Uses OpenAI or Gemini

FALSE_POSITIVE_LOG = "false_positive_notes.txt"


def save_false_positive_note(reasons: list, offense_id: str = "Unknown") -> None:
    """
    Save a note to a text file when an offense is marked as a false positive.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    note = f"[{timestamp}] Offense ID: {offense_id}\nReason(s):\n"
    for r in reasons:
        note += f"- {r}\n"
    note += "\n"

    with open(FALSE_POSITIVE_LOG, "a") as f:
        f.write(note)


def generate_dynamic_reasoning(reputation_results, similar_cases, decision) -> str:
    """
    Use LLM to generate a dynamic justification for the decision.
    """
    prompt = f"""
You are an L1 SOC analyst assistant. An offense has been analyzed using threat intelligence and memory lookup.

Decision: {decision.upper()}

Based on the following data, explain in 2-3 bullet points why this decision is reasonable.

Reputation results:
{reputation_results}

Similar past cases:
{similar_cases}

Avoid repeating the input and avoid headers like 'Explanation:'. Just write the reasoning.
    """.strip()

    response = get_model_response(prompt)
    return response.strip()


def make_decision(reputation_results, similar_cases, offense_id: str = "Unknown") -> dict:
    """
    Given reputation data and memory results, decide whether the offense
    should be escalated or marked as false positive. Returns decision + reasoning.
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

    # If still false positive, generate dynamic LLM explanation
    if decision == "false_positive":
        dynamic_reason = generate_dynamic_reasoning(reputation_results, similar_cases, decision)
        reasons = [dynamic_reason]
        save_false_positive_note(reasons, offense_id)

    return {
        "decision": decision,
        "reasoning": reasons
    }
