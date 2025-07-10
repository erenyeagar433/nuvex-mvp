# app/agents/offense_analyzer.py

from app.utils.reputation import get_reputation
from app.agents.memory_agent import find_similar_cases
from app.agents.log_query_agent import generate_log_instructions


def analyze_behavior(offense_data: dict) -> dict:
    """
    Original L1-style behavior analysis based on IP patterns and log types.
    """
    magnitude = offense_data.get("magnitude", 0)
    source_ips = offense_data.get("source_ips", [])
    destination_ips = offense_data.get("destination_ips", [])
    log_sources = offense_data.get("log_sources", [])
    event_count = offense_data.get("event_count", 0)
    events = offense_data.get("events", [])

    # Deduce direction of attack and possible behavior
    if len(source_ips) == 1 and len(destination_ips) > 5:
        pattern = "single_remote_to_many_local"
        behavior = "Remote scanner or probing"
    elif len(destination_ips) == 1 and len(source_ips) > 5:
        pattern = "many_remote_to_single_local"
        behavior = "Targeted attack or flooding"
    else:
        pattern = "general_traffic"
        behavior = "Mixed or normal pattern"

    # Derive log types
    log_types = list(set([e.get("category", "unknown") for e in events]))

    summary = (
        f"Observed {behavior.lower()} behavior with {event_count} events. "
        f"Source IPs: {len(source_ips)}, Destination IPs: {len(destination_ips)}. "
        f"Log types observed: {', '.join(log_types)}."
    )

    return {
        "pattern": pattern,
        "behavior": behavior,
        "log_types": log_types,
        "magnitude": magnitude,
        "event_count": event_count,
        "summary": summary
    }


def analyze_offense(offense_data: dict) -> dict:
    """
    Main analyzer agent: combines behavior analysis, reputation, memory lookup,
    and dynamic log request generation.
    """
    # Step 1: Behavioral summary
    behavior_summary = analyze_behavior(offense_data)

    # Step 2: Extract IOCs and perform reputation lookup
    iocs = offense_data.get("source_ips", []) + offense_data.get("destination_ips", [])
    reputation_results = get_reputation(iocs)

    # Step 3: Find similar past offenses
    similar_cases = find_similar_cases(offense_data, top_k=3)

    # Step 4: Decision logic with reason
    if any(r.get("malicious_votes", 0) > 1 or r.get("abuse_confidence", 0) > 50 for r in reputation_results):
        decision = "escalate"
        reason = "High malicious votes or abuse confidence in IOC reputation"
    elif similar_cases and all("Data Exfiltration" in c.get("tags", []) for c in similar_cases):
        decision = "escalate"
        reason = "All similar cases tagged as Data Exfiltration"
    else:
        decision = "false_positive"
        reason = "No strong IOC or past pattern match"

    # Step 5: If escalated, generate log query instructions
    log_request = (
        generate_log_instructions(behavior_summary["summary"], offense_data)
        if decision == "escalate" else None
    )

    return {
        "summary": behavior_summary["summary"],
        "pattern": behavior_summary["pattern"],
        "behavior": behavior_summary["behavior"],
        "log_types": behavior_summary["log_types"],
        "reputation": reputation_results,
        "similar_cases": similar_cases,
        "decision": decision,
        "reason": reason,
        "log_request": log_request
    }
