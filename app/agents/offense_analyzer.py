# app/agents/offense_analyzer.py

from app.utils.reputation import get_reputation
from app.agents.memory_agent import find_similar_cases
from app.agents.log_query_agent import generate_log_instructions
from app.utils.log_writer import save_log_instructions
from app.agents.decision_agent import make_decision


def analyze_behavior(offense_data: dict) -> dict:
    magnitude = offense_data.get("magnitude", 0)
    source_ips = offense_data.get("source_ips", [])
    destination_ips = offense_data.get("destination_ips", [])
    log_sources = offense_data.get("log_sources", [])
    event_count = offense_data.get("event_count", 0)
    events = offense_data.get("events", [])

    if len(source_ips) == 1 and len(destination_ips) > 5:
        pattern = "single_remote_to_many_local"
        behavior = "Remote scanner or probing"
    elif len(destination_ips) == 1 and len(source_ips) > 5:
        pattern = "many_remote_to_single_local"
        behavior = "Targeted attack or flooding"
    else:
        pattern = "general_traffic"
        behavior = "Mixed or normal pattern"

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
    offense_id = offense_data.get("offense_id", "unknown")

    # Step 1: Behavior analysis
    behavior_summary = analyze_behavior(offense_data)

    # Step 2: IOC reputation
    iocs = offense_data.get("source_ips", []) + offense_data.get("destination_ips", [])
    reputation_results = get_reputation(iocs)

    # Step 3: Memory retrieval
    similar_cases = find_similar_cases(offense_data, top_k=3)

    # Step 4: Decision agent
    decision_result = make_decision(reputation_results, similar_cases)
    decision = decision_result["decision"]
    reasoning = decision_result["reasoning"]

    # Step 5: Log instruction generation and saving
    log_request = None
    if decision == "escalate":
        log_request = generate_log_instructions(
            offense_summary=behavior_summary["summary"],
            offense_details=offense_data
        )
        save_log_instructions(offense_id, log_request)

    return {
        "summary": behavior_summary["summary"],
        "pattern": behavior_summary["pattern"],
        "behavior": behavior_summary["behavior"],
        "log_types": behavior_summary["log_types"],
        "reputation": reputation_results,
        "similar_cases": similar_cases,
        "decision": decision,
        "reasoning": reasoning,
        "log_request": log_request
    }
