# nuvex-mvp/app/agents/offense_analyzer.py

def analyze_offense(offense_data: dict) -> dict:
    """
    Takes extracted offense fields and returns a summarized interpretation
    of the offense behavior for further decision making.
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
