# nuvex-mvp/app/utils/field_extractor.py
import datetime

def extract_fields(offense: dict) -> dict:
    return {
        "offense_id": offense.get("offense_id"),
        "description": offense.get("description"),
        "magnitude": offense.get("magnitude"),
        "source_ips": offense.get("source_ips", []),
        "destination_ips": offense.get("destination_ips", []),
        "log_sources": offense.get("log_sources", []),
        "username": offense.get("username", "Unknown"),
        "start_time": _format_time(offense.get("start_time")),
        "event_count": offense.get("event_count", 0),
        "events": _extract_sample_events(offense.get("events", []))
    }

def _extract_sample_events(events):
    # Only pick the first 5 events for lightweight processing
    return [
        {
            "name": e.get("event_name"),
            "category": e.get("low_level_category"),
            "action": e.get("action"),
            "payload": e.get("payload")
        } for e in events[:5]
    ]

def _format_time(timestamp):
    if not timestamp:
        return "Unknown"
    try:
        return datetime.datetime.fromisoformat(timestamp).strftime("%b %d, %Y, %I:%M:%S %p")
    except Exception:
        return timestamp
