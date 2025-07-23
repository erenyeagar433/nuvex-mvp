# app/agents/offense_analyzer.py
from app.utils.reputation import get_reputation
from app.agents.log_query_agent import generate_log_instructions
from app.utils.log_writer import save_log_instructions

def enrich_offense(offense_data: dict) -> dict:
    """Adds reputation and log instruction details to the offense"""
    source_ips = offense_data.get("source_ips", [])

    reputation_results = [get_reputation(ip) for ip in source_ips]
    log_instructions = generate_log_instructions(offense_data)
    save_log_instructions(offense_data.get("offense_id", "unknown"), log_instructions)  # Changed from "id" to "offense_id"

    offense_data["reputation"] = reputation_results
    offense_data["log_instructions"] = log_instructions
    return offense_data
