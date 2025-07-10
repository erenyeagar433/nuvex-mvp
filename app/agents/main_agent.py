
# app/agents/main_agent.py

from app.utils.field_extractor import extract_fields
from app.agents.offense_analyzer import analyze_offense
from app.utils.log_writer import save_log_instructions

async def handle_offense(offense: dict) -> dict:
    # Step 1: Extract fields
    extracted = extract_fields(offense)

    # Step 2: Analyze offense
    analysis = analyze_offense(extracted)

    # Step 3: If escalated, save generated log instructions
    if analysis["decision"] == "escalate" and analysis.get("log_request"):
        offense_id = extracted.get("offense_id", "unknown")
        path = save_log_instructions(offense_id, analysis["log_request"])
        analysis["log_instruction_saved_to"] = path

    return analysis
