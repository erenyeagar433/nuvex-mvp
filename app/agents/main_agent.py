# app/agents/main_agent.py

from app.agents.offense_analyzer import analyze_offense
from app.agents.memory_agent import MemoryAgent
from app.agents.decision_agent import make_decision
from app.agents.incident_reporter import generate_incident_report
from app.utils.emailer import send_email  # Optional email sender
import uuid

memory_agent = MemoryAgent(db_path="dummy_data/memory_base.json")

async def handle_offense(offense: dict) -> dict:
    """
    Main agent that handles the offense analysis workflow.
    """
    offense_id = offense.get("offense_id") or str(uuid.uuid4())
    print(f"\n[NuVex] Handling offense ID: {offense_id}")

    # Step 1: Analyze the offense
    extracted = offense  # Assuming already extracted
    analysis = analyze_offense(extracted)

    # Step 2: Memory lookup
    similar = memory_agent.search_similar_offenses(offense)
    analysis["similar_cases"] = [
        {
            "description": c["offense"].get("description", "No description"),
            "source_ips": c["offense"].get("source_ips", []),
            "destination_ips": c["offense"].get("destination_ips", []),
            "log_source": c["offense"].get("log_source", "unknown"),
            "tags": c["offense"].get("tags", []),
            "similarity_score": round(c["score"], 3)
        }
        for c in similar
    ]

    # Step 3: Make decision
    decision = make_decision(analysis["reputation"], analysis["similar_cases"])
    analysis.update(decision)  # Add decision + reasoning to result

    # Step 4: If escalated, generate incident report and simulate email
    if decision["decision"] == "escalate":
        report = generate_incident_report(offense_id, offense, analysis)

        print("\n=== Incident Report ===")
        print(report)

        # Optional: Simulate email notification
        send_email(
            subject=f"[ALERT] Escalated Offense {offense_id}",
            body=report,
            to="soc.team@example.com"
        )

    return analysis
