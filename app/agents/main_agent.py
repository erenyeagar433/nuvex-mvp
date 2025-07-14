# app/agents/main_agent.py

from app.agents.offense_analyzer import analyze_offense
from app.agents.memory_agent import MemoryAgent
from app.agents.decision_agent import make_decision
from app.agents.incident_reporter import generate_incident_report
from app.utils.emailer import send_email  # Optional email sender
import uuid

# Initialize memory agent with dummy KB
memory_agent = MemoryAgent(db_path="dummy_data/memory_base.json")

async def handle_offense(offense: dict) -> dict:
    """
    Main NuVex Agent handler for incoming offenses.
    Handles analysis, memory recall, decision-making, and escalation simulation.
    """
    # Assign or generate a unique offense ID
    offense_id = offense.get("offense_id") or str(uuid.uuid4())
    print(f"\n[NuVex] 🧠 Handling Offense ID: {offense_id}")

    # STEP 1: Analyze the offense (log pattern, behavior, reputation, etc.)
    extracted = offense  # (In MVP, assume already extracted)
    analysis = analyze_offense(extracted)

    # STEP 2: Retrieve similar past offenses from memory (ChromaDB or dummy KB)
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

    # STEP 3: Decision engine — escalate or mark false positive
    decision = make_decision(
        reputation_data=analysis.get("reputation", []),
        similar_cases=analysis.get("similar_cases", [])
    )
    analysis.update(decision)

    # STEP 4: If escalation is needed, generate full SOC report + simulate notification
    if decision["decision"] == "escalate":
        report = generate_incident_report(offense_id, offense, analysis)

        print("\n=== 🚨 Incident Report ===")
        print(report)

        try:
            # Optional: Simulate email notification (can skip if offline or stubbed)
            send_email(
                subject=f"[ALERT] Escalated Offense: {offense_id}",
                body=report,
                to="soc.team@example.com"
            )
        except Exception as e:
            print(f"[NuVex] Email simulation failed: {e}")

    return analysis
