# app/agents/main_agent.py

import uuid
from app.agents.offense_analyzer import enrich_offense as analyze_offense
from app.agents.memory_agent import find_similar_cases
from app.agents.decision_agent import make_decision
from app.agents.incident_reporter import generate_incident_report

async def handle_offense(offense: dict) -> dict:
    """
    Main NuVex Agent handler for incoming offenses.
    Handles analysis, memory recall, decision-making, and escalation simulation.
    """
    # Assign or generate a unique offense ID
    offense_id = offense.get("offense_id") or str(uuid.uuid4())
    print(f"\n[NuVex] 🧠 Handling Offense ID: {offense_id}")

    # STEP 1: Analyze the offense (log pattern, behavior, reputation, etc.)
    offense["offense_id"] = offense_id  # Ensure it's set for log writing
    analysis = analyze_offense(offense)

    # STEP 2: Retrieve similar past offenses from memory
    similar_cases = find_similar_cases(offense)
    analysis["similar_cases"] = similar_cases

    # STEP 3: Decision engine — escalate or mark false positive
    decision = make_decision(
        reputation_results=analysis.get("reputation", []),
        similar_cases=similar_cases,
        offense_id=offense_id
    )
    analysis.update(decision)

    # STEP 4: If escalation is needed, generate full SOC report
    if decision["decision"] == "escalate":
        report_path, report_content = generate_incident_report(offense_id, offense, analysis)
        print("\n=== 🚨 Incident Report ===")
        print(report_content)
        print(f"[NuVex] ✅ Incident report saved at: {report_path}")

    return analysis
