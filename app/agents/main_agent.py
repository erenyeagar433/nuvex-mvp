# app/agents/main_agent.py

import uuid
from app.agents.offense_analyzer import enrich_offense as analyze_offense
from app.agents.memory_agent import find_similar_cases
from app.agents.decision_agent import make_decision
from app.agents.incident_reporter import generate_incident_report
from app.agents.model_router import generate_dynamic_prompt

def infer_offense_type(offense: dict) -> str:
    prompt = f"""You are a SOC Analyst AI. Based on the following offense description and sample events, infer the offense type.

Offense Description:
{offense.get("description", "")}

Events:
{[e.get("event_type", "") for e in offense.get("events", [])]}

Respond with only the offense type in 3-5 words. No explanation."""
    return generate_dynamic_prompt(prompt).strip()

async def handle_offense(offense: dict) -> dict:
    """
    Main NuVex Agent handler for incoming offenses.
    Handles analysis, memory recall, decision-making, and escalation simulation.
    """
    # Assign or generate a unique offense ID
    offense_id = offense.get("offense_id") or str(uuid.uuid4())
    print(f"\n[NuVex] 🧠 Handling Offense ID: {offense_id}")
    offense["offense_id"] = offense_id

    # STEP 1: Analyze the offense (log pattern, behavior, reputation, etc.)
    analysis = analyze_offense(offense)

    # STEP 1.5: Dynamically infer offense type if not provided
    if not offense.get("offense_type"):
        offense["offense_type"] = infer_offense_type(offense)
        print(f"[NuVex] 🏷️ Inferred offense type: {offense['offense_type']}")

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
