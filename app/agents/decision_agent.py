# app/agents/decision_agent.py

def make_decision(reputation_results, similar_cases) -> dict:
    """
    Given reputation data and memory results, decide whether the offense
    should be escalated or marked as false positive. Returns decision + reason.
    """
    decision = "false_positive"
    reasons = []

    # Rule 1: Any IOC with high malicious or abuse score
    for r in reputation_results:
        if r.get("malicious_votes", 0) > 1:
            decision = "escalate"
            reasons.append(f"Malicious score > 1 for {r.get('ioc', r.get('ip', 'unknown'))}")
        if r.get("abuse_confidence", 0) > 50:
            decision = "escalate"
            reasons.append(f"AbuseIPDB confidence > 50 for {r.get('ip', 'unknown')}")

    # Rule 2: Past cases tagged as critical behavior
    if similar_cases:
        tag_matches = [c for c in similar_cases if "Data Exfiltration" in c.get("tags", [])]
        if tag_matches:
            decision = "escalate"
            reasons.append("Similar past cases tagged as Data Exfiltration")

    if not reasons:
        reasons.append("No significant threat indicators detected")

    return {
        "decision": decision,
        "reasoning": reasons
    }
