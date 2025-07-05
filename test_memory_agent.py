from app.agents.memory_agent import find_similar_cases

# Dummy test offense (copying one of your offense samples)
test_offense = {
    "description": "SSH Brute Force Detected",
    "source_ips": ["185.6.233.20"],
    "destination_ips": ["10.0.0.5"],
    "log_sources": ["Firewall-1"]
}

similar_cases = find_similar_cases(test_offense, top_k=3)

print("=== Top Similar Offenses ===")
for i, case in enumerate(similar_cases, 1):
    print(f"\n[{i}] Description: {case['description']}")
    print(f"    Source IPs: {case['source_ips']}")
    print(f"    Dest IPs: {case['destination_ips']}")
    print(f"    Log Source: {case['log_source']}")
    print(f"    Tags: {case.get('tags', [])}")
    print(f"    Similarity Score: {case['similarity_score']}")
