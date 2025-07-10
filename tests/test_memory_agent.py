# tests/test_memory_agent.py

from app.agents.memory_agent import find_similar_cases

def test_memory_lookup():
    query = {
        "description": "Inbound connection from remote IP to multiple local IPs",
        "source_ips": ["20.64.104.142"],
        "destination_ips": ["202.52.44.1", "202.52.44.100"],
        "log_sources": ["HDC-PA-FW-PRI"]
    }

    results = find_similar_cases(query, top_k=3)
    print("\n--- Top Matches ---")
    for i, res in enumerate(results, 1):
        print(f"\n[{i}]")
        print("Similarity Score:", res["similarity_score"])
        print("Description     :", res["description"])
        print("Source IPs      :", res["source_ips"])
        print("Destination IPs :", res["destination_ips"])
        print("Log Source      :", res["log_source"])
        print("Tags            :", ", ".join(res.get("tags", [])))
        print("Comment         :", res.get("comment", "No comment"))

if __name__ == "__main__":
    test_memory_lookup()
