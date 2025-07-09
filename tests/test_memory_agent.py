# tests/test_memory_agent.py

from app.agents.memory_agent import MemoryAgent

def test_memory_lookup():
    agent = MemoryAgent(db_path="dummy_data/memory_base.json")
    query = {
        "description": "Inbound connection from remote IP to multiple local IPs",
        "source_ips": ["20.64.104.142"],
        "destination_ips": ["202.52.44.1", "202.52.44.100"],
        "log_sources": ["HDC-PA-FW-PRI"]
    }

    results = agent.search_similar_offenses(query, top_k=3)
    print("\n--- Top Matches ---")
    for i, res in enumerate(results, 1):
        print(f"\n[{i}]")
        print("Score:", res["score"])
        print("Description:", res["offense"]["description"])
        print("Comment:", res["offense"].get("comment", "No comment"))

if __name__ == "__main__":
    test_memory_lookup()
