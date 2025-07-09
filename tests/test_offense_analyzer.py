# tests/test_offense_analyzer.py

from app.agents.offense_analyzer import analyze_offense

def test_analyze_offense_sample():
    sample_offense = {
        "magnitude": 6,
        "source_ips": ["8.8.8.8"],
        "destination_ips": ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"],
        "log_sources": ["FIREWALL"],
        "event_count": 20,
        "events": [
            {"category": "network"},
            {"category": "firewall"},
            {"category": "firewall"},
            {"category": "unknown"},
        ]
    }

    result = analyze_offense(sample_offense)

    print("\n=== Offense Analysis Result ===")
    for k, v in result.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    test_analyze_offense_sample()
