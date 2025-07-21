# tests/test_main_flow.py

import os
import json
from app.main_agent import process_offense

def test_offense_flow():
    dummy_offense = {
        "id": "test123",
        "source_ip": "45.153.160.2",  # known malicious IP
        "destination_ip": "10.0.0.5",
        "category": "Data Exfiltration",
        "description": "Unusual data movement to external IP",
        "timestamp": "2025-07-14T10:00:00Z"
    }

    decision = process_offense(dummy_offense)

    assert decision["decision"] in ["escalate", "false_positive"]

    if decision["decision"] == "escalate":
        report_path = f"reports/offense_{dummy_offense['id']}.txt"
        assert os.path.exists(report_path)
        with open(report_path, "r") as file:
            content = file.read()
            assert "Summary" in content
            assert "Recommendation" in content
    else:
        notes_path = "reports/false_positive_notes.txt"
        assert os.path.exists(notes_path)
        with open(notes_path, "r") as file:
            content = file.read()
            assert dummy_offense["id"] in content

    print(f"Test Passed ✅ — Decision: {decision['decision']}")
