# tests/test_main_flow.py

import os
import asyncio
import pytest
from app.agents.main_agent import handle_offense

@pytest.mark.asyncio
async def test_offense_flow():
    dummy_offense = {
        "offense_id": "test-001",
        "description": "Simulated offense: Unusual data movement to external IP",
        "source_ips": ["45.153.160.2"],  # suspicious IP
        "destination_ips": ["10.0.0.5"],
        "log_source": "VPN-GW",
        "tags": ["Data Exfiltration", "Anomalous Behavior"]
    }

    result = await handle_offense(dummy_offense)

    assert result["decision"] in ["escalate", "false_positive"]

    if result["decision"] == "escalate":
        report_path = f"reports/offense_{dummy_offense['offense_id']}.txt"
        assert os.path.exists(report_path)
        with open(report_path, "r") as file:
            content = file.read()
            assert "Summary" in content
            assert "Recommendations" in content
    else:
        notes_path = "reports/false_positive_notes.txt"
        assert os.path.exists(notes_path)
        with open(notes_path, "r") as file:
            content = file.read()
            assert dummy_offense["offense_id"] in content

    print(f"✅ Test Passed — Decision: {result['decision']}")
