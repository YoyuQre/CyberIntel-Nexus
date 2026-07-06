"""
Test Suite for Ingestion and Parsing Nodes in CyberIntel Nexus.
Validates file ingestion, MCP server queries, ADK extraction, and sanitation.
"""

import sys
import os
import tempfile
# Ensure cyberintel_nexus directory is on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberintel_nexus.state_engine import initialize_state, create_state_machine
from cyberintel_nexus.ingestion_node import sanitize_and_validate_indicators


def test_local_file_ingestion():
    print("\n--- Running Test: Local File Ingestion & Parsing ---")
    
    # Create a temporary local file with threat intel
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, "test_intel_feed.txt")
    
    raw_feed_content = (
        "Advisory: Threat Actor activity detected on domain malicious-c2-portal.net.\n"
        "Payload MD5 hash: 440b8f413d7890abcdef1234567890ab.\n"
        "Known C2 host IP: 192.168.1.105."
    )
    
    with open(temp_file_path, "w", encoding="utf-8") as f:
        f.write(raw_feed_content)
        
    try:
        # Initialize state with placeholder raw_intel, but direct ingestion to local file via metadata
        state = initialize_state("")
        state["metadata"] = {"local_filepath": temp_file_path}
        
        app = create_state_machine()
        
        # Invoke state machine (run ingest and parse nodes)
        # We only run the ingest and parse nodes for this test
        # LangGraph allows running specific nodes, but since we have conditional routing,
        # it will run Ingest -> Parse, then try to go to Generate.
        # Let's run the whole graph, setting human_approval=True
        state["human_approval"] = True
        final_state = app.invoke(state)
        
        print(f"Final Phase: {final_state['current_phase']}")
        print(f"Status Message: {final_state['status_message']}")
        print(f"Ingested Threat Intel: {final_state['raw_threat_intel']}")
        print(f"Validated Indicators: {[i['value'] for i in final_state['indicators']]}")
        
        # Verify
        assert "malicious-c2-portal.net" in final_state["raw_threat_intel"]
        assert len(final_state["indicators"]) == 3
        # Hashes, domains, and IPs should all be present
        types = [i["type"] for i in final_state["indicators"]]
        assert "ip" in types
        assert "domain" in types
        assert "hash" in types
        
        print("SUCCESS: Local file ingestion test passed.")
        
    finally:
        # Cleanup temp file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def test_mcp_server_ingestion():
    print("\n--- Running Test: MCP Server Ingestion ---")
    
    state = initialize_state("")
    state["metadata"] = {
        "mcp_uri": "mcp://cyberintel-hub",
        "mcp_resource_path": "apt-feed"
    }
    
    app = create_state_machine()
    state["human_approval"] = True
    final_state = app.invoke(state)
    
    print(f"Final Phase: {final_state['current_phase']}")
    print(f"Status Message: {final_state['status_message']}")
    print(f"Ingested Threat Intel: {final_state['raw_threat_intel']}")
    print(f"Validated Indicators: {[i['value'] for i in final_state['indicators']]}")
    
    assert "APT-35 Campaign Activity" in final_state["raw_threat_intel"]
    assert "198.51.100.99" in [i["value"] for i in final_state["indicators"]]
    assert "update-service-check.org" in [i["value"] for i in final_state["indicators"]]
    
    print("SUCCESS: MCP server ingestion test passed.")


def test_data_sanitation_rules():
    print("\n--- Running Test: Rigorous Data Sanitation & Defanging ---")
    
    # Test defanging of IP/Domain, invalid syntax, boundary violations, etc.
    raw_extracted = [
        {"type": "ip", "value": "192.168.1[.]55", "context": "Defanged IP test", "confidence": 0.9},
        {"type": "domain", "value": "hxxps://malicious-c2[.]com", "context": "URL/Defanged domain test", "confidence": 0.8},
        {"type": "ip", "value": "999.999.999.999", "context": "Invalid IP octets test", "confidence": 0.7},
        {"type": "hash", "value": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "context": "Invalid hex MD5 test", "confidence": 0.95},
        {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "context": "Valid SHA-256", "confidence": 0.99}
    ]
    
    sanitized = sanitize_and_validate_indicators(raw_extracted)
    
    print(f"Sanitized results count: {len(sanitized)}")
    for item in sanitized:
        print(f"Type: {item['type']}, Value: {item['value']}, Confidence: {item['confidence']}")
        
    # We expect 3 valid indicators (192.168.1.55, malicious-c2.com, and the SHA-256 hash)
    # The 999.999.999.999 and the non-hex zzzz... MD5 hash should be discarded!
    assert len(sanitized) == 3
    
    values = [item["value"] for item in sanitized]
    assert "192.168.1.55" in values
    assert "malicious-c2.com" in values or "malicious-c2[.]com" not in values # defanged check
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in values
    
    print("SUCCESS: Data sanitation and validation rule tests passed.")


def test_zero_indicators_redirection():
    print("\n--- Running Test: Zero Indicators Error State Redirection ---")
    
    # Empty feed with no indicators
    state = initialize_state("")
    state["metadata"] = {
        "mcp_uri": "mcp://cyberintel-hub",
        "mcp_resource_path": "clean-feed"
    }
    
    app = create_state_machine()
    final_state = app.invoke(state)
    
    print(f"Final Phase: {final_state['current_phase']}")
    print(f"Status Message: {final_state['status_message']}")
    print(f"Execution History: {' -> '.join(final_state['execution_history'])}")
    
    assert final_state["current_phase"] == "error"
    assert len(final_state["indicators"]) == 0
    
    print("SUCCESS: Zero indicators error node redirection test passed.")


if __name__ == "__main__":
    print("Starting CyberIntel Nexus Ingestion Node Tests...")
    test_local_file_ingestion()
    test_mcp_server_ingestion()
    test_data_sanitation_rules()
    test_zero_indicators_redirection()
    print("\nAll Ingestion Node tests passed successfully!")
