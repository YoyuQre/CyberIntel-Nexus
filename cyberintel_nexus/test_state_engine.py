"""
Validation Test Suite for CyberIntel Nexus State Engine.
Tests deterministic state transitions, validation rules, and loop prevention mechanisms.
"""

import sys
import os
# Ensure cyberintel_nexus directory is on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberintel_nexus.state_engine import (
    initialize_state,
    create_state_machine,
    is_transition_safe,
    AgentState
)


def test_happy_path():
    print("\n--- Running Test: Happy Path (Extraction -> Gen -> Validate -> Approval -> Deploy) ---")
    raw_intel = "Threat actor seen using command and control IP 192.168.10.25 and domain bad-domain.net"
    state = initialize_state(raw_intel, max_retries=3)
    
    # Compile graph
    app = create_state_machine()
    
    # 1. Run through node sequence.
    # To simulate human approval mid-run, we will run the pipeline.
    # In a happy path, we need human approval to be set.
    # Let's mock a sequence where the orchestrator invokes nodes.
    
    # Let's run it by first setting human_approval = True
    state["human_approval"] = True
    final_state = app.invoke(state)
    
    print(f"Final Phase: {final_state['current_phase']}")
    print(f"Status Message: {final_state['status_message']}")
    print(f"Parsed Indicators: {[i['value'] for i in final_state['indicators']]}")
    print(f"Generated Rules: {[r['rule_name'] for r in final_state['rule_artifacts']]}")
    print(f"Validation Errors: {final_state['validation_errors']}")
    print(f"Execution History: {' -> '.join(final_state['execution_history'])}")
    
    assert final_state["current_phase"] == "completed"
    assert len(final_state["indicators"]) == 2
    assert len(final_state["rule_artifacts"]) == 2
    print("SUCCESS: Happy path test completed.")


def test_no_indicators_path():
    print("\n--- Running Test: No Indicators Found (Ingest -> Parse -> Error) ---")
    raw_intel = "Normal benign log info with no threats."
    state = initialize_state(raw_intel, max_retries=3)
    app = create_state_machine()
    
    final_state = app.invoke(state)
    
    print(f"Final Phase: {final_state['current_phase']}")
    print(f"Status Message: {final_state['status_message']}")
    print(f"Execution History: {' -> '.join(final_state['execution_history'])}")
    
    assert final_state["current_phase"] == "error"
    assert "isolation" in final_state["status_message"].lower() or "failed" in final_state["status_message"].lower()
    print("SUCCESS: Zero indicators error node redirection test completed.")


def test_loop_prevention_retry_limit():
    print("\n--- Running Test: Loop Prevention via Max Retry Limit ---")
    # We introduce "invalid_signature_test.com" to trigger a validation error
    raw_intel = "Threat activity detected at domain invalid_signature_test.com"
    state = initialize_state(raw_intel, max_retries=2)  # Set max retries to 2 for faster test
    app = create_state_machine()
    
    final_state = app.invoke(state)
    
    print(f"Final Phase: {final_state['current_phase']}")
    print(f"Status Message: {final_state['status_message']}")
    print(f"Execution History: {' -> '.join(final_state['execution_history'])}")
    print(f"Retry Counts: {final_state['retry_counts']}")
    
    assert final_state["current_phase"] == "error"
    assert final_state["retry_counts"]["generate"] >= 1
    print("SUCCESS: Infinite routing loop prevented via retry threshold containment.")


def test_cyclic_loop_detection():
    print("\n--- Running Test: Direct Cycle Detection and Rejection ---")
    state = initialize_state("Mock intel", max_retries=3)
    
    # Mock a transition history: generate -> validate -> generate -> validate
    state["current_phase"] = "validate"
    state["execution_history"] = ["ingest", "parse", "generate", "validate", "generate", "validate"]
    
    # Test if transition back to 'generate' is caught by the cyclic route bouncer
    is_safe = is_transition_safe(state, "generate")
    print(f"Is transition to 'generate' safe after cycle pattern? {is_safe}")
    
    assert is_safe is False
    print("SUCCESS: Cyclic loop detector successfully blocked oscillatory route.")


if __name__ == "__main__":
    print("Starting CyberIntel Nexus State Engine Tests...")
    test_happy_path()
    test_no_indicators_path()
    test_loop_prevention_retry_limit()
    test_cyclic_loop_detection()
    print("\nAll State Engine tests passed successfully!")
