import sys
import os
import json
import time

# Ensure package is on path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from cyberintel_nexus.state_engine import initialize_state, create_state_machine
    from cyberintel_nexus.staging_portal import build_staging_portal_graph, resume_from_staging
except ModuleNotFoundError:
    from state_engine import initialize_state, create_state_machine
    from staging_portal import build_staging_portal_graph, resume_from_staging

def run_showcase():
    print("=" * 70)
    print("      CYBERINTEL NEXUS: MULTI-AGENT STATE MACHINE DEMO")
    print("=" * 70)
    
    # 1. Setup raw input with a malicious domain that triggers a critic loop violation
    raw_intel = (
        "ALERT: Threat actor activity detected.\n"
        "C2 IP observed: 198.51.100.99\n"
        "C2 DNS queries: sandbox-violation.org (malicious)\n"
    )
    
    print("\n[1] INITIALIZING THREAT INTEL INPUT...")
    print(f"--- Unstructured Report ---\n{raw_intel}---------------------------")
    
    state = initialize_state(raw_intel, max_retries=3)
    app = create_state_machine()
    
    print("\n[2] RUNNING MULTI-AGENT PIPELINE (INGEST -> PARSE -> GENERATE -> VALIDATE)...")
    print("Note: 'sandbox-violation.org' will trigger a sandbox policy violation.")
    print("The Critic Loop will automatically engage to self-correct the rule!\n")
    time.sleep(1)
    
    # Run the main graph. It will run through generation, detect the violation,
    # self-correct the rule, re-validate, and then halt at the Human Gate ('approval')
    result_state = app.invoke(state)
    
    print("\n--- Pipeline Execution Complete (First Pass) ---")
    print(f"Final Phase reached: {result_state['current_phase']}")
    print(f"Status Message: {result_state['status_message']}")
    print(f"Execution History: {' -> '.join(result_state['execution_history'])}")
    print(f"Retry Counts: {result_state['retry_counts']}")
    
    print("\n--- Generated & Corrected Rule Artifacts ---")
    for rule in result_state['rule_artifacts']:
        print(f"\nRule Name: {rule['rule_name']} ({rule['rule_type'].upper()})")
        print("Content:")
        print(rule['content'])
    
    print("\n" + "=" * 70)
    print("    HUMAN-IN-THE-LOOP (HITL) GATE IS NOW FROZEN")
    print("=" * 70)
    print("The pipeline is holding. We will now resume and approve the rules...")
    time.sleep(1)
    
    # 2. Resume the frozen state by simulating human approval
    resumed_state = resume_from_staging(
        result_state, 
        approve=True, 
        reviewer_id="Judge_Panel", 
        notes="Rules look clean and policy-compliant. Approved for production."
    )
    
    print("\n[3] RESUMING GRAPH WITH EXPLICIT HUMAN APPROVAL...")
    final_state = app.invoke(resumed_state)
    
    print("\n--- Final Pipeline Outcomes ---")
    print(f"Final Phase: {final_state['current_phase']}")
    print(f"Status Message: {final_state['status_message']}")
    print(f"Execution History: {' -> '.join(final_state['execution_history'])}")
    print("\nDeployment complete! All checks passed successfully.")
    print("=" * 70)

if __name__ == "__main__":
    run_showcase()
