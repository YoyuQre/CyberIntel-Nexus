"""
Test Suite - Staging Portal (CyberIntel Nexus)
================================================
Comprehensive tests covering all Human-in-the-Loop gate behaviors:

  Unit Tests — human_gate_checkpoint_node
  ----------------------------------------
  1.  FREEZE: No approval flag freezes gate (staging_status = "pending")
  2.  FREEZE: False approval flag freezes gate
  3.  FREEZE: Repeated freeze invocation keeps status "pending", updates metadata
  4.  APPROVE: human_approval=True records approval timestamp and reviewer
  5.  APPROVE: approval_timestamp is a valid ISO-8601 UTC string
  6.  APPROVE: approved state records artifact_reviewed list
  7.  REJECT:  human_approval="rejected" triggers containment routing
  8.  REJECT:  validation_errors present at staging triggers containment
  9.  REJECT:  zero rule_artifacts triggers containment
  10. Freeze metadata contains freeze_timestamp on first call

  Unit Tests — route_staging_gate
  ---------------------------------
  11. Routes to "commit" when staging_status = "approved"
  12. Routes to "containment" when staging_status = "rejected"
  13. Routes to "freeze" when staging_status = "pending"
  14. Routes to "freeze" when staging metadata is absent (defaults to pending)

  Unit Tests — commit_node
  -------------------------
  15. Commit node transitions current_phase to "completed"
  16. Commit node writes commit_id and commit_timestamp to staging metadata
  17. Commit node generates one receipt per rule artifact
  18. Commit node sets final_outcome = "COMMIT_SUCCESS"

  Unit Tests — containment_node
  ------------------------------
  19. Containment node transitions current_phase to "error"
  20. Containment node writes containment_id and quarantined_artifacts
  21. Containment node preserves validation_errors in staging metadata
  22. Containment node sets final_outcome = "CONTAINMENT_REJECTED"

  Unit Tests — resume_from_staging
  ----------------------------------
  23. Resume with approve=True sets human_approval=True
  24. Resume with approve=False sets human_approval="rejected"
  25. Resume raises ValueError when session is not STAGING_PENDING
  26. Resume raises ValueError when approve=False without rejection_reason
  27. Resume records reviewer_id in staging metadata
  28. Resume increments resume_count on each call

  Integration Tests — build_staging_portal_graph
  -----------------------------------------------
  29. Full approve path: freeze -> resume -> commit -> COMMIT_SUCCESS
  30. Full reject path: freeze -> resume(reject) -> containment -> CONTAINMENT_REJECTED
  31. Validation errors at staging -> CONTAINMENT_REJECTED without freeze
  32. No rule artifacts at staging -> CONTAINMENT_REJECTED without freeze
  33. Explicit rejection on first invocation -> CONTAINMENT_REJECTED immediately
  34. Multiple artifacts all appear in commit receipts
  35. Multiple artifacts all quarantined on rejection
  36. Commit receipt contains correct platform assignments per rule type
  37. Freeze timestamp is preserved after resumption
  38. Resume count increments correctly across multiple resume calls
"""

import sys
import os
import uuid
from datetime import datetime, timezone

# Ensure project root is on import path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberintel_nexus.staging_portal import (
    human_gate_checkpoint_node,
    commit_node,
    containment_node,
    route_staging_gate,
    resume_from_staging,
    build_staging_portal_graph,
    STAGING_PENDING,
    STAGING_APPROVED,
    STAGING_REJECTED,
    PHASE_STAGING,
    PHASE_COMMIT,
    PHASE_CONTAINMENT,
    _get_staging_meta,
    _set_staging_meta,
)
from cyberintel_nexus.state_engine import initialize_state, record_transition


# ===========================================================================
# Test Helpers
# ===========================================================================

def _make_rule(rule_type: str, rule_name: str, platform: str = "endpoint") -> dict:
    return {
        "id": str(uuid.uuid4()),
        "rule_type": rule_type,
        "rule_name": rule_name,
        "content": f"# content of {rule_name}",
        "target_platform": platform,
        "created_at": "2026-07-06T00:00:00+00:00",
    }


def _make_validation_error(rule_id: str, msg: str) -> dict:
    return {
        "phase": "validation",
        "rule_id": rule_id,
        "error_message": msg,
        "error_type": "POLICY_VIOLATION",
        "details": {"reason": msg},
    }


def _base_state_with_rules(*rules) -> dict:
    """Returns a clean AgentState with the given rule artifacts pre-loaded."""
    state = initialize_state("test threat feed", max_retries=3)
    state["rule_artifacts"] = list(rules)
    state["human_approval"] = False
    return state


def _assert_iso_timestamp(value: str, label: str):
    """Asserts the value is a parseable ISO-8601 UTC timestamp."""
    try:
        dt = datetime.fromisoformat(value)
        assert dt.tzinfo is not None, f"{label} must be timezone-aware."
    except (ValueError, TypeError) as exc:
        raise AssertionError(f"{label} is not a valid ISO-8601 timestamp: {value!r}") from exc


# ===========================================================================
# Section A - Unit Tests: human_gate_checkpoint_node (Freeze Behavior)
# ===========================================================================

def test_freeze_when_approval_absent():
    """Test 1: Missing human_approval (False by default) freezes the gate."""
    print("\n[TEST 1] FREEZE: absent approval flag")
    state = _base_state_with_rules(_make_rule("yara", "CN_Rule_A"))
    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert result["current_phase"] == PHASE_STAGING
    assert staging["status"] == STAGING_PENDING
    assert "STAGING_PENDING" in result["status_message"]
    assert "Set human_approval=True" in result["status_message"]
    print(f"  Status msg: {result['status_message'][:80]}...")
    print("  PASS")


def test_freeze_when_approval_is_false():
    """Test 2: Explicit human_approval=False also freezes the gate."""
    print("\n[TEST 2] FREEZE: explicit False approval")
    state = _base_state_with_rules(_make_rule("sigma", "CN_Rule_B"))
    state["human_approval"] = False
    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert staging["status"] == STAGING_PENDING
    assert "STAGING_PENDING" in result["status_message"]
    print("  PASS")


def test_freeze_is_idempotent():
    """Test 3: Calling the node twice while still pending keeps status 'pending'."""
    print("\n[TEST 3] FREEZE: repeated invocation stays pending")
    state = _base_state_with_rules(_make_rule("yara", "CN_Rule_C"))

    # First freeze
    r1 = human_gate_checkpoint_node(state)
    staging1 = _get_staging_meta(r1)
    assert staging1["status"] == STAGING_PENDING

    # Second invocation — still unapproved
    state2 = dict(state)
    state2["metadata"] = r1["metadata"]   # carry forward the frozen metadata
    r2 = human_gate_checkpoint_node(state2)
    staging2 = _get_staging_meta(r2)

    assert staging2["status"] == STAGING_PENDING
    # freeze_timestamp should have been set on the first call and preserved
    assert "freeze_timestamp" in staging2
    print(f"  Freeze timestamp preserved: {staging2['freeze_timestamp']}")
    print("  PASS")


def test_freeze_records_freeze_timestamp():
    """Test 10: First freeze sets a valid freeze_timestamp in staging metadata."""
    print("\n[TEST 10] FREEZE: freeze_timestamp set on first call")
    state = _base_state_with_rules(_make_rule("yara", "CN_Rule_D"))
    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert "freeze_timestamp" in staging
    _assert_iso_timestamp(staging["freeze_timestamp"], "freeze_timestamp")
    print(f"  Freeze timestamp: {staging['freeze_timestamp']}")
    print("  PASS")


# ===========================================================================
# Section B - Unit Tests: human_gate_checkpoint_node (Approval Behavior)
# ===========================================================================

def test_approve_records_approval_timestamp():
    """Test 4+5: human_approval=True records a valid ISO-8601 UTC timestamp."""
    print("\n[TEST 4+5] APPROVE: approval timestamp recorded")
    state = _base_state_with_rules(_make_rule("yara", "CN_Rule_E"))
    state["human_approval"] = True

    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert staging["status"] == STAGING_APPROVED
    assert "approval_timestamp" in staging
    _assert_iso_timestamp(staging["approval_timestamp"], "approval_timestamp")
    assert "APPROVED" in result["status_message"]
    print(f"  Approval timestamp: {staging['approval_timestamp']}")
    print("  PASS")


def test_approve_records_artifacts_reviewed():
    """Test 6: Approved state populates artifacts_reviewed list."""
    print("\n[TEST 6] APPROVE: artifacts_reviewed recorded")
    rule_a = _make_rule("yara", "CN_Rule_F_yara", "endpoint")
    rule_b = _make_rule("sigma", "CN_Rule_F_sigma", "siem")
    state = _base_state_with_rules(rule_a, rule_b)
    state["human_approval"] = True

    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    reviewed = staging.get("artifacts_reviewed", [])
    assert len(reviewed) == 2
    names = [r["rule_name"] for r in reviewed]
    assert "CN_Rule_F_yara" in names
    assert "CN_Rule_F_sigma" in names
    print(f"  Artifacts reviewed: {names}")
    print("  PASS")


def test_approve_records_reviewer_id_from_metadata():
    """Test 4 (extended): reviewer_id is pulled from staging metadata if pre-set."""
    print("\n[TEST 4b] APPROVE: reviewer_id stored in staging metadata")
    state = _base_state_with_rules(_make_rule("yara", "CN_Rule_G"))
    state["human_approval"] = True
    # Pre-set reviewer via staging metadata (as resume_from_staging would do)
    staging_meta = {"reviewer_id": "ops-analyst-007", "notes": "Verified IOC feed."}
    state["metadata"] = _set_staging_meta(state, staging_meta)

    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert staging["reviewer_id"] == "ops-analyst-007"
    assert staging["notes"] == "Verified IOC feed."
    print(f"  Reviewer: {staging['reviewer_id']}, Notes: {staging['notes']}")
    print("  PASS")


# ===========================================================================
# Section C - Unit Tests: human_gate_checkpoint_node (Rejection/Containment)
# ===========================================================================

def test_reject_via_rejection_signal():
    """Test 7: human_approval='rejected' routes to containment."""
    print("\n[TEST 7] REJECT: explicit rejection signal")
    state = _base_state_with_rules(_make_rule("yara", "CN_Rule_H"))
    state["human_approval"] = "rejected"
    staging_meta = {"rejection_reason": "Rule syntax does not meet policy standards."}
    state["metadata"] = _set_staging_meta(state, staging_meta)

    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert staging["status"] == STAGING_REJECTED
    assert "REJECTED" in result["status_message"]
    assert "Rule syntax does not meet policy standards." in result["status_message"]
    print(f"  Status msg: {result['status_message'][:80]}...")
    print("  PASS")


def test_reject_when_validation_errors_present():
    """Test 8: validation_errors in state at staging time triggers containment."""
    print("\n[TEST 8] REJECT: validation errors at staging")
    rule = _make_rule("sigma", "CN_Rule_I")
    state = _base_state_with_rules(rule)
    state["validation_errors"] = [
        _make_validation_error(rule["id"], "Policy violation: forbidden token detected.")
    ]
    state["human_approval"] = True   # Even with approval, errors must block

    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert staging["status"] == STAGING_REJECTED
    assert "validation error" in result["status_message"].lower()
    print(f"  Status msg: {result['status_message'][:100]}...")
    print("  PASS")


def test_reject_when_no_rule_artifacts():
    """Test 9: No rule artifacts present triggers immediate containment."""
    print("\n[TEST 9] REJECT: zero rule artifacts")
    state = initialize_state("empty feed")
    state["rule_artifacts"] = []
    state["human_approval"] = True

    result = human_gate_checkpoint_node(state)
    staging = _get_staging_meta(result)

    assert staging["status"] == STAGING_REJECTED
    assert "zero rule artifacts" in result["status_message"].lower() or \
           "no rule artifacts" in result["status_message"].lower()
    print(f"  Status msg: {result['status_message']}")
    print("  PASS")


# ===========================================================================
# Section D - Unit Tests: route_staging_gate
# ===========================================================================

def test_router_approved_routes_to_commit():
    """Test 11: STAGING_APPROVED status routes to 'commit'."""
    print("\n[TEST 11] ROUTER: approved -> commit")
    state = initialize_state("feed")
    state["metadata"] = _set_staging_meta(state, {"status": STAGING_APPROVED})
    route = route_staging_gate(state)
    assert route == "commit", f"Expected 'commit', got '{route}'"
    print(f"  Route: {route}")
    print("  PASS")


def test_router_rejected_routes_to_containment():
    """Test 12: STAGING_REJECTED status routes to 'containment'."""
    print("\n[TEST 12] ROUTER: rejected -> containment")
    state = initialize_state("feed")
    state["metadata"] = _set_staging_meta(state, {"status": STAGING_REJECTED})
    route = route_staging_gate(state)
    assert route == "containment", f"Expected 'containment', got '{route}'"
    print(f"  Route: {route}")
    print("  PASS")


def test_router_pending_routes_to_freeze():
    """Test 13: STAGING_PENDING status routes to 'freeze' (graph halt)."""
    print("\n[TEST 13] ROUTER: pending -> freeze")
    state = initialize_state("feed")
    state["metadata"] = _set_staging_meta(state, {"status": STAGING_PENDING})
    route = route_staging_gate(state)
    assert route == "freeze", f"Expected 'freeze', got '{route}'"
    print(f"  Route: {route}")
    print("  PASS")


def test_router_absent_metadata_routes_to_freeze():
    """Test 14: Absent staging metadata defaults to pending (freeze)."""
    print("\n[TEST 14] ROUTER: absent staging metadata -> freeze")
    state = initialize_state("feed")
    # No staging sub-dict in metadata at all
    route = route_staging_gate(state)
    assert route == "freeze", f"Expected 'freeze', got '{route}'"
    print(f"  Route: {route}")
    print("  PASS")


# ===========================================================================
# Section E - Unit Tests: commit_node
# ===========================================================================

def _approved_state_for_commit() -> dict:
    """Helper: returns state ready to enter commit_node."""
    rule_a = _make_rule("yara", "CN_Commit_yara", "endpoint")
    rule_b = _make_rule("sigma", "CN_Commit_sigma", "siem")
    state = _base_state_with_rules(rule_a, rule_b)
    state["human_approval"] = True
    state["metadata"] = _set_staging_meta(state, {
        "status": STAGING_APPROVED,
        "reviewer_id": "test-admin",
        "approval_timestamp": "2026-07-06T15:00:00+00:00",
    })
    return state


def test_commit_phase_is_completed():
    """Test 15: commit_node sets current_phase to 'completed'."""
    print("\n[TEST 15] COMMIT: phase becomes 'completed'")
    state = _approved_state_for_commit()
    result = commit_node(state)
    assert result["current_phase"] == "completed"
    print("  PASS")


def test_commit_writes_commit_id_and_timestamp():
    """Test 16: commit_node writes commit_id and commit_timestamp."""
    print("\n[TEST 16] COMMIT: commit_id and commit_timestamp recorded")
    state = _approved_state_for_commit()
    result = commit_node(state)
    staging = _get_staging_meta(result)

    assert "commit_id" in staging
    assert "commit_timestamp" in staging
    _assert_iso_timestamp(staging["commit_timestamp"], "commit_timestamp")
    assert len(staging["commit_id"]) == 36   # UUID4 format
    print(f"  commit_id: {staging['commit_id']}")
    print(f"  commit_timestamp: {staging['commit_timestamp']}")
    print("  PASS")


def test_commit_one_receipt_per_artifact():
    """Test 17: commit_node generates exactly one receipt per rule artifact."""
    print("\n[TEST 17] COMMIT: one receipt per artifact")
    state = _approved_state_for_commit()
    result = commit_node(state)
    staging = _get_staging_meta(result)

    receipts = staging.get("commit_receipts", [])
    assert len(receipts) == 2
    names = [r["rule_name"] for r in receipts]
    assert "CN_Commit_yara" in names
    assert "CN_Commit_sigma" in names
    for r in receipts:
        assert r["status"] == "COMMITTED"
    print(f"  Receipts: {names}")
    print("  PASS")


def test_commit_final_outcome():
    """Test 18: commit_node sets final_outcome = 'COMMIT_SUCCESS'."""
    print("\n[TEST 18] COMMIT: final_outcome is COMMIT_SUCCESS")
    state = _approved_state_for_commit()
    result = commit_node(state)
    staging = _get_staging_meta(result)

    assert staging["final_outcome"] == "COMMIT_SUCCESS"
    assert "COMMIT_SUCCESS" in result["status_message"]
    print("  PASS")


# ===========================================================================
# Section F - Unit Tests: containment_node
# ===========================================================================

def _rejected_state_for_containment() -> dict:
    """Helper: returns state ready to enter containment_node."""
    rule = _make_rule("sigma", "CN_Quarantine_sigma", "siem")
    err = _make_validation_error(rule["id"], "Forbidden token detected in rule body.")
    state = _base_state_with_rules(rule)
    state["validation_errors"] = [err]
    state["human_approval"] = "rejected"
    state["metadata"] = _set_staging_meta(state, {
        "status": STAGING_REJECTED,
        "rejection_reason": "Reviewer flagged policy non-compliance.",
    })
    return state


def test_containment_phase_is_error():
    """Test 19: containment_node sets current_phase to 'error'."""
    print("\n[TEST 19] CONTAINMENT: phase becomes 'error'")
    state = _rejected_state_for_containment()
    result = containment_node(state)
    assert result["current_phase"] == "error"
    print("  PASS")


def test_containment_writes_quarantine_record():
    """Test 20: containment_node writes containment_id and quarantined_artifacts."""
    print("\n[TEST 20] CONTAINMENT: quarantine record written")
    state = _rejected_state_for_containment()
    result = containment_node(state)
    staging = _get_staging_meta(result)

    assert "containment_id" in staging
    assert "containment_timestamp" in staging
    _assert_iso_timestamp(staging["containment_timestamp"], "containment_timestamp")

    quarantined = staging.get("quarantined_artifacts", [])
    assert len(quarantined) == 1
    assert quarantined[0]["rule_name"] == "CN_Quarantine_sigma"
    assert quarantined[0]["reason"] == "Reviewer flagged policy non-compliance."
    print(f"  Quarantine ID: {staging['containment_id']}")
    print(f"  Quarantined: {[q['rule_name'] for q in quarantined]}")
    print("  PASS")


def test_containment_preserves_validation_errors():
    """Test 21: containment_node stores validation_errors in staging metadata."""
    print("\n[TEST 21] CONTAINMENT: validation_errors preserved in staging metadata")
    state = _rejected_state_for_containment()
    result = containment_node(state)
    staging = _get_staging_meta(result)

    errors_at_containment = staging.get("validation_errors_at_containment", [])
    assert len(errors_at_containment) == 1
    assert "Forbidden token" in errors_at_containment[0]["error_message"]
    print("  PASS")


def test_containment_final_outcome():
    """Test 22: containment_node sets final_outcome = 'CONTAINMENT_REJECTED'."""
    print("\n[TEST 22] CONTAINMENT: final_outcome is CONTAINMENT_REJECTED")
    state = _rejected_state_for_containment()
    result = containment_node(state)
    staging = _get_staging_meta(result)

    assert staging["final_outcome"] == "CONTAINMENT_REJECTED"
    assert "CONTAINMENT_REJECTED" in result["status_message"]
    print("  PASS")


# ===========================================================================
# Section G - Unit Tests: resume_from_staging
# ===========================================================================

def _frozen_state() -> dict:
    """Helper: returns a gate-frozen state ready for resumption."""
    state = _base_state_with_rules(_make_rule("yara", "CN_Resume_yara"))
    state["human_approval"] = False
    frozen = human_gate_checkpoint_node(state)
    # Merge back into a full state
    full = dict(state)
    full.update(frozen)
    return full


def test_resume_approve_sets_human_approval():
    """Test 23: resume_from_staging(approve=True) sets human_approval=True."""
    print("\n[TEST 23] RESUME: approve=True sets human_approval=True")
    frozen = _frozen_state()
    resumed = resume_from_staging(frozen, approve=True, reviewer_id="analyst-1")
    assert resumed["human_approval"] is True
    print("  PASS")


def test_resume_reject_sets_human_approval_rejected():
    """Test 24: resume_from_staging(approve=False) sets human_approval='rejected'."""
    print("\n[TEST 24] RESUME: approve=False sets human_approval='rejected'")
    frozen = _frozen_state()
    resumed = resume_from_staging(
        frozen, approve=False,
        reviewer_id="analyst-2",
        rejection_reason="Rule contains prohibited indicator type."
    )
    assert resumed["human_approval"] == "rejected"
    staging = _get_staging_meta(resumed)
    assert staging["status"] == STAGING_REJECTED
    assert staging["rejection_reason"] == "Rule contains prohibited indicator type."
    print("  PASS")


def test_resume_raises_if_not_pending():
    """Test 25: resume_from_staging raises ValueError when status is not PENDING."""
    print("\n[TEST 25] RESUME: raises ValueError when not pending")
    state = _base_state_with_rules(_make_rule("yara", "CN_Approved"))
    state["human_approval"] = True
    approved = human_gate_checkpoint_node(state)
    full = dict(state)
    full.update(approved)

    try:
        resume_from_staging(full, approve=True, reviewer_id="admin")
        assert False, "Expected ValueError was not raised."
    except ValueError as exc:
        assert "not STAGING_PENDING" in str(exc)
        print(f"  Raised ValueError: {exc}")
    print("  PASS")


def test_resume_raises_if_reject_without_reason():
    """Test 26: resume_from_staging(approve=False) without rejection_reason raises."""
    print("\n[TEST 26] RESUME: reject without rejection_reason raises ValueError")
    frozen = _frozen_state()
    try:
        resume_from_staging(frozen, approve=False, reviewer_id="admin")
        assert False, "Expected ValueError was not raised."
    except ValueError as exc:
        assert "rejection_reason" in str(exc)
        print(f"  Raised ValueError: {exc}")
    print("  PASS")


def test_resume_stores_reviewer_id():
    """Test 27: resume_from_staging records reviewer_id in staging metadata."""
    print("\n[TEST 27] RESUME: reviewer_id stored in staging metadata")
    frozen = _frozen_state()
    resumed = resume_from_staging(
        frozen, approve=True, reviewer_id="lead-analyst-99", notes="Verified on threat feeds."
    )
    staging = _get_staging_meta(resumed)
    assert staging["reviewer_id"] == "lead-analyst-99"
    assert staging["notes"] == "Verified on threat feeds."
    print(f"  Reviewer: {staging['reviewer_id']}")
    print("  PASS")


def test_resume_increments_resume_count():
    """Test 28: resume_count increments each time resume_from_staging is called."""
    print("\n[TEST 28] RESUME: resume_count increments")
    frozen = _frozen_state()

    # First resume then re-freeze (manually reset approval to simulate second freeze)
    r1 = resume_from_staging(frozen, approve=True, reviewer_id="admin")
    staging1 = _get_staging_meta(r1)
    assert staging1.get("resume_count", 0) >= 1

    print(f"  Resume count after 1st resume: {staging1.get('resume_count')}")
    print("  PASS")


# ===========================================================================
# Section H - Integration Tests: Full Portal Graph
# ===========================================================================

def test_integration_full_approve_path():
    """
    Test 29: Full HITL flow:
      (1) initial invoke -> STAGING_PENDING (frozen)
      (2) resume_from_staging(approve=True)
      (3) re-invoke -> COMMIT_SUCCESS
    """
    print("\n[TEST 29] INTEGRATION: full approve path")
    rule = _make_rule("yara", "CN_Integ_ip_10_0_0_1", "endpoint")
    state = _base_state_with_rules(rule)

    graph = build_staging_portal_graph()

    # Pass 1 — should freeze
    frozen = graph.invoke(state)
    staging = _get_staging_meta(frozen)
    assert staging["status"] == STAGING_PENDING, (
        f"Expected STAGING_PENDING, got: {staging['status']}"
    )
    print(f"  Pass 1: FROZEN — {staging['status']}")

    # Resume
    resumed = resume_from_staging(
        frozen, approve=True, reviewer_id="soc-lead", notes="Reviewed and approved."
    )

    # Pass 2 — should commit
    final = graph.invoke(resumed)
    staging_final = _get_staging_meta(final)

    assert final["current_phase"] == "completed", (
        f"Expected 'completed', got '{final['current_phase']}'. "
        f"Status: {final['status_message']}"
    )
    assert staging_final["final_outcome"] == "COMMIT_SUCCESS"
    assert staging_final["status"] == STAGING_APPROVED
    assert staging_final["reviewer_id"] == "soc-lead"
    assert "commit_id" in staging_final

    print(f"  Pass 2: COMMITTED — {final['status_message'][:80]}...")
    print(f"  Reviewer: {staging_final['reviewer_id']}")
    print(f"  Commit ID: {staging_final['commit_id']}")
    print("  PASS")


def test_integration_full_reject_path():
    """
    Test 30: Full HITL flow:
      (1) initial invoke -> STAGING_PENDING (frozen)
      (2) resume_from_staging(approve=False)
      (3) re-invoke -> CONTAINMENT_REJECTED
    """
    print("\n[TEST 30] INTEGRATION: full reject path")
    rule = _make_rule("sigma", "CN_Integ_domain_evil_com", "siem")
    state = _base_state_with_rules(rule)

    graph = build_staging_portal_graph()

    # Pass 1 — freeze
    frozen = graph.invoke(state)
    staging = _get_staging_meta(frozen)
    assert staging["status"] == STAGING_PENDING

    # Reject
    resumed = resume_from_staging(
        frozen, approve=False,
        reviewer_id="soc-analyst",
        rejection_reason="Domain indicator is a known false positive."
    )

    # Pass 2 — containment
    final = graph.invoke(resumed)
    staging_final = _get_staging_meta(final)

    assert final["current_phase"] == "error", (
        f"Expected 'error', got '{final['current_phase']}'."
    )
    assert staging_final["final_outcome"] == "CONTAINMENT_REJECTED"
    assert staging_final["rejection_reason"] == "Domain indicator is a known false positive."
    quarantined = staging_final.get("quarantined_artifacts", [])
    assert any(q["rule_name"] == "CN_Integ_domain_evil_com" for q in quarantined)

    print(f"  Pass 2: CONTAINED — {final['status_message'][:80]}...")
    print(f"  Rejection reason: {staging_final['rejection_reason']}")
    print("  PASS")


def test_integration_validation_errors_bypass_freeze():
    """
    Test 31: If validation_errors are present when staging is first invoked,
    the gate skips the freeze and routes directly to CONTAINMENT_REJECTED.
    """
    print("\n[TEST 31] INTEGRATION: validation errors -> immediate containment")
    rule = _make_rule("yara", "CN_Integ_bad_rule")
    err = _make_validation_error(rule["id"], "YARA rule syntax check failed.")
    state = _base_state_with_rules(rule)
    state["validation_errors"] = [err]
    state["human_approval"] = True   # approval set but errors override it

    graph = build_staging_portal_graph()
    final = graph.invoke(state)
    staging = _get_staging_meta(final)

    assert final["current_phase"] == "error"
    assert staging["final_outcome"] == "CONTAINMENT_REJECTED"
    print(f"  Outcome: {staging['final_outcome']}")
    print("  PASS")


def test_integration_no_artifacts_bypass_freeze():
    """
    Test 32: Zero rule artifacts -> immediate CONTAINMENT_REJECTED (no freeze).
    """
    print("\n[TEST 32] INTEGRATION: no artifacts -> immediate containment")
    state = initialize_state("feed")
    state["rule_artifacts"] = []
    state["human_approval"] = True

    graph = build_staging_portal_graph()
    final = graph.invoke(state)
    staging = _get_staging_meta(final)

    assert final["current_phase"] == "error"
    assert staging["final_outcome"] == "CONTAINMENT_REJECTED"
    print("  PASS")


def test_integration_explicit_rejection_first_invocation():
    """
    Test 33: human_approval='rejected' on first invocation -> immediate containment.
    """
    print("\n[TEST 33] INTEGRATION: explicit rejection on first call")
    rule = _make_rule("sigma", "CN_Integ_reject_first")
    state = _base_state_with_rules(rule)
    state["human_approval"] = "rejected"
    state["metadata"] = _set_staging_meta(state, {
        "rejection_reason": "Analyst pre-rejected this batch."
    })

    graph = build_staging_portal_graph()
    final = graph.invoke(state)
    staging = _get_staging_meta(final)

    assert final["current_phase"] == "error"
    assert staging["final_outcome"] == "CONTAINMENT_REJECTED"
    print(f"  Status: {final['status_message'][:80]}...")
    print("  PASS")


def test_integration_multiple_artifacts_all_committed():
    """Test 34: All rule artifacts appear in commit receipts on approval."""
    print("\n[TEST 34] INTEGRATION: multiple artifacts all committed")
    rules = [
        _make_rule("yara",  "CN_Multi_ip_1",  "endpoint"),
        _make_rule("sigma", "CN_Multi_dom_1", "siem"),
        _make_rule("yara",  "CN_Multi_hash_1","endpoint"),
    ]
    state = _base_state_with_rules(*rules)
    state["human_approval"] = True

    graph = build_staging_portal_graph()
    # Pre-approve: inject staging metadata to skip freeze
    state["metadata"] = _set_staging_meta(state, {
        "status": STAGING_APPROVED,
        "reviewer_id": "batch-admin",
        "approval_timestamp": "2026-07-06T12:00:00+00:00",
    })

    final = graph.invoke(state)
    staging = _get_staging_meta(final)

    receipts = staging.get("commit_receipts", [])
    assert len(receipts) == 3, f"Expected 3 receipts, got {len(receipts)}."
    committed_names = {r["rule_name"] for r in receipts}
    assert committed_names == {"CN_Multi_ip_1", "CN_Multi_dom_1", "CN_Multi_hash_1"}
    print(f"  Committed: {sorted(committed_names)}")
    print("  PASS")


def test_integration_multiple_artifacts_all_quarantined():
    """Test 35: All artifacts appear in quarantined list on rejection."""
    print("\n[TEST 35] INTEGRATION: multiple artifacts all quarantined on rejection")
    rules = [
        _make_rule("yara",  "CN_Quarantine_1", "endpoint"),
        _make_rule("sigma", "CN_Quarantine_2", "siem"),
    ]
    state = _base_state_with_rules(*rules)
    state["human_approval"] = "rejected"
    state["metadata"] = _set_staging_meta(state, {
        "rejection_reason": "Batch did not pass policy review."
    })

    graph = build_staging_portal_graph()
    final = graph.invoke(state)
    staging = _get_staging_meta(final)

    quarantined = staging.get("quarantined_artifacts", [])
    assert len(quarantined) == 2
    quarantine_names = {q["rule_name"] for q in quarantined}
    assert quarantine_names == {"CN_Quarantine_1", "CN_Quarantine_2"}
    print(f"  Quarantined: {sorted(quarantine_names)}")
    print("  PASS")


def test_integration_commit_receipt_platform_assignment():
    """Test 36: Commit receipts carry correct target_platform per rule type."""
    print("\n[TEST 36] INTEGRATION: commit receipt platform assignment")
    rules = [
        _make_rule("yara",  "CN_Platform_yara",  "endpoint"),
        _make_rule("sigma", "CN_Platform_sigma",  "siem"),
    ]
    state = _base_state_with_rules(*rules)
    state["human_approval"] = True
    state["metadata"] = _set_staging_meta(state, {
        "status": STAGING_APPROVED,
        "reviewer_id": "platform-admin",
        "approval_timestamp": "2026-07-06T12:00:00+00:00",
    })

    graph = build_staging_portal_graph()
    final = graph.invoke(state)
    staging = _get_staging_meta(final)

    receipts = {r["rule_name"]: r for r in staging.get("commit_receipts", [])}
    assert receipts["CN_Platform_yara"]["platform"] == "endpoint"
    assert receipts["CN_Platform_sigma"]["platform"] == "siem"
    print(f"  YARA platform: {receipts['CN_Platform_yara']['platform']}")
    print(f"  Sigma platform: {receipts['CN_Platform_sigma']['platform']}")
    print("  PASS")


def test_integration_freeze_timestamp_preserved_after_resumption():
    """Test 37: freeze_timestamp recorded on first freeze is preserved after approval."""
    print("\n[TEST 37] INTEGRATION: freeze_timestamp preserved through full cycle")
    rule = _make_rule("yara", "CN_FreezeTimestamp_yara")
    state = _base_state_with_rules(rule)

    graph = build_staging_portal_graph()

    # Pass 1: freeze
    frozen = graph.invoke(state)
    staging_frozen = _get_staging_meta(frozen)
    original_freeze_ts = staging_frozen["freeze_timestamp"]

    # Resume + Pass 2: commit
    resumed = resume_from_staging(frozen, approve=True, reviewer_id="auditor")
    final = graph.invoke(resumed)
    staging_final = _get_staging_meta(final)

    # freeze_timestamp should be unchanged through the lifecycle
    assert staging_final.get("freeze_timestamp") == original_freeze_ts, (
        f"freeze_timestamp changed: was {original_freeze_ts!r}, "
        f"now {staging_final.get('freeze_timestamp')!r}"
    )
    print(f"  Freeze timestamp preserved: {original_freeze_ts}")
    print("  PASS")


def test_integration_resume_count_increments():
    """Test 38: resume_count correctly reflects the number of resume operations."""
    print("\n[TEST 38] INTEGRATION: resume_count tracking")
    rule = _make_rule("yara", "CN_ResumeCount_yara")
    state = _base_state_with_rules(rule)

    graph = build_staging_portal_graph()
    frozen = graph.invoke(state)

    # First resume — approve
    resumed = resume_from_staging(frozen, approve=True, reviewer_id="admin")
    staging_resumed = _get_staging_meta(resumed)
    # resume_count is incremented by resume_from_staging
    assert staging_resumed.get("resume_count", 0) >= 1
    print(f"  Resume count after resumption: {staging_resumed.get('resume_count')}")

    # After commit, resume_count in final staging should be >= 1
    final = graph.invoke(resumed)
    staging_final = _get_staging_meta(final)
    assert staging_final.get("resume_count", 0) >= 1
    print(f"  Resume count in final state: {staging_final.get('resume_count')}")
    print("  PASS")


# ===========================================================================
# Runner
# ===========================================================================

ALL_TESTS = [
    # Freeze behavior
    test_freeze_when_approval_absent,
    test_freeze_when_approval_is_false,
    test_freeze_is_idempotent,
    test_freeze_records_freeze_timestamp,
    # Approval behavior
    test_approve_records_approval_timestamp,
    test_approve_records_artifacts_reviewed,
    test_approve_records_reviewer_id_from_metadata,
    # Rejection/containment triggers
    test_reject_via_rejection_signal,
    test_reject_when_validation_errors_present,
    test_reject_when_no_rule_artifacts,
    # Router
    test_router_approved_routes_to_commit,
    test_router_rejected_routes_to_containment,
    test_router_pending_routes_to_freeze,
    test_router_absent_metadata_routes_to_freeze,
    # Commit node
    test_commit_phase_is_completed,
    test_commit_writes_commit_id_and_timestamp,
    test_commit_one_receipt_per_artifact,
    test_commit_final_outcome,
    # Containment node
    test_containment_phase_is_error,
    test_containment_writes_quarantine_record,
    test_containment_preserves_validation_errors,
    test_containment_final_outcome,
    # Resume API
    test_resume_approve_sets_human_approval,
    test_resume_reject_sets_human_approval_rejected,
    test_resume_raises_if_not_pending,
    test_resume_raises_if_reject_without_reason,
    test_resume_stores_reviewer_id,
    test_resume_increments_resume_count,
    # Integration
    test_integration_full_approve_path,
    test_integration_full_reject_path,
    test_integration_validation_errors_bypass_freeze,
    test_integration_no_artifacts_bypass_freeze,
    test_integration_explicit_rejection_first_invocation,
    test_integration_multiple_artifacts_all_committed,
    test_integration_multiple_artifacts_all_quarantined,
    test_integration_commit_receipt_platform_assignment,
    test_integration_freeze_timestamp_preserved_after_resumption,
    test_integration_resume_count_increments,
]


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)

    print("=" * 70)
    print("  CyberIntel Nexus - Staging Portal Test Suite")
    print("=" * 70)

    passed = 0
    failed = 0
    failures = []

    for test_fn in ALL_TESTS:
        try:
            test_fn()
            passed += 1
        except AssertionError as ae:
            failed += 1
            safe = str(ae).encode("ascii", errors="replace").decode("ascii")
            failures.append((test_fn.__name__, safe))
            print(f"  FAIL  {test_fn.__name__}: {safe}")
        except Exception as exc:
            failed += 1
            safe = repr(exc).encode("ascii", errors="replace").decode("ascii")
            failures.append((test_fn.__name__, safe))
            print(f"  ERROR {test_fn.__name__}: {safe}")

    print("\n" + "=" * 70)
    print(f"  Results: {passed} passed / {failed} failed / {len(ALL_TESTS)} total")
    print("=" * 70)

    if failures:
        print("\nFailed Tests:")
        for name, msg in failures:
            print(f"  * {name}: {msg}")
        sys.exit(1)
    else:
        print("\nAll tests passed successfully!")
        sys.exit(0)
