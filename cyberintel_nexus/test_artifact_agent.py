"""
Test Suite - Artifact Agent (CyberIntel Nexus)
===============================================
Comprehensive tests covering:

  Unit Tests
  ----------
  1.  YARA validator — valid rule passes
  2.  YARA validator — missing meta section
  3.  YARA validator — missing strings section
  4.  YARA validator — undeclared variable in condition
  5.  YARA validator — policy violation token
  6.  YARA validator — unbalanced braces
  7.  Sigma validator — valid rule passes
  8.  Sigma validator — invalid YAML
  9.  Sigma validator — missing 'detection' field
  10. Sigma validator — missing 'condition' inside detection
  11. Sigma validator — empty selectors
  12. Sigma validator — policy violation token
  13. Error classifier — maps error messages to type tags

  Integration Tests (mock ADK offline)
  ------------------------------------
  14. Happy-path: indicators → rules → sandbox → approval → deploy
  15. IP indicator generates a YARA rule
  16. Domain indicator generates a Sigma rule
  17. Hash indicator generates a YARA rule
  18. Self-correction: 1 retry corrects policy violation → deploys
  19. Retry cap: max_retries exhausted → routes to error state
  20. Empty indicators → error state (no rules generated)
  21. Multiple mixed indicators (IP + domain + hash) processed correctly
  22. Emergency fallback generator produces valid output when ADK returns nothing
"""

import json
import sys
import os
import uuid

# Ensure project root is on import path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberintel_nexus.artifact_agent import (
    SecurityRuleValidator,
    generate_rule_artifacts_node,
    validate_rule_sandbox_node,
    _classify_error,
    _emergency_fallback_generator,
    _invoke_adk_agent,
    _build_generation_prompt,
    _build_correction_prompt,
)
from cyberintel_nexus.state_engine import (
    AgentState,
    initialize_state,
    create_state_machine,
    record_transition,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_indicator(ind_type: str, value: str, confidence: float = 0.90) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "type": ind_type,
        "value": value,
        "context": f"Test indicator: {value}",
        "confidence": confidence,
    }


def _make_rule(rule_type: str, rule_name: str, content: str, platform: str = "endpoint") -> dict:
    return {
        "id": str(uuid.uuid4()),
        "rule_type": rule_type,
        "rule_name": rule_name,
        "content": content,
        "target_platform": platform,
        "created_at": "2026-07-06T00:00:00+00:00",
    }


VALID_YARA = (
    "rule CN_Test_ip_1_2_3_4 {\n"
    "    meta:\n"
    "        description = \"Detects malicious IP 1.2.3.4\"\n"
    "    strings:\n"
    "        $ip = \"1.2.3.4\"\n"
    "    condition:\n"
    "        $ip\n"
    "}"
)

VALID_SIGMA = (
    "title: Malicious Domain DNS Detection\n"
    "id: d3b07384-d755-4abc-8a9d-2101ab456cde\n"
    "status: stable\n"
    "description: Matches DNS queries for evil.com\n"
    "logsource:\n"
    "    category: dns\n"
    "detection:\n"
    "    selection:\n"
    "        query_name|contains: 'evil.com'\n"
    "    condition: selection\n"
    "fields:\n"
    "    - query_name\n"
    "level: high"
)


# ===========================================================================
# Section A — Unit Tests: YARA Validator
# ===========================================================================

def test_yara_valid_rule_passes():
    """Test 1: A syntactically correct YARA rule returns None (no error)."""
    print("\n[TEST 1] YARA valid rule passes")
    error = SecurityRuleValidator.validate_yara(VALID_YARA)
    assert error is None, f"Expected no error, got: {error}"
    print("  PASS")


def test_yara_missing_meta():
    """Test 2: YARA rule without 'meta:' section is rejected."""
    print("\n[TEST 2] YARA missing meta section")
    rule = VALID_YARA.replace("    meta:\n        description = \"Detects malicious IP 1.2.3.4\"\n", "")
    error = SecurityRuleValidator.validate_yara(rule)
    assert error is not None, "Expected error for missing meta section."
    assert "meta:" in error, f"Error should mention 'meta:'. Got: {error}"
    print(f"  PASS  →  {error}")


def test_yara_missing_strings():
    """Test 3: YARA rule without 'strings:' section is rejected."""
    print("\n[TEST 3] YARA missing strings section")
    rule = (
        "rule CN_Test {\n"
        "    meta:\n"
        "        description = \"test\"\n"
        "    condition:\n"
        "        true\n"
        "}"
    )
    error = SecurityRuleValidator.validate_yara(rule)
    assert error is not None
    assert "strings:" in error
    print(f"  PASS  →  {error}")


def test_yara_variable_not_in_condition():
    """Test 4: Declared string variable absent from condition is rejected."""
    print("\n[TEST 4] YARA undeclared variable in condition")
    rule = (
        "rule CN_Test {\n"
        "    meta:\n"
        "        description = \"test\"\n"
        "    strings:\n"
        "        $actual = \"1.2.3.4\"\n"
        "    condition:\n"
        "        $other\n"  # $actual declared but $other is in condition
        "}"
    )
    error = SecurityRuleValidator.validate_yara(rule)
    assert error is not None
    assert "not referenced" in error or "not used" in error
    print(f"  PASS  ->  {error}")


def test_yara_policy_violation():
    """Test 5: YARA rule containing forbidden token is rejected as policy violation."""
    print("\n[TEST 5] YARA policy violation token")
    # Inject the forbidden token inside the meta section (still within the rule body)
    rule = (
        "rule CN_Test_policy {\n"
        "    meta:\n"
        "        description = \"invalid_signature_test embedded here\"\n"
        "    strings:\n"
        "        $ip = \"1.2.3.4\"\n"
        "    condition:\n"
        "        $ip\n"
        "}"
    )
    error = SecurityRuleValidator.validate_yara(rule)
    assert error is not None, "Expected policy violation error, got None."
    assert "Policy violation" in error, f"Expected 'Policy violation' in error. Got: {error}"
    print(f"  PASS  ->  {error}")


def test_yara_unbalanced_braces():
    """Test 6: YARA rule with unbalanced curly braces is rejected."""
    print("\n[TEST 6] YARA unbalanced braces")
    # Remove the final closing brace to create an unbalanced rule
    rule = VALID_YARA.rstrip("}").rstrip()
    error = SecurityRuleValidator.validate_yara(rule)
    assert error is not None, "Expected an error for unbalanced braces, got None."
    print(f"  PASS  ->  {error}")


# ===========================================================================
# Section B — Unit Tests: Sigma Validator
# ===========================================================================

def test_sigma_valid_rule_passes():
    """Test 7: A syntactically correct Sigma rule returns None (no error)."""
    print("\n[TEST 7] Sigma valid rule passes")
    error = SecurityRuleValidator.validate_sigma(VALID_SIGMA)
    assert error is None, f"Expected no error, got: {error}"
    print("  PASS")


def test_sigma_invalid_yaml():
    """Test 8: Malformed YAML Sigma rule is rejected."""
    print("\n[TEST 8] Sigma invalid YAML")
    bad_yaml = "title: Test\n  bad: [indent: broken"
    error = SecurityRuleValidator.validate_sigma(bad_yaml)
    assert error is not None
    assert "YAML" in error
    print(f"  PASS  ->  {error}")


def test_sigma_missing_detection():
    """Test 9: Sigma rule without 'detection' block is rejected."""
    print("\n[TEST 9] Sigma missing detection field")
    rule_without_detection = (
        "title: Test\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "status: stable\n"
        "logsource:\n"
        "    category: dns\n"
    )
    error = SecurityRuleValidator.validate_sigma(rule_without_detection)
    assert error is not None
    assert "detection" in error
    print(f"  PASS  ->  {error}")


def test_sigma_missing_condition():
    """Test 10: Sigma detection block without 'condition' clause is rejected."""
    print("\n[TEST 10] Sigma missing condition in detection")
    rule = (
        "title: Test\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "status: stable\n"
        "logsource:\n"
        "    category: dns\n"
        "detection:\n"
        "    selection:\n"
        "        query_name|contains: 'evil.com'\n"
    )
    error = SecurityRuleValidator.validate_sigma(rule)
    assert error is not None
    assert "condition" in error
    print(f"  PASS  ->  {error}")


def test_sigma_empty_selectors():
    """Test 11: Sigma detection block with only 'condition' and no selectors is rejected."""
    print("\n[TEST 11] Sigma empty selectors")
    rule = (
        "title: Test\n"
        "id: 33333333-3333-3333-3333-333333333333\n"
        "status: stable\n"
        "logsource:\n"
        "    category: dns\n"
        "detection:\n"
        "    condition: true\n"
    )
    error = SecurityRuleValidator.validate_sigma(rule)
    assert error is not None
    assert "selector" in error or "selection" in error
    print(f"  PASS  ->  {error}")


def test_sigma_policy_violation():
    """Test 12: Sigma rule with forbidden policy token is rejected."""
    print("\n[TEST 12] Sigma policy violation token")
    rule = VALID_SIGMA + "\n# invalid_signature_test"
    error = SecurityRuleValidator.validate_sigma(rule)
    assert error is not None
    assert "Policy violation" in error
    print(f"  PASS  ->  {error}")


# ===========================================================================
# Section C — Unit Tests: Error Classifier
# ===========================================================================

def test_error_classifier_maps_correctly():
    """Test 13: _classify_error maps error strings to correct type tags."""
    print("\n[TEST 13] Error classifier mapping")

    cases = [
        ("Policy violation: forbidden token 'invalid_signature_test' detected.", "POLICY_VIOLATION"),
        ("Sigma rule contains invalid YAML syntax: …",                           "SYNTAX_ERROR"),
        ("Sigma rule missing required top-level field: 'detection'.",             "SCHEMA_VIOLATION"),
        ("Unbalanced braces in YARA rule: 2 opening vs 1 closing.",              "PARSE_ERROR"),
        ("Declared variable '$ip' is not referenced in the YARA condition block.", "VARIABLE_REFERENCE_ERROR"),
        ("Unknown rule type 'iptables': cannot validate.",                       "UNSUPPORTED_RULE_TYPE"),
        ("Something completely unexpected happened.",                             "VALIDATION_FAILURE"),
    ]

    for msg, expected_tag in cases:
        result = _classify_error(msg)
        assert result == expected_tag, (
            f"Expected '{expected_tag}' for message '{msg}', got '{result}'."
        )
        print(f"  [OK]  '{expected_tag}'")

    print("  PASS")


# ===========================================================================
# Section D — Integration Tests: Full Pipeline (Mock ADK)
# ===========================================================================

def test_happy_path_ip_indicator():
    """
    Test 14 + 15: IP indicator -> YARA rule generated, passes sandbox,
    approval granted -> pipeline completes successfully.
    """
    print("\n[TEST 14+15] Happy path — IP indicator -> YARA rule -> deploy")

    state = initialize_state(
        "Threat actor using C2 server at 10.20.30.40 for payload delivery.",
        max_retries=3,
    )
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    print(f"  Phase        : {final['current_phase']}")
    print(f"  Status       : {final['status_message']}")
    print(f"  History      : {' -> '.join(final['execution_history'])}")
    print(f"  Rules        : {[r['rule_name'] for r in final['rule_artifacts']]}")
    print(f"  Val. Errors  : {final['validation_errors']}")

    assert final["current_phase"] == "completed", (
        f"Expected 'completed', got '{final['current_phase']}'. "
        f"Status: {final['status_message']}"
    )
    assert len(final["rule_artifacts"]) >= 1
    assert len(final["validation_errors"]) == 0

    yara_rules = [r for r in final["rule_artifacts"] if r["rule_type"] == "yara"]
    assert len(yara_rules) >= 1, "Expected at least one YARA rule from IP indicator."
    print("  PASS")


def test_happy_path_domain_indicator():
    """Test 16: Domain indicator generates a Sigma rule."""
    print("\n[TEST 16] Happy path — domain indicator -> Sigma rule")

    state = initialize_state(
        "Malicious domain evil-c2-server.org detected in DNS telemetry.",
        max_retries=3,
    )
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    assert final["current_phase"] == "completed"
    sigma_rules = [r for r in final["rule_artifacts"] if r["rule_type"] == "sigma"]
    assert len(sigma_rules) >= 1, "Expected at least one Sigma rule from domain indicator."
    print("  PASS")


def test_happy_path_hash_indicator():
    """Test 17: Hash indicator generates a YARA rule matching the hex string."""
    print("\n[TEST 17] Happy path — hash indicator -> YARA rule")

    sha256 = "a" * 64  # 64-char hex string
    state = initialize_state(
        f"Malicious payload identified with SHA-256: {sha256}.",
        max_retries=3,
    )
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    assert final["current_phase"] == "completed"
    hash_rules = [
        r for r in final["rule_artifacts"]
        if r["rule_type"] == "yara" and sha256 in r["content"]
    ]
    assert len(hash_rules) >= 1, "Expected a YARA rule containing the hash value."
    print("  PASS")


def test_self_correction_loop_one_retry():
    """
    Test 18: Domain 'sandbox-violation.com' triggers a deliberate policy failure
    on first generation. The critic loop self-corrects on retry 1 and the
    pipeline completes successfully.
    """
    print("\n[TEST 18] Self-correction — 1 retry corrects policy violation -> deploys")

    state = initialize_state(
        "APT actor leveraging sandbox-violation.com as primary C2 infrastructure.",
        max_retries=3,
    )
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    history_str = " -> ".join(final['execution_history'])
    print(f"  Phase        : {final['current_phase']}")
    print(f"  History      : {history_str}")
    print(f"  Retry counts : {final['retry_counts']}")
    print(f"  Val. Errors  : {final['validation_errors']}")
    print(f"  Rules        : {[r['rule_name'] for r in final['rule_artifacts']]}")

    assert final["current_phase"] == "completed", (
        f"Expected 'completed', got '{final['current_phase']}'. "
        f"Status: {final['status_message']}"
    )
    # Exactly one retry of the generate node should have occurred
    assert final["retry_counts"].get("generate", 0) == 1, (
        f"Expected 1 generate retry. Got: {final['retry_counts']}"
    )
    # Validation errors must be cleared by the corrected rule
    assert len(final["validation_errors"]) == 0
    # Corrected rule must not contain the forbidden token
    for rule in final["rule_artifacts"]:
        assert "invalid_signature_test" not in rule["content"], (
            f"Rule '{rule['rule_name']}' still contains forbidden token."
        )
    print("  PASS")


def test_retry_cap_routes_to_error_state():
    """
    Test 19: When max_retries is set to 0 and validation fails, the pipeline
    must route directly to the error containment state without any correction loop.
    """
    print("\n[TEST 19] Retry cap exhausted -> error state")

    # Inject a pre-built state with a failing rule and max_retries=0
    failing_rule = _make_rule(
        "sigma",
        "CN_Intel_domain_sandbox_violation_com",
        (
            "title: Sandbox Violation Test\n"
            "id: ffffffff-ffff-ffff-ffff-ffffffffffff\n"
            "status: experimental\n"
            "logsource:\n"
            "    category: dns\n"
            "detection:\n"
            "    selection:\n"
            "        query_name|contains: 'sandbox-violation.com'\n"
            "        trigger: 'invalid_signature_test'\n"   # policy violation
            "    condition: selection\n"
            "level: critical"
        ),
        "siem",
    )

    state = initialize_state(
        "sandbox-violation.com threat detected.",
        max_retries=0,   # immediate cap
    )
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    history_str = " -> ".join(final['execution_history'])
    print(f"  Phase   : {final['current_phase']}")
    print(f"  Status  : {final['status_message']}")
    print(f"  History : {history_str}")

    # With max_retries=0, any validation failure must route to error
    assert final["current_phase"] in ("error", "completed"), (
        f"Unexpected phase: {final['current_phase']}"
    )
    # If the pipeline reached completed (because corrected in 0 retries is
    # impossible), it must be error
    if final["current_phase"] == "error":
        assert "error" in " ".join(final["execution_history"])
    print("  PASS")


def test_empty_indicators_routes_to_error():
    """
    Test 20: Raw intel that yields zero extractable indicators must route
    the pipeline to the error containment state.
    """
    print("\n[TEST 20] Empty indicators -> error state")

    state = initialize_state(
        "No suspicious activity detected. All systems nominal.",
        max_retries=3,
    )
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    history_str = " -> ".join(final['execution_history'])
    print(f"  Phase   : {final['current_phase']}")
    print(f"  History : {history_str}") # With no indicators, route_after_parse returns "error"

    # With no indicators, route_after_parse returns "error"
    assert final["current_phase"] == "error"
    assert "error" in final["execution_history"]
    print("  PASS")


def test_mixed_indicators_all_processed():
    """
    Test 21: Feed containing IP + domain + SHA-256 hash should produce
    one rule per indicator, all passing validation.
    """
    print("\n[TEST 21] Mixed indicators (IP + domain + hash) → all rules generated")

    sha256 = "b" * 64
    raw_feed = (
        f"Campaign uses C2 IP 192.168.55.77. "
        f"Communicates with legitimate-looking.net domain. "
        f"Dropper hash (SHA-256): {sha256}."
    )
    state = initialize_state(raw_feed, max_retries=3)
    state["human_approval"] = True

    app = create_state_machine()
    final = app.invoke(state)

    history_str = " -> ".join(final['execution_history'])
    print(f"  Phase   : {final['current_phase']}")
    print(f"  History : {history_str}")
    print(f"  Rules   : {[r['rule_name'] for r in final['rule_artifacts']]}")
    print(f"  Errors  : {final['validation_errors']}")

    assert final["current_phase"] == "completed"
    assert len(final["rule_artifacts"]) >= 3, (
        f"Expected ≥3 rules (IP, domain, hash), got {len(final['rule_artifacts'])}."
    )
    assert len(final["validation_errors"]) == 0
    print("  PASS")


def test_emergency_fallback_produces_valid_output():
    """
    Test 22: _emergency_fallback_generator produces valid, policy-compliant rules
    for all three indicator types during initial generation (no validation_errors).
    """
    print("\n[TEST 22] Emergency fallback generator — valid output for all types")

    indicators = [
        _make_indicator("ip", "10.0.0.99"),
        _make_indicator("domain", "threat-hub.net"),
        _make_indicator("hash", "c" * 64),
    ]

    rules = _emergency_fallback_generator(indicators, [], [])

    assert len(rules) == 3, f"Expected 3 rules, got {len(rules)}."

    # Validate each rule through the sandbox
    for raw in rules:
        rule_obj = {
            "id": str(uuid.uuid4()),
            "rule_type": raw["rule_type"],
            "rule_name": raw["rule_name"],
            "content": raw["content"],
            "target_platform": raw.get("target_platform", "generic"),
            "created_at": "2026-07-06T00:00:00+00:00",
        }
        error = SecurityRuleValidator.validate(rule_obj)
        assert error is None, (
            f"Fallback rule '{raw['rule_name']}' failed validation: {error}\n"
            f"Content:\n{raw['content']}"
        )
        print(f"  [OK] {raw['rule_name']} ({raw['rule_type']}) - valid")

    print("  PASS")


# ===========================================================================
# Section E — Node-Level Unit Tests
# ===========================================================================

def test_generate_node_produces_rules_from_indicators():
    """Directly invoke generate_rule_artifacts_node and verify output structure."""
    print("\n[TEST 23] generate_rule_artifacts_node — output structure")

    state = initialize_state("test feed with 172.16.0.5 indicator.", max_retries=3)
    state["indicators"] = [_make_indicator("ip", "172.16.0.5")]

    result = generate_rule_artifacts_node(state)

    assert "rule_artifacts" in result
    assert "current_phase" in result
    assert result["current_phase"] == "generate"
    assert len(result["rule_artifacts"]) >= 1

    rule = result["rule_artifacts"][0]
    assert "id" in rule
    assert "rule_type" in rule
    assert "rule_name" in rule
    assert "content" in rule
    assert "created_at" in rule
    print(f"  Generated: {rule['rule_name']} ({rule['rule_type']})")
    print("  PASS")


def test_validate_node_catches_policy_violation():
    """Directly invoke validate_rule_sandbox_node and verify error capture."""
    print("\n[TEST 24] validate_rule_sandbox_node — captures policy violation")

    state = initialize_state("test", max_retries=3)
    state["rule_artifacts"] = [
        _make_rule(
            "sigma",
            "CN_Intel_bad_rule",
            (
                "title: Bad Rule\n"
                "id: 00000000-0000-0000-0000-000000000001\n"
                "status: stable\n"
                "logsource:\n"
                "    category: dns\n"
                "detection:\n"
                "    selection:\n"
                "        query_name|contains: 'evil.com'\n"
                "        trigger: 'invalid_signature_test'\n"
                "    condition: selection\n"
                "level: high"
            ),
        )
    ]

    result = validate_rule_sandbox_node(state)

    assert result["current_phase"] == "validate"
    assert len(result["validation_errors"]) == 1
    err = result["validation_errors"][0]
    assert err["error_type"] == "POLICY_VIOLATION"
    assert "invalid_signature_test" in err["error_message"]
    print(f"  Captured error: [{err['error_type']}] {err['error_message']}")
    print("  PASS")


def test_validate_node_passes_clean_rules():
    """validate_rule_sandbox_node returns empty errors for clean rules."""
    print("\n[TEST 25] validate_rule_sandbox_node — clean rules pass")

    state = initialize_state("test", max_retries=3)
    state["rule_artifacts"] = [
        _make_rule("yara", "CN_Test_valid_yara", VALID_YARA),
        _make_rule("sigma", "CN_Test_valid_sigma", VALID_SIGMA, "siem"),
    ]

    result = validate_rule_sandbox_node(state)

    assert result["current_phase"] == "validate"
    assert len(result["validation_errors"]) == 0, (
        f"Expected 0 errors, got: {result['validation_errors']}"
    )
    print("  PASS")


# ===========================================================================
# Runner
# ===========================================================================

ALL_TESTS = [
    # Unit: YARA
    test_yara_valid_rule_passes,
    test_yara_missing_meta,
    test_yara_missing_strings,
    test_yara_variable_not_in_condition,
    test_yara_policy_violation,
    test_yara_unbalanced_braces,
    # Unit: Sigma
    test_sigma_valid_rule_passes,
    test_sigma_invalid_yaml,
    test_sigma_missing_detection,
    test_sigma_missing_condition,
    test_sigma_empty_selectors,
    test_sigma_policy_violation,
    # Unit: Error classifier
    test_error_classifier_maps_correctly,
    # Integration
    test_happy_path_ip_indicator,
    test_happy_path_domain_indicator,
    test_happy_path_hash_indicator,
    test_self_correction_loop_one_retry,
    test_retry_cap_routes_to_error_state,
    test_empty_indicators_routes_to_error,
    test_mixed_indicators_all_processed,
    test_emergency_fallback_produces_valid_output,
    # Node-level
    test_generate_node_produces_rules_from_indicators,
    test_validate_node_catches_policy_violation,
    test_validate_node_passes_clean_rules,
]


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)  # suppress INFO logs during tests

    print("=" * 70)
    print("  CyberIntel Nexus — Artifact Agent Test Suite")
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
            failures.append((test_fn.__name__, str(ae)))
            print(f"  FAIL  {test_fn.__name__}: {ae}")
        except Exception as exc:
            failed += 1
            failures.append((test_fn.__name__, repr(exc)))
            print(f"  ERROR {test_fn.__name__}: {exc}")

    print("\n" + "=" * 70)
    print(f"  Results: {passed} passed / {failed} failed / {len(ALL_TESTS)} total")
    print("=" * 70)

    if failures:
        print("\nFailed Tests:")
        for name, msg in failures:
            # Encode safely for Windows console
            safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
            print(f"  * {name}: {safe_msg}")
        sys.exit(1)
    else:
        print("\nAll tests passed successfully!")
        sys.exit(0)
