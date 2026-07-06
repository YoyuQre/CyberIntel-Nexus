"""
Artifact Agent Module — CyberIntel Nexus
=========================================
Core action engine for the CyberIntel Nexus multi-agent pipeline.

Responsibilities:
  1. Consume structured IOC indicators (IPs, domains, hashes) from the AgentState.
  2. Generate syntactically valid security rule artifacts (YARA signatures, Sigma rules)
     using Gemini via the Google Agent Development Kit (ADK).
  3. Pass each generated rule through a local compilation sandbox / policy checker.
  4. Feed validation errors back into an LLM-as-a-judge critic loop for autonomous
     self-correction, capped by the max_retries limit in AgentState.
  5. On persistent failure, flag errors in validation_errors and route to error state.

Architecture:
  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────┐
  │  indicators │───>│ generate_rule_   │───>│ validate_rule_     │
  │  (state)    │    │ artifacts_node   │    │ sandbox_node       │
  └─────────────┘    └──────────────────┘    └────────────────────┘
                              ▲                        │
                              │  (validation_errors)   │
                              └────── critic loop ─────┘
                                     (max_retries)
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    try:
        from cyberintel_nexus.state_engine import AgentState, RuleArtifact, ValidationError
    except ImportError:
        from state_engine import AgentState, RuleArtifact, ValidationError

logger = logging.getLogger("CyberIntelNexus.ArtifactAgent")

# ---------------------------------------------------------------------------
# ADK / Gemini Import  (graceful fallback to mock for offline environments)
# ---------------------------------------------------------------------------
try:
    from google.adk.agents import Agent as _ADKAgent
    ADK_AVAILABLE = True
    logger.info("Google ADK available: using live Gemini model for rule generation.")
except ImportError:
    ADK_AVAILABLE = False

    class _ADKAgent:  # type: ignore
        """
        Offline mock that emulates ADK Agent behaviour for unit tests and
        CI environments where google-adk is not installed.

        Behaviour contract (mirrors the two real prompts sent by this module):
        - Generation prompt  → produces valid YARA / Sigma rules from indicators.
        - Correction prompt  → re-generates rules removing any policy violations.
        """

        def __init__(self, name: str, model: str, instruction: str):
            self.name = name
            self.model = model
            self.instruction = instruction

        # ------------------------------------------------------------------
        def run(self, input_prompt: str) -> str:
            """
            Dispatch to generation or self-correction branch based on
            prompt content, mirroring what a real Gemini response would do.
            """
            logger.info("Executing Mock ADK Gemini Agent (offline mode)…")

            if "FAILED RULE(S) FOR SELF-CORRECTION" in input_prompt:
                return self._self_correct(input_prompt)
            return self._generate_initial(input_prompt)

        # ------------------------------------------------------------------
        def _generate_initial(self, prompt: str) -> str:
            """Initial generation branch — creates rules from a JSON indicator list."""
            logger.info("Mock Agent: generating initial rules from indicators…")
            try:
                # Pull the JSON indicators block embedded in the prompt
                json_start = prompt.index("[")
                json_end = prompt.rindex("]") + 1
                indicators: List[Dict] = json.loads(prompt[json_start:json_end])
            except (ValueError, json.JSONDecodeError):
                indicators = []

            rules = []
            for ind in indicators:
                ind_type: str = ind.get("type", "")
                value: str = ind.get("value", "unknown")
                safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", value)
                rule_name = f"CN_Intel_{ind_type}_{safe_name}"

                if ind_type == "ip":
                    content = (
                        f"rule {rule_name} {{\n"
                        f"    meta:\n"
                        f"        description = \"Detects malicious IP: {value}\"\n"
                        f"        confidence = \"{ind.get('confidence', 0.9)}\"\n"
                        f"    strings:\n"
                        f"        $ip = \"{value}\"\n"
                        f"    condition:\n"
                        f"        $ip\n"
                        f"}}"
                    )
                    rules.append({
                        "rule_name": rule_name,
                        "rule_type": "yara",
                        "content": content,
                        "target_platform": "endpoint",
                    })

                elif ind_type == "domain":
                    # Inject a deliberate policy violation when the test domain is present
                    # so the self-correction loop can be exercised end-to-end.
                    trigger_line = (
                        "\n        trigger: 'invalid_signature_test'"
                        if "sandbox-violation" in value else ""
                    )
                    content = (
                        f"title: Threat Intel Domain — {value}\n"
                        f"id: {uuid.uuid4()}\n"
                        f"status: experimental\n"
                        f"description: DNS query detection for malicious domain {value}\n"
                        f"logsource:\n"
                        f"    category: dns\n"
                        f"detection:\n"
                        f"    selection:\n"
                        f"        query_name|contains: '{value}'{trigger_line}\n"
                        f"    condition: selection\n"
                        f"fields:\n"
                        f"    - query_name\n"
                        f"level: high"
                    )
                    rules.append({
                        "rule_name": rule_name,
                        "rule_type": "sigma",
                        "content": content,
                        "target_platform": "siem",
                    })

                elif ind_type == "hash":
                    hash_len = len(value)
                    hash_label = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(hash_len, "HASH")
                    content = (
                        f"rule {rule_name} {{\n"
                        f"    meta:\n"
                        f"        description = \"Detects {hash_label} hash: {value}\"\n"
                        f"    strings:\n"
                        f"        $hash = \"{value}\" ascii wide\n"
                        f"    condition:\n"
                        f"        $hash\n"
                        f"}}"
                    )
                    rules.append({
                        "rule_name": rule_name,
                        "rule_type": "yara",
                        "content": content,
                        "target_platform": "endpoint",
                    })

            return json.dumps({"rules": rules})

        # ------------------------------------------------------------------
        def _self_correct(self, prompt: str) -> str:
            """
            Self-correction branch — re-generates rules that failed validation,
            removing any policy-violating content.
            """
            logger.info("Mock Agent: self-correcting failed rules…")
            # Extract rule names being corrected from the prompt
            corrected = []
            for match in re.finditer(r"Rule Name:\s*(.+)\n", prompt):
                rule_name = match.group(1).strip()
                ind_type = "sigma" if "domain" in rule_name.lower() else "yara"
                value = rule_name.replace("CN_Intel_", "").replace("_", ".")

                if ind_type == "sigma":
                    content = (
                        f"title: Corrected Threat Intel Domain — {value}\n"
                        f"id: {uuid.uuid4()}\n"
                        f"status: stable\n"
                        f"description: Corrected DNS detection for {value}\n"
                        f"logsource:\n"
                        f"    category: dns\n"
                        f"detection:\n"
                        f"    selection:\n"
                        f"        query_name|contains: '{value}'\n"
                        f"    condition: selection\n"
                        f"fields:\n"
                        f"    - query_name\n"
                        f"level: high"
                    )
                else:
                    content = (
                        f"rule {rule_name} {{\n"
                        f"    meta:\n"
                        f"        description = \"Corrected rule for {value}\"\n"
                        f"    strings:\n"
                        f"        $val = \"{value}\"\n"
                        f"    condition:\n"
                        f"        $val\n"
                        f"}}"
                    )
                corrected.append({
                    "rule_name": rule_name,
                    "rule_type": ind_type,
                    "content": content,
                    "target_platform": "siem" if ind_type == "sigma" else "endpoint",
                })
            return json.dumps({"rules": corrected})


# ===========================================================================
# Section 1 — Security Rule Validator (Compilation Sandbox)
# ===========================================================================

class SecurityRuleValidator:
    """
    Local compilation sandbox that validates syntactic correctness and policy
    compliance of generated security rule artifacts before deployment.

    Each validator method returns:
        None   — rule passes all checks
        str    — error description when the rule fails
    """

    # -----------------------------------------------------------------------
    @staticmethod
    def validate_yara(content: str) -> Optional[str]:
        """
        Validates a YARA rule string for:
        - Correct rule header and balanced braces
        - Presence of required sections: meta, strings, condition
        - All declared string variables referenced in condition block
        - No forbidden policy tokens

        Returns:
            None if valid; error description string if invalid.
        """
        stripped = content.strip()

        # 1. Structural header check
        if not stripped.startswith("rule "):
            return "YARA rule must start with keyword 'rule <RuleName>'."

        if "{" not in stripped or not stripped.endswith("}"):
            return "YARA rule must open with '{' and close with '}'."

        open_count = stripped.count("{")
        close_count = stripped.count("}")
        if open_count != close_count:
            return (
                f"Unbalanced braces in YARA rule: "
                f"{open_count} opening vs {close_count} closing."
            )

        # 2. Required section presence
        for section in ("meta:", "strings:", "condition:"):
            if section not in stripped:
                return f"Missing required YARA section block: '{section}'."

        # 3. Declared string variable cross-reference
        strings_block = stripped.split("strings:", 1)[1].split("condition:", 1)[0]
        condition_block = stripped.split("condition:", 1)[1].rsplit("}", 1)[0].strip()

        declared_vars = re.findall(r"(\$[a-zA-Z0-9_]+)\s*=", strings_block)
        if not declared_vars:
            return "No string variables declared inside the YARA 'strings:' block."

        for var in declared_vars:
            if var not in condition_block:
                return (
                    f"Declared variable '{var}' is not referenced "
                    f"in the YARA condition block."
                )

        # 4. Policy enforcement
        if "invalid_signature_test" in stripped:
            return (
                "Policy violation: forbidden token 'invalid_signature_test' "
                "detected in YARA rule body."
            )

        return None  # All checks passed

    # -----------------------------------------------------------------------
    @staticmethod
    def validate_sigma(content: str) -> Optional[str]:
        """
        Validates a Sigma rule (YAML document) for:
        - Valid YAML syntax
        - Required top-level fields: title, logsource, detection
        - Detection block structure: at least one selector + condition reference
        - No forbidden policy tokens

        Returns:
            None if valid; error description string if invalid.
        """
        import yaml

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return f"Sigma rule contains invalid YAML syntax: {exc}"

        if not isinstance(data, dict):
            return "Sigma rule root element must be a YAML dictionary mapping."

        # Required top-level fields
        for field in ("title", "logsource", "detection"):
            if field not in data:
                return f"Sigma rule missing required top-level field: '{field}'."

        detection = data["detection"]
        if not isinstance(detection, dict):
            return "Sigma 'detection' block must be a nested YAML dictionary."

        if "condition" not in detection:
            return "Sigma 'detection' block must include a 'condition' clause."

        selectors = [k for k in detection if k != "condition"]
        if not selectors:
            return (
                "Sigma 'detection' block contains no search selection definitions "
                "(at least one selector beside 'condition' required)."
            )

        condition_expr = str(detection["condition"])
        for sel in selectors:
            if sel not in condition_expr:
                logger.warning(
                    f"Sigma selector '{sel}' is defined but not "
                    f"referenced in condition expression."
                )

        # Policy enforcement
        if "invalid_signature_test" in content:
            return (
                "Policy violation: forbidden token 'invalid_signature_test' "
                "detected in Sigma rule body."
            )

        return None  # All checks passed

    # -----------------------------------------------------------------------
    @classmethod
    def validate(cls, rule: Dict[str, Any]) -> Optional[str]:
        """
        Dispatcher: routes a rule artifact to the appropriate validator based
        on its rule_type field. Returns None on success or an error string.
        """
        rule_type: str = rule.get("rule_type", "").lower()
        content: str = rule.get("content", "")

        if rule_type == "yara":
            return cls.validate_yara(content)
        elif rule_type == "sigma":
            return cls.validate_sigma(content)
        else:
            return f"Unknown rule type '{rule_type}': cannot validate."


# ===========================================================================
# Section 2 — ADK Gemini Rule Generator / LLM-as-a-Judge Critic
# ===========================================================================

def _build_generation_prompt(indicators: List[Dict[str, Any]]) -> Tuple[str, str]:
    """
    Constructs the instruction and user prompt for initial rule generation.
    Returns: (instruction, user_prompt)
    """
    instruction = (
        "You are an expert Security Detection Engineer specialising in YARA and Sigma rules.\n\n"
        "Given a list of threat indicators (IPs, domains, hashes), generate one security rule "
        "per indicator:\n"
        "  • IP addresses → YARA rules using string matching.\n"
        "  • Domain names → Sigma rules targeting DNS log sources.\n"
        "  • Hashes       → YARA rules matching the hex string.\n\n"
        "YARA rule template:\n"
        "  rule RuleName {\n"
        "      meta:\n"
        "          description = \"...\"\n"
        "      strings:\n"
        "          $var = \"...\"\n"
        "      condition:\n"
        "          $var\n"
        "  }\n\n"
        "Sigma rule template (valid YAML):\n"
        "  title: ...\n"
        "  id: <uuid4>\n"
        "  status: stable\n"
        "  description: ...\n"
        "  logsource:\n"
        "      category: dns\n"
        "  detection:\n"
        "      selection:\n"
        "          query_name|contains: '...'\n"
        "      condition: selection\n"
        "  fields:\n"
        "      - query_name\n"
        "  level: high\n\n"
        "Return ONLY a JSON object — no markdown fences:\n"
        "{\n"
        "  \"rules\": [\n"
        "    {\n"
        "      \"rule_name\": \"CN_Intel_<type>_<safe_value>\",\n"
        "      \"rule_type\": \"yara\" | \"sigma\",\n"
        "      \"content\": \"<full rule text>\",\n"
        "      \"target_platform\": \"endpoint\" | \"siem\"\n"
        "    }\n"
        "  ]\n"
        "}"
    )
    user_prompt = (
        f"Generate security detection rules for the following IOC indicators:\n"
        f"{json.dumps(indicators, indent=2)}"
    )
    return instruction, user_prompt


def _build_correction_prompt(
    failed_rules: List[Dict[str, Any]],
    errors: List[Dict[str, Any]],
) -> Tuple[str, str]:
    """
    Constructs the instruction and user prompt for LLM-as-a-judge self-correction.
    Returns: (instruction, user_prompt)
    """
    instruction = (
        "You are a Security Rule Quality Engineer and LLM-as-a-judge critic.\n\n"
        "You will be given security rules that FAILED a compilation sandbox check along "
        "with their specific error messages. Your task is to return corrected versions of "
        "each failing rule.\n\n"
        "Correction rules:\n"
        "  • YARA: ensure all $variables declared in 'strings:' are referenced in 'condition:',\n"
        "    balanced braces, and no forbidden tokens.\n"
        "  • Sigma: ensure valid YAML, required fields (title, logsource, detection), "
        "    a 'condition' referencing at least one selector, and no forbidden tokens.\n"
        "  • Never include the token 'invalid_signature_test' in any rule.\n\n"
        "Return ONLY a JSON object — no markdown fences:\n"
        "{\n"
        "  \"rules\": [\n"
        "    {\n"
        "      \"rule_name\": \"<same name as failed rule>\",\n"
        "      \"rule_type\": \"yara\" | \"sigma\",\n"
        "      \"content\": \"<corrected full rule text>\",\n"
        "      \"target_platform\": \"endpoint\" | \"siem\"\n"
        "    }\n"
        "  ]\n"
        "}"
    )

    failure_blocks = []
    for err in errors:
        rule_id = err.get("rule_id")
        matched_rule = next(
            (r for r in failed_rules if r.get("id") == rule_id), None
        )
        if matched_rule:
            failure_blocks.append(
                f"Rule Name: {matched_rule['rule_name']}\n"
                f"Rule Type: {matched_rule['rule_type']}\n"
                f"Error Type: {err['error_type']}\n"
                f"Error Message: {err['error_message']}\n"
                f"Original Content:\n{matched_rule['content']}"
            )
        else:
            failure_blocks.append(
                f"Rule ID: {rule_id}\n"
                f"Error: {err['error_message']}"
            )

    separator = "\n" + ("─" * 60) + "\n"
    user_prompt = (
        "FAILED RULE(S) FOR SELF-CORRECTION:\n\n"
        + separator.join(failure_blocks)
    )
    return instruction, user_prompt


def _invoke_adk_agent(instruction: str, user_prompt: str) -> List[Dict[str, Any]]:
    """
    Instantiates an ADK Agent and invokes it with the given prompts.
    Parses the JSON response and returns the list of rule dicts.
    Falls back to an empty list on any parsing or communication failure.
    """
    agent = _ADKAgent(
        name="CyberIntelRuleEngineer",
        model="gemini-2.5-flash",
        instruction=instruction,
    )

    try:
        raw_response: str = agent.run(user_prompt)
    except Exception as exc:
        logger.error(f"ADK Agent invocation failed: {exc}")
        return []

    # Strip any accidental markdown code fences
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        lines = lines[1:] if lines[0].startswith("```") else lines
        lines = lines[:-1] if lines and lines[-1].startswith("```") else lines
        cleaned = "\n".join(lines).strip()

    try:
        data = json.loads(cleaned)
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("'rules' field is not a list.")
        return rules
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error(f"Failed to parse ADK Agent JSON response: {exc}. Raw: {cleaned[:300]}")
        return []


# ===========================================================================
# Section 3 — LangGraph Node: generate_rule_artifacts_node
# ===========================================================================

def generate_rule_artifacts_node(state: "AgentState") -> Dict[str, Any]:
    """
    LangGraph Node — Generate Rule Artifacts
    ─────────────────────────────────────────
    Consumes indicators from AgentState and produces security rule artifacts
    via Gemini (ADK). When called after a validation failure (validation_errors
    is non-empty), activates the LLM-as-a-judge critic loop to self-correct
    the failing rules instead of generating fresh ones.

    State updates returned:
        current_phase   : "generate"
        rule_artifacts  : updated list (new or corrected rules merged in)
        execution_history / retry_counts : updated by record_transition
        status_message  : human-readable summary
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, "generate")
    session_id = new_state["session_id"]
    logger.info(f"[{session_id}] Node: Generate Rule Artifacts")

    indicators: List[Dict[str, Any]] = state.get("indicators", [])
    existing_rules: List[Dict[str, Any]] = list(state.get("rule_artifacts", []))
    validation_errors: List[Dict[str, Any]] = list(state.get("validation_errors", []))

    # ── Branch: Self-correction (critic loop) ──────────────────────────────
    if validation_errors:
        retry_num = new_state["retry_counts"].get("generate", 0)
        logger.warning(
            f"[{session_id}] Self-correction loop engaged "
            f"(attempt {retry_num}/{state.get('max_retries', 3)}). "
            f"Fixing {len(validation_errors)} validation error(s)."
        )
        instruction, user_prompt = _build_correction_prompt(existing_rules, validation_errors)

    # ── Branch: Initial generation ─────────────────────────────────────────
    else:
        logger.info(f"[{session_id}] Initial rule generation for {len(indicators)} indicator(s).")
        instruction, user_prompt = _build_generation_prompt(indicators)

    # ── Invoke ADK / Gemini ────────────────────────────────────────────────
    raw_rules = _invoke_adk_agent(instruction, user_prompt)

    if not raw_rules:
        logger.warning(
            f"[{session_id}] ADK returned 0 rules. "
            "Falling back to local emergency rule generator."
        )
        raw_rules = _emergency_fallback_generator(
            indicators, existing_rules, validation_errors
        )

    # ── Map raw dicts to RuleArtifact schema ──────────────────────────────
    timestamp = datetime.now(timezone.utc).isoformat()
    merged_rules = list(existing_rules)

    added = 0
    for raw in raw_rules:
        rule_name = raw.get("rule_name", f"CN_Rule_{uuid.uuid4().hex[:8]}")
        new_artifact: RuleArtifact = {
            "id": str(uuid.uuid4()),
            "rule_type": raw.get("rule_type", "yara"),
            "rule_name": rule_name,
            "content": raw.get("content", ""),
            "target_platform": raw.get("target_platform", "generic"),
            "created_at": timestamp,
        }
        # Replace existing rule with the same name (corrected version)
        merged_rules = [r for r in merged_rules if r["rule_name"] != rule_name]
        merged_rules.append(new_artifact)
        added += 1

    status = (
        f"Generated {added} rule(s) "
        f"({'self-correction' if validation_errors else 'initial generation'}). "
        f"Total in state: {len(merged_rules)}."
    )
    logger.info(f"[{session_id}] {status}")

    return {
        "current_phase": "generate",
        "rule_artifacts": merged_rules,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status,
    }


# ===========================================================================
# Section 4 — LangGraph Node: validate_rule_sandbox_node
# ===========================================================================

def validate_rule_sandbox_node(state: "AgentState") -> Dict[str, Any]:
    """
    LangGraph Node — Validate Rule Sandbox
    ───────────────────────────────────────
    Passes all current rule artifacts through SecurityRuleValidator (the local
    compilation sandbox). Records per-rule errors into validation_errors.

    Routing (handled by state_engine.route_after_validate):
        validation_errors empty → route to approval
        errors present, retries remaining → route back to generate (critic loop)
        errors present, retries exhausted → route to error (containment)

    State updates returned:
        current_phase     : "validate"
        validation_errors : list of ValidationError dicts (empty if all pass)
        execution_history / retry_counts : updated by record_transition
        status_message    : human-readable summary
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, "validate")
    session_id = new_state["session_id"]
    logger.info(f"[{session_id}] Node: Validate Rule Sandbox")

    rules: List[Dict[str, Any]] = state.get("rule_artifacts", [])
    errors_found: List[ValidationError] = []

    for rule in rules:
        rule_name = rule.get("rule_name", "unknown")
        rule_id = rule.get("id", "")
        logger.debug(f"[{session_id}] Validating rule: {rule_name} ({rule.get('rule_type', '?')})")

        error_msg = SecurityRuleValidator.validate(rule)

        if error_msg:
            error_type = _classify_error(error_msg)
            errors_found.append({
                "phase": "validation",
                "rule_id": rule_id,
                "error_message": error_msg,
                "error_type": error_type,
                "details": {
                    "rule_name": rule_name,
                    "rule_type": rule.get("rule_type", "unknown"),
                    "reason": error_msg,
                    "content_preview": rule.get("content", "")[:200],
                },
            })
            logger.warning(
                f"[{session_id}] Rule '{rule_name}' FAILED validation "
                f"[{error_type}]: {error_msg}"
            )
        else:
            logger.info(f"[{session_id}] Rule '{rule_name}' passed sandbox validation ✓")

    pass_count = len(rules) - len(errors_found)
    status = (
        f"Sandbox validation complete: "
        f"{pass_count}/{len(rules)} rule(s) passed, "
        f"{len(errors_found)} failure(s) detected."
    )
    logger.info(f"[{session_id}] {status}")

    return {
        "current_phase": "validate",
        "validation_errors": errors_found,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status,
    }


# ===========================================================================
# Section 5 — Helper Utilities
# ===========================================================================

def _classify_error(error_message: str) -> str:
    """
    Classifies a validation error message into a structured error type tag
    for downstream diagnostic filtering.
    """
    msg_lower = error_message.lower()
    if "policy violation" in msg_lower or "forbidden token" in msg_lower:
        return "POLICY_VIOLATION"
    elif "yaml" in msg_lower or "syntax" in msg_lower:
        return "SYNTAX_ERROR"
    elif "missing" in msg_lower or "required" in msg_lower:
        return "SCHEMA_VIOLATION"
    elif "unbalanced" in msg_lower or "brace" in msg_lower:
        return "PARSE_ERROR"
    elif "not referenced" in msg_lower or "not used" in msg_lower:
        return "VARIABLE_REFERENCE_ERROR"
    elif "unknown rule type" in msg_lower:
        return "UNSUPPORTED_RULE_TYPE"
    else:
        return "VALIDATION_FAILURE"


def _emergency_fallback_generator(
    indicators: List[Dict[str, Any]],
    existing_rules: List[Dict[str, Any]],
    validation_errors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Emergency local rule generator invoked when the ADK/Gemini call returns
    empty output. Produces syntactically correct, policy-compliant rules from
    indicator data without any LLM dependency.

    During self-correction (validation_errors present), this generator
    produces clean replacements for all failing rules, ensuring the
    'invalid_signature_test' token is never included.
    """
    logger.info("Emergency fallback generator activated.")
    is_correcting = bool(validation_errors)
    failing_rule_ids = {e["rule_id"] for e in validation_errors}

    rules_to_fix = {
        r["rule_name"]: r
        for r in existing_rules
        if r.get("id") in failing_rule_ids
    } if is_correcting else {}

    generated = []
    for ind in indicators:
        ind_type: str = ind.get("type", "")
        value: str = ind.get("value", "unknown")
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", value)
        rule_name = f"CN_Intel_{ind_type}_{safe_name}"

        # Only regenerate if this rule has a failing version (during correction)
        if is_correcting and rule_name not in rules_to_fix:
            continue

        if ind_type == "ip":
            content = (
                f"rule {rule_name} {{\n"
                f"    meta:\n"
                f"        description = \"Detects malicious IP: {value}\"\n"
                f"    strings:\n"
                f"        $ip = \"{value}\"\n"
                f"    condition:\n"
                f"        $ip\n"
                f"}}"
            )
            generated.append({
                "rule_name": rule_name,
                "rule_type": "yara",
                "content": content,
                "target_platform": "endpoint",
            })

        elif ind_type == "domain":
            content = (
                f"title: Threat Intel Domain — {value}\n"
                f"id: {uuid.uuid4()}\n"
                f"status: stable\n"
                f"description: DNS detection for malicious domain {value}\n"
                f"logsource:\n"
                f"    category: dns\n"
                f"detection:\n"
                f"    selection:\n"
                f"        query_name|contains: '{value}'\n"
                f"    condition: selection\n"
                f"fields:\n"
                f"    - query_name\n"
                f"level: high"
            )
            generated.append({
                "rule_name": rule_name,
                "rule_type": "sigma",
                "content": content,
                "target_platform": "siem",
            })

        elif ind_type == "hash":
            hash_len = len(value)
            label = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(hash_len, "HASH")
            content = (
                f"rule {rule_name} {{\n"
                f"    meta:\n"
                f"        description = \"Detects {label}: {value}\"\n"
                f"    strings:\n"
                f"        $hash = \"{value}\" ascii wide\n"
                f"    condition:\n"
                f"        $hash\n"
                f"}}"
            )
            generated.append({
                "rule_name": rule_name,
                "rule_type": "yara",
                "content": content,
                "target_platform": "endpoint",
            })

    logger.info(f"Emergency fallback generator produced {len(generated)} rule(s).")
    return generated
