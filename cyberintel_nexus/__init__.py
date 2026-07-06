"""
CyberIntel Nexus Package.
Contains the LangGraph state machine, state definitions, validation logic, and nodes.
"""

from .state_engine import (
    AgentState,
    Indicator,
    RuleArtifact,
    ValidationError,
    create_state_machine,
    initialize_state,
    is_transition_safe,
    run_state_machine
)

from .ingestion_node import (
    ingest_threat_intel_node,
    parse_threat_intel_node,
    extract_indicators_with_adk,
    sanitize_and_validate_indicators
)

from .artifact_agent import (
    generate_rule_artifacts_node,
    validate_rule_sandbox_node,
    SecurityRuleValidator,
)

from .staging_portal import (
    human_gate_checkpoint_node,
    commit_node,
    containment_node,
    route_staging_gate,
    resume_from_staging,
    build_staging_portal_graph,
    STAGING_PENDING,
    STAGING_APPROVED,
    STAGING_REJECTED,
)

__all__ = [
    # State Engine
    "AgentState",
    "Indicator",
    "RuleArtifact",
    "ValidationError",
    "create_state_machine",
    "initialize_state",
    "is_transition_safe",
    "run_state_machine",
    # Ingestion Node
    "ingest_threat_intel_node",
    "parse_threat_intel_node",
    "extract_indicators_with_adk",
    "sanitize_and_validate_indicators",
    # Artifact Agent
    "generate_rule_artifacts_node",
    "validate_rule_sandbox_node",
    "SecurityRuleValidator",
    # Staging Portal
    "human_gate_checkpoint_node",
    "commit_node",
    "containment_node",
    "route_staging_gate",
    "resume_from_staging",
    "build_staging_portal_graph",
    "STAGING_PENDING",
    "STAGING_APPROVED",
    "STAGING_REJECTED",
]
