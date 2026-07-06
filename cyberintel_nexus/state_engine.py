"""
State Engine Module for CyberIntel Nexus.
This module establishes a deterministic state machine using LangGraph to manage 
the session memory and multi-agent task lifecycles for threat intelligence processing.
It contains transition validation helpers and infinite routing loop prevention.
"""

import logging
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict, Union, Literal

try:
    from cyberintel_nexus.db import SessionLocal, Session as DBSession, RuleArtifact as DBRuleArtifact
except ImportError:
    SessionLocal = None
    DBSession = None
    DBRuleArtifact = None

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberIntelNexus.StateEngine")

# Try to import extended ingestion nodes
try:
    from cyberintel_nexus.ingestion_node import ingest_threat_intel_node, parse_threat_intel_node
except ImportError:
    ingest_threat_intel_node = None
    parse_threat_intel_node = None

# Try to import extended generation and validation nodes
try:
    from cyberintel_nexus.artifact_agent import generate_rule_artifacts_node, validate_rule_sandbox_node
except ImportError:
    generate_rule_artifacts_node = None
    validate_rule_sandbox_node = None

# Try to import LangGraph components, fallback to mock classes if unavailable for offline usage
try:
    from langgraph.graph import StateGraph, START, END
    from langgraph.checkpoint.memory import MemorySaver
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    START = "__start__"
    END = "__end__"
    
    class StateGraph:
        """Mock StateGraph class to allow definition and unit testing without langgraph installed."""
        def __init__(self, state_schema):
            self.state_schema = state_schema
            self.nodes = {}
            self.edges = []
            self.conditional_edges = []
            self.entry_point = None

        def add_node(self, name: str, action_callable):
            self.nodes[name] = action_callable
            return self

        def add_edge(self, source: str, target: str):
            self.edges.append((source, target))
            return self

        def add_conditional_edges(self, source: str, path_callable, path_map: Dict[str, str]):
            self.conditional_edges.append((source, path_callable, path_map))
            return self

        def set_entry_point(self, name: str):
            self.entry_point = name
            return self

        def compile(self, **kwargs):
            class CompiledGraph:
                def __init__(self, graph):
                    self.graph = graph
                def invoke(self, state: dict, config: Optional[dict] = None) -> dict:
                    # Emulate deterministic execution of the state machine
                    current = self.graph.entry_point or "ingest"
                    current_state = dict(state)
                    
                    steps = 0
                    max_steps = 50
                    
                    while current != END and steps < max_steps:
                        steps += 1
                        if current in self.graph.nodes:
                            # Invoke node logic
                            node_updates = self.graph.nodes[current](current_state)
                            # Merge updates back to state (LangGraph merges dictionaries)
                            current_state.update(node_updates)
                            
                        # Find routing decision
                        next_node = None
                        # Check conditional edges first
                        for src, path_fn, path_map in self.graph.conditional_edges:
                            if src == current:
                                decision = path_fn(current_state)
                                next_node = path_map.get(decision)
                                break
                        
                        # Fallback to standard static edges
                        if not next_node:
                            for src, tgt in self.graph.edges:
                                if src == current:
                                    next_node = tgt
                                    break
                                    
                        if not next_node:
                            break
                        current = next_node
                    return current_state
            return CompiledGraph(self)


# ==========================================
# 1. State Schema & Sub-structures
# ==========================================

class Indicator(TypedDict):
    """Represents a parsed structured threat indicator."""
    id: str
    type: Literal["ip", "domain", "url", "hash", "email", "other"]
    value: str
    context: Optional[str]
    confidence: float  # Score from 0.0 to 1.0


class RuleArtifact(TypedDict):
    """Represents a generated security rule (YARA, Sigma, Snort)."""
    id: str
    rule_type: Literal["yara", "sigma", "snort"]
    rule_name: str
    content: str
    target_platform: Optional[str]
    created_at: str


class ValidationError(TypedDict):
    """Represents details of a sandbox validation failure."""
    phase: Literal["parsing", "generation", "validation"]
    rule_id: Optional[str]
    error_message: str
    error_type: str
    details: Optional[Dict[str, Any]]


class AgentState(TypedDict):
    """
    The central state schema for the CyberIntel Nexus multi-agent task lifecycle.
    Maps critical fields to manage session memory deterministically.
    """
    # User-Requested Critical Fields
    raw_threat_intel: str  # Raw threat intelligence input string (e.g., blogs, emails, logs)
    indicators: List[Indicator]  # Parsed structured indicator properties (IPs, domains, hashes)
    rule_artifacts: List[RuleArtifact]  # Generated detection rule artifacts (YARA, Sigma, Snort)
    validation_errors: List[ValidationError]  # Sandbox validation error details
    human_approval: bool  # Explicit human approval flag for deployment

    # Loop Prevention & State Control Fields
    session_id: str  # Unique session UUID
    current_phase: Literal["ingest", "parse", "generate", "validate", "approval", "deploy", "error", "completed"]
    execution_history: List[str]  # Chronological trail of visited phases/nodes
    retry_counts: Dict[str, int]  # Tracks execution retries per phase to block infinite loops
    max_retries: int  # Threshold for max retries of any phase before error redirection
    status_message: str  # Short description of the current task state
    metadata: Dict[str, Any]  # Session metadata parameters (such as local filepaths or MCP URIs)

# ==========================================
# 1.5 Database Persistence Helper
# ==========================================
def _persist_state(session_id: str, current_phase: str, status_message: str, rule_artifacts: list = None):
    if not SessionLocal:
        return
    try:
        db = SessionLocal()
        db_session = db.query(DBSession).filter(DBSession.session_id == session_id).first()
        if not db_session:
            db_session = DBSession(session_id=session_id, current_phase=current_phase, status_message=status_message)
            db.add(db_session)
        else:
            db_session.current_phase = current_phase
            db_session.status_message = status_message
        
        if rule_artifacts:
            for art in rule_artifacts:
                db_art = db.query(DBRuleArtifact).filter(DBRuleArtifact.id == art["id"]).first()
                if not db_art:
                    db_art = DBRuleArtifact(
                        id=art["id"],
                        session_id=session_id,
                        rule_type=art.get("rule_type"),
                        rule_name=art.get("rule_name"),
                        content=art.get("content"),
                        target_platform=art.get("target_platform")
                    )
                    db.add(db_art)
                else:
                    # Update content if changed (e.g. generation retry)
                    db_art.content = art.get("content")
        
        db.commit()
    except Exception as e:
        logger.error(f"DB persist error: {e}")
    finally:
        db.close()



# ==========================================
# 2. Validation Helper Functions
# ==========================================

def initialize_state(raw_intel: str, max_retries: int = 3) -> AgentState:
    """
    Helper function to securely initialize a clean AgentState with default values.
    """
    return {
        "raw_threat_intel": raw_intel,
        "indicators": [],
        "rule_artifacts": [],
        "validation_errors": [],
        "human_approval": False,
        "session_id": str(uuid.uuid4()),
        "current_phase": "ingest",
        "execution_history": ["ingest"],
        "retry_counts": {},
        "max_retries": max_retries,
        "status_message": "Session initialized. Raw intelligence ingested.",
        "metadata": {}
    }


def record_transition(state: AgentState, target_phase: str) -> AgentState:
    """
    Updates the state's metadata, appends target phase to execution history,
    and increments retry counters if a phase is re-visited.
    """
    updated_state = dict(state)
    updated_state["current_phase"] = target_phase
    updated_state["execution_history"] = list(state.get("execution_history", [])) + [target_phase]
    
    # If the target phase has been visited before, increment its retry count
    if target_phase in state.get("execution_history", []):
        retries = dict(state.get("retry_counts", {}))
        retries[target_phase] = retries.get(target_phase, 0) + 1
        updated_state["retry_counts"] = retries
        
    return updated_state


def is_transition_safe(state: AgentState, next_phase: str) -> bool:
    """
    Applies deterministic validation rules to ensure secure transitions between
    operational states and prevent infinite routing loops within the graph.
    """
    current = state.get("current_phase", "ingest")
    max_allowed = state.get("max_retries", 3)
    
    # Rule 1: Loop Prevention via Retry Cap
    retry_count = state.get("retry_counts", {}).get(next_phase, 0)
    if retry_count >= max_allowed:
        logger.error(
            f"[TRANSITION DENIED] '{current}' -> '{next_phase}' would violate safety parameters. "
            f"Phase '{next_phase}' has hit its maximum retry limit of {max_allowed}."
        )
        return False
        
    # Rule 2: Infinite Routing Loop Detection (Cyclic Route Bouncer)
    # Detects repeating cyclic patterns of lengths 1 to 4 that repeat more than max_allowed times
    history = state.get("execution_history", [])
    full_seq = list(history) + [next_phase]
    n = len(full_seq)
    for l in range(1, 5):  # Check cycle lengths 1 to 4
        if n >= l * (max_allowed + 1):
            # Extract consecutive segments of length l
            segments = [full_seq[n - (i + 1) * l : n - i * l] for i in range(max_allowed + 1)]
            # Check if all extracted segments are identical
            if all(seg == segments[0] for seg in segments):
                logger.error(
                    f"[TRANSITION DENIED] Cyclic loop of pattern {segments[0]} "
                    f"detected repeating {max_allowed + 1} times. Blocking transition."
                )
                return False

    # Rule 3: Data Integrity Constraints (Guardrails)
    # - Ingest to Parse: Must have raw intelligence data
    if next_phase == "parse" and not state.get("raw_threat_intel"):
        logger.warning("[TRANSITION DENIED] Cannot parse without raw threat intelligence.")
        return False

    # - Parse to Generate: Must have extracted indicators
    if next_phase == "generate" and not state.get("indicators"):
        logger.warning("[TRANSITION DENIED] Cannot generate rules without structured indicators.")
        return False
        
    # - Validation to Approval: Must have generated rule artifacts
    if next_phase == "approval" and not state.get("rule_artifacts"):
        logger.warning("[TRANSITION DENIED] Cannot request approval with zero rule artifacts.")
        return False
        
    # - Approval to Deploy: Must not have pending validation errors, must have rule artifacts and human approval
    if next_phase == "deploy":
        if state.get("validation_errors"):
            logger.warning("[TRANSITION DENIED] Cannot deploy rules with outstanding validation errors.")
            return False
        if not state.get("rule_artifacts"):
            logger.warning("[TRANSITION DENIED] Cannot deploy empty rule set.")
            return False
        if not state.get("human_approval"):
            logger.warning("[TRANSITION DENIED] Cannot deploy without explicit human approval.")
            return False

    return True


# ==========================================
# 3. Agent Graph Nodes (Business Logic)
# ==========================================

def ingest_node(state: AgentState) -> Dict[str, Any]:
    """Ingestion node that acts as the entry point for the threat intelligence lifecycle."""
    new_state = record_transition(state, "ingest")
    logger.info(f"[{new_state['session_id']}] Node: Ingest Threat Intel.")
    ret = {
        "current_phase": "ingest",
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": "Threat intelligence raw string loaded successfully."
    }
    _persist_state(new_state["session_id"], "ingest", ret["status_message"])
    return ret


def parse_node(state: AgentState) -> Dict[str, Any]:
    """Extracts structured indicator properties (IPs, domains) from raw input strings."""
    new_state = record_transition(state, "parse")
    logger.info(f"[{new_state['session_id']}] Node: Parse Structured Indicators.")
    
    raw = state.get("raw_threat_intel", "")
    indicators = list(state.get("indicators", []))
    
    # Extract IPv4 addresses
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw)
    # Extract domains (basic domain pattern matching supporting underscores)
    domains = re.findall(r'\b(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}\b', raw)
    
    # De-duplicate and register IPv4 indicators
    for ip in set(ips):
        # Basic octet boundary validation
        if all(0 <= int(part) <= 255 for part in ip.split('.')):
            if not any(ind["value"] == ip for ind in indicators):
                indicators.append({
                    "id": str(uuid.uuid4()),
                    "type": "ip",
                    "value": ip,
                    "context": f"Parsed IP from raw threat intel stream.",
                    "confidence": 0.90
                })
                
    # De-duplicate and register domain indicators
    for domain in set(domains):
        # Ignore false positives resembling floating point numbers
        if domain.replace('.', '').isdigit():
            continue
        # Ignore common base domains unless relevant
        if domain.lower() in ["github.com", "google.com"]:
            continue
        if not any(ind["value"] == domain for ind in indicators):
            indicators.append({
                "id": str(uuid.uuid4()),
                "type": "domain",
                "value": domain,
                "context": f"Parsed domain name from raw threat intel stream.",
                "confidence": 0.85
            })
            
    status = f"Parsed {len(indicators)} structured indicator(s) from threat feed."
    ret = {
        "current_phase": "parse",
        "indicators": indicators,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }
    _persist_state(new_state["session_id"], "parse", status)
    return ret


def generate_node(state: AgentState) -> Dict[str, Any]:
    """Generates detection rule artifacts based on structured indicators."""
    new_state = record_transition(state, "generate")
    logger.info(f"[{new_state['session_id']}] Node: Generate Rule Artifacts.")
    
    indicators = state.get("indicators", [])
    rule_artifacts = list(state.get("rule_artifacts", []))
    validation_errors = list(state.get("validation_errors", []))
    
    # If we arrived here due to validation feedback, we adapt/correct the rules
    error_context = ""
    if validation_errors:
        error_context = f"Fixing validation errors: {', '.join(e['error_message'] for e in validation_errors)}"
        validation_errors = []  # Reset validation errors since we are regenerating/fixing
        
    timestamp = datetime.utcnow().isoformat()
    new_rules = []
    
    for ind in indicators:
        rule_name = f"CN_Intel_{ind['type']}_{ind['value'].replace('.', '_').replace('-', '_')}"
        
        # Check if already generated (skip unless modifying due to validation error)
        if any(r["rule_name"] == rule_name for r in rule_artifacts) and not error_context:
            continue
            
        if ind["type"] == "ip":
            content = (
                f"rule {rule_name} {{\n"
                f"    meta:\n"
                f"        description = \"Detects connections to malicious IP: {ind['value']}\"\n"
                f"        indicator_confidence = \"{ind['confidence']}\"\n"
                f"        timestamp = \"{timestamp}\"\n"
                f"        resolution_context = \"{error_context}\"\n"
                f"    strings:\n"
                f"        $ip_pattern = \"{ind['value']}\"\n"
                f"    condition:\n"
                f"        $ip_pattern\n"
                f"}}"
            )
            rule_type = "yara"
        elif ind["type"] == "domain":
            content = (
                f"title: Threat Intel Domain Detection - {ind['value']}\n"
                f"id: {str(uuid.uuid4())}\n"
                f"status: stable\n"
                f"description: Matches network traffic directed towards blacklisted domain {ind['value']}\n"
                f"logsource:\n"
                f"    category: dns\n"
                f"detection:\n"
                f"    selection:\n"
                f"        query_name|contains: '{ind['value']}'\n"
                f"    condition: selection\n"
                f"fields:\n"
                f"    - query_name\n"
                f"level: critical"
            )
            rule_type = "sigma"
        else:
            continue
            
        new_rules.append({
            "id": str(uuid.uuid4()),
            "rule_type": rule_type,
            "rule_name": rule_name,
            "content": content,
            "target_platform": "endpoint" if rule_type == "yara" else "siem",
            "created_at": timestamp
        })
        
    # Replace or add rules
    # In case of validation retry, filter out old versions of rules being fixed
    for nr in new_rules:
        rule_artifacts = [r for r in rule_artifacts if r["rule_name"] != nr["rule_name"]]
        rule_artifacts.append(nr)
        
    status = f"Generated rule artifacts (Total: {len(rule_artifacts)} rules)."
    ret = {
        "current_phase": "generate",
        "rule_artifacts": rule_artifacts,
        "validation_errors": validation_errors,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }
    _persist_state(new_state["session_id"], "generate", status, rule_artifacts)
    return ret


def validate_node(state: AgentState) -> Dict[str, Any]:
    """Validates the generated rules against local policies and sandboxes."""
    new_state = record_transition(state, "validate")
    logger.info(f"[{new_state['session_id']}] Node: Validate Rule Sandbox.")
    
    rule_artifacts = state.get("rule_artifacts", [])
    validation_errors = []
    
    # Business Logic: Sandbox / Policy check simulation.
    # To demonstrate loop prevention and state transitions, we enforce policies:
    # 1. YARA rules cannot exceed 1000 characters (dummy constraint)
    # 2. Sigma rule names must match standard prefixes
    # 3. Explicit check: If rule content contains "invalid_signature_test" (to test validation failures)
    for rule in rule_artifacts:
        if "invalid_signature_test" in rule["content"]:
            validation_errors.append({
                "phase": "validation",
                "rule_id": rule["id"],
                "error_message": f"Syntax Error: Rule {rule['rule_name']} failed signature syntax checks.",
                "error_type": "SYNTAX_CHECK_FAIL",
                "details": {"violating_content": "invalid_signature_test"}
            })
        elif rule["rule_type"] == "yara" and len(rule["content"]) > 1000:
            validation_errors.append({
                "phase": "validation",
                "rule_id": rule["id"],
                "error_message": f"Policy Error: YARA rule {rule['rule_name']} size is too large.",
                "error_type": "SIZE_LIMIT_EXCEEDED",
                "details": {"size": len(rule["content"])}
            })

    status = f"Sandbox validation completed. Validation errors found: {len(validation_errors)}."
    ret = {
        "current_phase": "validate",
        "validation_errors": validation_errors,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }
    _persist_state(new_state["session_id"], "validate", status)
    return ret


# ==========================================
# 4. Routing Deciders (Conditional Edges)
# ==========================================

def route_after_parse(state: AgentState) -> str:
    """Decides transition paths after threat indicator parsing."""
    next_phase = "generate" if state.get("indicators") else "error"
    if is_transition_safe(state, next_phase):
        return next_phase
    return "error"


def route_after_validate(state: AgentState) -> str:
    """Routes state based on validation status, preventing infinite loops."""
    errors = state.get("validation_errors", [])
    
    if not errors:
        next_phase = "approval"
    else:
        # Check retry quota to prevent infinite parse-generate-validate loop
        generate_retries = state.get("retry_counts", {}).get("generate", 0)
        max_allowed = state.get("max_retries", 3)
        
        if generate_retries < max_allowed:
            next_phase = "generate"
            logger.warning(
                f"Validation failure detected. Rerouting to rule generation "
                f"(Retry {generate_retries + 1}/{max_allowed})."
            )
        else:
            next_phase = "error"
            logger.error(f"Validation failures unresolved after {max_allowed} attempts. Routing to containment error node.")
            
    if is_transition_safe(state, next_phase):
        return next_phase
    return "error"


def route_after_approval(state: AgentState) -> str:
    """Decides execution path post approval phase validation."""
    if state.get("human_approval"):
        next_phase = "deploy"
    else:
        next_phase = "error"
        logger.warning("Pipeline rejected: human validation declined.")
        
    if is_transition_safe(state, next_phase):
        return next_phase
    return "error"


# ==========================================
# 5. Graph Assembly & Compilation
# ==========================================

def approval_node(state: AgentState) -> Dict[str, Any]:
    """Halts execution to wait for human authorization before deployment."""
    new_state = record_transition(state, "approval")
    logger.info(f"[{new_state['session_id']}] Node: Await Human Approval.")
    
    meta = dict(state.get("metadata", {}))
    staging = dict(meta.get("staging", {}))
    
    status = "Pending human review."
    if state.get("human_approval"):
        status = "Human review approved. Proceeding to deployment."
        staging["status"] = "approved"
    else:
        staging["status"] = "pending"
        
    meta["staging"] = staging
    ret = {
        "current_phase": "approval",
        "metadata": meta,
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }
    _persist_state(new_state["session_id"], "approval", status)
    return ret


def deploy_node(state: AgentState) -> Dict[str, Any]:
    """Deploys validated rules to their respective security platforms."""
    new_state = record_transition(state, "deploy")
    logger.info(f"[{new_state['session_id']}] Node: Deploy Rules.")
    
    rules = state.get("rule_artifacts", [])
    deployed_names = [r["rule_name"] for r in rules]
    
    status = f"Successfully deployed {len(rules)} rules to target hubs: {', '.join(deployed_names)}"
    ret = {
        "current_phase": "completed",
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }
    _persist_state(new_state["session_id"], "completed", status)
    return ret


def error_node(state: AgentState) -> Dict[str, Any]:
    """Graceful error containment node for safety violations, rejections, or retries."""
    new_state = record_transition(state, "error")
    logger.error(f"[{new_state['session_id']}] Node: Session Route Failure.")
    
    # Reason analysis
    history = state.get("execution_history", [])
    retry_counts = state.get("retry_counts", {})
    errors = state.get("validation_errors", [])
    
    reason = "Generic pipeline interrupt."
    if errors:
        reason = f"Sandbox validation check failed: {errors[-1]['error_message']}"
    elif any(count >= state.get("max_retries", 3) for count in retry_counts.values()):
        reason = f"Infinite routing loop aborted. Phase retries exceeded: {retry_counts}"
    elif len(history) >= 2 and history[-2] == "approval" and not state.get("human_approval"):
        reason = "Deployment rejected during human approval review."

    status = f"Pipeline execution failed. Isolation Code: {reason}"
    ret = {
        "current_phase": "error",
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status
    }
    _persist_state(new_state["session_id"], "error", status)
    return ret


def create_state_machine() -> Any:
    """
    Assembles the CyberIntel Nexus task lifecycle state graph.
    Returns the compiled LangGraph object or functional mock emulator.
    """
    # Initialize state graph with the core schema
    workflow = StateGraph(AgentState)
    
    # Register graph nodes
    workflow.add_node("ingest", ingest_threat_intel_node or ingest_node)
    workflow.add_node("parse", parse_threat_intel_node or parse_node)
    workflow.add_node("generate", generate_rule_artifacts_node or generate_node)
    workflow.add_node("validate", validate_rule_sandbox_node or validate_node)
    workflow.add_node("approval", approval_node)
    workflow.add_node("deploy", deploy_node)
    workflow.add_node("error", error_node)
    
    # Establish entry point
    workflow.set_entry_point("ingest")
    
    # Direct transitions
    workflow.add_edge("ingest", "parse")
    workflow.add_edge("generate", "validate")
    
    # Conditional transitions
    workflow.add_conditional_edges(
        "parse",
        route_after_parse,
        {
            "generate": "generate",
            "error": "error"
        }
    )
    
    workflow.add_conditional_edges(
        "validate",
        route_after_validate,
        {
            "approval": "approval",
            "generate": "generate",
            "error": "error"
        }
    )
    
    workflow.add_conditional_edges(
        "approval",
        route_after_approval,
        {
            "deploy": "deploy",
            "error": "error"
        }
    )
    
    # End terminal endpoints
    workflow.add_edge("deploy", END)
    workflow.add_edge("error", END)
    
    return workflow.compile()


def run_state_machine(state: AgentState) -> AgentState:
    """Helper to run the compiled graph from start to completion/interrupt."""
    graph = create_state_machine()
    return graph.invoke(state)


if __name__ == "__main__":
    print(f"CyberIntel Nexus State Engine loaded. LangGraph integration: {'ENABLED' if LANGGRAPH_AVAILABLE else 'OFFLINE EMULATION'}")
