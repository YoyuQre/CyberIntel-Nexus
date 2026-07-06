"""
Staging Portal Module — CyberIntel Nexus
==========================================
Implements the Human-in-the-Loop (HITL) gate that acts as the final
administrative checkpoint before any security rule artifacts are committed
to a threat intelligence database or live production enforcement system.

Architecture — Gate Flow
-------------------------

  [validate] ---> [staging_gate]
                       |
                       |-- human_approval missing / False
                       |       --> STAGING_PENDING  (graph halts / freezes)
                       |           (external trigger sets human_approval = True)
                       |           (graph re-invoked from staging checkpoint)
                       |
                       |-- human_approval = True
                       |       --> [commit_node] --> COMMIT_SUCCESS
                       |
                       |-- human_approval = "rejected"  OR  validation_errors present
                               --> [containment_node] --> CONTAINMENT_REJECTED

State Fields Managed by This Module
-------------------------------------
All staging metadata is stored inside the top-level `metadata` dict key
`staging` on the AgentState to avoid schema-breaking TypedDict changes:

  metadata["staging"]["status"]           : "pending" | "approved" | "rejected"
  metadata["staging"]["approval_timestamp"]: ISO-8601 UTC string (when approved)
  metadata["staging"]["reviewer_id"]      : Optional admin identifier
  metadata["staging"]["notes"]            : Optional human review notes
  metadata["staging"]["rejection_reason"] : Optional rejection justification
  metadata["staging"]["artifacts_reviewed"]: List of rule_artifact IDs assessed
  metadata["staging"]["freeze_timestamp"] : ISO-8601 UTC string (when first frozen)
  metadata["staging"]["resume_count"]     : int, number of times gate was resumed

Public API
-----------
  human_gate_checkpoint_node(state)  -> dict   # LangGraph node
  commit_node(state)                 -> dict   # LangGraph node
  containment_node(state)            -> dict   # LangGraph node
  route_staging_gate(state)          -> str    # Conditional edge router
  build_staging_portal_graph()       -> Any    # Standalone compiled graph
  resume_from_staging(frozen_state, reviewer_id, notes, approve) -> AgentState
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# State Engine Imports
# ---------------------------------------------------------------------------
try:
    from cyberintel_nexus.state_engine import AgentState, RuleArtifact, ValidationError, _persist_state
except ImportError:
    from state_engine import AgentState, RuleArtifact, ValidationError, _persist_state  # type: ignore

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    pass  # AgentState already imported above

logger = logging.getLogger("CyberIntelNexus.StagingPortal")

# ---------------------------------------------------------------------------
# Staging Status Constants
# ---------------------------------------------------------------------------
STAGING_PENDING   = "pending"    # Gate frozen — awaiting human decision
STAGING_APPROVED  = "approved"   # Explicitly approved by a human reviewer
STAGING_REJECTED  = "rejected"   # Explicitly rejected by a human reviewer

# Phase label constants used in execution_history and current_phase
PHASE_STAGING    = "staging"
PHASE_COMMIT     = "commit"
PHASE_CONTAINMENT = "containment"


# ===========================================================================
# Section 1 — Staging Metadata Helpers
# ===========================================================================

def _get_staging_meta(state: AgentState) -> Dict[str, Any]:
    """Returns the staging sub-dict from state metadata, creating it if absent."""
    meta: Dict[str, Any] = dict(state.get("metadata", {}))
    staging: Dict[str, Any] = dict(meta.get("staging", {}))
    return staging


def _set_staging_meta(state: AgentState, staging: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a new metadata dict with the updated staging sub-dict merged in."""
    meta = dict(state.get("metadata", {}))
    meta["staging"] = staging
    return meta


def _utcnow() -> str:
    """Returns the current UTC timestamp as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _artifact_summary(rule_artifacts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Produces a compact summary list of rule artifacts for the staging audit log."""
    return [
        {
            "id": r.get("id", "unknown"),
            "rule_name": r.get("rule_name", "unknown"),
            "rule_type": r.get("rule_type", "unknown"),
            "target_platform": r.get("target_platform", "generic"),
        }
        for r in rule_artifacts
    ]


# ===========================================================================
# Section 2 — HITL Gate Node: human_gate_checkpoint_node
# ===========================================================================

def human_gate_checkpoint_node(state: "AgentState") -> Dict[str, Any]:
    """
    LangGraph Node — Human Gate Checkpoint (HITL)
    -----------------------------------------------
    The central Human-in-the-Loop enforcement point. Inspects rule_artifacts
    and the current human_approval flag to determine whether to freeze
    execution (STAGING_PENDING) or allow the pipeline to progress.

    Freeze / Halt behaviour
    ~~~~~~~~~~~~~~~~~~~~~~~
    When human_approval is absent or False this node:
      - Sets current_phase to "staging"
      - Records metadata["staging"]["status"] = "pending"
      - Records a freeze_timestamp in staging metadata
      - Returns state WITHOUT advancing to commit or containment

    The calling client then re-invokes the graph (or specifically this node)
    after setting human_approval = True (or "rejected"). The router
    `route_staging_gate` inspects staging_status to choose the correct
    onward path at that point.

    Resumption
    ~~~~~~~~~~
    On the second (resumed) invocation the approval flag is already set,
    so this node updates staging_status, records the approval_timestamp,
    and returns normally — allowing `route_staging_gate` to dispatch
    to commit or containment.

    State updates returned
    ~~~~~~~~~~~~~~~~~~~~~~
      current_phase    : "staging"
      metadata         : updated staging sub-dict
      execution_history / retry_counts : via record_transition
      status_message   : human-readable description of gate state
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, PHASE_STAGING)
    session_id = new_state["session_id"]

    rule_artifacts: List[Dict[str, Any]] = state.get("rule_artifacts", [])
    validation_errors: List[Dict[str, Any]] = state.get("validation_errors", [])
    human_approval = state.get("human_approval")   # bool | "rejected" | None | False

    staging = _get_staging_meta(state)

    # ── Case A: Explicit rejection signal ─────────────────────────────────
    if human_approval == "rejected" or staging.get("status") == STAGING_REJECTED:
        rejection_reason = staging.get("rejection_reason", "Human reviewer explicitly rejected artifact batch.")
        logger.warning(
            f"[{session_id}] HITL Gate: REJECTED by human reviewer. "
            f"Reason: {rejection_reason}"
        )
        staging.update({
            "status": STAGING_REJECTED,
            "rejection_reason": rejection_reason,
            "artifacts_reviewed": _artifact_summary(rule_artifacts),
        })
        ret = {
            "current_phase": PHASE_STAGING,
            "metadata": _set_staging_meta(state, staging),
            "execution_history": new_state["execution_history"],
            "retry_counts": new_state["retry_counts"],
            "status_message": (
                f"HITL Gate: REJECTED. "
                f"Reason: {rejection_reason}"
            ),
        }
        _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
        return ret

    # ── Case B: Outstanding validation errors at staging time ──────────────
    if validation_errors:
        error_summary = "; ".join(e.get("error_message", "?") for e in validation_errors)
        logger.error(
            f"[{session_id}] HITL Gate: staging blocked — "
            f"{len(validation_errors)} unresolved validation error(s): {error_summary}"
        )
        staging.update({
            "status": STAGING_REJECTED,
            "rejection_reason": (
                f"Staging inspection detected {len(validation_errors)} "
                f"unresolved validation error(s): {error_summary}"
            ),
            "artifacts_reviewed": _artifact_summary(rule_artifacts),
        })
        ret = {
            "current_phase": PHASE_STAGING,
            "metadata": _set_staging_meta(state, staging),
            "execution_history": new_state["execution_history"],
            "retry_counts": new_state["retry_counts"],
            "status_message": (
                f"HITL Gate: CONTAINMENT — unresolved validation errors detected. "
                f"{error_summary}"
            ),
        }
        _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
        return ret

    # ── Case C: No rule artifacts to review ───────────────────────────────
    if not rule_artifacts:
        logger.error(f"[{session_id}] HITL Gate: no rule artifacts present for review.")
        staging.update({
            "status": STAGING_REJECTED,
            "rejection_reason": "No rule artifacts available for staging review.",
            "artifacts_reviewed": [],
        })
        ret = {
            "current_phase": PHASE_STAGING,
            "metadata": _set_staging_meta(state, staging),
            "execution_history": new_state["execution_history"],
            "retry_counts": new_state["retry_counts"],
            "status_message": "HITL Gate: CONTAINMENT — zero rule artifacts found.",
        }
        _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
        return ret

    # ── Case D: Awaiting human decision (freeze / halt) ───────────────────
    if not human_approval:
        is_first_freeze = staging.get("status") != STAGING_PENDING
        if is_first_freeze:
            staging["freeze_timestamp"] = _utcnow()
            staging["resume_count"] = 0
            staging["artifacts_reviewed"] = _artifact_summary(rule_artifacts)
        staging["status"] = STAGING_PENDING

        artifact_names = [r.get("rule_name", "?") for r in rule_artifacts]
        logger.info(
            f"[{session_id}] HITL Gate: FROZEN — awaiting human approval for "
            f"{len(rule_artifacts)} artifact(s): {artifact_names}"
        )
        ret = {
            "current_phase": PHASE_STAGING,
            "metadata": _set_staging_meta(state, staging),
            "execution_history": new_state["execution_history"],
            "retry_counts": new_state["retry_counts"],
            "status_message": (
                f"HITL Gate: STAGING_PENDING — {len(rule_artifacts)} artifact(s) "
                f"awaiting human review: {', '.join(artifact_names)}. "
                f"Set human_approval=True to proceed."
            ),
        }
        _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
        return ret

    # ── Case E: Approved — record timestamp and pass through ──────────────
    reviewer_id = staging.get("reviewer_id", "system")
    notes = staging.get("notes", "")
    prior_freeze = staging.get("freeze_timestamp", _utcnow())
    resume_count = staging.get("resume_count", 0) + 1

    staging.update({
        "status": STAGING_APPROVED,
        "approval_timestamp": _utcnow(),
        "reviewer_id": reviewer_id,
        "notes": notes,
        "freeze_timestamp": prior_freeze,
        "resume_count": resume_count,
        "artifacts_reviewed": _artifact_summary(rule_artifacts),
    })

    artifact_names = [r.get("rule_name", "?") for r in rule_artifacts]
    logger.info(
        f"[{session_id}] HITL Gate: APPROVED by '{reviewer_id}'. "
        f"Clearing staging block for {len(rule_artifacts)} artifact(s). "
        f"Resume #{resume_count}."
    )
    ret = {
        "current_phase": PHASE_STAGING,
        "metadata": _set_staging_meta(state, staging),
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": (
            f"HITL Gate: APPROVED by '{reviewer_id}' at {staging['approval_timestamp']}. "
            f"Committing {len(rule_artifacts)} artifact(s): {', '.join(artifact_names)}."
        ),
    }
    _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
    return ret


# ===========================================================================
# Section 3 — Router: route_staging_gate
# ===========================================================================

def route_staging_gate(state: AgentState) -> str:
    """
    Conditional edge router — inspects staging metadata after
    human_gate_checkpoint_node and decides the next graph node.

    Returns
    -------
    "commit"      — human approved; proceed to commit node
    "containment" — human rejected, validation errors, or no artifacts
    "freeze"      — approval pending; halt graph (routes to END)
    """
    staging = _get_staging_meta(state)
    staging_status = staging.get("status", STAGING_PENDING)

    if staging_status == STAGING_APPROVED:
        logger.info("Staging router: approved -> commit")
        return "commit"

    if staging_status == STAGING_REJECTED:
        logger.warning("Staging router: rejected -> containment")
        return "containment"

    # STAGING_PENDING — freeze; route to END to halt the graph
    logger.info("Staging router: pending -> freeze (graph halts)")
    return "freeze"


# ===========================================================================
# Section 4 — Commit Node
# ===========================================================================

def commit_node(state: "AgentState") -> Dict[str, Any]:
    """
    LangGraph Node — Commit (COMMIT_SUCCESS)
    -----------------------------------------
    Invoked after human approval clears the HITL gate. Writes all validated,
    approved rule artifacts to the (mock) threat intelligence database / live
    enforcement registry and records a commit receipt in staging metadata.

    In a production system this node would:
      - Call the SIEM / EDR platform API to push rules
      - Write rule hashes to the immutable audit ledger
      - Emit a deployment event to the observability pipeline

    State updates
    ~~~~~~~~~~~~~
      current_phase : "completed"
      metadata      : commit receipt written to staging sub-dict
      status_message: COMMIT_SUCCESS summary
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, PHASE_COMMIT)
    session_id = new_state["session_id"]

    rule_artifacts: List[Dict[str, Any]] = state.get("rule_artifacts", [])
    staging = _get_staging_meta(state)

    commit_id = str(uuid.uuid4())
    commit_timestamp = _utcnow()

    # Simulate platform-specific deployment receipts
    receipts = []
    for rule in rule_artifacts:
        platform = rule.get("target_platform", "generic")
        receipt = {
            "rule_name": rule.get("rule_name"),
            "rule_type": rule.get("rule_type"),
            "platform": platform,
            "commit_id": commit_id,
            "committed_at": commit_timestamp,
            "status": "COMMITTED",
        }
        receipts.append(receipt)
        logger.info(
            f"[{session_id}] Committed rule '{rule.get('rule_name')}' "
            f"to platform '{platform}' (commit_id={commit_id})"
        )

    staging["commit_id"] = commit_id
    staging["commit_timestamp"] = commit_timestamp
    staging["commit_receipts"] = receipts
    staging["final_outcome"] = "COMMIT_SUCCESS"

    rule_names = [r.get("rule_name", "?") for r in rule_artifacts]
    status = (
        f"COMMIT_SUCCESS — {len(receipts)} rule(s) committed "
        f"(commit_id={commit_id}): {', '.join(rule_names)}"
    )
    logger.info(f"[{session_id}] {status}")

    ret = {
        "current_phase": "completed",
        "metadata": _set_staging_meta(state, staging),
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status,
    }
    
    try:
        from cyberintel_nexus.db import SessionLocal, RuleArtifact as DBRuleArtifact
        if SessionLocal:
            db = SessionLocal()
            for rule in rule_artifacts:
                db_art = db.query(DBRuleArtifact).filter(DBRuleArtifact.id == rule.get("id")).first()
                if db_art:
                    db_art.committed = True
                    db_art.commit_id = commit_id
            db.commit()
            db.close()
    except Exception as e:
        logger.error(f"Failed to update commit status in DB: {e}")
        
    _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
    return ret


# ===========================================================================
# Section 5 — Containment Node
# ===========================================================================

def containment_node(state: "AgentState") -> Dict[str, Any]:
    """
    LangGraph Node — Containment (CONTAINMENT_REJECTED)
    ----------------------------------------------------
    Reached when the HITL gate routes to rejection. Records the full
    containment reason, quarantines the artifact batch (marks them as
    rejected in staging metadata), and transitions current_phase to "error".

    Containment triggers:
      - Human reviewer explicitly set human_approval = "rejected"
      - staging_status == "rejected" at time of routing
      - Outstanding validation_errors detected during staging inspection
      - Zero rule artifacts passed to staging

    State updates
    ~~~~~~~~~~~~~
      current_phase : "error"
      metadata      : containment record written to staging sub-dict
      status_message: CONTAINMENT_REJECTED summary with quarantine reason
    """
    try:
        from cyberintel_nexus.state_engine import record_transition
    except ImportError:
        from state_engine import record_transition
    new_state = record_transition(state, PHASE_CONTAINMENT)
    session_id = new_state["session_id"]

    rule_artifacts: List[Dict[str, Any]] = state.get("rule_artifacts", [])
    validation_errors: List[Dict[str, Any]] = state.get("validation_errors", [])
    staging = _get_staging_meta(state)

    rejection_reason = staging.get(
        "rejection_reason",
        "Artifact batch quarantined: unspecified containment trigger."
    )
    containment_id = str(uuid.uuid4())
    containment_timestamp = _utcnow()

    quarantined = []
    for rule in rule_artifacts:
        quarantined.append({
            "rule_name": rule.get("rule_name"),
            "rule_type": rule.get("rule_type"),
            "quarantine_id": containment_id,
            "quarantined_at": containment_timestamp,
            "reason": rejection_reason,
        })

    staging["containment_id"] = containment_id
    staging["containment_timestamp"] = containment_timestamp
    staging["quarantined_artifacts"] = quarantined
    staging["validation_errors_at_containment"] = validation_errors
    staging["final_outcome"] = "CONTAINMENT_REJECTED"

    error_detail = ""
    if validation_errors:
        error_detail = (
            f" Validation errors: "
            + "; ".join(e.get("error_message", "?") for e in validation_errors)
        )

    status = (
        f"CONTAINMENT_REJECTED — {len(quarantined)} artifact(s) quarantined "
        f"(containment_id={containment_id}). "
        f"Reason: {rejection_reason}.{error_detail}"
    )
    logger.warning(f"[{session_id}] {status}")

    ret = {
        "current_phase": "error",
        "metadata": _set_staging_meta(state, staging),
        "execution_history": new_state["execution_history"],
        "retry_counts": new_state["retry_counts"],
        "status_message": status,
    }
    _persist_state(session_id, ret["current_phase"], ret["status_message"], rule_artifacts)
    return ret


# ===========================================================================
# Section 6 — Portal Resumption Helper
# ===========================================================================

def resume_from_staging(
    frozen_state: AgentState,
    *,
    approve: bool = True,
    reviewer_id: str = "admin",
    notes: str = "",
    rejection_reason: str = "",
) -> AgentState:
    """
    External API — Resume a frozen staging session.

    Simulates what a human dashboard or programmatic client would do to
    unfreeze a STAGING_PENDING session. Mutates and returns a new state
    dict ready to be re-invoked by the staging portal graph.

    Parameters
    ----------
    frozen_state    : The state dict returned by the frozen pipeline invocation.
    approve         : True to approve, False to reject.
    reviewer_id     : Identifier of the human reviewer (audit trail).
    notes           : Optional review notes to store in staging metadata.
    rejection_reason: Mandatory when approve=False; reason for rejection.

    Returns
    -------
    A new AgentState dict with human_approval and staging metadata updated,
    ready to be passed to build_staging_portal_graph().invoke().

    Raises
    ------
    ValueError  : If the session is not in STAGING_PENDING status.
    ValueError  : If approve=False and rejection_reason is empty.
    """
    staging = _get_staging_meta(frozen_state)

    current_status = staging.get("status")
    if current_status != STAGING_PENDING:
        raise ValueError(
            f"Cannot resume a session that is not STAGING_PENDING. "
            f"Current staging status: '{current_status}'."
        )

    if not approve and not rejection_reason:
        raise ValueError(
            "rejection_reason must be provided when approve=False."
        )

    resumed_state = dict(frozen_state)

    if approve:
        resumed_state["human_approval"] = True
        staging["reviewer_id"] = reviewer_id
        staging["notes"] = notes
        staging["resume_count"] = staging.get("resume_count", 0) + 1
        logger.info(
            f"[{frozen_state.get('session_id', '?')}] "
            f"Staging session resumed with APPROVAL by '{reviewer_id}'."
        )
    else:
        resumed_state["human_approval"] = "rejected"
        staging["status"] = STAGING_REJECTED
        staging["reviewer_id"] = reviewer_id
        staging["rejection_reason"] = rejection_reason
        staging["notes"] = notes
        logger.warning(
            f"[{frozen_state.get('session_id', '?')}] "
            f"Staging session resumed with REJECTION by '{reviewer_id}': {rejection_reason}"
        )

    resumed_state["metadata"] = _set_staging_meta(frozen_state, staging)
    return resumed_state


# ===========================================================================
# Section 7 — Standalone Staging Portal Graph
# ===========================================================================

def build_staging_portal_graph() -> Any:
    """
    Assembles and compiles a standalone LangGraph (or mock emulator) for the
    HITL staging portal. This graph can be used independently of the main
    CyberIntel Nexus pipeline for testing or as a composable sub-graph.

    Graph topology
    --------------
      [staging_gate] --approved---> [commit]  ---> END (COMMIT_SUCCESS)
                     --rejected--> [containment] -> END (CONTAINMENT_REJECTED)
                     --freeze----> END (STAGING_PENDING)

    Usage
    -----
      graph = build_staging_portal_graph()

      # First pass — will freeze if human_approval is False
      frozen_state = graph.invoke(initial_state)

      # Resume after human review
      resumed_state = resume_from_staging(frozen_state, approve=True, reviewer_id="ops-lead")
      final_state = graph.invoke(resumed_state)
    """
    try:
        from cyberintel_nexus.state_engine import StateGraph, END, AgentState as _AgentState
    except ImportError:
        from state_engine import StateGraph, END, AgentState as _AgentState
    workflow = StateGraph(_AgentState)

    # Register nodes
    workflow.add_node("staging", human_gate_checkpoint_node)
    workflow.add_node("commit", commit_node)
    workflow.add_node("containment", containment_node)

    # Entry point
    workflow.set_entry_point("staging")

    # Conditional edges from staging gate
    workflow.add_conditional_edges(
        "staging",
        route_staging_gate,
        {
            "commit":      "commit",
            "containment": "containment",
            "freeze":      END,       # Halts graph — awaiting human action
        }
    )

    # Terminal edges
    workflow.add_edge("commit",      END)
    workflow.add_edge("containment", END)

    return workflow.compile()
