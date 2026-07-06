"""
Production Entrypoint for CyberIntel Nexus.
Exposes the LangGraph threat intelligence state machine as a FastAPI REST service.
"""

import os
import sys
import uuid
import logging
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Path, status, Depends, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt, JWTError

try:
    from cyberintel_nexus.db import init_db, SessionLocal, User as DBUser, Session as DBSession, RuleArtifact as DBRuleArtifact
    if os.environ.get("INIT_DB") == "true":
        init_db()
except ImportError:
    SessionLocal = None

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberIntelNexus.API")

# Ensure the workspace root directory is in the path
root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from cyberintel_nexus.state_engine import (
        initialize_state,
        AgentState,
        LANGGRAPH_AVAILABLE,
        route_after_parse,
        route_after_validate
    )
    from cyberintel_nexus.ingestion_node import ingest_threat_intel_node, parse_threat_intel_node
    from cyberintel_nexus.artifact_agent import generate_rule_artifacts_node, validate_rule_sandbox_node
    from cyberintel_nexus.staging_portal import (
        human_gate_checkpoint_node,
        commit_node,
        containment_node,
        route_staging_gate,
        resume_from_staging,
        STAGING_PENDING,
        STAGING_APPROVED,
        STAGING_REJECTED
    )
except ImportError as e:
    logger.error(f"Failed to import from cyberintel_nexus package: {e}")
    sys.exit(1)

# ==========================================
# LangGraph Assembly (if available)
# ==========================================
compiled_graph = None

if LANGGRAPH_AVAILABLE:
    try:
        from langgraph.graph import StateGraph, START, END
        from langgraph.checkpoint.memory import MemorySaver
        
        # Build the unified graph using StateGraph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("ingest", ingest_threat_intel_node)
        workflow.add_node("parse", parse_threat_intel_node)
        workflow.add_node("generate", generate_rule_artifacts_node)
        workflow.add_node("validate", validate_rule_sandbox_node)
        workflow.add_node("staging", human_gate_checkpoint_node)
        workflow.add_node("commit", commit_node)
        workflow.add_node("containment", containment_node)
        
        # Set entry point
        workflow.set_entry_point("ingest")
        
        # Standard static edges
        workflow.add_edge("ingest", "parse")
        workflow.add_edge("generate", "validate")
        
        # Routing after parse
        workflow.add_conditional_edges(
            "parse",
            route_after_parse,
            {
                "generate": "generate",
                "error": "containment"
            }
        )
        
        # Routing after validate
        workflow.add_conditional_edges(
            "validate",
            route_after_validate,
            {
                "approval": "staging",
                "generate": "generate",
                "error": "containment"
            }
        )
        
        # Routing after staging
        workflow.add_conditional_edges(
            "staging",
            route_staging_gate,
            {
                "commit": "commit",
                "containment": "containment",
                "freeze": END
            }
        )
        
        # Endpoints
        workflow.add_edge("commit", END)
        workflow.add_edge("containment", END)
        
        # Compile with MemorySaver to support state restoration
        # We interrupt after 'staging' to freeze the session in STAGING_PENDING state
        memory_checkpointer = MemorySaver()
        compiled_graph = workflow.compile(
            checkpointer=memory_checkpointer,
            interrupt_after=["staging"]
        )
        logger.info("LangGraph compiled successfully with MemorySaver checkpointer.")
    except Exception as e:
        logger.error(f"Failed to assemble live LangGraph workflow: {e}. Falling back to offline emulation mode.")
        LANGGRAPH_AVAILABLE = False


# ==========================================
# Offline Emulation Runner (Mock Fallback)
# ==========================================
class MockGraphRunner:
    """Emulates checkpointer and state machine routing when LangGraph is unavailable."""
    def __init__(self):
        self.store: Dict[str, dict] = {}
        
    def get_state(self, thread_id: str) -> Optional[dict]:
        return self.store.get(thread_id)
        
    def update_state(self, thread_id: str, state: dict):
        self.store[thread_id] = dict(state)
        
    def invoke(self, state: dict, thread_id: str) -> dict:
        current_state = dict(state)
        session_id = thread_id
        current_phase = current_state.get("current_phase", "ingest")
        
        def run_node(node_fn, name):
            nonlocal current_state
            try:
                logger.info(f"[MockRunner] Executing node '{name}' for session {session_id}...")
                updates = node_fn(current_state)
                current_state.update(updates)
            except Exception as exc:
                logger.error(f"[MockRunner] Node '{name}' raised exception: {exc}")
                current_state["validation_errors"].append({
                    "phase": "validation",
                    "rule_id": None,
                    "error_message": f"Runtime error in node {name}: {str(exc)}",
                    "error_type": "RUNTIME_ERROR",
                    "details": {"exception": str(exc)}
                })
                current_state["current_phase"] = "error"
                current_state.update(containment_node(current_state))
        
        steps = 0
        max_steps = 50
        
        # If we are resuming from a frozen staging state
        if current_phase == "staging":
            # Note: Staging node human_gate_checkpoint_node ran in the first pass and froze the state.
            # Upon resumption, we go directly to routing and subsequent nodes.
            route = route_staging_gate(current_state)
            if route == "commit":
                run_node(commit_node, "commit")
            elif route == "containment":
                run_node(containment_node, "containment")
            elif route == "freeze":
                logger.info(f"[MockRunner] Session {session_id} frozen again.")
            
            self.update_state(session_id, current_state)
            return current_state
            
        # Standard execution flow from start
        # 1. Ingestion Node
        run_node(ingest_threat_intel_node, "ingest")
        
        # 2. Parsing Node
        run_node(parse_threat_intel_node, "parse")
        
        next_step = route_after_parse(current_state)
        if next_step == "error":
            run_node(containment_node, "containment")
            self.update_state(session_id, current_state)
            return current_state
            
        # 3. Generation & Validation Loop
        while steps < max_steps:
            steps += 1
            run_node(generate_rule_artifacts_node, "generate")
            run_node(validate_rule_sandbox_node, "validate")
            
            next_step = route_after_validate(current_state)
            if next_step == "approval":
                break
            elif next_step == "error":
                run_node(containment_node, "containment")
                self.update_state(session_id, current_state)
                return current_state
                
        if steps >= max_steps:
            current_state["validation_errors"].append({
                "phase": "validation",
                "rule_id": None,
                "error_message": "Exceeded maximum execution steps in generate-validate loop.",
                "error_type": "LOOP_LIMIT_EXCEEDED",
                "details": {}
            })
            run_node(containment_node, "containment")
            self.update_state(session_id, current_state)
            return current_state
            
        # 4. Staging Node
        run_node(human_gate_checkpoint_node, "staging")
        route = route_staging_gate(current_state)
        if route == "commit":
            run_node(commit_node, "commit")
        elif route == "containment":
            run_node(containment_node, "containment")
        elif route == "freeze":
            logger.info(f"[MockRunner] Session {session_id} frozen at staging gate.")
            
        self.update_state(session_id, current_state)
        return current_state


# ==========================================
# Unified Session State Manager
# ==========================================
class SessionStore:
    """Manages active sessions across both live LangGraph and offline fallback environments."""
    def __init__(self):
        self.mock_runner = MockGraphRunner()
        if SessionLocal:
            db = SessionLocal()
            try:
                db_sessions = db.query(DBSession).all()
                for s in db_sessions:
                    state = {
                        "session_id": s.session_id,
                        "current_phase": s.current_phase,
                        "status_message": s.status_message,
                        "rule_artifacts": [],
                        "validation_errors": [],
                        "metadata": {"staging": {}}
                    }
                    db_arts = db.query(DBRuleArtifact).filter(DBRuleArtifact.session_id == s.session_id).all()
                    for a in db_arts:
                        state["rule_artifacts"].append({
                            "id": a.id,
                            "rule_type": a.rule_type,
                            "rule_name": a.rule_name,
                            "content": a.content,
                            "target_platform": a.target_platform
                        })
                        if a.commit_id:
                            state["metadata"]["staging"]["status"] = "approved"
                        elif state["current_phase"] == "staging":
                            state["metadata"]["staging"]["status"] = "pending"
                    
                    self.mock_runner.store[s.session_id] = state
            except Exception as e:
                logger.error(f"Failed to load sessions from DB: {e}")
            finally:
                db.close()
        
        
    def start_session(self, session_id: str, raw_intel: str, metadata: dict) -> dict:
        state = initialize_state(raw_intel, max_retries=3)
        state["session_id"] = session_id
        state["metadata"].update(metadata)
        
        if LANGGRAPH_AVAILABLE and compiled_graph is not None:
            config = {"configurable": {"thread_id": session_id}}
            try:
                final_state = compiled_graph.invoke(state, config)
                return final_state
            except Exception as exc:
                logger.error(f"Error running LangGraph session {session_id}: {exc}. Activating manual fallback.")
                state["current_phase"] = "error"
                state["validation_errors"].append({
                    "phase": "validation",
                    "rule_id": None,
                    "error_message": f"LangGraph runtime exception: {str(exc)}",
                    "error_type": "RUNTIME_EXCEPTION",
                    "details": {"traceback": str(exc)}
                })
                state = containment_node(state)
                try:
                    compiled_graph.update_state(config, state)
                except Exception:
                    pass
                return state
        else:
            return self.mock_runner.invoke(state, session_id)
            
    def get_session(self, session_id: str) -> Optional[dict]:
        if LANGGRAPH_AVAILABLE and compiled_graph is not None:
            config = {"configurable": {"thread_id": session_id}}
            try:
                state_snapshot = compiled_graph.get_state(config)
                if state_snapshot and state_snapshot.values:
                    return state_snapshot.values
            except Exception as e:
                logger.error(f"Failed to fetch state snapshot for {session_id}: {e}")
            return None
        else:
            return self.mock_runner.get_state(session_id)
            
    def resume_session(self, session_id: str, approve: bool, reviewer_id: str, notes: str, rejection_reason: str) -> dict:
        current_state = self.get_session(session_id)
        if not current_state:
            raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
            
        try:
            resumed_state = resume_from_staging(
                current_state,
                approve=approve,
                reviewer_id=reviewer_id,
                notes=notes,
                rejection_reason=rejection_reason
            )
            
            # Ensure staging status and metadata are fully updated for unified graph routing
            if approve:
                from datetime import datetime, timezone
                staging = resumed_state.setdefault("metadata", {}).setdefault("staging", {})
                staging["status"] = "approved"
                staging["approval_timestamp"] = datetime.now(timezone.utc).isoformat()
                
                # Produce compact summary list of rule artifacts
                rule_artifacts = resumed_state.get("rule_artifacts", [])
                staging["artifacts_reviewed"] = [
                    {
                        "id": r.get("id", "unknown"),
                        "rule_name": r.get("rule_name", "unknown"),
                        "rule_type": r.get("rule_type", "unknown"),
                        "target_platform": r.get("target_platform", "generic"),
                    }
                    for r in rule_artifacts
                ]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
            
        if LANGGRAPH_AVAILABLE and compiled_graph is not None:
            config = {"configurable": {"thread_id": session_id}}
            try:
                # Update checkpoint memory state
                compiled_graph.update_state(config, resumed_state)
                # Re-invoke graph from checkpoint
                final_state = compiled_graph.invoke(None, config)
                return final_state
            except Exception as exc:
                logger.error(f"Error resuming LangGraph session {session_id}: {exc}")
                resumed_state["current_phase"] = "error"
                resumed_state["validation_errors"].append({
                    "phase": "validation",
                    "rule_id": None,
                    "error_message": f"Resume runtime exception: {str(exc)}",
                    "error_type": "RUNTIME_EXCEPTION",
                    "details": {}
                })
                final_state = containment_node(resumed_state)
                try:
                    compiled_graph.update_state(config, final_state)
                except Exception:
                    pass
                return final_state
        else:
            return self.mock_runner.invoke(resumed_state, session_id)


# ==========================================
# FastAPI Application & Routing
# ==========================================
app = FastAPI(
    title="CyberIntel Nexus REST API",
    description="Production-ready FastAPI entrypoint for deploying CyberIntel Nexus as a cloud-hosted service.",
    version="1.0.0"
)

# --- CORS Middleware Config ---
origins = [
    "http://localhost:5173",
]
frontend_origin = os.getenv("FRONTEND_ORIGIN")
if frontend_origin:
    origins.append(frontend_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

session_store = SessionStore()

# --- OAuth Security Dependency ---
security = HTTPBearer(auto_error=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey")
JWT_ALGORITHM = "HS256"
AUTHORIZED_REVIEWERS = os.getenv("AUTHORIZED_REVIEWERS", "*").split(",")

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing or malformed."
        )
    token = credentials.credentials
    client_id = os.getenv("GOOGLE_CLIENT_ID", "1088892229667-sdenmpdjkb3dor67rfu80lgvlr08bs7c.apps.googleusercontent.com")
    
    # Try local JWT first
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
        if email:
            return {"email": email, "name": email, "auth_provider": "local"}
    except JWTError:
        pass

    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), client_id)
        email = idinfo.get("email")
        name = idinfo.get("name")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is missing email claim."
            )
        return {"email": email, "name": name, "auth_provider": "google"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired credentials: {str(e)}"
        )

# --- Pydantic Schemas ---
class IngestRequest(BaseModel):
    raw_threat_intel: Optional[str] = Field(None, description="Raw threat intelligence text payload.")
    mcp_uri: Optional[str] = Field(None, description="Optional Model Context Protocol (MCP) server URI.")
    mcp_resource_path: Optional[str] = Field(None, description="Optional MCP resource path.")
    local_filepath: Optional[str] = Field(None, description="Optional local file path.")

class ResumeStagingRequest(BaseModel):
    session_id: str = Field(..., description="The unique session UUID.")
    action: str = Field(..., description="Action to perform: 'Approve' or 'Reject'")
    notes: Optional[str] = Field("", description="Optional notes from the reviewer.")

class IngestResponse(BaseModel):
    session_id: str
    current_phase: str
    status_message: str
    rule_artifacts_count: int
    validation_errors_count: int

class StatusResponse(BaseModel):
    session_id: str
    current_phase: str
    status_message: str
    rule_artifacts: List[Dict[str, Any]]
    validation_errors: List[Dict[str, Any]]
    staging: Dict[str, Any]

class UserCreate(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


# --- API Routes ---
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "langgraph_available": LANGGRAPH_AVAILABLE,
        "mode": "live" if LANGGRAPH_AVAILABLE else "emulated"
    }

@app.post("/auth/register")
async def register(user: UserCreate):
    if not SessionLocal:
        raise HTTPException(status_code=500, detail="Database not configured")
    db = SessionLocal()
    try:
        db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = pwd_context.hash(user.password)
        new_user = DBUser(email=user.email, password_hash=hashed_password)
        db.add(new_user)
        db.commit()
        return {"message": "User created successfully"}
    finally:
        db.close()

@app.post("/auth/login", response_model=Token)
async def login(user: UserCreate):
    if not SessionLocal:
        raise HTTPException(status_code=500, detail="Database not configured")
    db = SessionLocal()
    try:
        db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
        if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        expire = datetime.utcnow() + timedelta(hours=24)
        token_data = {"sub": db_user.email, "exp": expire}
        token = jwt.encode(token_data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    finally:
        db.close()


@app.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_payload(body: IngestRequest, user: dict = Depends(get_current_user)):
    # Validate payload parameters
    if not body.raw_threat_intel and not body.local_filepath and not (body.mcp_uri and body.mcp_resource_path):
        raise HTTPException(
            status_code=400,
            detail="At least one threat intelligence source must be supplied: 'raw_threat_intel', 'local_filepath', or 'mcp_uri' & 'mcp_resource_path'."
        )
        
    session_id = str(uuid.uuid4())
    metadata = {
        "mcp_uri": body.mcp_uri,
        "mcp_resource_path": body.mcp_resource_path,
        "local_filepath": body.local_filepath,
        "creator_email": user.get("email"),
        "creator_name": user.get("name")
    }
    
    try:
        final_state = session_store.start_session(
            session_id=session_id,
            raw_intel=body.raw_threat_intel or "",
            metadata=metadata
        )
    except Exception as e:
        logger.error(f"Unhandled exception in /ingest: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal pipeline invocation failed: {str(e)}"
        )
        
    return IngestResponse(
        session_id=session_id,
        current_phase=final_state.get("current_phase", "error"),
        status_message=final_state.get("status_message", "Ingestion initiated."),
        rule_artifacts_count=len(final_state.get("rule_artifacts", [])),
        validation_errors_count=len(final_state.get("validation_errors", []))
    )

@app.get("/state", response_model=StatusResponse)
async def get_state(session_id: str = Query(..., description="The session UUID.")):
    state = session_store.get_session(session_id)
    if not state:
        raise HTTPException(
            status_code=404,
            detail=f"Session {session_id} not found."
        )
        
    staging_state = state.get("metadata", {}).get("staging", {})
    
    return StatusResponse(
        session_id=session_id,
        current_phase=state.get("current_phase", "error"),
        status_message=state.get("status_message", ""),
        rule_artifacts=state.get("rule_artifacts", []),
        validation_errors=state.get("validation_errors", []),
        staging=staging_state
    )

@app.post("/resume-staging", response_model=StatusResponse)
async def resume_staging(body: ResumeStagingRequest, user: dict = Depends(get_current_user)):
    is_google = user.get("auth_provider") == "google"
    email = user.get("email")
    allowed = "*" in AUTHORIZED_REVIEWERS or email in AUTHORIZED_REVIEWERS
    
    if not is_google or not allowed:
        raise HTTPException(status_code=403, detail="Not authorized to review staging artifacts")
        
    approve = (body.action == "Approve")
    rejection_reason = body.notes if not approve else ""
    if not approve and not rejection_reason:
        raise HTTPException(
            status_code=400,
            detail="Notes must be provided as a rejection reason when rejecting."
        )
        
    try:
        final_state = session_store.resume_session(
            session_id=body.session_id,
            approve=approve,
            reviewer_id=user["email"],
            notes=body.notes or "",
            rejection_reason=rejection_reason
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Unhandled exception in /resume-staging: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal pipeline resumption failed: {str(e)}"
        )
        
    staging_state = final_state.get("metadata", {}).get("staging", {})
    
    return StatusResponse(
        session_id=body.session_id,
        current_phase=final_state.get("current_phase", "error"),
        status_message=final_state.get("status_message", ""),
        rule_artifacts=final_state.get("rule_artifacts", []),
        validation_errors=final_state.get("validation_errors", []),
        staging=staging_state
    )


if __name__ == "__main__":
    import uvicorn
    # Exposing port 8080 as requested
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
