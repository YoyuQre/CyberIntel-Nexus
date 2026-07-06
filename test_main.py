"""
Test Suite for CyberIntel Nexus REST API (main.py).
Tests health check, ingestion, status tracking, and HITL gate resumptions.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure root directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uuid

test_db_file = f"test_nexus_{uuid.uuid4().hex}.db"
os.environ["DATABASE_URL"] = f"sqlite:///{test_db_file}"
os.environ["AUTHORIZED_REVIEWERS"] = "test-reviewer@example.com"

from main import app, session_store, get_current_user

@pytest.fixture(scope="session", autouse=True)
def cleanup_test_db():
    yield
    if os.path.exists(test_db_file):
        try:
            os.remove(test_db_file)
        except OSError:
            pass

client = TestClient(app)

# Mock authentication dependency globally for tests
app.dependency_overrides[get_current_user] = lambda: {"email": "test-reviewer@example.com", "name": "Test Reviewer", "auth_provider": "google"}


def test_health_endpoint():
    """Verify health check returns status info."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "langgraph_available" in data
    assert "mode" in data


def test_ingest_bad_payload():
    """Verify ingestion fails if all sources are missing."""
    response = client.post("/ingest", json={})
    assert response.status_code == 400
    assert "At least one threat intelligence source" in response.json()["detail"]


def test_auth_register_login():
    """Verify local email/password registration and login works."""
    # Register
    res = client.post("/auth/register", json={"email": "operator@soc.local", "password": "password123"})
    assert res.status_code == 200
    assert res.json()["message"] == "User created successfully"
    
    # Login
    res = client.post("/auth/login", json={"email": "operator@soc.local", "password": "password123"})
    assert res.status_code == 200
    assert "access_token" in res.json()
    assert res.json()["token_type"] == "bearer"

def test_resume_staging_allowlist():
    """Verify that only authorized google users can resume staging."""
    payload = {"raw_threat_intel": "Observed connection attempt to malicious IP 198.51.100.42"}
    response = client.post("/ingest", json=payload)
    session_id = response.json()["session_id"]
    
    orig_overrides = app.dependency_overrides.copy()
    try:
        app.dependency_overrides[get_current_user] = lambda: {"email": "operator@soc.local", "name": "Local User", "auth_provider": "local"}
        resume_payload = {"session_id": session_id, "action": "Approve", "notes": "LGTM"}
        res = client.post("/resume-staging", json=resume_payload)
        assert res.status_code == 403
        assert "Not authorized" in res.json()["detail"]
        
        app.dependency_overrides[get_current_user] = lambda: {"email": "random@example.com", "name": "Random", "auth_provider": "google"}
        res = client.post("/resume-staging", json=resume_payload)
        assert res.status_code == 403
        assert "Not authorized" in res.json()["detail"]
        
        app.dependency_overrides[get_current_user] = lambda: {"email": "test-reviewer@example.com", "name": "Reviewer", "auth_provider": "google"}
        res = client.post("/resume-staging", json=resume_payload)
        assert res.status_code == 200
    finally:
        app.dependency_overrides = orig_overrides


def test_full_happy_path_hitl_approval():
    """
    Verify complete flow:
      1. Ingest threat report -> returns session in STAGING_PENDING phase.
      2. Check status -> returns pending staging status and rule artifacts.
      3. Resume /approve -> transitions phase to completed and commit outcome.
    """
    # 1. Ingest threat intel containing an IP and a domain
    payload = {
        "raw_threat_intel": "Observed connection attempt to malicious IP 198.51.100.42 and domain command-center.org."
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    session_id = data["session_id"]
    assert session_id is not None
    assert data["current_phase"] == "staging"
    assert "STAGING_PENDING" in data["status_message"]
    # Mock extractor parses 1 IP and 1 domain -> 2 rule artifacts
    assert data["rule_artifacts_count"] == 2
    assert data["validation_errors_count"] == 0

    # 2. Query status
    status_response = client.get(f"/state?session_id={session_id}")
    assert status_response.status_code == 200
    status_data = status_response.json()
    assert status_data["session_id"] == session_id
    assert status_data["current_phase"] == "staging"
    assert len(status_data["rule_artifacts"]) == 2
    assert status_data["staging"]["status"] == "pending"
    assert "freeze_timestamp" in status_data["staging"]

    # 3. Resume with approval
    resume_payload = {
        "session_id": session_id,
        "action": "Approve",
        "notes": "Verified against threat intelligence databases. Clean to deploy."
    }
    resume_response = client.post("/resume-staging", json=resume_payload)
    assert resume_response.status_code == 200
    
    resume_data = resume_response.json()
    assert resume_data["current_phase"] == "completed"
    assert resume_data["staging"]["status"] == "approved"
    assert resume_data["staging"]["reviewer_id"] == "test-reviewer@example.com"
    assert resume_data["staging"]["notes"] == "Verified against threat intelligence databases. Clean to deploy."
    assert resume_data["staging"]["final_outcome"] == "COMMIT_SUCCESS"
    assert "commit_id" in resume_data["staging"]


def test_full_rejection_containment_path():
    """
    Verify rejection flow:
      1. Ingest threat report -> returns session in STAGING_PENDING phase.
      2. Resume /reject -> transitions phase to error and quarantines artifacts.
    """
    # 1. Ingest threat intel
    payload = {
        "raw_threat_intel": "C2 activity detected to host 203.0.113.15."
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 201
    session_id = response.json()["session_id"]

    # 2. Resume with rejection
    resume_payload = {
        "session_id": session_id,
        "action": "Reject",
        "notes": "IP indicator is a known Cloudflare CDN node and represents a false positive."
    }
    resume_response = client.post("/resume-staging", json=resume_payload)
    assert resume_response.status_code == 200
    
    resume_data = resume_response.json()
    assert resume_data["current_phase"] == "error"
    assert resume_data["staging"]["status"] == "rejected"
    assert resume_data["staging"]["rejection_reason"] == "IP indicator is a known Cloudflare CDN node and represents a false positive."
    assert resume_data["staging"]["final_outcome"] == "CONTAINMENT_REJECTED"
    assert "containment_id" in resume_data["staging"]
    assert len(resume_data["staging"]["quarantined_artifacts"]) == 1
    assert resume_data["staging"]["quarantined_artifacts"][0]["reason"] == resume_payload["notes"]


def test_resume_missing_rejection_reason():
    """Verify that a rejection resume fails if rejection_reason (notes) is empty."""
    # Ingest threat intel
    payload = {
        "raw_threat_intel": "C2 activity detected to host 203.0.113.15."
    }
    response = client.post("/ingest", json=payload)
    session_id = response.json()["session_id"]

    # Resume with rejection, but omit notes
    resume_payload = {
        "session_id": session_id,
        "action": "Reject",
        "notes": ""
    }
    resume_response = client.post("/resume-staging", json=resume_payload)
    assert resume_response.status_code == 400
    assert "Notes must be provided as a rejection reason" in resume_response.json()["detail"]


def test_get_nonexistent_session():
    """Verify querying status for non-existent session returns 404."""
    response = client.get("/state?session_id=00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_emulated_mode_happy_path(monkeypatch):
    """Verify that the emulated fallback mode handles the happy path identically."""
    # Force emulation mode
    monkeypatch.setattr("main.LANGGRAPH_AVAILABLE", False)
    monkeypatch.setattr("main.compiled_graph", None)
    
    # 1. Ingest
    payload = {
        "raw_threat_intel": "Observed connection attempt to malicious IP 192.168.1.1 and domain attack-server.biz."
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    session_id = data["session_id"]
    assert session_id is not None
    assert data["current_phase"] == "staging"
    assert "STAGING_PENDING" in data["status_message"]
    assert data["rule_artifacts_count"] == 2

    # 2. Status
    status_response = client.get(f"/state?session_id={session_id}")
    assert status_response.status_code == 200
    assert status_response.json()["staging"]["status"] == "pending"

    # 3. Resume with approval
    resume_payload = {
        "session_id": session_id,
        "action": "Approve",
        "notes": "Emulated approval test."
    }
    resume_response = client.post("/resume-staging", json=resume_payload)
    assert resume_response.status_code == 200
    
    resume_data = resume_response.json()
    assert resume_data["current_phase"] == "completed"
    assert resume_data["staging"]["status"] == "approved"
    assert resume_data["staging"]["final_outcome"] == "COMMIT_SUCCESS"
    assert "commit_id" in resume_data["staging"]


def test_emulated_mode_rejection_path(monkeypatch):
    """Verify that the emulated fallback mode handles the rejection path identically."""
    # Force emulation mode
    monkeypatch.setattr("main.LANGGRAPH_AVAILABLE", False)
    monkeypatch.setattr("main.compiled_graph", None)
    
    # 1. Ingest
    payload = {
        "raw_threat_intel": "Observed connection attempt to malicious IP 192.168.1.2."
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 201
    session_id = response.json()["session_id"]

    # 2. Resume with rejection
    resume_payload = {
        "session_id": session_id,
        "action": "Reject",
        "notes": "Policy mismatch"
    }
    resume_response = client.post("/resume-staging", json=resume_payload)
    assert resume_response.status_code == 200
    
    resume_data = resume_response.json()
    assert resume_data["current_phase"] == "error"
    assert resume_data["staging"]["status"] == "rejected"
    assert resume_data["staging"]["final_outcome"] == "CONTAINMENT_REJECTED"
    assert "containment_id" in resume_data["staging"]


def test_unauthenticated_ingest():
    """Verify that calling /ingest without an Authorization header returns 401."""
    # Remove dependency overrides temporarily
    orig_overrides = app.dependency_overrides.copy()
    app.dependency_overrides.clear()
    try:
        payload = {
            "raw_threat_intel": "C2 activity detected."
        }
        response = client.post("/ingest", json=payload)
        assert response.status_code == 401
        assert "Authorization header is missing" in response.json()["detail"]
    finally:
        # Restore overrides
        app.dependency_overrides = orig_overrides


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
