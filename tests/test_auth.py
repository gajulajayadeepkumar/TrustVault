import pytest
from fastapi.testclient import TestClient
from tests.conftest import get_auth_headers

def test_login_success(client: TestClient):
    """Verifies that a valid user can log in and receive a session token."""
    response = client.post("/api/auth/login", json={
        "username": "owner_alice",
        "password": "Alice@TrustVault2026!"
    })
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert data["user"]["username"] == "owner_alice"
    assert data["user"]["role"] == "OWNER"

def test_login_invalid_password_fails(client: TestClient):
    """Verifies that invalid credentials return HTTP 401."""
    response = client.post("/api/auth/login", json={
        "username": "owner_alice",
        "password": "WrongPassword123!"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

def test_login_unknown_user_fails(client: TestClient):
    """Verifies that nonexistent users receive HTTP 401 with generic message (no enumeration)."""
    response = client.post("/api/auth/login", json={
        "username": "ghost_user_999",
        "password": "WrongPassword123!"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

def test_logout_invalidates_session(client: TestClient):
    """Verifies that logging out immediately invalidates subsequent requests."""
    headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    # 1. Access profile successfully
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    
    # 2. Log out
    logout_resp = client.post("/api/auth/logout", headers=headers)
    assert logout_resp.status_code == 200
    
    # 3. Subsequent request with invalidated token must be rejected
    rejected_resp = client.get("/api/auth/me", headers=headers)
    assert rejected_resp.status_code == 401

def test_mass_assignment_protection(client: TestClient):
    """Verifies that client cannot inject unexpected fields into Pydantic models."""
    response = client.post("/api/auth/login", json={
        "username": "owner_alice",
        "password": "Alice@TrustVault2026!",
        "role": "ADMIN",  # Forbidden extra field
        "is_admin": True  # Forbidden extra field
    })
    # Pydantic extra='forbid' returns 422 Unprocessable Entity
    assert response.status_code == 422
