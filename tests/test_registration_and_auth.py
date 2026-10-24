import pytest
from fastapi.testclient import TestClient
from app.csrf import generate_csrf_token

def test_registration_success(client: TestClient):
    """Verifies that a visitor can register a new account with email and password."""
    response = client.post("/api/auth/register", json={
        "full_name": "Marcus Vance",
        "email": "marcus.vance@example.com",
        "password": "SecurePassword2026!",
        "confirm_password": "SecurePassword2026!",
        "role": "OWNER"
    })
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "success"
    assert "token" in data
    assert data["user"]["email"] == "marcus.vance@example.com"
    assert data["user"]["full_name"] == "Marcus Vance"
    assert data["user"]["role"] == "OWNER"

def test_registration_duplicate_email_rejected(client: TestClient):
    """Verifies that duplicate email addresses are rejected case-insensitively."""
    # Attempt with existing demo email
    response = client.post("/api/auth/register", json={
        "full_name": "Alice Duplicate",
        "email": "ALICE@TRUSTVAULT.LOCAL",
        "password": "ValidPassword2026!",
        "confirm_password": "ValidPassword2026!",
        "role": "VIEWER"
    })
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"].lower()

def test_registration_weak_password_rejected(client: TestClient):
    """Verifies that weak passwords failing complexity rules are rejected."""
    # Too short (< 8 chars)
    resp_short = client.post("/api/auth/register", json={
        "full_name": "Test Short",
        "email": "short@example.com",
        "password": "Ab1!",
        "confirm_password": "Ab1!"
    })
    assert resp_short.status_code == 400
    assert "at least 8 characters" in resp_short.json()["detail"]

    # Missing uppercase
    resp_no_upper = client.post("/api/auth/register", json={
        "full_name": "Test NoUpper",
        "email": "noupper@example.com",
        "password": "password123!",
        "confirm_password": "password123!"
    })
    assert resp_no_upper.status_code == 400
    assert "uppercase" in resp_no_upper.json()["detail"]

    # Missing number
    resp_no_digit = client.post("/api/auth/register", json={
        "full_name": "Test NoDigit",
        "email": "nodigit@example.com",
        "password": "PasswordSpecial!",
        "confirm_password": "PasswordSpecial!"
    })
    assert resp_no_digit.status_code == 400
    assert "number" in resp_no_digit.json()["detail"]

    # Missing special character
    resp_no_special = client.post("/api/auth/register", json={
        "full_name": "Test NoSpecial",
        "email": "nospecial@example.com",
        "password": "Password12345",
        "confirm_password": "Password12345"
    })
    assert resp_no_special.status_code == 400
    assert "special character" in resp_no_special.json()["detail"]

def test_registration_password_mismatch_rejected(client: TestClient):
    """Verifies that mismatched confirm password returns HTTP 400."""
    response = client.post("/api/auth/register", json={
        "full_name": "Test Mismatch",
        "email": "mismatch@example.com",
        "password": "ValidPassword2026!",
        "confirm_password": "DifferentPassword2026!"
    })
    assert response.status_code == 400
    assert "passwords do not match" in response.json()["detail"].lower()

def test_registration_admin_role_strictly_forbidden(client: TestClient):
    """Verifies that public users cannot select or register themselves as ADMIN."""
    response = client.post("/api/auth/register", json={
        "full_name": "Malicious Admin",
        "email": "attacker@example.com",
        "password": "AttackerPassword2026!",
        "confirm_password": "AttackerPassword2026!",
        "role": "ADMIN"
    })
    assert response.status_code == 403
    assert "administrator accounts cannot be self-registered" in response.json()["detail"].lower()

def test_login_with_email_success(client: TestClient):
    """Verifies signing in using email address and password."""
    response = client.post("/api/auth/login", json={
        "email": "alice@trustvault.local",
        "password": "Alice@TrustVault2026!"
    })
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert data["user"]["email"] == "alice@trustvault.local"
    assert data["user"]["role"] == "OWNER"

def test_login_invalid_password_returns_401(client: TestClient):
    """Verifies that invalid password returns generic 401 without exposing details."""
    response = client.post("/api/auth/login", json={
        "email": "alice@trustvault.local",
        "password": "IncorrectPassword999!"
    })
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower() and "password" in response.json()["detail"].lower()

def test_login_nonexistent_email_returns_401(client: TestClient):
    """Verifies that nonexistent email returns 401 without enumeration leakage."""
    response = client.post("/api/auth/login", json={
        "email": "ghost.user@nonexistent.org",
        "password": "SomePassword123!"
    })
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower() and "password" in response.json()["detail"].lower()

def test_csrf_token_issuance_and_validation(client: TestClient):
    """Verifies that CSRF endpoint issues tokens and valid tokens pass."""
    csrf_resp = client.get("/api/auth/csrf-token")
    assert csrf_resp.status_code == 200
    csrf_token = csrf_resp.json()["csrf_token"]
    assert len(csrf_token) > 20

    # Registration with valid CSRF token passes
    reg_resp = client.post("/api/auth/register", json={
        "full_name": "CSRF Test User",
        "email": "csrf.user@example.com",
        "password": "CsrfPassword2026!",
        "confirm_password": "CsrfPassword2026!",
        "csrf_token": csrf_token
    })
    assert reg_resp.status_code == 200

def test_unauthenticated_protected_route_denied(client: TestClient):
    """Verifies that unauthenticated visitors cannot access documents or admin telemetry."""
    doc_resp = client.get("/api/documents")
    assert doc_resp.status_code == 401

    admin_resp = client.get("/api/admin/metrics")
    assert admin_resp.status_code == 401
