import os
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, get_db_connection
from seed_data import seed

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Ensure test database is initialized and seeded before running tests."""
    seed(force=True)
    yield

@pytest.fixture
def client():
    """Returns FastAPI TestClient."""
    with TestClient(app) as test_client:
        yield test_client

def get_auth_token(client: TestClient, username: str, password: str) -> str:
    """Helper to login and retrieve bearer session token."""
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, f"Login failed for {username}: {response.text}"
    return response.json()["token"]

def get_auth_headers(client: TestClient, username: str, password: str) -> dict:
    """Helper to get Authorization headers for a specific user."""
    token = get_auth_token(client, username, password)
    return {"Authorization": f"Bearer {token}"}
