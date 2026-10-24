import pytest
from fastapi.testclient import TestClient
from tests.conftest import get_auth_headers

def test_immediate_revocation_enforced(client: TestClient):
    """
    THREAT-07 (Stale Permissions / Immediate Revocation):
    Verifies that when an owner revokes access, subsequent requests are DENIED IMMEDIATELY.
    No cached tokens or stale permissions survive revocation.
    """
    charlie_headers = get_auth_headers(client, "charlie", "Charlie@TrustVault2026!")
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    # 1. Charlie uploads a new confidential document
    files = {"file": ("charlie_secret.pdf", b"%PDF-1.4 Charlie Secret Research", "application/pdf")}
    data = {"title": "Charlie Secret Project", "category": "Engineering"}
    up_resp = client.post("/api/documents/upload", files=files, data=data, headers=charlie_headers)
    assert up_resp.status_code == 200
    doc_id = up_resp.json()["document_id"]

    # 2. Bob attempts to download Charlie's document -> Blocked (403)
    bob_resp1 = client.get(f"/api/documents/{doc_id}/download", headers=bob_headers)
    assert bob_resp1.status_code == 403

    # 3. Charlie grants Bob READ permission
    grant_resp = client.post(
        f"/api/documents/{doc_id}/permissions",
        json={"target_username": "viewer_bob", "permission_level": "READ"},
        headers=charlie_headers
    )
    assert grant_resp.status_code == 200

    # 4. Bob downloads document -> Allowed (200)
    bob_resp2 = client.get(f"/api/documents/{doc_id}/download", headers=bob_headers)
    assert bob_resp2.status_code == 200
    assert b"Charlie Secret Research" in bob_resp2.content

    # 5. Charlie IMMEDIATELY revokes Bob's permission
    # First get Bob's user ID
    user_me = client.get("/api/auth/me", headers=bob_headers).json()
    bob_user_id = user_me["id"]

    revoke_resp = client.delete(f"/api/documents/{doc_id}/permissions/{bob_user_id}", headers=charlie_headers)
    assert revoke_resp.status_code == 200

    # 6. Bob IMMEDIATELY attempts to download again -> Must be DENIED (403)
    bob_resp3 = client.get(f"/api/documents/{doc_id}/download", headers=bob_headers)
    assert bob_resp3.status_code == 403
    assert "Access denied" in bob_resp3.json()["detail"]

def test_non_owner_cannot_grant_or_revoke_permissions(client: TestClient):
    """Verifies that only document owners can manage permissions."""
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    # Bob attempts to grant permission on Alice's document (Doc ID 2)
    resp = client.post(
        "/api/documents/2/permissions",
        json={"target_username": "charlie", "permission_level": "READ"},
        headers=bob_headers
    )
    assert resp.status_code == 403
    assert "Only the document owner can grant or revoke permissions" in resp.json()["detail"]
