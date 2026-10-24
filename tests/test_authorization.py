import pytest
from fastapi.testclient import TestClient
from tests.conftest import get_auth_headers

def test_idor_unshared_document_access_blocked(client: TestClient):
    """
    THREAT-01 (BOLA/IDOR):
    Verifies that a user (Bob) cannot view or download another user's (Alice's) unshared document.
    Doc ID 1 is Alice's confidential Q3 Financial Report.
    """
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    # 1. Attempt to view metadata
    view_resp = client.get("/api/documents/1", headers=bob_headers)
    assert view_resp.status_code == 403
    assert "Access denied" in view_resp.json()["detail"]
    
    # 2. Attempt to download file
    dl_resp = client.get("/api/documents/1/download", headers=bob_headers)
    assert dl_resp.status_code == 403
    assert "Access denied" in dl_resp.json()["detail"]

def test_admin_cannot_access_unshared_document_contents(client: TestClient):
    """
    THREAT-02 (Admin Privilege Boundary / Admin Blindness Rule):
    Verifies that an Administrator CANNOT read, preview, or download confidential documents
    that are not explicitly shared with the admin.
    """
    admin_headers = get_auth_headers(client, "admin", "Admin@TrustVault2026!")
    
    # Admin attempts to read Alice's unshared financial report (Doc ID 1)
    view_resp = client.get("/api/documents/1", headers=admin_headers)
    assert view_resp.status_code == 403
    assert "ADMIN role does not bypass confidential document privacy" in view_resp.json()["detail"]
    
    # Admin attempts to download Alice's unshared financial report (Doc ID 1)
    dl_resp = client.get("/api/documents/1/download", headers=admin_headers)
    assert dl_resp.status_code == 403
    assert "ADMIN role does not bypass confidential document privacy" in dl_resp.json()["detail"]

def test_viewer_cannot_edit_or_delete_document(client: TestClient):
    """
    THREAT-03 (Unauthorized Modification):
    Bob has READ permission on Doc ID 2 (Enterprise Security Policy).
    Verifies that Bob CANNOT edit or delete this document.
    """
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    # Bob can view metadata
    read_resp = client.get("/api/documents/2", headers=bob_headers)
    assert read_resp.status_code == 200
    assert read_resp.json()["user_permission"] == "READ"
    
    # Bob attempts to EDIT metadata
    edit_resp = client.put("/api/documents/2", json={"title": "Hacked Title"}, headers=bob_headers)
    assert edit_resp.status_code == 403
    assert "requires 'EDIT' permission" in edit_resp.json()["detail"]
    
    # Bob attempts to DELETE document
    del_resp = client.delete("/api/documents/2", headers=bob_headers)
    assert del_resp.status_code == 403
    assert "Only the document owner has permission to delete" in del_resp.json()["detail"]

def test_viewer_cannot_upload_root_document(client: TestClient):
    """
    Verifies that users with the VIEWER role are strictly read-only and blocked from uploading.
    """
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    files = {"file": ("test.pdf", b"%PDF-1.4 dummy", "application/pdf")}
    data = {"title": "Viewer Upload Attempt", "category": "General"}
    
    resp = client.post("/api/documents/upload", files=files, data=data, headers=bob_headers)
    assert resp.status_code == 403
    assert "VIEWER accounts are read-only" in resp.json()["detail"]

def test_unauthenticated_request_denied_by_default(client: TestClient):
    """Verifies that requests without authentication token are denied with HTTP 401."""
    resp = client.get("/api/documents")
    assert resp.status_code == 401
