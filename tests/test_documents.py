import pytest
from fastapi.testclient import TestClient
from tests.conftest import get_auth_headers

def test_search_and_listing_leakage_prevented(client: TestClient):
    """
    THREAT-04 (Information Leakage via Search/Listing):
    Verifies that search, listings, and counts NEVER expose unauthorized documents.
    Doc 3 is Charlie's private Quantum Patent.
    Doc 1 is Alice's private Financial Report.
    Doc 2 is shared with Bob.
    Bob should ONLY see Doc 2 in listing and search.
    """
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    
    # 1. Bob lists all visible documents
    list_resp = client.get("/api/documents", headers=bob_headers)
    assert list_resp.status_code == 200
    docs = list_resp.json()
    doc_ids = [d["id"] for d in docs]
    assert 2 in doc_ids
    assert 1 not in doc_ids, "Alice's unshared document leaked in Bob's document list!"
    assert 3 not in doc_ids, "Charlie's unshared patent leaked in Bob's document list!"

    # 2. Bob searches specifically for 'Patent'
    search_resp = client.get("/api/documents?search=Patent", headers=bob_headers)
    assert search_resp.status_code == 200
    search_results = search_resp.json()
    assert len(search_results) == 0, "Unauthorized document leaked through search query!"

def test_mime_magic_bytes_spoofing_rejected(client: TestClient):
    """
    THREAT-06 (File Extension & MIME Spoofing):
    Attacker uploads a malicious file declaring Content-Type: application/pdf,
    but containing executable binary header or PHP script.
    """
    alice_headers = get_auth_headers(client, "owner_alice", "Alice@TrustVault2026!")
    
    # Fake PDF containing PHP code
    spoofed_php_content = b"<?php phpinfo(); ?>"
    files = {"file": ("exploit.pdf", spoofed_php_content, "application/pdf")}
    data = {"title": "Spoofed PHP Document", "category": "General"}
    
    resp = client.post("/api/documents/upload", files=files, data=data, headers=alice_headers)
    assert resp.status_code == 400
    assert "File content signature does not match declared MIME type" in resp.json()["detail"]

def test_disallowed_extension_rejected(client: TestClient):
    """Verifies that non-whitelisted extensions (e.g. .exe, .sh, .py) are rejected."""
    alice_headers = get_auth_headers(client, "owner_alice", "Alice@TrustVault2026!")
    
    files = {"file": ("malware.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/octet-stream")}
    data = {"title": "Malware Executable", "category": "General"}
    
    resp = client.post("/api/documents/upload", files=files, data=data, headers=alice_headers)
    assert resp.status_code == 400
    assert "Disallowed file extension" in resp.json()["detail"]

def test_path_traversal_sanitized(client: TestClient):
    """
    THREAT-05 (Path Traversal in Upload):
    Attacker passes traversal sequences in filename (e.g., ../../../../etc/passwd).
    Verifies that filename is sanitized and stored safely in vault.
    """
    alice_headers = get_auth_headers(client, "owner_alice", "Alice@TrustVault2026!")
    
    valid_pdf_bytes = b"%PDF-1.4 Safe Traversal Test Content"
    traversal_name = "../../../../etc/passwd.pdf"
    files = {"file": (traversal_name, valid_pdf_bytes, "application/pdf")}
    data = {"title": "Traversal Test Document", "category": "General"}
    
    resp = client.post("/api/documents/upload", files=files, data=data, headers=alice_headers)
    assert resp.status_code == 200
    data_out = resp.json()
    assert "../" not in data_out["filename"]
    assert data_out["filename"] == "passwd.pdf"
