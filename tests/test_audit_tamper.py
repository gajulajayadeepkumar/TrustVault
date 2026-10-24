import pytest
from app.database import get_db_connection
from app.audit import verify_audit_chain
from fastapi.testclient import TestClient
from tests.conftest import get_auth_headers

def test_audit_chain_initially_valid():
    """Verifies that the audit ledger is cryptographically valid in its normal state."""
    conn = get_db_connection()
    try:
        is_valid, total, broken_id, error_msg, elapsed_ms = verify_audit_chain(conn)
        assert is_valid is True
        assert total > 0
        assert broken_id is None
        assert error_msg is None
    finally:
        conn.close()

def test_tamper_detection_altered_entry():
    """
    THREAT-08 (Audit Log Tampering - Modification):
    Simulates an attacker or malicious DBA modifying an audit record's payload directly in the database.
    Verifies that the cryptographic verification engine immediately detects the tampering and identifies the exact record ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Target Record ID 2 for tampering
    cursor.execute("SELECT id, details, record_hash FROM audit_events WHERE id = 2;")
    orig_row = cursor.fetchone()
    assert orig_row is not None
    orig_details = orig_row["details"]
    
    try:
        # Malicious DBA silently alters details in database
        cursor.execute("UPDATE audit_events SET details = 'TAMPERED: Altered audit details by rogue DBA' WHERE id = 2;")
        conn.commit()
        
        # Run verification engine
        is_valid, total, broken_id, error_msg, elapsed_ms = verify_audit_chain(conn)
        
        assert is_valid is False, "Verification engine failed to detect modified record payload!"
        assert broken_id == 2, f"Expected broken record ID 2, got {broken_id}"
        assert "Tampered record payload at ID 2" in error_msg
    finally:
        # Restore record to maintain test purity
        cursor.execute("UPDATE audit_events SET details = ? WHERE id = 2;", (orig_details,))
        conn.commit()
        conn.close()

def test_tamper_detection_deleted_entry():
    """
    THREAT-08 (Audit Log Tampering - Row Deletion):
    Simulates an attacker silently deleting an incriminating audit row from the database.
    Verifies that the verification engine detects the missing sequence / broken chain.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Save row 3 before deletion
    cursor.execute("SELECT * FROM audit_events WHERE id = 3;")
    orig_row3 = dict(cursor.fetchone())
    
    try:
        # Delete row 3
        cursor.execute("DELETE FROM audit_events WHERE id = 3;")
        conn.commit()
        
        # Run verification engine
        is_valid, total, broken_id, error_msg, elapsed_ms = verify_audit_chain(conn)
        
        assert is_valid is False, "Verification engine failed to detect deleted record!"
        assert "discontinuity" in error_msg or "Broken cryptographic hash linkage" in error_msg
    finally:
        # Restore row 3
        cols = list(orig_row3.keys())
        placeholders = ", ".join(["?"] * len(cols))
        cursor.execute(f"INSERT INTO audit_events ({', '.join(cols)}) VALUES ({placeholders})", list(orig_row3.values()))
        conn.commit()
        conn.close()

def test_operations_generate_audit_events(client: TestClient):
    """Verifies that security operations automatically log audit records without leaking secrets."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_events;")
    count_before = cursor.fetchone()[0]
    
    # Perform a denied access
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    client.get("/api/documents/1/download", headers=bob_headers)
    
    cursor.execute("SELECT COUNT(*) FROM audit_events;")
    count_after = cursor.fetchone()[0]
    assert count_after > count_before
    
    # Check the latest logged event
    cursor.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 1;")
    last_event = cursor.fetchone()
    assert last_event["action_type"] == "ACCESS_DENIED"
    assert last_event["actor_username"] == "viewer_bob"
    assert last_event["outcome"] == "DENIED"
    assert "password" not in last_event["details"].lower()
    assert "token" not in last_event["details"].lower()
    conn.close()
