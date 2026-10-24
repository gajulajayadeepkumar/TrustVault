"""
TrustVault Audit Trail Verification Utility (CLI)
Verifies the cryptographic integrity of the SHA-256 audit hash chain.
Detects altered rows, deleted events, missing sequences, and hash mismatch attacks.
"""
import sys
from app.database import get_db_connection
from app.audit import verify_audit_chain

def run_verification():
    print("=" * 65)
    print(" TRUSTVAULT AUDIT TRAIL INTEGRITY VERIFICATION UTILITY")
    print("=" * 65)
    print("Connecting to ledger database...")
    
    conn = get_db_connection()
    try:
        is_valid, total, broken_id, error_msg, elapsed_ms = verify_audit_chain(conn)
        print(f"Total Audit Events Inspected: {total}")
        print(f"Verification Duration:        {elapsed_ms:.2f} ms")
        print("-" * 65)
        
        if is_valid:
            print(" [PASS] Cryptographic Integrity VERIFIED.")
            print(" All SHA-256 hash chains, timestamps, and sequence numbers are untampered.")
            print("=" * 65)
            sys.exit(0)
        else:
            print(" [ALERT] TAMPERING DETECTED IN AUDIT LEDGER!")
            print(f" Corrupted / Broken Record ID: {broken_id}")
            print(f" Failure Reason:              {error_msg}")
            print("=" * 65)
            sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    run_verification()
