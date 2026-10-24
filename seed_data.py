"""
TrustVault Database Seeder
Populates initial roles, demo accounts, sample confidential documents, and permissions.
"""
import os
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Safe fallback for build-time or non-runtime CLI execution
os.environ.setdefault("TRUSTVAULT_SECRET_KEY", "build-temporary-seed-key-trustvault")

from app.config import STORAGE_VAULT_DIR, DATABASE_PATH
from app.database import init_db, get_db_connection
from app.security import hash_password
from app.audit import log_audit_event

def seed(force: bool = False):
    print("Initializing Database schema...")
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users;")
    user_count = cursor.fetchone()[0]

    if user_count > 0 and not force:
        print(f"Database already populated ({user_count} users). Skipping destructive seed to preserve data.")
        conn.close()
        return

    # Clear existing data for fresh reproducible setup when forced
    cursor.execute("DELETE FROM document_permissions;")
    cursor.execute("DELETE FROM documents;")
    cursor.execute("DELETE FROM sessions;")
    cursor.execute("DELETE FROM users;")
    cursor.execute("DELETE FROM audit_events;")
    cursor.execute("DELETE FROM sqlite_sequence;")
    conn.commit()

    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Seed Demo Accounts
    users_to_seed = [
        {
            "username": "admin",
            "full_name": "System Administrator",
            "email": "admin@trustvault.local",
            "password": "Admin@TrustVault2026!",
            "role": "ADMIN",
            "desc": "System & Security Administrator (Cannot view unshared files)"
        },
        {
            "username": "owner_alice",
            "full_name": "Alice Document Owner",
            "email": "alice@trustvault.local",
            "password": "Alice@TrustVault2026!",
            "role": "OWNER",
            "desc": "Document Owner (Full control over owned documents & sharing)"
        },
        {
            "username": "viewer_bob",
            "full_name": "Bob Restricted Viewer",
            "email": "bob@trustvault.local",
            "password": "Bob@TrustVault2026!",
            "role": "VIEWER",
            "desc": "Restricted Viewer (Read-only access to specifically shared files)"
        },
        {
            "username": "charlie",
            "full_name": "Charlie Engineer",
            "email": "charlie@trustvault.local",
            "password": "Charlie@TrustVault2026!",
            "role": "OWNER",
            "desc": "Independent Document Owner (Used for cross-tenant isolation testing)"
        }
    ]

    user_ids = {}
    for u in users_to_seed:
        pw_hash = hash_password(u["password"])
        cursor.execute("""
            INSERT INTO users (username, full_name, email, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """, (u["username"], u["full_name"], u["email"], pw_hash, u["role"], now_utc, now_utc))
        user_ids[u["username"]] = cursor.lastrowid
        print(f"Created user: {u['username']} ({u['role']})")

    conn.commit()

    # 2. Seed Sample Files in Private Storage Vault
    sample_docs = [
        {
            "title": "Q3 Executive Financial Audit Report",
            "description": "Confidential corporate quarterly revenue breakdown and audit statements.",
            "category": "Finance",
            "filename": "Q3_Financial_Audit_Report.pdf",
            "content": b"%PDF-1.5 TrustVault Confidential Financial Report\nQ3 Revenue: $42,500,000 USD\nStatus: Strictly Confidential",
            "mime": "application/pdf",
            "owner": "owner_alice"
        },
        {
            "title": "Enterprise Security & Access Policy 2026",
            "description": "Standard company information security policies and guidelines for personnel.",
            "category": "Legal",
            "filename": "Enterprise_Security_Policy_2026.docx",
            "content": b"PK\x03\x04TrustVault Enterprise Security Policy 2026\nMandatory zero-trust protocols.",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "owner": "owner_alice"
        },
        {
            "title": "Quantum Cryptography Patent Draft",
            "description": "Proprietary research on post-quantum lattice encryption keys.",
            "category": "Engineering",
            "filename": "Quantum_Crypto_Patent_Draft.pdf",
            "content": b"%PDF-1.4 Proprietary Patent Specification\nInventor: Charlie\nDo Not Distribute.",
            "mime": "application/pdf",
            "owner": "charlie"
        }
    ]

    doc_ids = {}
    for doc in sample_docs:
        # Write to storage vault with UUID filename
        stored_uuid = f"{uuid.uuid4().hex}.dat"
        vault_path = STORAGE_VAULT_DIR / stored_uuid
        with open(vault_path, "wb") as f:
            f.write(doc["content"])

        file_size = len(doc["content"])
        sha256 = hashlib.sha256(doc["content"]).hexdigest()
        owner_id = user_ids[doc["owner"]]

        cursor.execute("""
            INSERT INTO documents 
            (title, description, category, original_filename, stored_filename, file_size, mime_type, file_hash_sha256, owner_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            doc["title"],
            doc["description"],
            doc["category"],
            doc["filename"],
            stored_uuid,
            file_size,
            doc["mime"],
            sha256,
            owner_id,
            now_utc,
            now_utc
        ))
        doc_id = cursor.lastrowid
        doc_ids[doc["filename"]] = doc_id

        log_audit_event(
            conn=conn,
            action_type="DOC_UPLOAD",
            target_type="DOCUMENT",
            target_id=str(doc_id),
            outcome="SUCCESS",
            details=f"Seeded document '{doc['title']}' ({doc['filename']})",
            actor_id=owner_id,
            actor_username=doc["owner"],
            ip_address="127.0.0.1"
        )
        print(f"Uploaded sample doc: {doc['title']} (Owner: {doc['owner']})")

    # 3. Grant Explicit Read Permission:
    # owner_alice shares 'Enterprise_Security_Policy_2026.docx' with viewer_bob (READ)
    alice_id = user_ids["owner_alice"]
    bob_id = user_ids["viewer_bob"]
    policy_doc_id = doc_ids["Enterprise_Security_Policy_2026.docx"]

    cursor.execute("""
        INSERT INTO document_permissions (document_id, user_id, permission_level, granted_by, granted_at)
        VALUES (?, ?, 'READ', ?, ?)
    """, (policy_doc_id, bob_id, alice_id, now_utc))
    conn.commit()

    log_audit_event(
        conn=conn,
        action_type="PERM_GRANT",
        target_type="PERMISSION",
        target_id=str(policy_doc_id),
        outcome="SUCCESS",
        details=f"Owner 'owner_alice' granted READ permission to 'viewer_bob' on 'Enterprise_Security_Policy_2026.docx'",
        actor_id=alice_id,
        actor_username="owner_alice",
        ip_address="127.0.0.1"
    )
    print("Granted READ permission for 'Enterprise_Security_Policy_2026.docx' to viewer_bob")

    conn.close()
    print("\n--- TrustVault Seed Completed Successfully! ---")

if __name__ == "__main__":
    force_seed = "--force" in sys.argv
    seed(force=force_seed)
