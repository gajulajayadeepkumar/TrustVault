import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
from app.config import DATABASE_PATH, GENESIS_HASH

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

def init_db(db_path: Path = DATABASE_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('ADMIN', 'OWNER', 'VIEWER')),
        is_active INTEGER DEFAULT 1,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # Active Sessions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    """)

    # Documents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        file_hash_sha256 TEXT NOT NULL,
        owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # Document Permissions Table (Granular Access)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS document_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        permission_level TEXT NOT NULL CHECK(permission_level IN ('READ', 'EDIT')),
        granted_by INTEGER NOT NULL REFERENCES users(id),
        granted_at TEXT NOT NULL,
        UNIQUE(document_id, user_id)
    );
    """)

    # Tamper-Evident Audit Ledger (SHA-256 Hash Chained)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor_id INTEGER,
        actor_username TEXT,
        action_type TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT,
        outcome TEXT NOT NULL CHECK(outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
        details TEXT,
        ip_address TEXT,
        prev_hash TEXT NOT NULL,
        record_hash TEXT NOT NULL
    );
    """)

    # Create Indexes for Fast & Secure Lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_permissions_doc_user ON document_permissions(document_id, user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id);")

    # Seed Genesis Event in Audit Ledger if empty
    cursor.execute("SELECT COUNT(*) FROM audit_events;")
    if cursor.fetchone()[0] == 0:
        from app.audit import compute_record_hash
        now_utc = datetime.now(timezone.utc).isoformat()
        genesis_record_hash = compute_record_hash(
            prev_hash=GENESIS_HASH,
            record_id=1,
            timestamp=now_utc,
            actor_username="SYSTEM",
            action_type="GENESIS_ROOT",
            target_type="SYSTEM",
            target_id="0",
            outcome="SUCCESS",
            details="TrustVault Audit Ledger Initialized"
        )
        cursor.execute("""
            INSERT INTO audit_events 
            (id, timestamp, actor_id, actor_username, action_type, target_type, target_id, outcome, details, ip_address, prev_hash, record_hash)
            VALUES (1, ?, NULL, 'SYSTEM', 'GENESIS_ROOT', 'SYSTEM', '0', 'SUCCESS', 'TrustVault Audit Ledger Initialized', '127.0.0.1', ?, ?)
        """, (now_utc, GENESIS_HASH, genesis_record_hash))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at", DATABASE_PATH)
