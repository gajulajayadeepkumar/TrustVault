import time
import hashlib
from datetime import datetime, timezone
import sqlite3
from typing import Optional, Dict, Any, Tuple
from app.config import GENESIS_HASH

import threading

# Thread lock to serialize cryptographic hash chaining across concurrent worker threads
_audit_lock = threading.Lock()

def compute_record_hash(
    prev_hash: str,
    record_id: int,
    timestamp: str,
    actor_username: str,
    action_type: str,
    target_type: str,
    target_id: str,
    outcome: str,
    details: str
) -> str:
    """Computes deterministic SHA-256 hash for a tamper-evident audit record."""
    canonical_payload = (
        f"{prev_hash}:{record_id}:{timestamp}:{actor_username}:{action_type}:"
        f"{target_type}:{target_id}:{outcome}:{details}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

def log_audit_event(
    conn: sqlite3.Connection,
    action_type: str,
    target_type: str,
    target_id: Optional[str] = None,
    outcome: str = "SUCCESS",
    details: Optional[str] = None,
    actor_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> int:
    """
    Appends a new cryptographically chained record to the audit ledger.
    Serialized via _audit_lock to ensure mathematical chain continuity during concurrent requests.
    """
    with _audit_lock:
        cursor = conn.cursor()
        
        # Clean and sanitize strings (never log passwords or tokens)
        clean_details = (details or "").replace("\r", " ").replace("\n", " ").strip()
        clean_target_id = str(target_id or "")
        clean_actor_user = str(actor_username or "ANONYMOUS")
        clean_ip = str(ip_address or "UNKNOWN")
        now_utc = datetime.now(timezone.utc).isoformat()
        
        # Retrieve the last record in the chain
        cursor.execute("SELECT id, record_hash FROM audit_events ORDER BY id DESC LIMIT 1;")
        last_row = cursor.fetchone()
    
        if last_row:
            next_id = last_row["id"] + 1
            prev_hash = last_row["record_hash"]
        else:
            next_id = 1
            prev_hash = GENESIS_HASH
            
        record_hash = compute_record_hash(
            prev_hash=prev_hash,
            record_id=next_id,
            timestamp=now_utc,
            actor_username=clean_actor_user,
            action_type=action_type,
            target_type=target_type,
            target_id=clean_target_id,
            outcome=outcome,
            details=clean_details
        )
        
        cursor.execute("""
            INSERT INTO audit_events 
            (id, timestamp, actor_id, actor_username, action_type, target_type, target_id, outcome, details, ip_address, prev_hash, record_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            next_id, now_utc, actor_id, clean_actor_user, action_type,
            target_type, clean_target_id, outcome, clean_details, clean_ip,
            prev_hash, record_hash
        ))
        conn.commit()
        return next_id


def verify_audit_chain(conn: sqlite3.Connection) -> Tuple[bool, int, Optional[int], Optional[str], float]:
    """
    Verifies the entire cryptographic integrity of the audit ledger.
    Detects:
    1. Altered field values
    2. Missing / deleted records
    3. Reordered or injected records
    4. Invalid hashes or broken links
    Returns: (is_valid, total_events, broken_event_id, error_message, elapsed_time_ms)
    """
    start_time = time.perf_counter()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_events ORDER BY id ASC;")
    rows = cursor.fetchall()
    
    if not rows:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return True, 0, None, None, elapsed_ms

    expected_prev_hash = GENESIS_HASH
    expected_id = 1
    
    for row in rows:
        current_id = row["id"]
        # Check 1: Sequence continuity
        if current_id != expected_id:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return (
                False,
                len(rows),
                current_id,
                f"Sequence discontinuity: Expected ID {expected_id}, found ID {current_id}. Record was deleted or reordered.",
                elapsed_ms
            )
            
        # Check 2: Previous hash link
        if row["prev_hash"] != expected_prev_hash:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return (
                False,
                len(rows),
                current_id,
                f"Broken cryptographic hash linkage at record ID {current_id}: Expected prev_hash {expected_prev_hash[:16]}..., found {row['prev_hash'][:16]}...",
                elapsed_ms
            )
            
        # Check 3: Current record hash integrity
        expected_hash = compute_record_hash(
            prev_hash=row["prev_hash"],
            record_id=row["id"],
            timestamp=row["timestamp"],
            actor_username=row["actor_username"],
            action_type=row["action_type"],
            target_type=row["target_type"],
            target_id=str(row["target_id"] or ""),
            outcome=row["outcome"],
            details=row["details"] or ""
        )
        
        if row["record_hash"] != expected_hash:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return (
                False,
                len(rows),
                current_id,
                f"Tampered record payload at ID {current_id}: Calculated hash {expected_hash[:16]}... does not match stored hash {row['record_hash'][:16]}...",
                elapsed_ms
            )
            
        expected_prev_hash = row["record_hash"]
        expected_id += 1

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return True, len(rows), None, None, elapsed_ms
